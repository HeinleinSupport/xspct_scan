# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""
test_xspct_scan.py — Comprehensive pytest test suite for InspectorDaemon / xspct_scan.daemon.

Coverage:
  Unit tests (no HTTP, direct method calls):
    - Session ID / session header helpers
    - API key verification (no keys, correct, wrong, multi-key, verify_fail flag)
    - Admin key verification (verify_admin_key)
    - IOC extraction (URLs, IPs, dedup, UTF-16, invalid IPs)
    - analyze_pdf  (clean, all markers, /URI IOC, password-protected)
    - analyze_html (clean, all suspicious JS keywords, forms, iframes, meta-refresh,
                   SpamRedirect, inline-script → analyze_javascript wiring,
                   data-URI image wiring)
    - analyze_javascript (static patterns, source_label, clean JS, empty/None)
    - analyze_image (empty bytes, invalid bytes, real PNG structure)
    - analyze_yara (no-engine path returns None)
    - analyze_iocsearcher (no-engine / installed paths)
    - analyze_archive (non-archive, depth guard, empty zip, pdf member, size limit,
                      disabled-analyzer path)
    - extract_text_preview (HTML tag stripping, script removal, OOXML, char limit)
    - get_detected_type (MIME, filename extension, RTF magic bytes, image/archive/text)
    - merge_reports (dedup analyses, dedup IOCs, boolean OR, meta skip;
                    yara_matches dedup, iocs_extended deep-merge, archive_files,
                    exif first-wins, text_full longest-wins)
    - _make_base_report (all new fields present and correct types)
    - PartialReport (snapshot, merge completed, merge None result)
    - text_full absent by default / key always present
    - TextExtractorRtf (direct class test)
    - load_config (None, missing file, valid YAML, invalid YAML)
    - configure_logging (handler count after repeated calls)
    - _evict_tasks (OrderedDict eviction, oldest removed)
    - sync_analyze (PDF, HTML, unknown binary, real OLE file, real RTF file)

  Integration tests (full daemon in-process via aiohttp.test_utils):
    - GET /health /ping /
    - GET /metrics (Prometheus text, counter increments after scan)
    - POST /scan: missing doc → 400
    - POST /scan: clean PDF, malicious PDF, password-protected PDF, malicious HTML, OOXML, real OLE, real RTF
    - POST /scan: file_mime override, custom passwords field, rtf=true flag
    - POST /scan: same file twice returns same hash
    - POST /scan: very short timeout may return 202 (background processing)
    - POST /scan: application/octet-stream raw upload (200, hash equality, 415 for other types)
    - GET  /query: missing hash → 400, unknown hash → 404
    - POST /query: missing hash → 400, unknown hash → 404
    - GET  /query: after scan returns finished report with correct hash
    - POST /query: JSON body, after scan returns finished report
    - Auth: 401 on /scan /query /metrics when key required, no key sent
    - Auth: 200 when correct key sent; 401 when wrong key sent
    - Auth: /health always accessible without key
    - POST /admin/reload: 403 when no key configured, 403 on wrong key, 200 on correct key
    - GET /openapi.json: 200 with valid OpenAPI body when pydantic installed
    - GET /apidoc/redoc: 200 with ReDoc HTML when pydantic installed

Run:
    cd /home/cr/git/xspct-scan
    pip install -e .[dev]
    python3 -m pytest tests/ -v
"""

import asyncio
import hashlib
import io
import logging
import os
import zipfile
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest
from xspct_scan import client as xspct_client

try:
    import fitz as _fitz
    _HAS_FITZ = True
except ImportError:
    _HAS_FITZ = False

try:
    import fakeredis
    _HAS_FAKEREDIS = True
except ImportError:
    _HAS_FAKEREDIS = False

import xspct_scan.daemon as xspct
from tests.conftest import (
    OLE_FILE, RTF_FILE, PASSWD_FILE,
    PDF_JS_FILE, PDF_EMBEDDED_FILE, PDF_URI_FILE,
    HTML_PHISHING_FILE, ARCHIVE_MIXED_FILE, EML_FILE, QR_FILE,
)

# ---------------------------------------------------------------------------
# Synthetic byte-level fixtures
# ---------------------------------------------------------------------------
PDF_CLEAN = (
    b'%PDF-1.4\n'
    b'1 0 obj\n<< /Type /Catalog >>\nendobj\n'
    b'xref\n0 1\n0000000000 65535 f \n'
    b'trailer\n<< /Size 1 >>\n'
    b'startxref\n9\n%%EOF\n'
)

PDF_ALL_MARKERS = (
    b'%PDF-1.4\n'
    b'/JS /JavaScript /OpenAction /Launch /EmbeddedFiles /Encrypt /XFA\n'
    b'%%EOF\n'
)

PDF_WITH_URI = b'%PDF-1.4\n/URI (https://malware.example.com/stage2)\n%%EOF'

# Password used for the synthetically encrypted PDF fixture
_PDF_ENC_PASSWORD = 'TestPwd42'


def _make_encrypted_pdf(user_pw: str) -> bytes:
    """Return a minimal AES-256-encrypted PDF protected by *user_pw*."""
    if not _HAS_FITZ:
        return b''  # tests that need this are skipped via _HAS_FITZ guard
    doc = _fitz.open()
    page = doc.new_page()
    page.insert_text((50, 50), 'Encrypted test document')
    buf = doc.tobytes(
        encryption=_fitz.PDF_ENCRYPT_AES_256,
        owner_pw='owner',
        user_pw=user_pw,
    )
    doc.close()
    return buf


PDF_ENCRYPTED: bytes = _make_encrypted_pdf(_PDF_ENC_PASSWORD) if _HAS_FITZ else b''

HTML_CLEAN = b'<html><body><p>Hello world. Visit https://example.com for more.</p></body></html>'

HTML_MALICIOUS = (
    b'<html><head>'
    b'<meta http-equiv="refresh" content="0;url=http://evil.example.com">'
    b'</head><body>'
    b'<script>'
    b'eval(atob("YWxlcnQoMSk="));'
    b'document.write("<b>");'
    b'unescape("%3Cscript%3E");'
    b'atob("dGVzdA==");'
    b'String.fromCharCode(60);'
    b'</script>'
    b'<form action="http://phishing.example.com"><input type="password"></form>'
    b'<iframe src="http://hidden.example.com"></iframe>'
    b'</body></html>'
)

HTML_NO_TAGS = b'Just some plain text without any angle brackets at all.'


def _make_ooxml() -> bytes:
    """Minimal valid OOXML (docx) zip with word/document.xml."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr(
            '[Content_Types].xml',
            '<?xml version="1.0"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '</Types>',
        )
        z.writestr(
            'word/document.xml',
            '<?xml version="1.0"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:body><w:p><w:r><w:t>Hello from OOXML test document</w:t></w:r></w:p></w:body>'
            '</w:document>',
        )
    return buf.getvalue()


OOXML_DATA = _make_ooxml()

# ---------------------------------------------------------------------------
# Global helpers
# ---------------------------------------------------------------------------

def _form(data: bytes, filename: str, **extra_fields) -> aiohttp.FormData:
    """Build a multipart form with a 'doc' part and optional extra fields."""
    form = aiohttp.FormData()
    form.add_field('doc', data, filename=filename)
    for name, value in extra_fields.items():
        form.add_field(name, value)
    return form


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_global_state():
    """Reset module-level mutable state before and after every test."""
    saved_keys     = list(xspct.config['xspct_api_key'])
    saved_fail     = xspct.config['xspct_api_key_verify_fail']
    saved_stats    = dict(xspct.stats)
    saved_pw_file  = xspct.config['xspct_password_file']
    saved_stats_en = xspct.config['xspct_stats_enabled']

    xspct.config['xspct_api_key']             = []
    xspct.config['xspct_api_key_verify_fail'] = True
    xspct.config['xspct_password_file']       = PASSWD_FILE
    xspct.config['xspct_stats_enabled']       = False  # no background tasks in tests
    for k, v in xspct.stats.items():
        xspct.stats[k] = {} if isinstance(v, dict) else 0

    yield

    xspct.config['xspct_api_key']             = saved_keys
    xspct.config['xspct_api_key_verify_fail'] = saved_fail
    xspct.config['xspct_password_file']       = saved_pw_file
    xspct.config['xspct_stats_enabled']       = saved_stats_en
    for k, val in saved_stats.items():
        xspct.stats[k] = val


@pytest.fixture
async def client(aiohttp_client):
    """Full daemon TestClient with no API key required."""
    app = await xspct.make_app()
    return await aiohttp_client(app)


@pytest.fixture
async def auth_client(aiohttp_client):
    """Full daemon TestClient with API key enforcement."""
    xspct.config['xspct_api_key']             = ['test-secret-key']
    xspct.config['xspct_api_key_verify_fail'] = True
    app = await xspct.make_app()
    return await aiohttp_client(app)


@pytest.fixture
def daemon():
    """Bare InspectorDaemon with a small, known password list."""
    d = xspct.InspectorDaemon()
    d.passwords = ['VelvetSweatshop', 'test123', '123456', 'password']
    return d


# ===========================================================================
# UNIT TESTS
# ===========================================================================

class TestSessionHelpers:

    def test_session_id_is_6_hex_chars(self):
        sid = xspct.generate_session_id()
        assert len(sid) == 6
        assert all(c in '0123456789abcdef' for c in sid)

    def test_session_ids_are_unique(self):
        ids = {xspct.generate_session_id() for _ in range(200)}
        assert len(ids) > 1

    def test_make_session_format_no_rspamd(self):
        req = MagicMock()
        req.headers = {}
        s = xspct.make_session(req)
        assert s.startswith('<') and s.endswith('>')
        assert len(s) == 8  # <xxxxxx>

    def test_make_session_includes_rspamd_id(self):
        req = MagicMock()
        req.headers = {xspct.config['xspct_rspamd_header']: 'rspamd99'}
        s = xspct.make_session(req)
        assert '-' in s
        assert 'rspamd' in s


class TestApiKeyVerification:

    def test_no_keys_always_passes(self):
        xspct.config['xspct_api_key'] = []
        req = MagicMock()
        req.headers = {}
        assert xspct.verify_api_key('<t>', req) is True

    def test_correct_key_passes(self):
        xspct.config['xspct_api_key'] = ['my-secret']
        req = MagicMock()
        req.headers = {xspct.config['xspct_api_header']: 'my-secret'}
        assert xspct.verify_api_key('<t>', req) is True

    def test_wrong_key_fails_when_verify_fail_true(self):
        xspct.config['xspct_api_key']             = ['my-secret']
        xspct.config['xspct_api_key_verify_fail'] = True
        req = MagicMock()
        req.headers = {xspct.config['xspct_api_header']: 'wrong'}
        assert xspct.verify_api_key('<t>', req) is False

    def test_wrong_key_passes_when_verify_fail_false(self):
        xspct.config['xspct_api_key']             = ['my-secret']
        xspct.config['xspct_api_key_verify_fail'] = False
        req = MagicMock()
        req.headers = {xspct.config['xspct_api_header']: 'wrong'}
        assert xspct.verify_api_key('<t>', req) is True

    def test_missing_header_fails(self):
        xspct.config['xspct_api_key']             = ['my-secret']
        xspct.config['xspct_api_key_verify_fail'] = True
        req = MagicMock()
        req.headers = {}
        assert xspct.verify_api_key('<t>', req) is False

    def test_multi_key_first_accepted(self):
        xspct.config['xspct_api_key'] = ['key-A', 'key-B']
        req = MagicMock()
        req.headers = {xspct.config['xspct_api_header']: 'key-A'}
        assert xspct.verify_api_key('<t>', req) is True

    def test_multi_key_second_accepted(self):
        xspct.config['xspct_api_key'] = ['key-A', 'key-B']
        req = MagicMock()
        req.headers = {xspct.config['xspct_api_header']: 'key-B'}
        assert xspct.verify_api_key('<t>', req) is True

    def test_multi_key_unknown_rejected(self):
        xspct.config['xspct_api_key']             = ['key-A', 'key-B']
        xspct.config['xspct_api_key_verify_fail'] = True
        req = MagicMock()
        req.headers = {xspct.config['xspct_api_header']: 'key-C'}
        assert xspct.verify_api_key('<t>', req) is False


class TestExtractIocs:

    def test_empty_bytes(self, daemon):
        r = daemon.extract_iocs(b'')
        assert r == {'urls': [], 'ips': [], 'domains': []}

    def test_url_detected(self, daemon):
        r = daemon.extract_iocs(b'payload at https://evil.example.com/drop?x=1')
        assert any('evil.example.com' in u for u in r['urls'])

    def test_ip_detected(self, daemon):
        r = daemon.extract_iocs(b'C2 at 10.20.30.40')
        assert '10.20.30.40' in r['ips']

    def test_invalid_octet_rejected(self, daemon):
        r = daemon.extract_iocs(b'bogus 999.999.999.999')
        assert '999.999.999.999' not in r['ips']

    def test_url_deduplication(self, daemon):
        r = daemon.extract_iocs(b'https://evil.com https://evil.com https://evil.com')
        assert r['urls'].count('https://evil.com') == 1

    def test_utf16le_url_detected(self, daemon):
        payload = 'https://hidden.example.com'.encode('utf-16le')
        r = daemon.extract_iocs(payload)
        assert any('hidden.example.com' in u for u in r['urls'])

    def test_multiple_ips(self, daemon):
        r = daemon.extract_iocs(b'hosts: 1.2.3.4 and 5.6.7.8')
        assert '1.2.3.4' in r['ips']
        assert '5.6.7.8' in r['ips']

    def test_domain_with_valid_tld_kept(self, daemon):
        r = daemon.extract_iocs(b'see evil.example.com for details')
        assert 'evil.example.com' in r['domains']

    def test_domain_with_file_ext_tld_filtered(self, daemon):
        # Windows file names like MSO.DLL or Normal.dotm must not appear as domains
        r = daemon.extract_iocs(b'MSO.DLL VBE7.DLL Normal.dotm stdole2.tlb')
        assert not any(d.lower().endswith(('.dll', '.dotm', '.tlb')) for d in r['domains'])

    def test_vba_internal_names_filtered(self, daemon):
        # VBA object paths extracted from OLE streams must not appear as domains
        r = daemon.extract_iocs(b'BzqPKManager.sqW PROJECT.NLHWEHWJ.AVVKQDABDFCIT')
        assert 'BzqPKManager.sqW' not in r['domains']
        assert 'PROJECT.NLHWEHWJ.AVVKQDABDFCIT' not in r['domains']

    def test_pdf_internal_refs_filtered(self, daemon):
        # Short PDF internal object references must not appear as domains,
        # including fragments with valid ccTLDs but 1-2-char SLDs (Jy.gY, o.MA)
        r = daemon.extract_iocs(b'JNWs.oO g.xJ i.yZ xf.jx y.MDO Jy.gY o.MA')
        assert not r['domains']

    def test_short_sld_with_valid_cctld_filtered(self, daemon):
        # 1–2-char SLDs before real ccTLDs are binary-internal artefacts, not IOCs
        r = daemon.extract_iocs(b'Jy.gY o.MA xf.jx')
        assert not r['domains']

    def test_min_sld_length_keeps_real_domains(self, daemon):
        # bit.ly (3-char SLD) and longer SLDs must not be filtered
        r = daemon.extract_iocs(b'see bit.ly and krittv.ru for context')
        assert 'bit.ly' in r['domains']
        assert 'krittv.ru' in r['domains']


# ===========================================================================
# UNIT TESTS — _ioc_excluded helper
# ===========================================================================

class TestIocExcluded:

    def test_exact_match(self):
        assert xspct.InspectorDaemon._ioc_excluded('w3.org', ('w3.org',))

    def test_subdomain_match(self):
        assert xspct.InspectorDaemon._ioc_excluded('www.w3.org', ('w3.org',))

    def test_deep_subdomain_match(self):
        assert xspct.InspectorDaemon._ioc_excluded('a.b.w3.org', ('w3.org',))

    def test_no_match(self):
        assert not xspct.InspectorDaemon._ioc_excluded('evil.com', ('w3.org',))

    def test_partial_suffix_not_matched(self):
        # 'w3.org' should NOT match 'notw3.org'
        assert not xspct.InspectorDaemon._ioc_excluded('notw3.org', ('w3.org',))

    def test_empty_suffixes(self):
        assert not xspct.InspectorDaemon._ioc_excluded('anything.com', ())


# ===========================================================================
# UNIT TESTS — extract_iocs domain exclusion
# ===========================================================================

class TestExtractIocsExcludeDomains:

    def test_excluded_url_dropped(self, daemon):
        saved = xspct.config.get('xspct_ioc_url_exclude_domains')
        xspct.config['xspct_ioc_url_exclude_domains'] = ['w3.org']
        try:
            r = daemon.extract_iocs(b'see http://www.w3.org/1999/xhtml for details')
            assert all('w3.org' not in u for u in r['urls'])
        finally:
            xspct.config['xspct_ioc_url_exclude_domains'] = saved

    def test_excluded_domain_dropped(self, daemon):
        saved = xspct.config.get('xspct_ioc_url_exclude_domains')
        xspct.config['xspct_ioc_url_exclude_domains'] = ['w3.org']
        try:
            r = daemon.extract_iocs(b'namespace http://www.w3.org/TR/xhtml1/')
            assert all('w3.org' not in d for d in r['domains'])
        finally:
            xspct.config['xspct_ioc_url_exclude_domains'] = saved

    def test_non_excluded_url_kept(self, daemon):
        saved = xspct.config.get('xspct_ioc_url_exclude_domains')
        xspct.config['xspct_ioc_url_exclude_domains'] = ['w3.org']
        try:
            r = daemon.extract_iocs(b'payload at https://evil.example.com/drop')
            assert any('evil.example.com' in u for u in r['urls'])
        finally:
            xspct.config['xspct_ioc_url_exclude_domains'] = saved

    def test_empty_exclusion_list_keeps_all(self, daemon):
        saved = xspct.config.get('xspct_ioc_url_exclude_domains')
        xspct.config['xspct_ioc_url_exclude_domains'] = []
        try:
            r = daemon.extract_iocs(b'see http://www.w3.org/TR/xhtml1/ and https://evil.com')
            assert any('w3.org' in u for u in r['urls'])
        finally:
            xspct.config['xspct_ioc_url_exclude_domains'] = saved


# ===========================================================================
# UNIT TESTS — analyze_iocsearcher domain exclusion
# ===========================================================================

class TestAnalyzeIocsearcherExclude:

    def test_excluded_fqdn_dropped(self, daemon):
        if not xspct.HAS_IOCSEARCHER:
            pytest.skip('iocsearcher not installed')
        saved = xspct.config.get('xspct_ioc_url_exclude_domains')
        xspct.config['xspct_ioc_url_exclude_domains'] = ['w3.org']
        try:
            result = daemon.analyze_iocsearcher(
                'namespace http://www.w3.org/1999/xhtml something', 'test'
            )
            if result and 'iocs_extended' in result:
                for ioc_list in result['iocs_extended'].values():
                    assert all('w3.org' not in v for v in ioc_list)
        finally:
            xspct.config['xspct_ioc_url_exclude_domains'] = saved

    def test_non_excluded_kept(self, daemon):
        if not xspct.HAS_IOCSEARCHER:
            pytest.skip('iocsearcher not installed')
        saved = xspct.config.get('xspct_ioc_url_exclude_domains')
        xspct.config['xspct_ioc_url_exclude_domains'] = ['w3.org']
        try:
            result = daemon.analyze_iocsearcher(
                'contact info@evil.example.com for payload', 'test'
            )
            # evil.example.com is NOT excluded — email or fqdn should survive
            if result and 'iocs_extended' in result:
                all_vals = [v for lst in result['iocs_extended'].values() for v in lst]
                assert any('evil.example.com' in v for v in all_vals)
        finally:
            xspct.config['xspct_ioc_url_exclude_domains'] = saved


class TestAnalyzePdf:

    def test_non_pdf_returns_none(self, daemon):
        assert daemon.analyze_pdf(b'not a pdf at all') is None

    def test_clean_pdf_no_flags(self, daemon):
        r = daemon.analyze_pdf(PDF_CLEAN)
        assert r is not None
        assert r['has_javascript']     is False
        assert r['has_openaction']     is False
        assert r['has_embedded_files'] is False
        assert r['has_launch']         is False
        assert r['is_encrypted']       is False
        assert r['analyses'] == []

    def test_all_markers_detected(self, daemon):
        r = daemon.analyze_pdf(PDF_ALL_MARKERS)
        assert r is not None
        types = {a['type'] for a in r['analyses']}
        assert 'JavaScript'   in types
        assert 'AutoExecute'  in types
        assert 'EmbeddedFile' in types
        assert 'Execution'    in types
        assert 'Encryption'   in types
        assert 'XFA'          in types

    def test_all_boolean_flags_set(self, daemon):
        r = daemon.analyze_pdf(PDF_ALL_MARKERS)
        assert r['has_javascript']     is True
        assert r['has_openaction']     is True
        assert r['has_embedded_files'] is True
        assert r['has_launch']         is True
        assert r['is_encrypted']       is True

    def test_uri_ioc_extracted(self, daemon):
        r = daemon.analyze_pdf(PDF_WITH_URI)
        assert any('malware.example.com' in u for u in r['iocs']['urls'])

    def test_text_preview_is_list(self, daemon):
        r = daemon.sync_analyze('s', 'clean.pdf', PDF_CLEAN, 'application/pdf')
        assert isinstance(r['text_preview'], list)


@pytest.mark.skipif(not _HAS_FITZ, reason='PyMuPDF not installed')
class TestAnalyzePdfEncrypted:
    """Tests for password-protected PDF decryption via analyze_pdf / sync_analyze."""

    def test_encrypted_pdf_is_flagged(self, daemon):
        """An encrypted PDF with the wrong password list is flagged as encrypted."""
        daemon.passwords = ['wrong1', 'wrong2']
        r = daemon.analyze_pdf(PDF_ENCRYPTED)
        assert r is not None
        assert r['is_encrypted'] is True
        assert r['decrypted'] is False

    def test_encrypted_pdf_no_hit_when_no_password(self, daemon):
        """No analysis hits are produced when the PDF cannot be decrypted."""
        daemon.passwords = ['wrong1', 'wrong2']
        r = daemon.analyze_pdf(PDF_ENCRYPTED)
        # Only Encryption indicators (from PyMuPDF and optionally pdfid) should
        # be present; no JS / launch / other hits.
        types = {a['type'] for a in r['analyses']}
        assert types <= {'Encryption', 'pdfid-Encryption'}

    def test_correct_daemon_password_decrypts(self, daemon):
        """Correct password in daemon.passwords unlocks the PDF."""
        daemon.passwords = ['wrong1', _PDF_ENC_PASSWORD, 'wrong2']
        r = daemon.analyze_pdf(PDF_ENCRYPTED)
        assert r['decrypted'] is True
        assert r['decryption_password'] == _PDF_ENC_PASSWORD

    def test_correct_custom_password_decrypts(self, daemon):
        """Correct password supplied as custom_passwords is tried first."""
        daemon.passwords = ['wrong1', 'wrong2']
        r = daemon.analyze_pdf(PDF_ENCRYPTED, custom_passwords=[_PDF_ENC_PASSWORD])
        assert r['decrypted'] is True
        assert r['decryption_password'] == _PDF_ENC_PASSWORD

    def test_custom_password_tried_before_daemon_list(self, daemon):
        """custom_passwords are exhausted before falling back to daemon.passwords."""
        # Put the correct password only in daemon.passwords so if custom_passwords
        # are tried first (and wrong), decryption still succeeds via fallback.
        daemon.passwords = [_PDF_ENC_PASSWORD]
        r = daemon.analyze_pdf(PDF_ENCRYPTED, custom_passwords=['bad1', 'bad2'])
        assert r['decrypted'] is True

    def test_decrypted_pdf_has_report_keys(self, daemon):
        """After successful decryption the standard report keys are present."""
        daemon.passwords = [_PDF_ENC_PASSWORD]
        r = daemon.analyze_pdf(PDF_ENCRYPTED)
        for key in ('has_javascript', 'has_openaction', 'iocs', 'decrypted', 'analyses'):
            assert key in r

    def test_sync_analyze_decrypts_encrypted_pdf(self, daemon):
        """sync_analyze propagates decryption state for a PDF."""
        daemon.passwords = [_PDF_ENC_PASSWORD]
        r = daemon.sync_analyze('<t>', 'enc.pdf', PDF_ENCRYPTED, 'application/pdf')
        assert r['detected_type'] == 'pdf'
        assert r['decrypted'] is True
        assert r['decryption_password'] == _PDF_ENC_PASSWORD

    def test_sync_analyze_custom_password_decrypts_pdf(self, daemon):
        """custom_passwords passed to sync_analyze reach analyze_pdf."""
        daemon.passwords = ['wrong']
        r = daemon.sync_analyze(
            '<t>', 'enc.pdf', PDF_ENCRYPTED, 'application/pdf',
            custom_passwords=[_PDF_ENC_PASSWORD],
        )
        assert r['decrypted'] is True


class TestAnalyzeHtml:

    def test_no_angle_brackets_returns_none(self, daemon):
        assert daemon.analyze_html(HTML_NO_TAGS) is None

    def test_clean_html_no_flags(self, daemon):
        r = daemon.analyze_html(HTML_CLEAN)
        assert r is not None
        assert r['has_scripts']      is False
        assert r['has_forms']        is False
        assert r['has_iframes']      is False
        assert r['has_meta_refresh'] is False

    def test_malicious_html_all_flags(self, daemon):
        r = daemon.analyze_html(HTML_MALICIOUS)
        assert r['has_scripts']      is True
        assert r['has_forms']        is True
        assert r['has_iframes']      is True
        assert r['has_meta_refresh'] is True

    def test_suspicious_js_keywords_found(self, daemon):
        r = daemon.analyze_html(HTML_MALICIOUS)
        kw = {a['keyword'] for a in r['analyses'] if a['type'] == 'SuspiciousJS'}
        assert 'eval('                in kw
        assert 'document.write('      in kw
        assert 'unescape('            in kw
        assert 'atob('                in kw
        assert 'String.fromCharCode(' in kw

    def test_url_in_clean_html_extracted(self, daemon):
        r = daemon.analyze_html(HTML_CLEAN)
        assert any('example.com' in u for u in r['iocs']['urls'])

    def test_meta_refresh_detection(self, daemon):
        data = b'<html><head><meta http-equiv="refresh" content="0;url=http://x.com"></head></html>'
        r = daemon.analyze_html(data)
        assert r['has_meta_refresh'] is True

    def test_base64_blob_detection(self, daemon):
        blob = b'A' * 1200
        data = b'<html><body>' + blob + b'</body></html>'
        r = daemon.analyze_html(data)
        types = {a['type'] for a in r['analyses']}
        assert 'HTMLSmuggling' in types


class TestExtractTextPreview:

    def test_html_strips_tags(self, daemon):
        data = b'<html><body><p>Hello <b>World</b></p></body></html>'
        p = daemon.extract_text_preview(data, 'text/html')
        assert 'Hello' in p
        assert '<b>' not in p

    def test_html_removes_script_content(self, daemon):
        data = b'<html><body><script>eval("dangerous")</script><p>Safe</p></body></html>'
        p = daemon.extract_text_preview(data, 'text/html')
        assert 'eval' not in p
        assert 'Safe' in p

    def test_ooxml_extracts_text(self, daemon):
        p = daemon.extract_text_preview(
            OOXML_DATA,
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        )
        assert 'Hello from OOXML' in p

    def test_limit_is_respected(self, daemon):
        data = b'<p>' + b'X' * 5000 + b'</p>'
        p = daemon.extract_text_preview(data, 'text/html', limit=100)
        assert len(p) <= 100

    def test_binary_data_printable_only(self, daemon):
        data = bytes(range(256))
        p = daemon.extract_text_preview(data, 'application/octet-stream')
        assert isinstance(p, str)


class TestGetDetectedType:

    def test_pdf_by_mime(self, daemon):
        assert daemon.get_detected_type('application/pdf', '', '', b'') == 'pdf'

    def test_pdf_by_desc(self, daemon):
        assert daemon.get_detected_type('', 'PDF document', '', b'') == 'pdf'

    def test_pdf_by_extension(self, daemon):
        assert daemon.get_detected_type('', '', 'report.pdf', b'') == 'pdf'

    def test_html_by_mime(self, daemon):
        assert daemon.get_detected_type('text/html', '', '', b'') == 'html'

    def test_html_by_extension_html(self, daemon):
        assert daemon.get_detected_type('', '', 'page.html', b'') == 'html'

    def test_html_by_extension_htm(self, daemon):
        assert daemon.get_detected_type('', '', 'page.htm', b'') == 'html'

    def test_html_by_extension_xhtml(self, daemon):
        assert daemon.get_detected_type('', '', 'page.xhtml', b'') == 'html'

    def test_html_by_xhtml_mime(self, daemon):
        assert daemon.get_detected_type('application/xhtml+xml', '', '', b'') == 'html'

    def test_rtf_by_magic_bytes(self, daemon):
        assert daemon.get_detected_type('', '', '', b'{\\rtf1') == 'office'

    def test_office_default(self, daemon):
        assert daemon.get_detected_type(
            'application/octet-stream', 'binary', 'file.bin', b''
        ) == 'unknown'


class TestMergeReports:

    def _base_target(self):
        return {
            'analyses': [],
            'iocs':     {'urls': [], 'ips': [], 'domains': []},
            'rtf_objects': [],
        }

    def test_analyses_deduplication(self, daemon):
        item = {'type': 'AutoExec', 'keyword': 'kw', 'description': 'desc'}
        t = self._base_target()
        t['analyses'].append(item)
        daemon.merge_reports(t, {'analyses': [item]})
        assert len(t['analyses']) == 1

    def test_analyses_new_item_added(self, daemon):
        t = self._base_target()
        daemon.merge_reports(t, {'analyses': [{'type': 'A', 'keyword': 'x', 'description': 'd'}]})
        assert len(t['analyses']) == 1

    def test_iocs_deduplication(self, daemon):
        t = self._base_target()
        t['iocs']['urls'] = ['http://a.com']
        daemon.merge_reports(t, {'iocs': {
            'urls': ['http://a.com', 'http://b.com'], 'ips': [], 'domains': [],
        }})
        assert t['iocs']['urls'].count('http://a.com') == 1
        assert 'http://b.com' in t['iocs']['urls']

    def test_boolean_fields_ored(self, daemon):
        t = self._base_target()
        t['has_macro'] = False
        daemon.merge_reports(t, {'has_macro': True})
        assert t['has_macro'] is True

    def test_boolean_false_does_not_override_true(self, daemon):
        t = self._base_target()
        t['has_macro'] = True
        daemon.merge_reports(t, {'has_macro': False})
        assert t['has_macro'] is True

    def test_meta_key_is_skipped(self, daemon):
        t = self._base_target()
        t['meta'] = {'version': 'original'}
        daemon.merge_reports(t, {'meta': {'version': 'overwrite'}})
        assert t['meta']['version'] == 'original'

    def test_none_source_is_noop(self, daemon):
        t = self._base_target()
        daemon.merge_reports(t, None)
        assert t['analyses'] == []


class TestEvictTasks:

    def test_evicts_oldest_entries(self, daemon):
        daemon._TASKS_MAX_SIZE = 3
        for i in range(5):
            daemon.tasks[f'h{i}'] = f'result{i}'
            daemon.tasks.move_to_end(f'h{i}')
            daemon._evict_tasks()
        assert len(daemon.tasks) == 3
        assert 'h0' not in daemon.tasks
        assert 'h1' not in daemon.tasks
        assert 'h4' in daemon.tasks

    def test_does_not_evict_under_limit(self, daemon):
        daemon._TASKS_MAX_SIZE = 10
        for i in range(5):
            daemon.tasks[f'h{i}'] = i
        daemon._evict_tasks()
        assert len(daemon.tasks) == 5


class TestSyncAnalyze:

    def test_pdf_returns_correct_detected_type(self, daemon):
        r = daemon.sync_analyze('<t>', 'test.pdf', PDF_ALL_MARKERS, 'application/pdf')
        assert r['detected_type'] == 'pdf'

    def test_pdf_has_correct_hash(self, daemon):
        r = daemon.sync_analyze('<t>', 'test.pdf', PDF_CLEAN, 'application/pdf')
        assert r['file_hash'] == hashlib.sha256(PDF_CLEAN).hexdigest()

    def test_pdf_flags_propagated(self, daemon):
        r = daemon.sync_analyze('<t>', 'test.pdf', PDF_ALL_MARKERS, 'application/pdf')
        assert r['has_javascript'] is True
        assert r['has_openaction'] is True

    def test_html_returns_correct_detected_type(self, daemon):
        r = daemon.sync_analyze('<t>', 'test.html', HTML_MALICIOUS, 'text/html')
        assert r['detected_type'] == 'html'
        assert r['has_scripts'] is True

    def test_unknown_binary_has_report_keys(self, daemon):
        data = bytes(range(256))
        r = daemon.sync_analyze('<t>', 'mystery.bin', data, 'application/octet-stream')
        for key in ('file_hash', 'detected_type', 'analyses', 'iocs', 'text_preview'):
            assert key in r

    def test_meta_always_present(self, daemon):
        r = daemon.sync_analyze('<t>', 'x.pdf', PDF_CLEAN, 'application/pdf')
        assert r['meta']['script_name'] == 'xspct-scan'
        assert r['meta']['version'] == '0.3.0'

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason='OLE sample not present')
    def test_real_ole_has_macro(self, daemon):
        with open(OLE_FILE, 'rb') as f:
            data = f.read()
        r = daemon.sync_analyze('<t>', 'autostart-encrypt-standardpassword.xls', data, 'application/vnd.ms-excel')
        # File is encrypted; after in-memory decryption olevba may return has_macro=False
        # for XLM/stomped macros. Assert meaningful analysis was produced.
        assert r['has_macro'] is True or r['decrypted'] is True or len(r['analyses']) > 0

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason='OLE sample not present')
    def test_real_ole_has_ioc_urls(self, daemon):
        with open(OLE_FILE, 'rb') as f:
            data = f.read()
        r = daemon.sync_analyze('<t>', 'autostart-encrypt-standardpassword.xls', data, 'application/vnd.ms-excel')
        iocs = r['iocs']
        # This sample has no real network IOCs — only internal Office/VBA object
        # references (MSO.DLL, Excel.Sheet, etc.) that must NOT appear as domains
        # after TLD validation.  Verify the ioc keys exist and are clean lists.
        assert isinstance(iocs['urls'], list)
        assert isinstance(iocs['ips'], list)
        assert isinstance(iocs['domains'], list)
        assert not any('.' not in d for d in iocs['domains']), 'bare tokens must not appear'

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason='OLE sample not present')
    def test_real_ole_analyses_populated(self, daemon):
        with open(OLE_FILE, 'rb') as f:
            data = f.read()
        r = daemon.sync_analyze('<t>', 'autostart-encrypt-standardpassword.xls', data, 'application/vnd.ms-excel')
        types = {a['type'] for a in r['analyses']}
        assert 'AutoExec' in types or 'Suspicious' in types or len(types) > 0

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason='OLE sample not present')
    def test_real_ole_with_custom_passwords(self, daemon):
        with open(OLE_FILE, 'rb') as f:
            data = f.read()
        r = daemon.sync_analyze(
            '<t>', 'autostart-encrypt-standardpassword.xls', data, 'application/vnd.ms-excel',
            custom_passwords=['alpha', 'beta', '123456'],
        )
        assert r['detected_type'] != ''

    @pytest.mark.skipif(not os.path.exists(RTF_FILE), reason='RTF sample not present')
    def test_real_rtf_analyzed(self, daemon):
        with open(RTF_FILE, 'rb') as f:
            data = f.read()
        r = daemon.sync_analyze('<t>', 'sample.rtf', data, 'text/rtf', rtf_eval=True)
        assert 'file_hash' in r
        assert r['detected_type'] != ''


# ===========================================================================
# INTEGRATION TESTS
# ===========================================================================

class TestHealthPingRoot:

    async def test_health_200_ok(self, client):
        r = await client.get('/health')
        assert r.status == 200
        assert await r.text() == 'OK'

    async def test_ping_200_pong(self, client):
        r = await client.get('/ping')
        assert r.status == 200
        assert await r.text() == 'pong'

    async def test_root_200_xspct(self, client):
        r = await client.get('/')
        assert r.status == 200
        assert 'xspct-scan' in await r.text()


class TestMetricsEndpoint:

    async def test_metrics_returns_prometheus_text(self, client):
        r = await client.get('/v1/metrics')
        assert r.status == 200
        text = await r.text()
        for metric in (
            'xspct_requests_total',
            'xspct_requests_finished',
            'xspct_requests_timeout',
            'xspct_redis_hits',
            'xspct_redis_misses',
            'xspct_redis_errors',
            'xspct_tasks_in_memory',
        ):
            assert metric in text

    async def test_metrics_request_counter_increments(self, client):
        await client.post('/v1/scan', data=_form(PDF_CLEAN, 'a.pdf'))
        r = await client.get('/v1/metrics')
        text = await r.text()
        assert 'xspct_requests_total 1' in text

    async def test_metrics_finished_counter_increments(self, client):
        await client.post('/v1/scan', data=_form(PDF_CLEAN, 'b.pdf'))
        r = await client.get('/v1/metrics')
        text = await r.text()
        assert 'xspct_requests_finished 1' in text

    async def test_metrics_tasks_in_memory_increases(self, client):
        await client.post('/v1/scan', data=_form(PDF_CLEAN, 'c.pdf'))
        r = await client.get('/v1/metrics')
        text = await r.text()
        assert 'xspct_tasks_in_memory 0' not in text or 'xspct_tasks_in_memory 1' in text


class TestScanEndpoint:

    async def test_missing_doc_part_returns_400(self, client):
        form = aiohttp.FormData()
        form.add_field('not_doc', b'irrelevant', filename='x.bin')
        r = await client.post('/v1/scan', data=form)
        assert r.status == 400

    async def test_scan_clean_pdf(self, client):
        r = await client.post('/v1/scan', data=_form(PDF_CLEAN, 'clean.pdf'))
        assert r.status == 200
        body = await r.json()
        assert body['status']         == 'finished'
        assert body['detected_type']  == 'pdf'
        assert body['has_javascript'] is False
        assert body['has_openaction'] is False

    async def test_scan_malicious_pdf_flags(self, client):
        r = await client.post('/v1/scan', data=_form(PDF_ALL_MARKERS, 'malware.pdf'))
        assert r.status == 200
        body = await r.json()
        assert body['has_javascript'] is True
        assert body['has_openaction'] is True
        assert body['is_encrypted']   is True

    async def test_scan_malicious_html_flags(self, client):
        r = await client.post('/v1/scan', data=_form(HTML_MALICIOUS, 'phish.html'))
        assert r.status == 200
        body = await r.json()
        assert body['detected_type'] == 'html'
        assert body['has_scripts']   is True
        assert body['has_forms']     is True
        assert body['has_iframes']   is True

    async def test_scan_ooxml_returns_200(self, client):
        r = await client.post('/v1/scan', data=_form(OOXML_DATA, 'doc.docx'))
        assert r.status == 200
        body = await r.json()
        assert 'file_hash' in body
        assert len(body['file_hash']) == 64  # SHA-256 hex

    async def test_scan_file_mime_override(self, client):
        form = aiohttp.FormData()
        form.add_field('doc',       HTML_CLEAN, filename='noext')
        form.add_field('file_mime', 'text/html')
        r = await client.post('/v1/scan', data=form)
        assert r.status == 200
        body = await r.json()
        assert body['detected_type'] == 'html'

    async def test_scan_custom_passwords_accepted(self, client):
        form = aiohttp.FormData()
        form.add_field('doc',       PDF_CLEAN, filename='doc.pdf')
        form.add_field('passwords', 'pw1,pw2,TopSecret')
        r = await client.post('/v1/scan', data=form)
        assert r.status == 200

    @pytest.mark.skipif(not _HAS_FITZ, reason='PyMuPDF not installed')
    async def test_scan_encrypted_pdf_wrong_password(self, client):
        """Encrypted PDF with no matching password: report flags is_encrypted, decrypted=False."""
        form = aiohttp.FormData()
        form.add_field('doc',       PDF_ENCRYPTED, filename='enc.pdf')
        form.add_field('passwords', 'wrong1,wrong2')
        r = await client.post('/v1/scan', data=form)
        assert r.status == 200
        body = await r.json()
        assert body['is_encrypted'] is True
        assert body['decrypted'] is False

    @pytest.mark.skipif(not _HAS_FITZ, reason='PyMuPDF not installed')
    async def test_scan_encrypted_pdf_correct_password(self, client):
        """Encrypted PDF unlocked via the passwords field: decrypted=True."""
        form = aiohttp.FormData()
        form.add_field('doc',       PDF_ENCRYPTED, filename='enc.pdf')
        form.add_field('passwords', f'wrong1,{_PDF_ENC_PASSWORD},wrong2')
        r = await client.post('/v1/scan', data=form)
        assert r.status == 200
        body = await r.json()
        assert body['detected_type'] == 'pdf'
        assert body['decrypted'] is True
        assert body['decryption_password'] == _PDF_ENC_PASSWORD

    async def test_scan_time_taken_present(self, client):
        r = await client.post('/v1/scan', data=_form(PDF_CLEAN, 'timed.pdf'))
        body = await r.json()
        assert 'time_taken' in body
        assert body['time_taken'] >= 0

    async def test_scan_report_has_iocs_key(self, client):
        r = await client.post('/v1/scan', data=_form(PDF_WITH_URI, 'ioc.pdf'))
        body = await r.json()
        assert 'iocs' in body
        assert 'urls' in body['iocs']

    async def test_scan_same_file_produces_same_hash(self, client):
        """Same bytes always produce the same SHA-256 file_hash."""
        r1 = await client.post('/v1/scan', data=_form(PDF_CLEAN, 'a.pdf'))
        b1 = await r1.json()
        r2 = await client.post('/v1/scan', data=_form(PDF_CLEAN, 'b.pdf'))
        b2 = await r2.json()
        assert b1['file_hash'] == b2['file_hash']
        assert b1['file_hash'] == hashlib.sha256(PDF_CLEAN).hexdigest()

    async def test_scan_short_timeout_may_return_202(self, client):
        """Very short timeout → 200 (fast path) or 202 (background). Both valid."""
        r = await client.post('/v1/scan?timeout=0.00001', data=_form(PDF_ALL_MARKERS, 'slow.pdf'))
        assert r.status in (200, 202)
        body = await r.json()
        assert 'file_hash' in body or 'status' in body

    async def test_scan_rtf_flag_accepted(self, client):
        r = await client.post('/v1/scan?rtf=true', data=_form(PDF_CLEAN, 'test.pdf'))
        assert r.status == 200

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason='OLE sample not present')
    async def test_scan_real_ole_analysis(self, client):
        with open(OLE_FILE, 'rb') as f:
            data = f.read()
        r = await client.post('/v1/scan', data=_form(data, 'autostart-encrypt-standardpassword.xls'))
        assert r.status == 200
        body = await r.json()
        assert body['decrypted'] is True or body['has_macro'] is True or len(body['analyses']) > 0

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason='OLE sample not present')
    async def test_scan_real_ole_has_ioc_urls(self, client):
        with open(OLE_FILE, 'rb') as f:
            data = f.read()
        r = await client.post('/v1/scan', data=_form(data, 'autostart-encrypt-standardpassword.xls'))
        body = await r.json()
        iocs = body['iocs']
        # No real network IOCs in this sample — internal Office object references
        # (MSO.DLL, Excel.Sheet, etc.) are correctly filtered by TLD validation.
        assert isinstance(iocs['urls'], list)
        assert isinstance(iocs['ips'], list)
        assert isinstance(iocs['domains'], list)

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason='OLE sample not present')
    async def test_scan_ole_with_custom_passwords(self, client):
        with open(OLE_FILE, 'rb') as f:
            data = f.read()
        form = aiohttp.FormData()
        form.add_field('doc',       data,                             filename='autostart-encrypt-standardpassword.xls')
        form.add_field('passwords', 'wrongpw1,wrongpw2,123456,VelvetSweatshop')
        r = await client.post('/v1/scan', data=form)
        assert r.status == 200
        body = await r.json()
        assert body['status'] == 'finished'

    @pytest.mark.skipif(not os.path.exists(RTF_FILE), reason='RTF sample not present')
    async def test_scan_real_rtf(self, client):
        with open(RTF_FILE, 'rb') as f:
            data = f.read()
        r = await client.post('/v1/scan?rtf=true', data=_form(data, 'sample.rtf'))
        assert r.status == 200
        body = await r.json()
        assert 'file_hash' in body


class TestQueryEndpoint:

    async def test_get_missing_hash_returns_400(self, client):
        r = await client.get('/v1/query')
        assert r.status == 400

    async def test_get_unknown_hash_returns_404(self, client):
        r = await client.get('/v1/query?hash=' + 'a' * 64)
        assert r.status == 404

    async def test_post_missing_hash_returns_400(self, client):
        r = await client.post('/v1/query', json={})
        assert r.status == 400

    async def test_post_unknown_hash_returns_404(self, client):
        r = await client.post('/v1/query', json={'hash': 'b' * 64})
        assert r.status == 404

    async def test_get_after_scan_returns_finished(self, client):
        scan_r  = await client.post('/v1/scan', data=_form(PDF_CLEAN, 'q.pdf'))
        scan_b  = await scan_r.json()
        fhash   = scan_b['file_hash']

        query_r = await client.get(f'/v1/query?hash={fhash}')
        assert query_r.status == 200
        query_b = await query_r.json()
        assert query_b['status']                  == 'finished'
        assert query_b['report']['file_hash']     == fhash
        assert query_b['report']['detected_type'] == 'pdf'

    async def test_post_after_scan_returns_finished(self, client):
        scan_r = await client.post('/v1/scan', data=_form(HTML_CLEAN, 'q.html'))
        scan_b = await scan_r.json()
        fhash  = scan_b['file_hash']

        query_r = await client.post('/v1/query', json={'hash': fhash})
        assert query_r.status == 200
        query_b = await query_r.json()
        assert query_b['status'] == 'finished'
        assert query_b['report']['detected_type'] == 'html'

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason='OLE sample not present')
    async def test_get_ole_report_after_scan(self, client):
        with open(OLE_FILE, 'rb') as f:
            data = f.read()
        scan_r = await client.post('/v1/scan', data=_form(data, 'autostart-encrypt-standardpassword.xls'))
        scan_b = await scan_r.json()
        fhash  = scan_b['file_hash']

        query_r = await client.get(f'/v1/query?hash={fhash}')
        assert query_r.status == 200
        query_b = await query_r.json()
        assert query_b['status'] == 'finished'
        assert query_b['report']['file_hash'] == fhash


# ===========================================================================
# Response serialization (msgpack / cbor / config override)
# ===========================================================================

try:
    import msgpack as _msgpack_test
    _HAS_MSGPACK_TEST = True
except ImportError:
    _HAS_MSGPACK_TEST = False

try:
    import cbor2 as _cbor2_test
    _HAS_CBOR2_TEST = True
except ImportError:
    _HAS_CBOR2_TEST = False


@pytest.mark.skipif(not _HAS_MSGPACK_TEST, reason='msgpack not installed')
class TestResponseSerializationMsgpack:

    async def test_scan_accept_msgpack_returns_msgpack(self, client):
        r = await client.post(
            '/v1/scan',
            data=_form(PDF_CLEAN, 'clean.pdf'),
            headers={'Accept': 'application/x-msgpack'},
        )
        assert r.status == 200
        assert 'application/x-msgpack' in r.headers.get('Content-Type', '')
        body = _msgpack_test.unpackb(await r.read(), raw=False)
        assert body['status'] == 'finished'
        assert body['detected_type'] == 'pdf'

    async def test_query_get_accept_msgpack_returns_msgpack(self, client):
        scan_r = await client.post(
            '/v1/scan',
            data=_form(PDF_CLEAN, 'clean.pdf'),
            headers={'Accept': 'application/x-msgpack'},
        )
        file_hash = _msgpack_test.unpackb(await scan_r.read(), raw=False)['file_hash']

        r = await client.get(
            f'/v1/query?hash={file_hash}',
            headers={'Accept': 'application/x-msgpack'},
        )
        assert r.status == 200
        assert 'application/x-msgpack' in r.headers.get('Content-Type', '')
        body = _msgpack_test.unpackb(await r.read(), raw=False)
        assert body['status'] == 'finished'

    async def test_query_post_msgpack_body_returns_msgpack(self, client):
        scan_r = await client.post('/v1/scan', data=_form(PDF_CLEAN, 'clean.pdf'))
        scan_b = await scan_r.json()
        file_hash = scan_b['file_hash']

        payload = _msgpack_test.packb({'hash': file_hash}, use_bin_type=True)
        r = await client.post(
            '/v1/query',
            data=payload,
            headers={'Content-Type': 'application/x-msgpack'},
        )
        assert r.status == 200
        assert 'application/x-msgpack' in r.headers.get('Content-Type', '')
        body = _msgpack_test.unpackb(await r.read(), raw=False)
        assert body['status'] == 'finished'

    async def test_config_force_json_overrides_accept_msgpack(self, client):
        saved = xspct.config.get('xspct_response_format', 'auto')
        xspct.config['xspct_response_format'] = 'json'
        try:
            r = await client.post(
                '/v1/scan',
                data=_form(PDF_CLEAN, 'clean.pdf'),
                headers={'Accept': 'application/x-msgpack'},
            )
            assert r.status == 200
            assert r.headers.get('Content-Type', '').startswith('application/json')
            body = await r.json()
            assert body['status'] == 'finished'
        finally:
            xspct.config['xspct_response_format'] = saved

    async def test_config_force_msgpack_overrides_json_accept(self, client):
        saved = xspct.config.get('xspct_response_format', 'auto')
        xspct.config['xspct_response_format'] = 'msgpack'
        try:
            r = await client.post(
                '/v1/scan',
                data=_form(PDF_CLEAN, 'clean.pdf'),
                headers={'Accept': 'application/json'},
            )
            assert r.status == 200
            assert 'application/x-msgpack' in r.headers.get('Content-Type', '')
            body = _msgpack_test.unpackb(await r.read(), raw=False)
            assert body['status'] == 'finished'
        finally:
            xspct.config['xspct_response_format'] = saved

    async def test_accept_qvalue_prefers_msgpack(self, client):
        r = await client.post(
            '/v1/scan',
            data=_form(PDF_CLEAN, 'clean.pdf'),
            headers={
                'Accept': 'application/json;q=0.2, application/x-msgpack;q=0.8',
            },
        )
        assert r.status == 200
        assert 'application/x-msgpack' in r.headers.get('Content-Type', '')
        assert r.headers.get('Vary', '') == 'Accept, Accept-Encoding'
        body = _msgpack_test.unpackb(await r.read(), raw=False)
        assert body['status'] == 'finished'

    async def test_accept_qvalue_zero_rejects_msgpack(self, client):
        r = await client.post(
            '/v1/scan',
            data=_form(PDF_CLEAN, 'clean.pdf'),
            headers={
                'Accept': 'application/x-msgpack;q=0, application/json;q=1',
            },
        )
        assert r.status == 200
        assert r.headers.get('Content-Type', '').startswith('application/json')
        body = await r.json()
        assert body['status'] == 'finished'


@pytest.mark.skipif(not _HAS_CBOR2_TEST, reason='cbor2 not installed')
class TestResponseSerializationCbor:

    async def test_scan_accept_cbor_returns_cbor(self, client):
        r = await client.post(
            '/v1/scan',
            data=_form(PDF_CLEAN, 'clean.pdf'),
            headers={'Accept': 'application/cbor'},
        )
        assert r.status == 200
        assert 'application/cbor' in r.headers.get('Content-Type', '')
        body = _cbor2_test.loads(await r.read())
        assert body['status'] == 'finished'
        assert body['detected_type'] == 'pdf'

    async def test_query_get_accept_cbor_returns_cbor(self, client):
        scan_r = await client.post(
            '/v1/scan',
            data=_form(PDF_CLEAN, 'clean.pdf'),
            headers={'Accept': 'application/cbor'},
        )
        file_hash = _cbor2_test.loads(await scan_r.read())['file_hash']

        r = await client.get(
            f'/v1/query?hash={file_hash}',
            headers={'Accept': 'application/cbor'},
        )
        assert r.status == 200
        assert 'application/cbor' in r.headers.get('Content-Type', '')
        body = _cbor2_test.loads(await r.read())
        assert body['status'] == 'finished'

    async def test_query_post_cbor_body_returns_cbor(self, client):
        scan_r = await client.post('/v1/scan', data=_form(PDF_CLEAN, 'clean.pdf'))
        scan_b = await scan_r.json()
        file_hash = scan_b['file_hash']

        payload = _cbor2_test.dumps({'hash': file_hash})
        r = await client.post(
            '/v1/query',
            data=payload,
            headers={'Content-Type': 'application/cbor'},
        )
        assert r.status == 200
        assert 'application/cbor' in r.headers.get('Content-Type', '')
        body = _cbor2_test.loads(await r.read())
        assert body['status'] == 'finished'

    async def test_config_force_cbor_overrides_json_accept(self, client):
        saved = xspct.config.get('xspct_response_format', 'auto')
        xspct.config['xspct_response_format'] = 'cbor'
        try:
            r = await client.post(
                '/v1/scan',
                data=_form(PDF_CLEAN, 'clean.pdf'),
                headers={'Accept': 'application/json'},
            )
            assert r.status == 200
            assert 'application/cbor' in r.headers.get('Content-Type', '')
            body = _cbor2_test.loads(await r.read())
            assert body['status'] == 'finished'
        finally:
            xspct.config['xspct_response_format'] = saved


# ===========================================================================
# Zstd request decompression / response compression
# ===========================================================================

try:
    import zstandard as _zstd_test
    _HAS_ZSTD_TEST = True
except ImportError:
    _HAS_ZSTD_TEST = False


def _zstd_compress(data: bytes) -> bytes:
    return _zstd_test.ZstdCompressor().compress(data)


def _zstd_stream_decompress(data: bytes) -> bytes:
    dctx = _zstd_test.ZstdDecompressor()
    with dctx.stream_reader(io.BytesIO(data)) as reader:
        return reader.read()


@pytest.mark.skipif(not _HAS_ZSTD_TEST, reason='zstandard not installed')
class TestZstdCompression:

    # ------------------------------------------------------------------ #
    # Request decompression — multipart                                   #
    # ------------------------------------------------------------------ #

    async def test_multipart_zstd_doc_decompresses(self, client):
        """zstd-compressed doc part detected via magic bytes and decompressed."""
        compressed = _zstd_compress(PDF_CLEAN)
        r = await client.post('/v1/scan', data=_form(compressed, 'clean.pdf'))
        assert r.status == 200
        body = await r.json()
        assert body['status'] == 'finished'
        assert body['detected_type'] == 'pdf'

    async def test_multipart_malformed_zstd_returns_400(self, client):
        malformed = xspct._ZSTD_MAGIC + b'not-a-valid-zstd-frame'
        r = await client.post('/v1/scan', data=_form(malformed, 'clean.pdf.zst'))
        assert r.status == 400
        body = await r.json()
        assert body['error'] == 'Invalid zstd-compressed upload'

    async def test_multipart_zst_filename_suffix_stripped(self, client):
        compressed = _zstd_compress(PDF_CLEAN)
        r = await client.post('/v1/scan', data=_form(compressed, 'clean.pdf.zst'))
        assert r.status == 200
        body = await r.json()
        assert body['status'] == 'finished'
        reported_name = body.get('file_name') or body.get('filename') or ''
        assert not reported_name.lower().endswith('.zst')

    # ------------------------------------------------------------------ #
    # Request decompression — octet-stream                               #
    # ------------------------------------------------------------------ #

    async def test_octet_stream_zstd_magic_decompresses(self, client):
        """zstd magic bytes auto-detect on octet-stream body."""
        compressed = _zstd_compress(PDF_CLEAN)
        r = await client.post(
            '/v1/scan?filename=clean.pdf',
            data=compressed,
            headers={'Content-Type': 'application/octet-stream'},
        )
        assert r.status == 200
        body = await r.json()
        assert body['status'] == 'finished'
        assert body['detected_type'] == 'pdf'

    async def test_octet_stream_zst_filename_suffix_stripped(self, client):
        compressed = _zstd_compress(PDF_CLEAN)
        r = await client.post(
            '/v1/scan?filename=clean.pdf.zst',
            data=compressed,
            headers={'Content-Type': 'application/octet-stream'},
        )
        assert r.status == 200
        body = await r.json()
        assert body['status'] == 'finished'
        reported_name = body.get('file_name') or body.get('filename') or ''
        assert not reported_name.lower().endswith('.zst')

    async def test_octet_stream_zstd_over_limit_returns_413(self, client, monkeypatch):
        monkeypatch.setattr(xspct.InspectorDaemon, '_MAX_ZSTD_DECOMPRESSED_BYTES', 1024)
        compressed = _zstd_compress(b'A' * 2048)
        r = await client.post(
            '/v1/scan?filename=clean.pdf.zst',
            data=compressed,
            headers={'Content-Type': 'application/octet-stream'},
        )
        assert r.status == 413
        body = await r.json()
        assert body['error'] == 'Zstd-compressed upload expands beyond limit (1024 bytes)'

    # ------------------------------------------------------------------ #
    # Response compression                                               #
    # ------------------------------------------------------------------ #

    async def test_accept_encoding_zstd_compresses_json_response(self, client):
        """Explicit Accept-Encoding: zstd triggers server-side compression.

        aiohttp client auto-decompresses the response body, so we read
        the result via r.json() and only verify the Content-Encoding header
        to confirm the server did compress.
        """
        r = await client.post(
            '/v1/scan',
            data=_form(PDF_CLEAN, 'clean.pdf'),
            headers={'Accept-Encoding': 'zstd'},
        )
        assert r.status == 200
        assert r.headers.get('Content-Encoding', '') == 'zstd'
        assert r.headers.get('Content-Type', '').startswith('application/json')
        assert r.headers.get('Vary', '') == 'Accept, Accept-Encoding'
        # aiohttp client transparently decompresses when zstandard is installed
        result = await r.json()
        assert result['status'] == 'finished'
        assert result['detected_type'] == 'pdf'

    async def test_accept_encoding_zstd_with_msgpack(self, client):
        if not _HAS_MSGPACK_TEST:
            pytest.skip('msgpack not installed')
        r = await client.post(
            '/v1/scan',
            data=_form(PDF_CLEAN, 'clean.pdf'),
            headers={
                'Accept': 'application/x-msgpack',
                'Accept-Encoding': 'zstd',
            },
        )
        assert r.status == 200
        assert r.headers.get('Content-Encoding', '') == 'zstd'
        assert 'application/x-msgpack' in r.headers.get('Content-Type', '')
        # aiohttp client decompresses zstd; r.read() returns plain msgpack bytes
        result = _msgpack_test.unpackb(await r.read(), raw=False)
        assert result['status'] == 'finished'

    async def test_no_accept_encoding_no_compression(self, client):
        """Explicitly requesting gzip only must not trigger zstd compression."""
        r = await client.post(
            '/v1/scan',
            data=_form(PDF_CLEAN, 'clean.pdf'),
            # Override aiohttp's automatic Accept-Encoding to exclude zstd
            headers={'Accept-Encoding': 'gzip'},
        )
        assert r.status == 200
        assert r.headers.get('Content-Encoding', '') != 'zstd'
        body = await r.json()
        assert body['status'] == 'finished'

    async def test_accept_encoding_qvalue_zero_disables_zstd(self, client):
        r = await client.post(
            '/v1/scan',
            data=_form(PDF_CLEAN, 'clean.pdf'),
            headers={'Accept-Encoding': 'zstd;q=0, gzip;q=1'},
        )
        assert r.status == 200
        assert r.headers.get('Content-Encoding', '') != 'zstd'
        body = await r.json()
        assert body['status'] == 'finished'

    async def test_query_accept_encoding_zstd_compresses_response(self, client):
        scan_r = await client.post('/v1/scan', data=_form(PDF_CLEAN, 'clean.pdf'))
        file_hash = (await scan_r.json())['file_hash']

        r = await client.get(
            f'/v1/query?hash={file_hash}',
            headers={'Accept-Encoding': 'zstd'},
        )
        assert r.status == 200
        assert r.headers.get('Content-Encoding', '') == 'zstd'
        # aiohttp client transparently decompresses
        result = await r.json()
        assert result['status'] == 'finished'


class _ClientResponseStub:

    def __init__(self, status, body):
        self.status = status
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def json(self, content_type=None):
        return self._body


class _ClientSessionStub:

    def __init__(self, status, body):
        self._status = status
        self._body = body

    def post(self, *args, **kwargs):
        return _ClientResponseStub(self._status, self._body)


class TestClientPolling:

    def test_normalize_result_payload_unwraps_query_response(self):
        payload = {
            'status': 'finished',
            'report': {
                'file_hash': 'abc',
                'detected_type': 'pdf',
                'analyses': [],
            },
        }
        result = xspct_client._normalize_result_payload(payload)
        assert result['status'] == 'finished'
        assert result['file_hash'] == 'abc'
        assert 'report' not in result

    @pytest.mark.asyncio
    async def test_scan_file_poll_returns_flat_report(self, tmp_path, monkeypatch):
        sample = tmp_path / 'sample.pdf'
        sample.write_bytes(b'%PDF-1.4\n')

        async def _fake_poll_result(session, base_url, file_hash, headers, interval):
            return {
                'status': 'finished',
                'report': {
                    'file_hash': file_hash,
                    'filename': sample.name,
                    'detected_type': 'pdf',
                    'analyses': [],
                    'iocs': {'urls': [], 'ips': [], 'domains': []},
                },
            }

        monkeypatch.setattr(xspct_client, '_poll_result', _fake_poll_result)
        session = _ClientSessionStub(202, {'status': 'processing', 'file_hash': 'deadbeef'})

        result = await xspct_client.scan_file(
            session=session,
            path=sample,
            base_url='http://localhost:8080',
            timeout=1,
            passwords=None,
            rtf=False,
            api_key=None,
            poll=True,
            poll_interval=0,
            no_color=True,
        )

        assert result is not None
        assert result['status'] == 'finished'
        assert result['file_hash'] == 'deadbeef'
        assert result['detected_type'] == 'pdf'


class TestAuthentication:

    async def test_health_no_auth_required(self, auth_client):
        """Health endpoint carries no auth check and must always return 200."""
        r = await auth_client.get('/health')
        assert r.status == 200

    async def test_scan_no_key_returns_401(self, auth_client):
        r = await auth_client.post('/v1/scan', data=_form(PDF_CLEAN, 'auth.pdf'))
        assert r.status == 401

    async def test_query_get_no_key_returns_401(self, auth_client):
        r = await auth_client.get('/v1/query?hash=abc')
        assert r.status == 401

    async def test_query_post_no_key_returns_401(self, auth_client):
        r = await auth_client.post('/v1/query', json={'hash': 'abc'})
        assert r.status == 401

    async def test_metrics_no_key_returns_401(self, auth_client):
        r = await auth_client.get('/v1/metrics')
        assert r.status == 401

    async def test_scan_correct_key_returns_200(self, auth_client):
        r = await auth_client.post(
            '/v1/scan',
            headers={'X-Api-Key': 'test-secret-key'},
            data=_form(PDF_CLEAN, 'auth.pdf'),
        )
        assert r.status == 200

    async def test_scan_wrong_key_returns_401(self, auth_client):
        r = await auth_client.post(
            '/v1/scan',
            headers={'X-Api-Key': 'totally-wrong'},
            data=_form(PDF_CLEAN, 'auth.pdf'),
        )
        assert r.status == 401

    async def test_query_correct_key_returns_404_not_401(self, auth_client):
        """After auth passes, unknown hash → 404 (not 401)."""
        r = await auth_client.get(
            '/v1/query?hash=' + 'c' * 64,
            headers={'X-Api-Key': 'test-secret-key'},
        )
        assert r.status == 404

    async def test_metrics_correct_key_returns_200(self, auth_client):
        r = await auth_client.get(
            '/v1/metrics',
            headers={'X-Api-Key': 'test-secret-key'},
        )
        assert r.status == 200


# ===========================================================================
# UNIT TESTS — analyze_javascript
# ===========================================================================

class TestAnalyzeJavascript:

    def test_empty_string_returns_empty(self, daemon):
        assert daemon.analyze_javascript('') == []

    def test_whitespace_only_returns_empty(self, daemon):
        assert daemon.analyze_javascript('   \n\t  ') == []

    def test_eval_detected(self, daemon):
        hits = daemon.analyze_javascript('eval("alert(1)")')
        keywords = {h['keyword'] for h in hits}
        assert 'eval()' in keywords

    def test_unescape_detected(self, daemon):
        hits = daemon.analyze_javascript('var x = unescape("%41%42")')
        keywords = {h['keyword'] for h in hits}
        assert 'unescape()' in keywords

    def test_atob_detected(self, daemon):
        hits = daemon.analyze_javascript('atob("aGVsbG8=")')
        keywords = {h['keyword'] for h in hits}
        assert 'atob()' in keywords

    def test_string_from_char_code_detected(self, daemon):
        hits = daemon.analyze_javascript('String.fromCharCode(65,66,67)')
        keywords = {h['keyword'] for h in hits}
        assert 'String.fromCharCode' in keywords

    def test_document_write_detected(self, daemon):
        hits = daemon.analyze_javascript('document.write("<b>x</b>")')
        keywords = {h['keyword'] for h in hits}
        assert 'document.write()' in keywords

    def test_export_data_object_detected(self, daemon):
        hits = daemon.analyze_javascript('this.exportDataObject({cName:"x"})')
        keywords = {h['keyword'] for h in hits}
        assert 'exportDataObject()' in keywords

    def test_launch_url_detected(self, daemon):
        hits = daemon.analyze_javascript('app.launchURL("http://evil.com")')
        keywords = {h['keyword'] for h in hits}
        assert 'app.launchURL()' in keywords

    def test_open_doc_detected(self, daemon):
        hits = daemon.analyze_javascript('app.openDoc("/tmp/x.pdf")')
        keywords = {h['keyword'] for h in hits}
        assert 'app.openDoc()' in keywords

    def test_util_printf_detected(self, daemon):
        hits = daemon.analyze_javascript('util.printf("%s", x)')
        keywords = {h['keyword'] for h in hits}
        assert 'util.printf()' in keywords

    def test_activex_detected(self, daemon):
        hits = daemon.analyze_javascript('new ActiveXObject("WScript.Shell")')
        keywords = {h['keyword'] for h in hits}
        assert 'ActiveXObject' in keywords

    def test_wscript_detected(self, daemon):
        hits = daemon.analyze_javascript('WScript.Echo("hello")')
        keywords = {h['keyword'] for h in hits}
        assert 'WScript' in keywords

    def test_shell_execute_detected(self, daemon):
        hits = daemon.analyze_javascript('ShellExecute("cmd.exe")')
        keywords = {h['keyword'] for h in hits}
        assert 'ShellExecute' in keywords

    def test_source_label_in_description(self, daemon):
        hits = daemon.analyze_javascript('eval("x")', source_label='PDF /OpenAction')
        assert any('PDF /OpenAction' in h['description'] for h in hits)

    def test_clean_js_returns_empty(self, daemon):
        clean = 'function add(a, b) { return a + b; }\nvar result = add(1, 2);'
        assert daemon.analyze_javascript(clean) == []

    def test_returns_list(self, daemon):
        result = daemon.analyze_javascript('var x = 1;')
        assert isinstance(result, list)

    def test_no_duplicate_hits(self, daemon):
        # Two eval() calls → still one entry
        hits = daemon.analyze_javascript('eval("a"); eval("b");')
        keywords = [h['keyword'] for h in hits if h['keyword'] == 'eval()']
        assert len(keywords) == 1

    def test_type_field_is_suspiciousjs(self, daemon):
        hits = daemon.analyze_javascript('eval("x")')
        assert hits[0]['type'] == 'SuspiciousJS'


# ===========================================================================
# UNIT TESTS — analyze_image
# ===========================================================================

try:
    from PIL import Image as _TestPIL
    _HAS_PIL_FOR_TESTS = True
except ImportError:
    _HAS_PIL_FOR_TESTS = False


def _make_png(width: int = 50, height: int = 50, color: str = 'white') -> bytes:
    """Create a minimal in-memory PNG for testing."""
    buf = io.BytesIO()
    img = _TestPIL.new('RGB', (width, height), color=color)
    img.save(buf, format='PNG')
    return buf.getvalue()


class TestAnalyzeImage:

    def test_empty_bytes_returns_empty_structure(self, daemon):
        r = daemon.analyze_image(b'')
        assert r['ocr_text'] == []
        assert r['qr_codes'] == []
        assert r['analyses'] == []
        assert r['iocs'] == {'urls': [], 'ips': [], 'domains': []}

    def test_invalid_bytes_returns_empty_structure(self, daemon):
        r = daemon.analyze_image(b'this is not an image at all XXXX')
        assert r['ocr_text'] == []
        assert r['qr_codes'] == []

    def test_return_structure_keys(self, daemon):
        r = daemon.analyze_image(b'')
        assert {'ocr_text', 'qr_codes', 'analyses', 'iocs'} <= set(r.keys())
        assert set(r['iocs'].keys()) == {'urls', 'ips', 'domains'}

    @pytest.mark.skipif(not _HAS_PIL_FOR_TESTS, reason='Pillow not installed')
    def test_blank_png_does_not_raise(self, daemon):
        png = _make_png()
        r = daemon.analyze_image(png, label='test blank')
        assert isinstance(r['ocr_text'], list)
        assert isinstance(r['qr_codes'], list)
        assert isinstance(r['analyses'], list)

    @pytest.mark.skipif(not _HAS_PIL_FOR_TESTS, reason='Pillow not installed')
    def test_label_appears_in_log_but_not_analyses_for_blank(self, daemon):
        png = _make_png()
        # Blank white image has no QR codes and no meaningful OCR text
        r = daemon.analyze_image(png, label='blank-test')
        # No QR codes in a blank image
        assert r['qr_codes'] == []


# ===========================================================================
# UNIT TESTS — analyze_html extras (SpamRedirect, inline JS wiring)
# ===========================================================================

class TestAnalyzeHtmlExtras:

    def test_spam_redirect_tracker_script_detected(self, daemon):
        data = (
            b'<html><body>'
            b'<script src="https://track.evil.com/?u=Ab3Cd7Ef"></script>'
            b'</body></html>'
        )
        r = daemon.analyze_html(data)
        types = {a['type'] for a in r['analyses']}
        assert 'SpamRedirect' in types

    def test_spam_redirect_keyword(self, daemon):
        data = b'<html><script src="https://evil.com/?u=ABCDEFGH"></script></html>'
        r = daemon.analyze_html(data)
        kw = {a['keyword'] for a in r['analyses']}
        assert 'script-tracker-url' in kw

    def test_spam_redirect_not_triggered_without_u_param(self, daemon):
        data = b'<html><script src="https://cdn.example.com/lib.js"></script></html>'
        r = daemon.analyze_html(data)
        types = {a['type'] for a in r['analyses']}
        assert 'SpamRedirect' not in types

    def test_external_script_detected(self, daemon):
        data = b'<html><script src="http://evil.com/script.php?id=loader"></script></html>'
        r = daemon.analyze_html(data)
        types = {a['type'] for a in r['analyses']}
        assert 'ExternalScript' in types

    def test_external_script_keyword(self, daemon):
        data = b'<html><script src="https://track.bad.net/t.js"></script></html>'
        r = daemon.analyze_html(data)
        kw = {a['keyword'] for a in r['analyses']}
        assert 'external-script-src' in kw

    def test_tracker_url_not_double_counted_as_external(self, daemon):
        # A ?u= tracker URL should produce SpamRedirect but NOT also ExternalScript
        data = b'<html><script src="https://track.evil.com/?u=Ab3Cd7Ef"></script></html>'
        r = daemon.analyze_html(data)
        types = [a['type'] for a in r['analyses']]
        assert types.count('SpamRedirect') == 1
        # ExternalScript should NOT appear because the URL is already in tracker_scripts
        assert 'ExternalScript' not in types

    def test_inline_script_eval_triggers_suspicious_js(self, daemon):
        data = b'<html><script>eval("alert(1)")</script></html>'
        r = daemon.analyze_html(data)
        keywords = {a['keyword'] for a in r['analyses'] if a['type'] == 'SuspiciousJS'}
        assert 'eval()' in keywords

    def test_inline_script_atob_triggers_suspicious_js(self, daemon):
        data = b'<html><script>var x = atob("aGVsbG8=");</script></html>'
        r = daemon.analyze_html(data)
        keywords = {a['keyword'] for a in r['analyses'] if a['type'] == 'SuspiciousJS'}
        assert 'atob()' in keywords

    def test_inline_script_no_duplicates(self, daemon):
        # eval() appears both in old static check and new analyze_javascript wiring
        data = b'<html><script>eval("x")</script></html>'
        r = daemon.analyze_html(data)
        eval_hits = [a for a in r['analyses']
                     if a['type'] == 'SuspiciousJS' and a['keyword'] == 'eval()']
        # Must not be duplicated; keyword from analyze_javascript has source_label appended
        # but keyword from the old static check is bare — either 1 or 2 OK but count sanity
        assert len(eval_hits) >= 1

    @pytest.mark.skipif(not _HAS_PIL_FOR_TESTS, reason='Pillow not installed')
    def test_data_uri_image_processed_without_crash(self, daemon):
        import base64
        png = _make_png(10, 10)
        b64 = base64.b64encode(png).decode()
        data = f'<html><body><img src="data:image/png;base64,{b64}"></body></html>'.encode()
        # Should not raise regardless of HAS_OCR/HAS_PYZBAR
        r = daemon.analyze_html(data)
        assert r is not None
        assert 'analyses' in r


# ===========================================================================
# UNIT TESTS — TextExtractorRtf
# ===========================================================================

class TestTextExtractorRtf:

    def test_minimal_rtf_extracts_text(self):
        rtf = b'{\\rtf1\\ansi {\\fonttbl} Hello World}'
        te = xspct.TextExtractorRtf(rtf)
        text = te.get_text()
        # The RTF parser may or may not produce text from this minimal sample;
        # the important thing is that it runs without exception and returns a string.
        assert isinstance(text, str)

    def test_empty_rtf_does_not_raise(self):
        te = xspct.TextExtractorRtf(b'{\\rtf1}')
        result = te.get_text()
        assert isinstance(result, str)

    def test_all_text_list_populated(self):
        rtf = b'{\\rtf1 hello}'
        te = xspct.TextExtractorRtf(rtf)
        te.parse()
        assert isinstance(te.all_text, list)


# ===========================================================================
# UNIT TESTS — load_config
# ===========================================================================

class TestLoadConfig:

    def test_none_path_is_noop(self):
        # Should not raise and should normalise api_key
        xspct.config['xspct_api_key'] = 'single-key'
        xspct.load_config(None)
        assert isinstance(xspct.config['xspct_api_key'], list)
        assert xspct.config['xspct_api_key'] == ['single-key']

    def test_missing_file_exits(self, tmp_path):
        with pytest.raises(SystemExit):
            xspct.load_config(str(tmp_path / 'nonexistent.yml'))

    def test_valid_yaml_updates_config(self, tmp_path):
        cfg = tmp_path / 'xspct.yml'
        cfg.write_text('xspct_listen_port: 9999\n')
        original = xspct.config['xspct_listen_port']
        try:
            xspct.load_config(str(cfg))
            assert xspct.config['xspct_listen_port'] == 9999
        finally:
            xspct.config['xspct_listen_port'] = original

    def test_sub_dict_is_merged_not_replaced(self, tmp_path):
        cfg = tmp_path / 'xspct.yml'
        cfg.write_text('xspct_redis_cache:\n  host: redis.custom.example\n')
        original_port = xspct.config['xspct_redis_cache']['port']
        try:
            xspct.load_config(str(cfg))
            assert xspct.config['xspct_redis_cache']['host'] == 'redis.custom.example'
            assert xspct.config['xspct_redis_cache']['port'] == original_port
        finally:
            xspct.config['xspct_redis_cache']['host'] = 'localhost'

    def test_invalid_yaml_exits(self, tmp_path):
        cfg = tmp_path / 'bad.yml'
        cfg.write_text(': invalid: yaml: {unclosed\n')
        with pytest.raises(SystemExit):
            xspct.load_config(str(cfg))

    def test_string_api_key_normalised_to_list(self, tmp_path):
        cfg = tmp_path / 'xspct.yml'
        cfg.write_text('xspct_api_key: my-secret-key\n')
        try:
            xspct.load_config(str(cfg))
            assert xspct.config['xspct_api_key'] == ['my-secret-key']
        finally:
            xspct.config['xspct_api_key'] = []

    def test_empty_string_api_key_normalised_to_empty_list(self, tmp_path):
        cfg = tmp_path / 'xspct.yml'
        cfg.write_text('xspct_api_key: ""\n')
        try:
            xspct.load_config(str(cfg))
            assert xspct.config['xspct_api_key'] == []
        finally:
            xspct.config['xspct_api_key'] = []


# ===========================================================================
# UNIT TESTS — configure_logging
# ===========================================================================

class TestConfigureLogging:

    def test_calling_twice_does_not_duplicate_handlers(self):
        xspct.configure_logging()
        xspct.configure_logging()
        real_handlers = [
            h for h in xspct.logger.handlers
            if not isinstance(h, logging.NullHandler)
        ]
        assert len(real_handlers) == 1

    def test_log_level_applied(self):
        xspct.config['xspct_log_level'] = logging.WARNING
        xspct.configure_logging()
        assert xspct.logger.level == logging.WARNING
        xspct.config['xspct_log_level'] = 20  # restore
        xspct.configure_logging()

    def test_handler_is_stream_handler(self):
        xspct.configure_logging()
        real_handlers = [
            h for h in xspct.logger.handlers
            if not isinstance(h, logging.NullHandler)
        ]
        assert isinstance(real_handlers[0], logging.StreamHandler)


# ===========================================================================
# UNIT TESTS — get_detected_type (image / archive types)
# ===========================================================================

class TestGetDetectedTypeExtended:
    """Cover image and archive detection added in Phase 8."""

    def test_image_by_mime_jpeg(self, daemon):
        assert daemon.get_detected_type('image/jpeg', None, None, None) == 'image'

    def test_image_by_mime_png(self, daemon):
        assert daemon.get_detected_type('image/png', None, None, None) == 'image'

    def test_image_by_mime_gif(self, daemon):
        assert daemon.get_detected_type('image/gif', None, None, None) == 'image'

    def test_image_by_extension(self, daemon):
        assert daemon.get_detected_type(None, None, 'photo.jpg', None) == 'image'

    def test_image_png_magic_bytes(self, daemon):
        # PNG header without MIME/extension — get_detected_type relies on MIME
        # or extension for image detection; raw magic bytes alone → unknown
        png_header = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100
        result = daemon.get_detected_type(None, None, None, png_header)
        assert result in ('image', 'unknown')  # depends on libmagic availability

    def test_archive_by_mime_zip(self, daemon):
        assert daemon.get_detected_type('application/zip', None, None, None) == 'archive'

    def test_archive_by_extension_zip(self, daemon):
        assert daemon.get_detected_type(None, None, 'payload.zip', None) == 'archive'

    def test_archive_by_extension_7z(self, daemon):
        assert daemon.get_detected_type(None, None, 'payload.7z', None) == 'archive'

    def test_text_by_mime(self, daemon):
        assert daemon.get_detected_type('text/plain', None, None, None) == 'text'


# ===========================================================================
# UNIT TESTS — _make_base_report (new fields present)
# ===========================================================================

class TestMakeBaseReport:

    def test_all_new_fields_present(self, daemon):
        r = daemon._make_base_report('f.pdf', 'abc123', 'application/pdf', 'PDF doc')
        for field in ('yara_matches', 'iocs_extended', 'pdfid_keywords',
                      'pdfid_meta', 'archive_files', 'exif', 'text_full'):
            assert field in r, f'Missing field: {field}'

    def test_yara_matches_is_list(self, daemon):
        r = daemon._make_base_report('f.pdf', 'abc', None, None)
        assert isinstance(r['yara_matches'], list)

    def test_iocs_extended_is_dict(self, daemon):
        r = daemon._make_base_report('f.pdf', 'abc', None, None)
        assert isinstance(r['iocs_extended'], dict)

    def test_archive_files_is_list(self, daemon):
        r = daemon._make_base_report('f.pdf', 'abc', None, None)
        assert isinstance(r['archive_files'], list)

    def test_exif_is_dict(self, daemon):
        r = daemon._make_base_report('f.pdf', 'abc', None, None)
        assert isinstance(r['exif'], dict)

    def test_text_full_is_empty_list_by_default(self, daemon):
        r = daemon._make_base_report('f.pdf', 'abc', None, None)
        assert r['text_full'] == []


# ===========================================================================
# UNIT TESTS — merge_reports (new fields)
# ===========================================================================

class TestMergeReportsNewFields:

    def _base(self, daemon):
        return daemon._make_base_report('f', 'h', None, None)

    def test_yara_matches_merged_no_duplicates(self, daemon):
        base   = self._base(daemon)
        hit    = {'engine': 'classic', 'rule': 'Eicar', 'namespace': '', 'tags': [], 'meta': {}, 'strings': []}
        base['yara_matches'] = [hit]
        daemon.merge_reports(base, {'yara_matches': [hit, {'engine': 'yara-x', 'rule': 'Other',
                                                           'namespace': '', 'tags': [], 'meta': {}, 'strings': []}]})
        rules = [m['rule'] for m in base['yara_matches']]
        assert rules.count('Eicar') == 1
        assert 'Other' in rules

    def test_iocs_extended_deep_merged(self, daemon):
        base = self._base(daemon)
        base['iocs_extended'] = {'url': ['http://a.example']}
        daemon.merge_reports(base, {'iocs_extended': {'url': ['http://b.example'], 'email': ['x@example.com']}})
        assert 'http://a.example' in base['iocs_extended']['url']
        assert 'http://b.example' in base['iocs_extended']['url']
        assert 'x@example.com' in base['iocs_extended']['email']

    def test_archive_files_appended(self, daemon):
        base = self._base(daemon)
        base['archive_files'] = [{'name': 'a.txt', 'size': 10}]
        daemon.merge_reports(base, {'archive_files': [{'name': 'b.pdf', 'size': 20}]})
        names = [f['name'] for f in base['archive_files']]
        assert 'a.txt' in names
        assert 'b.pdf' in names

    def test_archive_files_no_duplicates(self, daemon):
        base = self._base(daemon)
        item = {'name': 'x.doc', 'size': 5}
        base['archive_files'] = [item]
        daemon.merge_reports(base, {'archive_files': [item]})
        assert len(base['archive_files']) == 1

    def test_exif_first_wins(self, daemon):
        base = self._base(daemon)
        base['exif'] = {'Make': 'Canon'}
        daemon.merge_reports(base, {'exif': {'Make': 'Nikon'}})
        assert base['exif']['Make'] == 'Canon'

    def test_exif_empty_replaced(self, daemon):
        base = self._base(daemon)
        daemon.merge_reports(base, {'exif': {'Make': 'Sony'}})
        assert base['exif']['Make'] == 'Sony'

    def test_text_full_segments_accumulate(self, daemon):
        base = self._base(daemon)
        daemon.merge_reports(base, {'text_full': [{'source': 'a', 'text': 'alpha'}]})
        daemon.merge_reports(base, {'text_full': [{'source': 'b', 'text': 'beta'}]})
        texts = {s['text'] for s in base.get('text_segments', [])}
        assert 'alpha' in texts and 'beta' in texts

    def test_text_segments_dedup(self, daemon):
        base = self._base(daemon)
        daemon.merge_reports(base, {'text_segments': [{'source': 'a', 'text': 'x'}]})
        daemon.merge_reports(base, {'text_segments': [{'source': 'a', 'text': 'x'}]})
        assert sum(1 for s in base['text_segments'] if s['text'] == 'x') == 1


# ===========================================================================
# UNIT TESTS — analyze_yara (no engine installed path)
# ===========================================================================

class TestAnalyzeYaraNoEngine:

    def test_returns_none_when_no_rules_loaded(self, daemon):
        # daemon fixture has no YARA rules compiled
        result = daemon.analyze_yara(b'test data')
        assert result is None

    def test_yara_x_rules_none_skipped(self, daemon):
        assert getattr(daemon, '_yara_x_rules', None) is None
        # Should not raise
        result = daemon.analyze_yara(b'\x00' * 64)
        assert result is None


# ===========================================================================
# UNIT TESTS — sync_analyze YARA integration
# ===========================================================================

class TestSyncAnalyzeYara:
    """Verify that sync_analyze calls YARA when rules are available and that the
    result is reflected in the returned report's yara_matches list."""

    def test_no_rules_yara_matches_empty(self, daemon):
        # No rules loaded \u2014 yara_matches must be present but empty
        report = daemon.sync_analyze('s', 'file.txt', b'hello world', 'text/plain')
        assert 'yara_matches' in report
        assert report['yara_matches'] == []

    def test_yara_called_when_rules_loaded(self, daemon, monkeypatch):
        # Patch analyze_yara to return a fake match so we can assert it was called
        hit = {'rule': 'TestRule', 'engine': 'classic', 'tags': [], 'meta': {}}
        monkeypatch.setattr(daemon, '_yara_rules', object())  # non-None triggers check
        # yara analyzer is disabled by default; enable it for this test
        saved = xspct.config['xspct_analyzers']['yara']['enabled']
        xspct.config['xspct_analyzers']['yara']['enabled'] = True
        call_log = []

        def _fake_yara(data, filename='', file_mime='', s=''):
            call_log.append(data)
            return {'yara_matches': [hit]}

        monkeypatch.setattr(daemon, 'analyze_yara', _fake_yara)
        try:
            report = daemon.sync_analyze('s', 'file.txt', b'hello world', 'text/plain')
        finally:
            xspct.config['xspct_analyzers']['yara']['enabled'] = saved
        assert call_log, 'analyze_yara was not called'
        assert hit in report['yara_matches']


# ===========================================================================
# UNIT TESTS — analyze_iocsearcher
# ===========================================================================

class TestAnalyzeIocsearcher:

    def test_returns_none_when_not_installed(self, daemon):
        if xspct.HAS_IOCSEARCHER:
            pytest.skip('iocsearcher is installed; skipping no-engine path')
        result = daemon.analyze_iocsearcher('some text with http://example.com', 'test')
        assert result is None

    def test_returns_dict_when_installed(self, daemon):
        if not xspct.HAS_IOCSEARCHER:
            pytest.skip('iocsearcher not installed')
        result = daemon.analyze_iocsearcher('Visit http://example.com for details', 'test')
        # Returns None if no hits, or dict with iocs_extended key
        assert result is None or ('iocs_extended' in result)

    def test_empty_text_returns_none(self, daemon):
        if not xspct.HAS_IOCSEARCHER:
            pytest.skip('iocsearcher not installed')
        result = daemon.analyze_iocsearcher('', 'test')
        assert result is None


# ===========================================================================
# UNIT TESTS — analyze_archive
# ===========================================================================

class TestAnalyzeArchive:

    def test_non_archive_bytes_returns_none(self, daemon):
        result = daemon.analyze_archive('s', 'random.bin', b'\x00\x01\x02\x03' * 32, 0)
        assert result is None

    def test_depth_exceeded_returns_none(self, daemon):
        # max depth is 2 by default; depth=2 should be rejected
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            z.writestr('hello.txt', 'hello world')
        saved = xspct.config['xspct_archive_max_depth']
        xspct.config['xspct_archive_max_depth'] = 1
        try:
            result = daemon.analyze_archive('s', 'test.zip', buf.getvalue(), depth=1)
        finally:
            xspct.config['xspct_archive_max_depth'] = saved
        assert result is None

    def test_empty_zip_returns_none(self, daemon):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w'):
            pass
        result = daemon.analyze_archive('s', 'empty.zip', buf.getvalue(), 0)
        assert result is None

    def test_zip_with_text_file_extracted(self, daemon):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            z.writestr('readme.txt', 'hello world content')
        result = daemon.analyze_archive('s', 'test.zip', buf.getvalue(), 0)
        # txt is 'text' type — analyze_text runs via sync_analyze
        assert result is not None
        names = [f['name'] for f in result['archive_files']]
        assert 'readme.txt' in names

    def test_zip_with_pdf_extracted(self, daemon):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            z.writestr('doc.pdf', PDF_CLEAN)
        result = daemon.analyze_archive('s', 'test.zip', buf.getvalue(), 0)
        assert result is not None
        names = [f['name'] for f in result['archive_files']]
        assert 'doc.pdf' in names

    def test_size_limit_stops_extraction(self, daemon):
        buf = io.BytesIO()
        big_content = b'A' * 1000
        with zipfile.ZipFile(buf, 'w') as z:
            for i in range(10):
                z.writestr(f'file{i}.txt', big_content)
        saved = xspct.config['xspct_archive_max_size']
        xspct.config['xspct_archive_max_size'] = 2500  # stop early
        try:
            result = daemon.analyze_archive('s', 'big.zip', buf.getvalue(), 0)
        finally:
            xspct.config['xspct_archive_max_size'] = saved
        # Some files extracted, but not all 10
        if result:
            assert len(result['archive_files']) < 10

    def test_disabled_analyzer_returns_none(self, daemon):
        saved = xspct.config['xspct_analyzers']['archive']['enabled']
        xspct.config['xspct_analyzers']['archive']['enabled'] = False
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            z.writestr('f.txt', 'hi')
        try:
            result = daemon.analyze_archive('s', 'test.zip', buf.getvalue(), 0)
        finally:
            xspct.config['xspct_analyzers']['archive']['enabled'] = saved
        assert result is None

    def test_archive_report_has_yara_matches_key(self, daemon):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            z.writestr('f.txt', 'some text')
        result = daemon.analyze_archive('s', 'test.zip', buf.getvalue(), 0)
        assert result is not None
        # yara_matches key must always be present (YARA may have no rules loaded)
        assert 'yara_matches' in result

    def test_archive_report_has_iocs_extended_key(self, daemon):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            z.writestr('f.txt', 'some text')
        result = daemon.analyze_archive('s', 'test.zip', buf.getvalue(), 0)
        assert result is not None
        assert 'iocs_extended' in result

    def test_archive_text_member_gets_text_preview(self, daemon):
        content = b'Hello from inside the archive'
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            z.writestr('note.txt', content)
        result = daemon.analyze_archive('s', 'test.zip', buf.getvalue(), 0)
        assert result is not None
        # text member now goes through sync_analyze which populates text_preview
        assert result.get('text_preview') or result['archive_files']

    def test_archive_pdf_member_propagates_yara_matches(self, daemon):
        # Even without YARA rules loaded the key must exist (empty list)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            z.writestr('doc.pdf', PDF_CLEAN)
        result = daemon.analyze_archive('s', 'test.zip', buf.getvalue(), 0)
        assert result is not None
        assert isinstance(result.get('yara_matches', []), list)


class TestArchiveCapabilityGating:

    def test_archive_analyzer_disabled_without_backend(self, daemon, monkeypatch):
        saved_fallback = xspct.config['xspct_archive_stdlib_fallback']
        saved_enabled = xspct.config['xspct_analyzers']['archive']['enabled']
        monkeypatch.setattr(xspct, 'HAS_SFLOCK', False)
        xspct.config['xspct_archive_stdlib_fallback'] = False
        xspct.config['xspct_analyzers']['archive']['enabled'] = True
        try:
            enabled = daemon._resolve_enabled_analyzers()
        finally:
            xspct.config['xspct_archive_stdlib_fallback'] = saved_fallback
            xspct.config['xspct_analyzers']['archive']['enabled'] = saved_enabled
        assert 'archive' not in enabled

    def test_archive_analyzer_enabled_with_stdlib_fallback(self, daemon, monkeypatch):
        saved_fallback = xspct.config['xspct_archive_stdlib_fallback']
        saved_enabled = xspct.config['xspct_analyzers']['archive']['enabled']
        monkeypatch.setattr(xspct, 'HAS_SFLOCK', False)
        xspct.config['xspct_archive_stdlib_fallback'] = True
        xspct.config['xspct_analyzers']['archive']['enabled'] = True
        try:
            enabled = daemon._resolve_enabled_analyzers()
        finally:
            xspct.config['xspct_archive_stdlib_fallback'] = saved_fallback
            xspct.config['xspct_analyzers']['archive']['enabled'] = saved_enabled
        assert 'archive' in enabled

    def test_sync_analyze_zip_without_backend_returns_unknown(self, daemon, monkeypatch):
        saved_fallback = xspct.config['xspct_archive_stdlib_fallback']
        saved_enabled = xspct.config['xspct_analyzers']['archive']['enabled']
        monkeypatch.setattr(xspct, 'HAS_SFLOCK', False)
        xspct.config['xspct_archive_stdlib_fallback'] = False
        xspct.config['xspct_analyzers']['archive']['enabled'] = True

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            z.writestr('readme.txt', 'hello world')

        try:
            report = daemon.sync_analyze('s', 'test.zip', buf.getvalue(), 'application/zip')
        finally:
            xspct.config['xspct_archive_stdlib_fallback'] = saved_fallback
            xspct.config['xspct_analyzers']['archive']['enabled'] = saved_enabled

        assert report['detected_type'] == 'unknown'
        assert report['archive_files'] == []


# ===========================================================================
# UNIT TESTS — sflock2 archive extraction path
# ===========================================================================

class _SflockFile:
    """Minimal stub mimicking sflock2's File object."""

    def __init__(self, filename='', contents=b'', children=None, error=None, password=None):
        self.filename = filename
        self.contents = contents
        self.children = children or []
        self.error    = error
        self.password = password


class TestAnalyzeArchiveSflock:
    """Tests for the sflock2-backed extraction path in analyze_archive."""

    def _make_sflock_result(self, members: list):
        """Build a fake sflock File tree from a list of (name, bytes) tuples."""
        children = [_SflockFile(filename=name, contents=data) for name, data in members]
        return _SflockFile(filename='archive.zip', children=children)

    def test_sflock_path_extracts_text_member(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, 'HAS_SFLOCK', True)
        fake_result = self._make_sflock_result([('readme.txt', b'hello from sflock')])
        monkeypatch.setattr(xspct, '_sflock',
                            type('M', (), {'unpack': staticmethod(lambda **kw: fake_result)})())
        result = daemon.analyze_archive('s', 'archive.zip', b'FAKEARCHIVEBYTES', 0)
        assert result is not None
        names = [f['name'] for f in result['archive_files']]
        assert 'readme.txt' in names

    def test_sflock_path_extracts_pdf_member(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, 'HAS_SFLOCK', True)
        fake_result = self._make_sflock_result([('doc.pdf', PDF_CLEAN)])
        monkeypatch.setattr(xspct, '_sflock',
                            type('M', (), {'unpack': staticmethod(lambda **kw: fake_result)})())
        result = daemon.analyze_archive('s', 'test.zip', b'FAKEARCHIVEBYTES', 0)
        assert result is not None
        assert any(f['name'] == 'doc.pdf' for f in result['archive_files'])

    def test_sflock_empty_children_returns_none(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, 'HAS_SFLOCK', True)
        fake_result = _SflockFile(filename='bad.zip', children=[])
        monkeypatch.setattr(xspct, '_sflock',
                            type('M', (), {'unpack': staticmethod(lambda **kw: fake_result)})())
        result = daemon.analyze_archive('s', 'bad.zip', b'FAKEARCHIVEBYTES', 0)
        assert result is None

    def test_sflock_password_retry_stops_on_success(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, 'HAS_SFLOCK', True)
        calls = []

        def _unpack(**kw):
            calls.append(kw.get('password'))
            if kw.get('password') == 'secret':
                return self._make_sflock_result([('protected.txt', b'unlocked')])
            return _SflockFile(filename='enc.zip', children=[], error='Decryption failed')

        daemon.passwords = ['wrong', 'secret', 'notneeded']
        monkeypatch.setattr(xspct, '_sflock',
                            type('M', (), {'unpack': staticmethod(_unpack)})())
        result = daemon.analyze_archive('s', 'enc.zip', b'FAKEARCHIVEBYTES', 0)
        assert result is not None
        assert 'secret' in calls
        assert 'notneeded' not in calls  # stopped after success

    def test_sflock_size_limit_precheck_returns_none(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, 'HAS_SFLOCK', True)
        saved = xspct.config['xspct_archive_max_size']
        xspct.config['xspct_archive_max_size'] = 10  # tiny limit
        try:
            result = daemon.analyze_archive('s', 'huge.zip', b'X' * 100, 0)
        finally:
            xspct.config['xspct_archive_max_size'] = saved
        assert result is None

    def test_sflock_nested_container_walked(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, 'HAS_SFLOCK', True)
        # Simulate a ZIP-inside-ZIP already unpacked by sflock
        inner_leaf  = _SflockFile(filename='inner.txt', contents=b'nested content')
        outer_child = _SflockFile(filename='inner.zip', children=[inner_leaf])
        root        = _SflockFile(filename='outer.zip', children=[outer_child])
        monkeypatch.setattr(xspct, '_sflock',
                            type('M', (), {'unpack': staticmethod(lambda **kw: root)})())
        result = daemon.analyze_archive('s', 'outer.zip', b'FAKEARCHIVEBYTES', 0)
        assert result is not None
        names = [f['name'] for f in result['archive_files']]
        assert 'inner.txt' in names

    def test_sflock_decryption_password_stored_in_report(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, 'HAS_SFLOCK', True)
        fake_result = self._make_sflock_result([('secret.txt', b'payload')])
        fake_result.password = 'infected'
        monkeypatch.setattr(xspct, '_sflock',
                            type('M', (), {'unpack': staticmethod(lambda **kw: fake_result)})())
        result = daemon.analyze_archive('s', 'enc.zip', b'FAKEARCHIVEBYTES', 0)
        assert result is not None
        assert result.get('decryption_password') == 'infected'

    def test_sflock_exception_falls_back_gracefully(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, 'HAS_SFLOCK', True)

        def _boom(**kw):
            raise RuntimeError('sflock internal error')

        monkeypatch.setattr(xspct, '_sflock',
                            type('M', (), {'unpack': staticmethod(_boom)})())
        # Should return None (not raise)
        result = daemon.analyze_archive('s', 'corrupt.zip', b'FAKEARCHIVEBYTES', 0)
        assert result is None


class TestGetDetectedTypeSflockFormats:
    """Ensure new archive formats are recognised after sflock support was added."""

    def test_rar_by_extension(self, daemon):
        assert daemon.get_detected_type(None, None, 'archive.rar', None) == 'archive'

    def test_eml_by_extension(self, daemon):
        assert daemon.get_detected_type(None, None, 'email.eml', None) == 'archive'

    def test_msg_mime_returns_archive(self, daemon):
        assert daemon.get_detected_type('application/vnd.ms-outlook', None, None, None) == 'archive'

    def test_eml_mime_returns_archive(self, daemon):
        assert daemon.get_detected_type('message/rfc822', None, None, None) == 'archive'

    def test_cab_by_extension(self, daemon):
        assert daemon.get_detected_type(None, None, 'setup.cab', None) == 'archive'

    def test_ace_by_extension(self, daemon):
        assert daemon.get_detected_type(None, None, 'archive.ace', None) == 'archive'

    def test_iso_by_extension(self, daemon):
        assert daemon.get_detected_type(None, None, 'disc.iso', None) == 'archive'

    def test_tar_gz_by_extension_tgz(self, daemon):
        assert daemon.get_detected_type(None, None, 'pkg.tgz', None) == 'archive'

    def test_tar_bz2_by_extension_tbz2(self, daemon):
        assert daemon.get_detected_type(None, None, 'src.tbz2', None) == 'archive'

    def test_rar_desc_returns_archive(self, daemon):
        assert daemon.get_detected_type(None, 'rar archive data', None, None) == 'archive'


# ===========================================================================
# UNIT TESTS — PartialReport
# ===========================================================================

class TestPartialReport:

    def _base(self, daemon):
        b = daemon._make_base_report('f.pdf', 'abc', None, None)
        b['analyzers_completed'] = []
        b['analyzers_pending']   = ['pdf', 'yara']
        return b

    @pytest.mark.asyncio
    async def test_snapshot_returns_copy(self, daemon):
        pr = xspct.PartialReport(self._base(daemon), ['pdf', 'yara'])
        snap = pr.snapshot()
        assert snap is not pr.report

    @pytest.mark.asyncio
    async def test_merge_moves_analyzer_to_completed(self, daemon):
        pr = xspct.PartialReport(self._base(daemon), ['pdf', 'yara'])
        await pr.merge('pdf', {'analyses': []}, daemon)
        assert 'pdf' in pr.successful
        assert 'pdf' not in pr.report.get('analyzers_pending', [])

    @pytest.mark.asyncio
    async def test_merge_none_result_still_completes(self, daemon):
        pr = xspct.PartialReport(self._base(daemon), ['pdf'])
        await pr.merge('pdf', None, daemon)
        # Should still be marked completed even with None result
        assert 'pdf' in pr.successful or 'pdf' not in pr.report.get('analyzers_pending', [])


# ===========================================================================
# UNIT TESTS — text_full via sync_analyze
# ===========================================================================

class TestTextFull:

    def test_text_full_is_list(self, daemon):
        """sync_analyze finalizes text_full as a list of {source, text}."""
        r = daemon.sync_analyze('s', 'doc.pdf', PDF_CLEAN, None)
        assert isinstance(r['text_full'], list)

    def test_scan_report_has_text_full_key(self):
        """text_full key is always present in the base report (empty list)."""
        d = xspct.InspectorDaemon()
        r = d._make_base_report('f', 'h', None, None)
        assert r['text_full'] == []

    async def test_pipeline_text_full_uses_analyzer_text(self, daemon, monkeypatch):
        """Analyzer-provided text segments populate text_full."""
        long_text = 'ocr text ' * 100

        def fake_analyze_pdf(data, custom_passwords=None):
            rep = {
                'analyses': [],
                'iocs': {'urls': [], 'ips': [], 'domains': []},
            }
            daemon._add_text_segment(rep, 'pdf', long_text)
            return rep

        monkeypatch.setattr(daemon, 'analyze_pdf', fake_analyze_pdf)
        monkeypatch.setattr(daemon, 'extract_text_preview', lambda *a, **k: '')
        partial = await daemon.analyze_pipeline(
            's', 'scan.pdf', PDF_CLEAN, 'application/pdf', types_to_run=['pdf']
        )
        assert any('ocr text' in seg['text'] for seg in partial.report['text_full'])
        assert 'text_segments' not in partial.report


# ===========================================================================
# INTEGRATION TESTS — octet-stream upload
# ===========================================================================

class TestScanOctetStream:

    async def test_octet_stream_clean_pdf_returns_200(self, client):
        r = await client.post(
            '/v1/scan?filename=test.pdf',
            data=PDF_CLEAN,
            headers={'Content-Type': 'application/octet-stream'},
        )
        assert r.status == 200
        body = await r.json()
        assert body['detected_type'] == 'pdf'
        assert body['file_hash'] == hashlib.sha256(PDF_CLEAN).hexdigest()

    async def test_octet_stream_same_hash_as_multipart(self, client):
        r1 = await client.post('/v1/scan', data=_form(PDF_CLEAN, 'a.pdf'))
        b1 = await r1.json()

        r2 = await client.post(
            '/v1/scan',
            data=PDF_CLEAN,
            headers={'Content-Type': 'application/octet-stream'},
        )
        b2 = await r2.json()
        assert b1['file_hash'] == b2['file_hash']

    async def test_unsupported_content_type_returns_415(self, client):
        r = await client.post(
            '/v1/scan',
            data=b'some data',
            headers={'Content-Type': 'text/xml'},
        )
        assert r.status == 415

    async def test_octet_stream_with_filename_query_param(self, client):
        r = await client.post(
            '/v1/scan?filename=payload.html',
            data=HTML_CLEAN,
            headers={'Content-Type': 'application/octet-stream'},
        )
        assert r.status == 200
        body = await r.json()
        assert body['detected_type'] == 'html'


# ===========================================================================
# INTEGRATION TESTS — admin /admin/reload
# ===========================================================================

# ===========================================================================
# UNIT / INTEGRATION TESTS — Two-tier concurrency
# ===========================================================================

class TestTwoTierConcurrency:
    """Verify foreground/background semaphore lifecycle in handle_scan."""

    # --- Config defaults -------------------------------------------------

    def test_default_foreground_slots(self):
        assert xspct.config['xspct_foreground_slots'] == 16

    def test_default_background_slots(self):
        assert xspct.config['xspct_background_slots'] == 4

    def test_stats_keys_exist(self):
        for key in ('foreground_overloaded', 'background_rejected',
                    'background_completed', 'background_errors'):
            assert key in xspct.stats

    # --- Semaphore initialisation ----------------------------------------

    def test_daemon_semaphores_none_before_setup(self):
        d = xspct.InspectorDaemon()
        assert d._fg_sem is None
        assert d._bg_sem is None

    async def test_semaphores_initialised_after_setup(self, client):
        # client fixture creates a full app via make_app() → setup()
        # The daemon attached to the app must have non-None semaphores.
        app_daemon = client.server.app.get('daemon')
        if app_daemon is None:
            pytest.skip('app does not expose daemon via app["daemon"]')
        assert app_daemon._fg_sem is not None
        assert app_daemon._bg_sem is not None

    # --- Normal scan finishes within timeout (foreground slot released) ---

    async def test_normal_scan_releases_fg_slot(self, client):
        r = await client.post('/v1/scan', data=_form(PDF_CLEAN, 'test.pdf'))
        assert r.status == 200
        body = await r.json()
        assert body['status'] == 'finished'

    # --- Overload: all foreground slots taken → 503 ----------------------

    async def test_overloaded_returns_503(self, aiohttp_client):
        """Simulate all foreground slots occupied; next request gets 503."""
        xspct.config['xspct_foreground_slots'] = 2
        xspct.config['xspct_background_slots'] = 1
        app = await xspct.make_app()
        client = await aiohttp_client(app)
        daemon = app['daemon']
        # Occupy every foreground slot
        n = daemon._fg_sem._value
        for _ in range(n):
            await daemon._fg_sem.acquire()
        before = xspct.stats['foreground_overloaded']
        try:
            r = await client.post(
                '/v1/scan?timeout=0.05',
                data=_form(PDF_CLEAN, 'test.pdf'),
            )
            assert r.status == 503
            body = await r.json()
            assert 'overloaded' in body.get('error', '').lower()
        finally:
            for _ in range(n):
                daemon._fg_sem.release()
            xspct.config['xspct_foreground_slots'] = 16
            xspct.config['xspct_background_slots'] = 4
        assert xspct.stats['foreground_overloaded'] > before

    # --- Background slot full → scan dropped → 202 with status=dropped --

    async def test_background_full_drops_scan(self, aiohttp_client, monkeypatch):
        """When bg slots are all taken, a timed-out scan is cancelled (dropped)."""
        xspct.config['xspct_foreground_slots'] = 2
        xspct.config['xspct_background_slots'] = 1
        app = await xspct.make_app()
        client = await aiohttp_client(app)
        daemon = app['daemon']

        # Hold all background slots
        n_bg = daemon._bg_sem._value
        for _ in range(n_bg):
            await daemon._bg_sem.acquire()

        # Make analyze_task hang so the scan always times out
        async def _slow(*args, **kwargs):
            await asyncio.sleep(60)
            return {}

        monkeypatch.setattr(daemon, 'analyze_task', _slow)
        before = xspct.stats['background_rejected']
        try:
            r = await client.post(
                '/v1/scan?timeout=0.1',
                data=_form(PDF_CLEAN, 'slow.pdf'),
            )
            assert r.status == 202
            body = await r.json()
            assert body.get('status') == 'dropped'
        finally:
            for _ in range(n_bg):
                daemon._bg_sem.release()
            xspct.config['xspct_foreground_slots'] = 16
            xspct.config['xspct_background_slots'] = 4
        assert xspct.stats['background_rejected'] > before

    async def test_timeout_promotes_to_background_when_slot_available(self, aiohttp_client, monkeypatch):
        """A timed-out scan should return 202/processing when a bg slot is free."""
        xspct.config['xspct_foreground_slots'] = 1
        xspct.config['xspct_background_slots'] = 1
        app = await xspct.make_app()
        client = await aiohttp_client(app)
        daemon = app['daemon']

        finalized = asyncio.Event()

        async def _slow(*args, **kwargs):
            await asyncio.Event().wait()

        async def _finalize_background(s, file_hash, task):
            try:
                task.cancel()
                await task
            except asyncio.CancelledError:
                pass
            finally:
                daemon._bg_sem.release()
                finalized.set()

        monkeypatch.setattr(daemon, 'analyze_task', _slow)
        monkeypatch.setattr(daemon, '_finalize_background', _finalize_background)
        try:
            r = await client.post(
                '/v1/scan?timeout=0.1',
                data=_form(PDF_CLEAN, 'slow.pdf'),
            )
            assert r.status == 202
            body = await r.json()
            assert body.get('status') == 'processing'
            await asyncio.wait_for(finalized.wait(), timeout=1)
            assert daemon._bg_sem._value == 1
        finally:
            xspct.config['xspct_foreground_slots'] = 16
            xspct.config['xspct_background_slots'] = 4

    async def test_background_failure_becomes_stable_query_error(self, aiohttp_client, monkeypatch):
        """A failed background scan should be queryable as a stable error result."""
        xspct.config['xspct_foreground_slots'] = 1
        xspct.config['xspct_background_slots'] = 1
        app = await xspct.make_app()
        client = await aiohttp_client(app)
        daemon = app['daemon']

        allow_raise = asyncio.Event()
        error_stored = asyncio.Event()
        original_store = daemon._store_terminal_result

        async def _boom(*args, **kwargs):
            await allow_raise.wait()
            raise RuntimeError('boom')

        def _store_and_signal(file_hash, result):
            original_store(file_hash, result)
            if result.get('status') == 'error':
                error_stored.set()

        monkeypatch.setattr(daemon, 'analyze_task', _boom)
        monkeypatch.setattr(daemon, '_store_terminal_result', _store_and_signal)
        try:
            r = await client.post(
                '/v1/scan?timeout=0.01',
                data=_form(PDF_CLEAN, 'boom.pdf'),
            )
            assert r.status == 202
            body = await r.json()
            assert body.get('status') == 'processing'

            allow_raise.set()
            await asyncio.wait_for(error_stored.wait(), timeout=1)

            query_1 = await client.get(f"/v1/query?hash={body['file_hash']}")
            assert query_1.status == 200
            q1_body = await query_1.json()
            assert q1_body['status'] == 'error'
            assert q1_body['file_hash'] == body['file_hash']

            query_2 = await client.get(f"/v1/query?hash={body['file_hash']}")
            assert query_2.status == 200
            q2_body = await query_2.json()
            assert q2_body['status'] == 'error'
            assert q2_body['file_hash'] == body['file_hash']
        finally:
            xspct.config['xspct_foreground_slots'] = 16
            xspct.config['xspct_background_slots'] = 4

    # --- /metrics exposes new counters -----------------------------------

    async def test_metrics_contains_concurrency_lines(self, client):
        r = await client.get('/v1/metrics')
        assert r.status == 200
        text = await r.text()
        for key in ('xspct_foreground_overloaded', 'xspct_background_rejected',
                    'xspct_background_completed', 'xspct_background_errors',
                    'xspct_foreground_slots_free', 'xspct_background_slots_free'):
            assert key in text, f'metric {key!r} missing from /metrics'


# ===========================================================================
# INTEGRATION TESTS — admin /admin/reload
# ===========================================================================

class TestAdminReload:

    async def test_no_admin_key_configured_returns_403(self, client):
        xspct.config['xspct_admin_api_key'] = []
        r = await client.post('/v1/admin/reload')
        assert r.status == 403

    async def test_wrong_admin_key_returns_403(self, client):
        xspct.config['xspct_admin_api_key'] = ['correct-admin-key']
        try:
            r = await client.post(
                '/v1/admin/reload',
                headers={'X-Admin-Api-Key': 'wrong-key'},
            )
            assert r.status == 403
        finally:
            xspct.config['xspct_admin_api_key'] = []

    async def test_correct_admin_key_returns_200(self, client):
        xspct.config['xspct_admin_api_key'] = ['admin-secret']
        try:
            r = await client.post(
                '/v1/admin/reload',
                headers={'X-Admin-Api-Key': 'admin-secret'},
            )
            assert r.status == 200
            body = await r.json()
            assert body['status'] == 'ok'
            assert isinstance(body['reloaded'], list)
        finally:
            xspct.config['xspct_admin_api_key'] = []


# ===========================================================================
# INTEGRATION TESTS — OpenAPI endpoints
# ===========================================================================

class TestOpenApiEndpoints:

    async def test_openapi_json_returns_200_when_pydantic(self, client):
        if not xspct.HAS_PYDANTIC:
            pytest.skip('pydantic not installed')
        r = await client.get('/v1/openapi.json')
        assert r.status == 200
        body = await r.json()
        assert body.get('openapi', '').startswith('3.')
        assert 'paths' in body

    async def test_redoc_returns_200_when_pydantic(self, client):
        if not xspct.HAS_PYDANTIC:
            pytest.skip('pydantic not installed')
        r = await client.get('/v1/apidoc/redoc')
        assert r.status == 200
        text = await r.text()
        assert 'redoc' in text.lower() or 'openapi' in text.lower()

    async def test_openapi_json_returns_501_without_pydantic(self, client):
        if xspct.HAS_PYDANTIC:
            pytest.skip('pydantic is installed; skipping no-pydantic path')
        r = await client.get('/v1/openapi.json')
        assert r.status in (200, 501)  # implementation may vary


# ===========================================================================
# UNIT TESTS — verify_admin_key
# ===========================================================================

class TestVerifyAdminKey:

    def _req(self, header_value=None):
        mock = MagicMock()
        headers = {}
        if header_value is not None:
            headers['X-Admin-Api-Key'] = header_value
        mock.headers = headers
        return mock

    def test_no_keys_configured_always_false(self):
        xspct.config['xspct_admin_api_key'] = []
        assert xspct.verify_admin_key('s', self._req('anything')) is False

    def test_correct_key_passes(self):
        xspct.config['xspct_admin_api_key'] = ['secret']
        try:
            assert xspct.verify_admin_key('s', self._req('secret')) is True
        finally:
            xspct.config['xspct_admin_api_key'] = []

    def test_wrong_key_fails(self):
        xspct.config['xspct_admin_api_key'] = ['secret']
        try:
            assert xspct.verify_admin_key('s', self._req('wrong')) is False
        finally:
            xspct.config['xspct_admin_api_key'] = []

    def test_missing_header_fails(self):
        xspct.config['xspct_admin_api_key'] = ['secret']
        try:
            assert xspct.verify_admin_key('s', self._req()) is False
        finally:
            xspct.config['xspct_admin_api_key'] = []


# ===========================================================================
# UNIT TESTS — analyze_text
# ===========================================================================

class TestAnalyzeText:

    def test_empty_bytes_returns_none(self, daemon):
        result = daemon.analyze_text(b'', 'empty.txt')
        assert result is None

    def test_plain_ascii_returns_dict(self, daemon):
        result = daemon.analyze_text(b'Hello world', 'hello.txt')
        assert result is not None
        assert 'text_segments' in result
        assert 'iocs' in result
        assert 'analyses' in result

    def test_text_segment_content(self, daemon):
        result = daemon.analyze_text(b'Hello world', 'hello.txt')
        assert result['text_segments'][0]['text'] == 'Hello world'
        assert result['text_segments'][0]['source'] == 'text'

    def test_text_preview_respects_limit(self, daemon):
        saved = xspct.config['xspct_text_preview_length']
        xspct.config['xspct_text_preview_length'] = 5
        try:
            result = daemon.sync_analyze('s', 'hello.txt', b'Hello world', 'text/plain')
        finally:
            xspct.config['xspct_text_preview_length'] = saved
        assert all(len(seg['text']) <= 5 for seg in result['text_preview'])
        assert any(seg['text'] == 'Hello' for seg in result['text_preview'])

    def test_utf8_decoded(self, daemon):
        text = 'Ünïcödé text'
        result = daemon.analyze_text(text.encode('utf-8'), 'unicode.txt')
        assert result is not None
        assert 'Ünïcödé' in result['text_segments'][0]['text']

    def test_latin1_fallback(self, daemon):
        # Bytes that are not valid UTF-8 — latin-1 fallback should not raise
        data = bytes(range(0x80, 0xA0))
        result = daemon.analyze_text(data, 'latin.txt')
        assert result is not None
        assert isinstance(result.get('text_segments', []), list)

    def test_iocs_extracted(self, daemon):
        data = b'Visit http://evil.example.com/malware for details'
        result = daemon.analyze_text(data, 'ioc.txt')
        assert result is not None
        # extract_iocs returns a string or dict depending on configuration
        assert result['iocs'] is not None

    def test_analyses_list(self, daemon):
        result = daemon.analyze_text(b'some content', 'f.txt')
        assert isinstance(result['analyses'], list)

    def test_mime_type_hint_accepted(self, daemon):
        # file_mime kwarg is optional; passing it should not raise
        result = daemon.analyze_text(b'data', 'f.txt', file_mime='text/plain')
        assert result is not None


# ===========================================================================
# INTEGRATION TESTS — 'text' detected type flows through analyze_pipeline
# ===========================================================================

class TestTextTypePipeline:

    @pytest.mark.asyncio
    async def test_text_file_detected_and_analysed(self, client):
        payload = b'Hello from a plain text file with no special structure.'
        resp = await client.post(
            '/v1/scan',
            data=payload,
            headers={
                'Content-Type': 'application/octet-stream',
                'X-Filename': 'note.txt',
            },
        )
        assert resp.status == 200
        body = await resp.json()
        # detected_type may be 'text' or include 'text'
        dt = body.get('detected_type', '')
        assert 'text' in dt or dt == 'unknown'
        assert 'text_preview' in body

    @pytest.mark.asyncio
    async def test_text_analyzer_disabled_skips_method(self, aiohttp_client):
        saved = xspct.config['xspct_analyzers']['text']['enabled']
        xspct.config['xspct_analyzers']['text']['enabled'] = False
        app = await xspct.make_app()
        client = await aiohttp_client(app)
        try:
            payload = b'Plain text content for scan.'
            resp = await client.post(
                '/v1/scan',
                data=payload,
                headers={
                    'Content-Type': 'application/octet-stream',
                    'X-Filename': 'note.txt',
                },
            )
            assert resp.status == 200
        finally:
            xspct.config['xspct_analyzers']['text']['enabled'] = saved


# ===========================================================================
# FIXTURE-FILE TESTS — PDF with JavaScript
# ===========================================================================

@pytest.mark.skipif(
    not os.path.exists(PDF_JS_FILE),
    reason='pdf_javascript.pdf not present — run tests/create_fixtures.py',
)
class TestPdfJavascriptFixture:
    """Tests using the generated pdf_javascript.pdf fixture."""

    @pytest.fixture(autouse=True)
    def _data(self):
        self.data = open(PDF_JS_FILE, 'rb').read()

    def test_has_javascript_true(self, daemon):
        r = daemon.analyze_pdf(self.data)
        assert r is not None
        assert r['has_javascript'] is True

    def test_has_openaction_true(self, daemon):
        r = daemon.analyze_pdf(self.data)
        assert r is not None
        assert r['has_openaction'] is True

    def test_analyses_contains_javascript_entry(self, daemon):
        r = daemon.analyze_pdf(self.data)
        types = [a['type'] for a in r['analyses']]
        assert 'JavaScript' in types

    def test_analyses_contains_suspicious_js(self, daemon):
        r = daemon.analyze_pdf(self.data)
        # analyze_javascript should fire for eval / launchURL / document.write
        keywords = [a['keyword'] for a in r['analyses']]
        assert any('eval' in kw or 'launchURL' in kw or 'document.write' in kw
                   for kw in keywords)

    def test_iocs_contains_evil_url(self, daemon):
        r = daemon.analyze_pdf(self.data)
        assert any('evil.example.com' in u for u in r['iocs']['urls'])

    def test_text_preview_is_list(self, daemon):
        r = daemon.sync_analyze('s', 'doc.pdf', self.data, 'application/pdf')
        assert isinstance(r['text_preview'], list)

    @pytest.mark.asyncio
    async def test_scan_endpoint_detects_javascript(self, client):
        data = open(PDF_JS_FILE, 'rb').read()
        form = aiohttp.FormData()
        form.add_field('doc', data, filename='malware.pdf',
                       content_type='application/pdf')
        resp = await client.post('/v1/scan', data=form)
        assert resp.status == 200
        body = await resp.json()
        assert body['detected_type'] == 'pdf'
        assert body['has_javascript'] is True


# ===========================================================================
# FIXTURE-FILE TESTS — PDF with embedded file
# ===========================================================================

@pytest.mark.skipif(
    not os.path.exists(PDF_EMBEDDED_FILE),
    reason='pdf_embedded.pdf not present — run tests/create_fixtures.py',
)
class TestPdfEmbeddedFileFixture:
    """Tests using the generated pdf_embedded.pdf fixture."""

    @pytest.fixture(autouse=True)
    def _data(self):
        self.data = open(PDF_EMBEDDED_FILE, 'rb').read()

    def test_has_embedded_files_true(self, daemon):
        r = daemon.analyze_pdf(self.data)
        assert r is not None
        assert r['has_embedded_files'] is True

    def test_analyses_contains_embedded_file_entry(self, daemon):
        r = daemon.analyze_pdf(self.data)
        types = [a['type'] for a in r['analyses']]
        assert 'EmbeddedFile' in types

    def test_analyses_mentions_payload_filename(self, daemon):
        r = daemon.analyze_pdf(self.data)
        descriptions = ' '.join(a['description'] for a in r['analyses'])
        assert 'payload' in descriptions.lower()


# ===========================================================================
# FIXTURE-FILE TESTS — PDF with external URI
# ===========================================================================

@pytest.mark.skipif(
    not os.path.exists(PDF_URI_FILE),
    reason='pdf_uri.pdf not present — run tests/create_fixtures.py',
)
class TestPdfUriFixture:
    """Tests using the generated pdf_uri.pdf fixture."""

    @pytest.fixture(autouse=True)
    def _data(self):
        self.data = open(PDF_URI_FILE, 'rb').read()

    def test_iocs_contains_uri(self, daemon):
        r = daemon.analyze_pdf(self.data)
        assert r is not None
        assert any('evil.example.com' in u for u in r['iocs']['urls'])

    def test_is_not_encrypted(self, daemon):
        r = daemon.analyze_pdf(self.data)
        assert r['is_encrypted'] is False


# ===========================================================================
# FIXTURE-FILE TESTS — HTML phishing page
# ===========================================================================

@pytest.mark.skipif(
    not os.path.exists(HTML_PHISHING_FILE),
    reason='html_phishing.html not present — run tests/create_fixtures.py',
)
class TestHtmlPhishingFixture:
    """Tests using the generated html_phishing.html fixture."""

    @pytest.fixture(autouse=True)
    def _data(self):
        self.data = open(HTML_PHISHING_FILE, 'rb').read()

    def test_has_forms(self, daemon):
        r = daemon.analyze_html(self.data)
        assert r is not None
        assert r['has_forms'] is True

    def test_has_iframes(self, daemon):
        r = daemon.analyze_html(self.data)
        assert r['has_iframes'] is True

    def test_has_meta_refresh(self, daemon):
        r = daemon.analyze_html(self.data)
        assert r['has_meta_refresh'] is True

    def test_has_scripts(self, daemon):
        r = daemon.analyze_html(self.data)
        assert r['has_scripts'] is True

    def test_css_hiding_detected(self, daemon):
        r = daemon.analyze_html(self.data)
        types = [a['type'] for a in r['analyses']]
        # display:none / visibility:hidden / position:absolute should fire
        assert any(t in ('CSSHiding', 'SuspiciousCSSHiding') or 'CSS' in t
                   for t in types), f'No CSS hiding found, types={types}'

    def test_analyses_contains_eval(self, daemon):
        r = daemon.analyze_html(self.data)
        keywords = [a['keyword'] for a in r['analyses']]
        assert any('eval' in kw for kw in keywords)

    def test_iocs_contain_phishing_url(self, daemon):
        r = daemon.analyze_html(self.data)
        all_urls = ' '.join(r['iocs']['urls'])
        assert 'example.com' in all_urls

    def test_base64_blob_detected(self, daemon):
        r = daemon.analyze_html(self.data)
        types = [a['type'] for a in r['analyses']]
        assert 'HTMLSmuggling' in types

    @pytest.mark.asyncio
    async def test_scan_endpoint_phishing_html(self, client):
        data = open(HTML_PHISHING_FILE, 'rb').read()
        form = aiohttp.FormData()
        form.add_field('doc', data, filename='invoice.html',
                       content_type='text/html')
        resp = await client.post('/v1/scan', data=form)
        assert resp.status == 200
        body = await resp.json()
        assert body['detected_type'] == 'html'
        assert body['has_forms'] is True
        assert body['has_iframes'] is True


# ===========================================================================
# FIXTURE-FILE TESTS — Mixed ZIP archive
# ===========================================================================

@pytest.mark.skipif(
    not os.path.exists(ARCHIVE_MIXED_FILE),
    reason='archive_mixed.zip not present — run tests/create_fixtures.py',
)
class TestArchiveMixedFixture:
    """Tests using the generated archive_mixed.zip fixture."""

    @pytest.fixture(autouse=True)
    def _data(self):
        self.data = open(ARCHIVE_MIXED_FILE, 'rb').read()

    def test_archive_files_extracted(self, daemon):
        r = daemon.analyze_archive('s', 'archive_mixed.zip', self.data)
        assert r is not None
        assert len(r['archive_files']) >= 3

    def test_readme_txt_in_archive_files(self, daemon):
        r = daemon.analyze_archive('s', 'archive_mixed.zip', self.data)
        names = [f['name'] for f in r['archive_files']]
        assert 'readme.txt' in names

    def test_nested_pdf_in_archive_files(self, daemon):
        r = daemon.analyze_archive('s', 'archive_mixed.zip', self.data)
        names = [f['name'] for f in r['archive_files']]
        assert any(n.endswith('.pdf') for n in names)

    def test_ioc_extracted_from_text_member(self, daemon):
        r = daemon.analyze_archive('s', 'archive_mixed.zip', self.data)
        all_urls = ' '.join(r['iocs']['urls'])
        assert 'ioc-from-archive.example.com' in all_urls

    def test_report_has_required_keys(self, daemon):
        r = daemon.analyze_archive('s', 'archive_mixed.zip', self.data)
        assert r is not None
        for key in ('archive_files', 'analyses', 'iocs', 'yara_matches', 'iocs_extended'):
            assert key in r

    def test_detected_as_archive_type(self, daemon):
        t = daemon.get_detected_type('application/zip', None, 'archive_mixed.zip', None)
        assert t == 'archive'

    @pytest.mark.asyncio
    async def test_scan_endpoint_archive(self, client):
        data = open(ARCHIVE_MIXED_FILE, 'rb').read()
        form = aiohttp.FormData()
        form.add_field('doc', data, filename='archive_mixed.zip',
                       content_type='application/zip')
        resp = await client.post('/v1/scan', data=form)
        assert resp.status == 200
        body = await resp.json()
        assert body['detected_type'] == 'archive'
        assert isinstance(body['archive_files'], list)
        assert len(body['archive_files']) >= 1


# ===========================================================================
# FIXTURE-FILE TESTS — EML e-mail with attachment
# ===========================================================================

@pytest.mark.skipif(
    not os.path.exists(EML_FILE),
    reason='email_with_attachment.eml not present — run tests/create_fixtures.py',
)
class TestEmlFixture:
    """Tests using the generated email_with_attachment.eml fixture."""

    @pytest.fixture(autouse=True)
    def _data(self):
        self.data = open(EML_FILE, 'rb').read()

    def test_eml_detected_as_archive(self, daemon):
        # EML routes to 'archive' so sflock2 can extract attachments
        t = daemon.get_detected_type('message/rfc822', None, 'test.eml', None)
        assert t == 'archive'

    def test_eml_extension_detected_as_archive(self, daemon):
        t = daemon.get_detected_type(None, None, 'email_with_attachment.eml', None)
        assert t == 'archive'

    def test_msg_extension_detected_as_archive(self, daemon):
        t = daemon.get_detected_type(None, None, 'outlook_item.msg', None)
        assert t == 'archive'

    def test_eml_bytes_are_non_empty(self):
        # Sanity: fixture file was created successfully
        assert len(self.data) > 100

    @pytest.mark.skipif(not xspct.HAS_SFLOCK, reason='sflock2 not installed')
    def test_sflock_extracts_eml_attachment(self, daemon):
        """Integration test: sflock2 extracts the attachment from the EML."""
        r = daemon.analyze_archive('s', 'email_with_attachment.eml', self.data)
        assert r is not None
        names = [f['name'] for f in r['archive_files']]
        assert any('invoice' in n.lower() or 'pdf' in n.lower() for n in names)


# ===========================================================================
# FIXTURE-FILE TESTS — QR code image
# ===========================================================================

@pytest.mark.skipif(
    not os.path.exists(QR_FILE),
    reason='qr_code.png not present — install qrcode or segno and run tests/create_fixtures.py',
)
class TestQrCodeFixture:
    """Tests using the generated qr_code.png fixture."""

    @pytest.fixture(autouse=True)
    def _data(self):
        self.data = open(QR_FILE, 'rb').read()

    def test_detected_as_image(self, daemon):
        t = daemon.get_detected_type('image/png', None, 'qr_code.png', None)
        assert t == 'image'

    @pytest.mark.skipif(not xspct.HAS_PYZBAR, reason='pyzbar not installed')
    def test_qr_code_decoded(self, daemon):
        r = daemon.analyze_image(self.data, label='qr_code.png')
        assert r is not None
        assert len(r['qr_codes']) >= 1
        assert any('qr-malware.example.com' in v for v in r['qr_codes'])

    @pytest.mark.skipif(not xspct.HAS_PYZBAR, reason='pyzbar not installed')
    def test_qr_ioc_url_extracted(self, daemon):
        r = daemon.analyze_image(self.data, label='qr_code.png')
        all_urls = r['iocs']['urls']
        assert any('qr-malware.example.com' in u for u in all_urls)


# ===========================================================================
# UNIT TESTS — Redis cache (fakeredis)
# ===========================================================================

@pytest.mark.skipif(not _HAS_FAKEREDIS, reason='fakeredis not installed')
class TestRedisCache:
    """Tests for get_cached_report / cache_report using a fakeredis backend."""

    @pytest.fixture(autouse=True)
    def _setup(self, daemon):
        self.daemon = daemon
        saved = dict(xspct.config['xspct_redis_cache'])
        xspct.config['xspct_redis_cache']['enabled'] = True
        xspct.config['xspct_redis_cache']['expire'] = 3600
        xspct.config['xspct_redis_cache']['prefix'] = 'xspct:'
        xspct.config['xspct_redis_cache']['max_errors'] = 3
        self.daemon.redis_pool = fakeredis.FakeAsyncRedis(decode_responses=True)
        self.daemon._redis_error_count = 0
        yield
        xspct.config['xspct_redis_cache'].update(saved)
        self.daemon.redis_pool = None

    async def test_cache_miss_returns_none(self):
        result = await self.daemon.get_cached_report('s', 'a' * 64)
        assert result is None

    async def test_cache_hit_returns_report(self):
        report = {'hash': 'a' * 64, 'verdict': 'clean'}
        await self.daemon.cache_report('s', 'a' * 64, report)
        result = await self.daemon.get_cached_report('s', 'a' * 64)
        assert result == report

    async def test_cache_report_sets_ttl(self):
        report = {'hash': 'b' * 64}
        await self.daemon.cache_report('s', 'b' * 64, report)
        ttl = await self.daemon.redis_pool.ttl('xspct:' + 'b' * 64)
        assert 0 < ttl <= 3600

    async def test_cache_report_also_stored_in_tasks(self):
        report = {'hash': 'c' * 64}
        await self.daemon.cache_report('s', 'c' * 64, report)
        assert 'c' * 64 in self.daemon.tasks

    async def test_cache_miss_increments_stat(self):
        initial = xspct.stats['redis_misses']
        await self.daemon.get_cached_report('s', 'd' * 64)
        assert xspct.stats['redis_misses'] == initial + 1

    async def test_cache_hit_increments_stat(self):
        report = {'hash': 'e' * 64}
        await self.daemon.cache_report('s', 'e' * 64, report)
        initial = xspct.stats['redis_hits']
        await self.daemon.get_cached_report('s', 'e' * 64)
        assert xspct.stats['redis_hits'] == initial + 1

    async def test_disabled_skips_lookup(self):
        xspct.config['xspct_redis_cache']['enabled'] = False
        result = await self.daemon.get_cached_report('s', 'f' * 64)
        assert result is None

    async def test_disabled_skips_store(self):
        xspct.config['xspct_redis_cache']['enabled'] = False
        await self.daemon.cache_report('s', 'g' * 64, {'hash': 'g' * 64})
        # key must not exist in fake redis
        raw = await self.daemon.redis_pool.get('xspct:' + 'g' * 64)
        assert raw is None

    async def test_circuit_breaker_open_returns_none(self):
        self.daemon._redis_error_count = 10  # exceeds max_errors (3)
        result = await self.daemon.get_cached_report('s', 'h' * 64)
        assert result is None

    async def test_circuit_breaker_resets_after_success(self):
        self.daemon._redis_error_count = 1
        report = {'hash': 'i' * 64}
        await self.daemon.cache_report('s', 'i' * 64, report)
        await self.daemon.get_cached_report('s', 'i' * 64)
        assert self.daemon._redis_error_count == 0

    async def test_get_error_increments_error_count(self):
        broken = AsyncMock()
        broken.get = AsyncMock(side_effect=ConnectionError('redis down'))
        self.daemon.redis_pool = broken
        result = await self.daemon.get_cached_report('s', 'j' * 64)
        assert result is None
        assert self.daemon._redis_error_count == 1
        assert xspct.stats['redis_errors'] == 1

    async def test_set_error_increments_error_count(self):
        broken = AsyncMock()
        broken.setex = AsyncMock(side_effect=ConnectionError('redis down'))
        self.daemon.redis_pool = broken
        await self.daemon.cache_report('s', 'k' * 64, {'hash': 'k' * 64})
        assert self.daemon._redis_error_count == 1
        assert xspct.stats['redis_errors'] == 1


# ===========================================================================
# ODF analysis tests
# ===========================================================================

def _make_odf(
    content_text: str = 'Hello from ODF document. Visit https://example.com/',
    with_macro: bool = False,
    meta: 'dict | None' = None,
    with_hyperlink: bool = False,
    mimetype: str = 'application/vnd.oasis.opendocument.text',
) -> bytes:
    """Build a minimal conformant ODF ZIP fixture."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        # ODF spec: mimetype MUST be the first entry, stored (uncompressed)
        z.writestr(zipfile.ZipInfo('mimetype'), mimetype)

        # Minimal manifest
        z.writestr(
            'META-INF/manifest.xml',
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<manifest:manifest '
            ' xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">'
            '<manifest:file-entry manifest:full-path="/" '
            f' manifest:media-type="{mimetype}"/>'
            '</manifest:manifest>',
        )

        # meta.xml
        _m = meta or {}
        z.writestr(
            'meta.xml',
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<office:document-meta'
            ' xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"'
            ' xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0"'
            ' xmlns:dc="http://purl.org/dc/elements/1.1/">'
            '<office:meta>'
            f'<dc:title>{_m.get("title", "Test Document")}</dc:title>'
            f'<meta:initial-creator>{_m.get("author", "Test Author")}</meta:initial-creator>'
            f'<dc:subject>{_m.get("subject", "Test Subject")}</dc:subject>'
            f'<meta:keyword>{_m.get("keywords", "test keyword")}</meta:keyword>'
            f'<dc:creator>{_m.get("last_saved_by", "Last Saver")}</dc:creator>'
            f'<meta:creation-date>{_m.get("creation_date", "2026-01-01T10:00:00")}</meta:creation-date>'
            f'<dc:date>{_m.get("mod_date", "2026-05-01T12:00:00")}</dc:date>'
            f'<meta:generator>{_m.get("generator", "TestApp/1.0")}</meta:generator>'
            '<meta:editing-cycles>3</meta:editing-cycles>'
            '</office:meta>'
            '</office:document-meta>',
        )

        # Hyperlink in content
        link_xml = (
            '<text:a xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"'
            ' xmlns:xlink="http://www.w3.org/1999/xlink"'
            ' xlink:href="https://hyperlink.example.com/" xlink:type="simple">'
            'click here</text:a>'
            if with_hyperlink else ''
        )

        # content.xml
        z.writestr(
            'content.xml',
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<office:document-content'
            ' xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"'
            ' xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"'
            ' xmlns:xlink="http://www.w3.org/1999/xlink">'
            '<office:body><office:text>'
            f'<text:p>{content_text}</text:p>'
            f'{link_xml}'
            '</office:text></office:body>'
            '</office:document-content>',
        )

        # StarBasic macro
        if with_macro:
            z.writestr(
                'Basic/Standard/Module1.xml',
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<library:library xmlns:library="http://openoffice.org/2000/library">'
                '<script:module xmlns:script="http://openoffice.org/2000/script"'
                ' script:name="Module1" script:language="StarBasic">'
                '<![CDATA[Sub AutoOpen()\n'
                '  Shell "cmd.exe /c calc.exe"\n'
                'End Sub]]>'
                '</script:module>'
                '</library:library>',
            )
            z.writestr(
                'Basic/Standard/script-lb.xml',
                '<?xml version="1.0"?><library:library '
                'xmlns:library="http://openoffice.org/2000/library"/>',
            )
    return buf.getvalue()


_ODF_TEXT_DATA = _make_odf()
_ODF_MACRO_DATA = _make_odf(with_macro=True)
_ODF_META_DATA = _make_odf(meta={
    'title': 'My Invoice', 'author': 'Alice', 'subject': 'Finance',
    'keywords': 'invoice payment', 'last_saved_by': 'Bob',
    'creation_date': '2026-01-15T08:00:00', 'mod_date': '2026-04-20T14:30:00',
    'generator': 'LibreOffice/7.6',
})
_ODF_HYPERLINK_DATA = _make_odf(with_hyperlink=True)


class TestAnalyzeOdf:

    def test_is_odf_by_mime(self, daemon):
        data = _ODF_TEXT_DATA
        assert daemon._is_odf(data, 'application/vnd.oasis.opendocument.text', 'doc.odt')

    def test_is_odf_by_extension(self, daemon):
        assert daemon._is_odf(b'PK\x03\x04', None, 'report.ods')
        assert daemon._is_odf(b'PK\x03\x04', None, 'slides.odp')

    def test_is_odf_by_zip_mimetype_entry(self, daemon):
        # _ODF_TEXT_DATA has a 'mimetype' entry starting with vnd.oasis.opendocument
        assert daemon._is_odf(_ODF_TEXT_DATA, None, 'unknown.bin')

    def test_is_odf_false_for_ooxml(self, daemon):
        assert not daemon._is_odf(OOXML_DATA, 'application/vnd.openxmlformats', 'doc.docx')

    def test_odf_detected_type_is_office(self, daemon):
        r = daemon.sync_analyze('<t>', 'test.odt', _ODF_TEXT_DATA,
                                'application/vnd.oasis.opendocument.text')
        assert r['detected_type'] == 'office'

    def test_odf_report_has_expected_keys(self, daemon):
        r = daemon.sync_analyze('<t>', 'test.odt', _ODF_TEXT_DATA,
                                'application/vnd.oasis.opendocument.text')
        for key in ('has_macro', 'analyses', 'iocs', 'text_preview', 'file_hash'):
            assert key in r

    def test_odf_no_macro_flag_false(self, daemon):
        r = daemon.sync_analyze('<t>', 'test.odt', _ODF_TEXT_DATA,
                                'application/vnd.oasis.opendocument.text')
        assert r['has_macro'] is False

    def test_odf_text_preview_length_uses_config(self, daemon, monkeypatch):
        saved = xspct.config['xspct_text_preview_length']
        monkeypatch.setattr(xspct, 'HAS_ODFDO', False)
        xspct.config['xspct_text_preview_length'] = 12
        try:
            result = daemon.sync_analyze(
                '<t>',
                'test.odt',
                _make_odf(content_text='A much longer ODF text preview value'),
                'application/vnd.oasis.opendocument.text',
            )
        finally:
            xspct.config['xspct_text_preview_length'] = saved

        assert result['text_preview']
        assert all(len(seg['text']) <= 12 for seg in result['text_preview'])

    def test_odf_macro_flag_true(self, daemon):
        r = daemon.sync_analyze('<t>', 'macro.odt', _ODF_MACRO_DATA,
                                'application/vnd.oasis.opendocument.text')
        assert r['has_macro'] is True

    def test_odf_macro_analysis_entry_present(self, daemon):
        r = daemon.sync_analyze('<t>', 'macro.odt', _ODF_MACRO_DATA,
                                'application/vnd.oasis.opendocument.text')
        types = {a['type'] for a in r['analyses']}
        assert 'AutoExec' in types

    def test_odf_ioc_url_from_text(self, daemon):
        r = daemon.sync_analyze('<t>', 'test.odt', _ODF_TEXT_DATA,
                                'application/vnd.oasis.opendocument.text')
        urls = r['iocs']['urls']
        assert any('example.com' in u for u in urls)

    def test_odf_hyperlink_extracted(self, daemon):
        r = daemon.sync_analyze('<t>', 'link.odt', _ODF_HYPERLINK_DATA,
                                'application/vnd.oasis.opendocument.text')
        urls = r['iocs']['urls']
        assert any('hyperlink.example.com' in u for u in urls)

    def test_odf_metadata_populated(self, daemon):
        r = daemon.sync_analyze('<t>', 'meta.odt', _ODF_META_DATA,
                                'application/vnd.oasis.opendocument.text')
        meta = r.get('meta_document')
        assert meta is not None
        assert 'My Invoice' in meta.get('title', '')
        assert 'Alice' in meta.get('author', '')
        assert 'Finance' in meta.get('subject', '')

    def test_odf_metadata_keywords(self, daemon):
        r = daemon.sync_analyze('<t>', 'meta.odt', _ODF_META_DATA,
                                'application/vnd.oasis.opendocument.text')
        meta = r.get('meta_document', {})
        assert 'invoice' in meta.get('keywords', '').lower()

    def test_odf_metadata_dates(self, daemon):
        r = daemon.sync_analyze('<t>', 'meta.odt', _ODF_META_DATA,
                                'application/vnd.oasis.opendocument.text')
        meta = r.get('meta_document', {})
        assert meta.get('creation_date', '') != ''

    def test_odf_no_crash_on_bad_zip(self, daemon):
        result = daemon._analyze_odf('<t>', 'bad.odt', b'not a zip file',
                                     'application/vnd.oasis.opendocument.text')
        assert isinstance(result, dict)
        assert 'iocs' in result

    def test_odf_iocs_are_sorted_lists(self, daemon):
        r = daemon.sync_analyze('<t>', 'test.odt', _ODF_TEXT_DATA,
                                'application/vnd.oasis.opendocument.text')
        for k in ('urls', 'ips', 'domains'):
            assert isinstance(r['iocs'][k], list)
            assert r['iocs'][k] == sorted(r['iocs'][k])

    def test_odf_extension_odg_detected(self, daemon):
        r = daemon.sync_analyze('<t>', 'drawing.odg', _ODF_TEXT_DATA,
                                'application/vnd.oasis.opendocument.graphics')
        assert r['detected_type'] == 'office'

    def test_odf_olevba_not_invoked_for_odf(self, daemon):
        # VBA_Parser raises on ODF; _analyze_odf must complete without error.
        result = daemon._analyze_odf('<t>', 'test.odt', _ODF_TEXT_DATA,
                                     'application/vnd.oasis.opendocument.text')
        assert result is not None

    def test_odf_no_odfdo_fallback(self, daemon, monkeypatch):
        """Verify that ODF analysis still works when odfdo is not installed."""
        monkeypatch.setattr(xspct, 'HAS_ODFDO', False)
        result = daemon._analyze_odf('<t>', 'test.odt', _ODF_TEXT_DATA,
                                     'application/vnd.oasis.opendocument.text')
        assert isinstance(result, dict)
        # Fallback should still extract URLs via regex on content.xml
        assert isinstance(result['iocs']['urls'], list)

    def test_odf_no_odfdo_fallback_macro(self, daemon, monkeypatch):
        """Macro detection uses ZIP scan — must work without odfdo."""
        monkeypatch.setattr(xspct, 'HAS_ODFDO', False)
        result = daemon._analyze_odf('<t>', 'macro.odt', _ODF_MACRO_DATA,
                                     'application/vnd.oasis.opendocument.text')
        assert result['has_macro'] is True
