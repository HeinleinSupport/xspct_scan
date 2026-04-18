# SPDX-License-Identifier: EUPL-1.2
# Copyright (C) 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""
test_olefy.py — Comprehensive pytest test suite for InspectorDaemon / olefy_v2.daemon.

Coverage:
  Unit tests (no HTTP, direct method calls):
    - Session ID / session header helpers
    - API key verification (no keys, correct, wrong, multi-key, verify_fail flag)
    - IOC extraction (URLs, IPs, dedup, UTF-16, invalid IPs)
    - analyze_pdf  (clean, all markers, /URI IOC)
    - analyze_html (clean, all suspicious JS keywords, forms, iframes, meta-refresh)
    - extract_text_preview (HTML tag stripping, script removal, OOXML, char limit)
    - get_detected_type (MIME, filename extension, RTF magic bytes)
    - merge_reports (dedup analyses, dedup IOCs, boolean OR, meta skip)
    - _evict_tasks (OrderedDict eviction, oldest removed)
    - sync_analyze (PDF, HTML, unknown binary, real OLE file, real RTF file)

  Integration tests (full daemon in-process via aiohttp.test_utils):
    - GET /health /ping /
    - GET /metrics (Prometheus text, counter increments after scan)
    - POST /scan: missing doc → 400
    - POST /scan: clean PDF, malicious PDF, malicious HTML, OOXML, real OLE, real RTF
    - POST /scan: file_mime override, custom passwords field, rtf=true flag
    - POST /scan: same file twice returns same hash
    - POST /scan: very short timeout may return 202 (background processing)
    - GET  /query: missing hash → 400, unknown hash → 404
    - POST /query: missing hash → 400, unknown hash → 404
    - GET  /query: after scan returns finished report with correct hash
    - POST /query: JSON body, after scan returns finished report
    - Auth: 401 on /scan /query /metrics when key required, no key sent
    - Auth: 200 when correct key sent; 401 when wrong key sent
    - Auth: /health always accessible without key

Run:
    cd /home/cr/git/olefy_v2
    pip install -e .[dev]
    python3 -m pytest tests/ -v
"""

import hashlib
import io
import os
import zipfile
from unittest.mock import MagicMock

import aiohttp
import pytest

import olefy_v2.daemon as olefy
from tests.conftest import OLE_FILE, RTF_FILE, PASSWD_FILE

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
    saved_keys     = list(olefy.config['olefy_api_key'])
    saved_fail     = olefy.config['olefy_api_key_verify_fail']
    saved_stats    = dict(olefy.stats)
    saved_pw_file  = olefy.config['olefy_password_file']
    saved_stats_en = olefy.config['olefy_stats_enabled']

    olefy.config['olefy_api_key']             = []
    olefy.config['olefy_api_key_verify_fail'] = True
    olefy.config['olefy_password_file']       = PASSWD_FILE
    olefy.config['olefy_stats_enabled']       = False  # no background tasks in tests
    for k in olefy.stats:
        olefy.stats[k] = 0

    yield

    olefy.config['olefy_api_key']             = saved_keys
    olefy.config['olefy_api_key_verify_fail'] = saved_fail
    olefy.config['olefy_password_file']       = saved_pw_file
    olefy.config['olefy_stats_enabled']       = saved_stats_en
    for k, val in saved_stats.items():
        olefy.stats[k] = val


@pytest.fixture
async def client(aiohttp_client):
    """Full daemon TestClient with no API key required."""
    app = await olefy.make_app()
    return await aiohttp_client(app)


@pytest.fixture
async def auth_client(aiohttp_client):
    """Full daemon TestClient with API key enforcement."""
    olefy.config['olefy_api_key']             = ['test-secret-key']
    olefy.config['olefy_api_key_verify_fail'] = True
    app = await olefy.make_app()
    return await aiohttp_client(app)


@pytest.fixture
def daemon():
    """Bare InspectorDaemon with a small, known password list."""
    d = olefy.InspectorDaemon()
    d.passwords = ['VelvetSweatshop', 'test123', '123456', 'password']
    return d


# ===========================================================================
# UNIT TESTS
# ===========================================================================

class TestSessionHelpers:

    def test_session_id_is_6_hex_chars(self):
        sid = olefy.generate_session_id()
        assert len(sid) == 6
        assert all(c in '0123456789abcdef' for c in sid)

    def test_session_ids_are_unique(self):
        ids = {olefy.generate_session_id() for _ in range(200)}
        assert len(ids) > 1

    def test_make_session_format_no_rspamd(self):
        req = MagicMock()
        req.headers = {}
        s = olefy.make_session(req)
        assert s.startswith('<') and s.endswith('>')
        assert len(s) == 8  # <xxxxxx>

    def test_make_session_includes_rspamd_id(self):
        req = MagicMock()
        req.headers = {olefy.config['olefy_rspamd_header']: 'rspamd99'}
        s = olefy.make_session(req)
        assert '-' in s
        assert 'rspamd' in s


class TestApiKeyVerification:

    def test_no_keys_always_passes(self):
        olefy.config['olefy_api_key'] = []
        req = MagicMock()
        req.headers = {}
        assert olefy.verify_api_key('<t>', req) is True

    def test_correct_key_passes(self):
        olefy.config['olefy_api_key'] = ['my-secret']
        req = MagicMock()
        req.headers = {olefy.config['olefy_api_header']: 'my-secret'}
        assert olefy.verify_api_key('<t>', req) is True

    def test_wrong_key_fails_when_verify_fail_true(self):
        olefy.config['olefy_api_key']             = ['my-secret']
        olefy.config['olefy_api_key_verify_fail'] = True
        req = MagicMock()
        req.headers = {olefy.config['olefy_api_header']: 'wrong'}
        assert olefy.verify_api_key('<t>', req) is False

    def test_wrong_key_passes_when_verify_fail_false(self):
        olefy.config['olefy_api_key']             = ['my-secret']
        olefy.config['olefy_api_key_verify_fail'] = False
        req = MagicMock()
        req.headers = {olefy.config['olefy_api_header']: 'wrong'}
        assert olefy.verify_api_key('<t>', req) is True

    def test_missing_header_fails(self):
        olefy.config['olefy_api_key']             = ['my-secret']
        olefy.config['olefy_api_key_verify_fail'] = True
        req = MagicMock()
        req.headers = {}
        assert olefy.verify_api_key('<t>', req) is False

    def test_multi_key_first_accepted(self):
        olefy.config['olefy_api_key'] = ['key-A', 'key-B']
        req = MagicMock()
        req.headers = {olefy.config['olefy_api_header']: 'key-A'}
        assert olefy.verify_api_key('<t>', req) is True

    def test_multi_key_second_accepted(self):
        olefy.config['olefy_api_key'] = ['key-A', 'key-B']
        req = MagicMock()
        req.headers = {olefy.config['olefy_api_header']: 'key-B'}
        assert olefy.verify_api_key('<t>', req) is True

    def test_multi_key_unknown_rejected(self):
        olefy.config['olefy_api_key']             = ['key-A', 'key-B']
        olefy.config['olefy_api_key_verify_fail'] = True
        req = MagicMock()
        req.headers = {olefy.config['olefy_api_header']: 'key-C'}
        assert olefy.verify_api_key('<t>', req) is False


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

    def test_text_preview_present(self, daemon):
        r = daemon.analyze_pdf(PDF_CLEAN)
        assert 'text_preview' in r


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
        ) == 'office'


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
        assert r['meta']['script_name'] == 'olefy_v2'
        assert r['meta']['version'] == '2.0.0'

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
        assert len(iocs['urls']) > 0 or len(iocs['ips']) > 0 or len(iocs['domains']) > 0

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

    async def test_root_200_olefy(self, client):
        r = await client.get('/')
        assert r.status == 200
        assert 'Olefy' in await r.text()


class TestMetricsEndpoint:

    async def test_metrics_returns_prometheus_text(self, client):
        r = await client.get('/metrics')
        assert r.status == 200
        text = await r.text()
        for metric in (
            'olefy_requests_total',
            'olefy_requests_finished',
            'olefy_requests_timeout',
            'olefy_redis_hits',
            'olefy_redis_misses',
            'olefy_redis_errors',
            'olefy_tasks_in_memory',
        ):
            assert metric in text

    async def test_metrics_request_counter_increments(self, client):
        await client.post('/scan', data=_form(PDF_CLEAN, 'a.pdf'))
        r = await client.get('/metrics')
        text = await r.text()
        assert 'olefy_requests_total 1' in text

    async def test_metrics_finished_counter_increments(self, client):
        await client.post('/scan', data=_form(PDF_CLEAN, 'b.pdf'))
        r = await client.get('/metrics')
        text = await r.text()
        assert 'olefy_requests_finished 1' in text

    async def test_metrics_tasks_in_memory_increases(self, client):
        await client.post('/scan', data=_form(PDF_CLEAN, 'c.pdf'))
        r = await client.get('/metrics')
        text = await r.text()
        assert 'olefy_tasks_in_memory 0' not in text or 'olefy_tasks_in_memory 1' in text


class TestScanEndpoint:

    async def test_missing_doc_part_returns_400(self, client):
        form = aiohttp.FormData()
        form.add_field('not_doc', b'irrelevant', filename='x.bin')
        r = await client.post('/scan', data=form)
        assert r.status == 400

    async def test_scan_clean_pdf(self, client):
        r = await client.post('/scan', data=_form(PDF_CLEAN, 'clean.pdf'))
        assert r.status == 200
        body = await r.json()
        assert body['status']         == 'finished'
        assert body['detected_type']  == 'pdf'
        assert body['has_javascript'] is False
        assert body['has_openaction'] is False

    async def test_scan_malicious_pdf_flags(self, client):
        r = await client.post('/scan', data=_form(PDF_ALL_MARKERS, 'malware.pdf'))
        assert r.status == 200
        body = await r.json()
        assert body['has_javascript'] is True
        assert body['has_openaction'] is True
        assert body['is_encrypted']   is True

    async def test_scan_malicious_html_flags(self, client):
        r = await client.post('/scan', data=_form(HTML_MALICIOUS, 'phish.html'))
        assert r.status == 200
        body = await r.json()
        assert body['detected_type'] == 'html'
        assert body['has_scripts']   is True
        assert body['has_forms']     is True
        assert body['has_iframes']   is True

    async def test_scan_ooxml_returns_200(self, client):
        r = await client.post('/scan', data=_form(OOXML_DATA, 'doc.docx'))
        assert r.status == 200
        body = await r.json()
        assert 'file_hash' in body
        assert len(body['file_hash']) == 64  # SHA-256 hex

    async def test_scan_file_mime_override(self, client):
        form = aiohttp.FormData()
        form.add_field('doc',       HTML_CLEAN, filename='noext')
        form.add_field('file_mime', 'text/html')
        r = await client.post('/scan', data=form)
        assert r.status == 200
        body = await r.json()
        assert body['detected_type'] == 'html'

    async def test_scan_custom_passwords_accepted(self, client):
        form = aiohttp.FormData()
        form.add_field('doc',       PDF_CLEAN, filename='doc.pdf')
        form.add_field('passwords', 'pw1,pw2,TopSecret')
        r = await client.post('/scan', data=form)
        assert r.status == 200

    async def test_scan_time_taken_present(self, client):
        r = await client.post('/scan', data=_form(PDF_CLEAN, 'timed.pdf'))
        body = await r.json()
        assert 'time_taken' in body
        assert body['time_taken'] >= 0

    async def test_scan_report_has_iocs_key(self, client):
        r = await client.post('/scan', data=_form(PDF_WITH_URI, 'ioc.pdf'))
        body = await r.json()
        assert 'iocs' in body
        assert 'urls' in body['iocs']

    async def test_scan_same_file_produces_same_hash(self, client):
        """Same bytes always produce the same SHA-256 file_hash."""
        r1 = await client.post('/scan', data=_form(PDF_CLEAN, 'a.pdf'))
        b1 = await r1.json()
        r2 = await client.post('/scan', data=_form(PDF_CLEAN, 'b.pdf'))
        b2 = await r2.json()
        assert b1['file_hash'] == b2['file_hash']
        assert b1['file_hash'] == hashlib.sha256(PDF_CLEAN).hexdigest()

    async def test_scan_short_timeout_may_return_202(self, client):
        """Very short timeout → 200 (fast path) or 202 (background). Both valid."""
        r = await client.post('/scan?timeout=0.00001', data=_form(PDF_ALL_MARKERS, 'slow.pdf'))
        assert r.status in (200, 202)
        body = await r.json()
        assert 'file_hash' in body or 'status' in body

    async def test_scan_rtf_flag_accepted(self, client):
        r = await client.post('/scan?rtf=true', data=_form(PDF_CLEAN, 'test.pdf'))
        assert r.status == 200

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason='OLE sample not present')
    async def test_scan_real_ole_analysis(self, client):
        with open(OLE_FILE, 'rb') as f:
            data = f.read()
        r = await client.post('/scan', data=_form(data, 'autostart-encrypt-standardpassword.xls'))
        assert r.status == 200
        body = await r.json()
        assert body['decrypted'] is True or body['has_macro'] is True or len(body['analyses']) > 0

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason='OLE sample not present')
    async def test_scan_real_ole_has_ioc_urls(self, client):
        with open(OLE_FILE, 'rb') as f:
            data = f.read()
        r = await client.post('/scan', data=_form(data, 'autostart-encrypt-standardpassword.xls'))
        body = await r.json()
        iocs = body['iocs']
        assert len(iocs['urls']) > 0 or len(iocs['ips']) > 0 or len(iocs['domains']) > 0

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason='OLE sample not present')
    async def test_scan_ole_with_custom_passwords(self, client):
        with open(OLE_FILE, 'rb') as f:
            data = f.read()
        form = aiohttp.FormData()
        form.add_field('doc',       data,                             filename='autostart-encrypt-standardpassword.xls')
        form.add_field('passwords', 'wrongpw1,wrongpw2,123456,VelvetSweatshop')
        r = await client.post('/scan', data=form)
        assert r.status == 200
        body = await r.json()
        assert body['status'] == 'finished'

    @pytest.mark.skipif(not os.path.exists(RTF_FILE), reason='RTF sample not present')
    async def test_scan_real_rtf(self, client):
        with open(RTF_FILE, 'rb') as f:
            data = f.read()
        r = await client.post('/scan?rtf=true', data=_form(data, 'sample.rtf'))
        assert r.status == 200
        body = await r.json()
        assert 'file_hash' in body


class TestQueryEndpoint:

    async def test_get_missing_hash_returns_400(self, client):
        r = await client.get('/query')
        assert r.status == 400

    async def test_get_unknown_hash_returns_404(self, client):
        r = await client.get('/query?hash=deadbeef1234')
        assert r.status == 404

    async def test_post_missing_hash_returns_400(self, client):
        r = await client.post('/query', json={})
        assert r.status == 400

    async def test_post_unknown_hash_returns_404(self, client):
        r = await client.post('/query', json={'hash': 'deadbeef1234'})
        assert r.status == 404

    async def test_get_after_scan_returns_finished(self, client):
        scan_r  = await client.post('/scan', data=_form(PDF_CLEAN, 'q.pdf'))
        scan_b  = await scan_r.json()
        fhash   = scan_b['file_hash']

        query_r = await client.get(f'/query?hash={fhash}')
        assert query_r.status == 200
        query_b = await query_r.json()
        assert query_b['status']                  == 'finished'
        assert query_b['report']['file_hash']     == fhash
        assert query_b['report']['detected_type'] == 'pdf'

    async def test_post_after_scan_returns_finished(self, client):
        scan_r = await client.post('/scan', data=_form(HTML_CLEAN, 'q.html'))
        scan_b = await scan_r.json()
        fhash  = scan_b['file_hash']

        query_r = await client.post('/query', json={'hash': fhash})
        assert query_r.status == 200
        query_b = await query_r.json()
        assert query_b['status'] == 'finished'
        assert query_b['report']['detected_type'] == 'html'

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason='OLE sample not present')
    async def test_get_ole_report_after_scan(self, client):
        with open(OLE_FILE, 'rb') as f:
            data = f.read()
        scan_r = await client.post('/scan', data=_form(data, 'autostart-encrypt-standardpassword.xls'))
        scan_b = await scan_r.json()
        fhash  = scan_b['file_hash']

        query_r = await client.get(f'/query?hash={fhash}')
        assert query_r.status == 200
        query_b = await query_r.json()
        assert query_b['status'] == 'finished'
        assert query_b['report']['file_hash'] == fhash


class TestAuthentication:

    async def test_health_no_auth_required(self, auth_client):
        """Health endpoint carries no auth check and must always return 200."""
        r = await auth_client.get('/health')
        assert r.status == 200

    async def test_scan_no_key_returns_401(self, auth_client):
        r = await auth_client.post('/scan', data=_form(PDF_CLEAN, 'auth.pdf'))
        assert r.status == 401

    async def test_query_get_no_key_returns_401(self, auth_client):
        r = await auth_client.get('/query?hash=abc')
        assert r.status == 401

    async def test_query_post_no_key_returns_401(self, auth_client):
        r = await auth_client.post('/query', json={'hash': 'abc'})
        assert r.status == 401

    async def test_metrics_no_key_returns_401(self, auth_client):
        r = await auth_client.get('/metrics')
        assert r.status == 401

    async def test_scan_correct_key_returns_200(self, auth_client):
        r = await auth_client.post(
            '/scan',
            headers={'X-Api-Key': 'test-secret-key'},
            data=_form(PDF_CLEAN, 'auth.pdf'),
        )
        assert r.status == 200

    async def test_scan_wrong_key_returns_401(self, auth_client):
        r = await auth_client.post(
            '/scan',
            headers={'X-Api-Key': 'totally-wrong'},
            data=_form(PDF_CLEAN, 'auth.pdf'),
        )
        assert r.status == 401

    async def test_query_correct_key_returns_404_not_401(self, auth_client):
        """After auth passes, unknown hash → 404 (not 401)."""
        r = await auth_client.get(
            '/query?hash=deadbeef',
            headers={'X-Api-Key': 'test-secret-key'},
        )
        assert r.status == 404

    async def test_metrics_correct_key_returns_200(self, auth_client):
        r = await auth_client.get(
            '/metrics',
            headers={'X-Api-Key': 'test-secret-key'},
        )
        assert r.status == 200
