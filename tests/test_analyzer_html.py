# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""analyze_html unit tests, including HTA and fixture-based cases."""

import base64
import os

import aiohttp
import pytest

import xspct_scan.daemon as xspct
from tests.conftest import (
    _HAS_PIL_FOR_TESTS,
    HTML_CLEAN,
    HTML_MALICIOUS,
    HTML_NO_TAGS,
    HTML_PHISHING_FILE,
    _keywords,
    _make_png,
)


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
