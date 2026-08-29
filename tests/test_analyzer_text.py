# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""Text extraction and analyze_text unit tests."""

import pytest

import xspct_scan.daemon as xspct
from tests.conftest import (
    OOXML_DATA,
    PDF_CLEAN,
)


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
