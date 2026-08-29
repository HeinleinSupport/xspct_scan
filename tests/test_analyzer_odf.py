# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""ODF (OpenDocument) analyzer tests."""

import io
import zipfile

import xspct_scan.daemon as xspct
from tests.conftest import (
    OOXML_DATA,
)


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
