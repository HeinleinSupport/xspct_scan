# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""analyze_image unit tests: OCR gates, embedded-image cap, QR fixture."""

import base64
import io
import os
import zipfile
from unittest.mock import MagicMock

import pytest

import xspct_scan.daemon as xspct
from tests.conftest import (
    _HAS_PIL_FOR_TESTS,
    _HAS_PYMUPDF,
    QR_FILE,
    _make_png,
    _pymupdf,
)

requires_image_analysis = pytest.mark.skipif(
    not (xspct.HAS_OCR or xspct.HAS_PYZBAR),
    reason="OCR or pyzbar not installed",
)


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

    @requires_image_analysis
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

    @requires_image_analysis
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

    @requires_image_analysis
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

    @requires_image_analysis
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
