# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""analyze_pdf unit tests, including encrypted-PDF and fixture-based cases."""

import os

import aiohttp
import pytest

import xspct_scan.daemon as xspct
from tests.conftest import (
    _HAS_PYMUPDF,
    _PDF_ENC_PASSWORD,
    PDF_ALL_MARKERS,
    PDF_CLEAN,
    PDF_EMBEDDED_FILE,
    PDF_ENCRYPTED,
    PDF_JS_FILE,
    PDF_URI_FILE,
    PDF_WITH_URI,
)


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

    @pytest.mark.skipif(not xspct.HAS_PYMUPDF, reason="PyMuPDF not installed")
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

    @pytest.mark.skipif(not xspct.HAS_PYMUPDF, reason="PyMuPDF not installed")
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
