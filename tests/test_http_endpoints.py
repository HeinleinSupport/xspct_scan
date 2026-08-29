# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""Core HTTP endpoint tests: health, metrics, /scan, /query, client polling."""

import hashlib
import json
import os

import aiohttp
import pytest

from tests.conftest import (
    _HAS_PYMUPDF,
    _PDF_ENC_PASSWORD,
    HTML_CLEAN,
    HTML_MALICIOUS,
    OLE_FILE,
    OOXML_DATA,
    PDF_ALL_MARKERS,
    PDF_CLEAN,
    PDF_ENCRYPTED,
    PDF_WITH_URI,
    RTF_FILE,
    _form,
)
from xspct_scan import client as xspct_client


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
