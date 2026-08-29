# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""Structured multipart metadata+file upload tests."""

import base64
import hashlib
import io
import json
import logging
import quopri

import aiohttp
import pytest

from tests.conftest import (
    _HAS_MSGPACK_TEST,
    _HAS_PYMUPDF,
    _HAS_ZSTD_TEST,
    _PDF_ENC_PASSWORD,
    PDF_CLEAN,
    PDF_ENCRYPTED,
    _form,
    _metadata_form,
    _zstd_compress,
)


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
