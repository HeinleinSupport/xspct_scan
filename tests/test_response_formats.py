# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""Response serialization tests: msgpack, cbor, zstd compression."""

import pytest

import xspct_scan.daemon as xspct
from tests.conftest import (
    _HAS_MSGPACK_TEST,
    _HAS_ZSTD_TEST,
    PDF_CLEAN,
    _form,
    _msgpack_test,
    _zstd_compress,
)

try:
    import cbor2 as _cbor2_test

    _HAS_CBOR2_TEST = True
except ImportError:
    _cbor2_test = None
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
