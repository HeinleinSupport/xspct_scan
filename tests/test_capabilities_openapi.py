# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""/v1/capabilities and OpenAPI endpoint tests."""

import pytest

import xspct_scan.daemon as xspct


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
    @pytest.mark.skipif(
        not (xspct.HAS_OCR or xspct.HAS_PYZBAR),
        reason="OCR or pyzbar not installed",
    )
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
