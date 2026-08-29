# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""API key and admin key verification, HTTP authentication tests."""

from unittest.mock import MagicMock

import xspct_scan.daemon as xspct
from tests.conftest import (
    PDF_CLEAN,
    _form,
)


class TestApiKeyVerification:
    def test_no_keys_always_passes(self):
        xspct.config["xspct_api_key"] = []
        req = MagicMock()
        req.headers = {}
        assert xspct.verify_api_key("<t>", req) is True

    def test_correct_key_passes(self):
        xspct.config["xspct_api_key"] = ["my-secret"]
        req = MagicMock()
        req.headers = {xspct.config["xspct_api_header"]: "my-secret"}
        assert xspct.verify_api_key("<t>", req) is True

    def test_wrong_key_fails_when_verify_fail_true(self):
        xspct.config["xspct_api_key"] = ["my-secret"]
        xspct.config["xspct_api_key_verify_fail"] = True
        req = MagicMock()
        req.headers = {xspct.config["xspct_api_header"]: "wrong"}
        assert xspct.verify_api_key("<t>", req) is False

    def test_wrong_key_passes_when_verify_fail_false(self):
        xspct.config["xspct_api_key"] = ["my-secret"]
        xspct.config["xspct_api_key_verify_fail"] = False
        req = MagicMock()
        req.headers = {xspct.config["xspct_api_header"]: "wrong"}
        assert xspct.verify_api_key("<t>", req) is True

    def test_missing_header_fails(self):
        xspct.config["xspct_api_key"] = ["my-secret"]
        xspct.config["xspct_api_key_verify_fail"] = True
        req = MagicMock()
        req.headers = {}
        assert xspct.verify_api_key("<t>", req) is False

    def test_multi_key_first_accepted(self):
        xspct.config["xspct_api_key"] = ["key-A", "key-B"]
        req = MagicMock()
        req.headers = {xspct.config["xspct_api_header"]: "key-A"}
        assert xspct.verify_api_key("<t>", req) is True

    def test_multi_key_second_accepted(self):
        xspct.config["xspct_api_key"] = ["key-A", "key-B"]
        req = MagicMock()
        req.headers = {xspct.config["xspct_api_header"]: "key-B"}
        assert xspct.verify_api_key("<t>", req) is True

    def test_multi_key_unknown_rejected(self):
        xspct.config["xspct_api_key"] = ["key-A", "key-B"]
        xspct.config["xspct_api_key_verify_fail"] = True
        req = MagicMock()
        req.headers = {xspct.config["xspct_api_header"]: "key-C"}
        assert xspct.verify_api_key("<t>", req) is False


class TestAuthentication:
    async def test_health_no_auth_required(self, auth_client):
        """Health endpoint carries no auth check and must always return 200."""
        r = await auth_client.get("/health")
        assert r.status == 200

    async def test_scan_no_key_returns_401(self, auth_client):
        r = await auth_client.post("/v1/scan", data=_form(PDF_CLEAN, "auth.pdf"))
        assert r.status == 401

    async def test_query_get_no_key_returns_401(self, auth_client):
        r = await auth_client.get("/v1/query?hash=abc")
        assert r.status == 401

    async def test_query_post_no_key_returns_401(self, auth_client):
        r = await auth_client.post("/v1/query", json={"hash": "abc"})
        assert r.status == 401

    async def test_metrics_no_key_returns_401(self, auth_client):
        r = await auth_client.get("/v1/metrics")
        assert r.status == 401

    async def test_scan_correct_key_returns_200(self, auth_client):
        r = await auth_client.post(
            "/v1/scan",
            headers={"X-Api-Key": "test-secret-key"},
            data=_form(PDF_CLEAN, "auth.pdf"),
        )
        assert r.status == 200

    async def test_scan_wrong_key_returns_401(self, auth_client):
        r = await auth_client.post(
            "/v1/scan",
            headers={"X-Api-Key": "totally-wrong"},
            data=_form(PDF_CLEAN, "auth.pdf"),
        )
        assert r.status == 401

    async def test_query_correct_key_returns_404_not_401(self, auth_client):
        """After auth passes, unknown hash → 404 (not 401)."""
        r = await auth_client.get(
            "/v1/query?hash=" + "c" * 64,
            headers={"X-Api-Key": "test-secret-key"},
        )
        assert r.status == 404

    async def test_metrics_correct_key_returns_200(self, auth_client):
        r = await auth_client.get(
            "/v1/metrics",
            headers={"X-Api-Key": "test-secret-key"},
        )
        assert r.status == 200


# ===========================================================================
# UNIT TESTS — analyze_javascript
# ===========================================================================


class TestVerifyAdminKey:
    def _req(self, header_value=None):
        mock = MagicMock()
        headers = {}
        if header_value is not None:
            headers["X-Admin-Api-Key"] = header_value
        mock.headers = headers
        return mock

    def test_no_keys_configured_always_false(self):
        xspct.config["xspct_admin_api_key"] = []
        assert xspct.verify_admin_key("s", self._req("anything")) is False

    def test_correct_key_passes(self):
        xspct.config["xspct_admin_api_key"] = ["secret"]
        try:
            assert xspct.verify_admin_key("s", self._req("secret")) is True
        finally:
            xspct.config["xspct_admin_api_key"] = []

    def test_wrong_key_fails(self):
        xspct.config["xspct_admin_api_key"] = ["secret"]
        try:
            assert xspct.verify_admin_key("s", self._req("wrong")) is False
        finally:
            xspct.config["xspct_admin_api_key"] = []

    def test_missing_header_fails(self):
        xspct.config["xspct_admin_api_key"] = ["secret"]
        try:
            assert xspct.verify_admin_key("s", self._req()) is False
        finally:
            xspct.config["xspct_admin_api_key"] = []


# ===========================================================================
# UNIT TESTS — analyze_text
# ===========================================================================


class TestAdminReload:
    async def test_no_admin_key_configured_returns_403(self, client):
        xspct.config["xspct_admin_api_key"] = []
        r = await client.post("/v1/admin/reload")
        assert r.status == 403

    async def test_wrong_admin_key_returns_403(self, client):
        xspct.config["xspct_admin_api_key"] = ["correct-admin-key"]
        try:
            r = await client.post(
                "/v1/admin/reload",
                headers={"X-Admin-Api-Key": "wrong-key"},
            )
            assert r.status == 403
        finally:
            xspct.config["xspct_admin_api_key"] = []

    async def test_correct_admin_key_returns_200(self, client):
        xspct.config["xspct_admin_api_key"] = ["admin-secret"]
        try:
            r = await client.post(
                "/v1/admin/reload",
                headers={"X-Admin-Api-Key": "admin-secret"},
            )
            assert r.status == 200
            body = await r.json()
            assert body["status"] == "ok"
            assert isinstance(body["reloaded"], list)
        finally:
            xspct.config["xspct_admin_api_key"] = []


# ===========================================================================
# INTEGRATION TESTS — OpenAPI endpoints
# ===========================================================================
