# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""Rspamd digest and Redis cache tests."""

import asyncio
import hashlib
from unittest.mock import AsyncMock, MagicMock

import pytest

import xspct_scan.daemon as xspct
from tests.conftest import (
    PDF_CLEAN,
    _form,
    _metadata_form,
)

try:
    import fakeredis

    _HAS_FAKEREDIS = True
except ImportError:
    fakeredis = None
    _HAS_FAKEREDIS = False


class TestRspamdDigest:
    def test_key_is_64_bytes(self):
        """The Rspamd key is BLAKE2b-512 of b'rspamd' = 64 bytes."""

        assert len(hashlib.blake2b(b"rspamd").digest()) == 64

    def test_digest_length(self):
        """Result is always 128 hex chars (64 bytes = BLAKE2b-512)."""
        assert len(xspct._rspamd_digest(b"")) == 128
        assert len(xspct._rspamd_digest(b"hello")) == 128

    def test_digest_deterministic(self):
        data = b"test attachment content"
        assert xspct._rspamd_digest(data) == xspct._rspamd_digest(data)

    def test_digest_differs_from_plain_blake2b(self):

        data = b"some data"
        plain = hashlib.blake2b(data).hexdigest()
        keyed = xspct._rspamd_digest(data)
        assert plain != keyed  # keyed != unkeyed

    def test_digest_in_file_section(self):
        """Finished v2 report contains a non-empty rspamd_digest in file section."""
        d = xspct.InspectorDaemon()
        v1 = d._make_base_report("test.pdf", "a" * 64, "application/pdf", "PDF")
        v1["detected_type"] = "pdf"
        v1["text_preview"] = []
        v1["text_full"] = []
        rdigest = xspct._rspamd_digest(PDF_CLEAN)
        v2 = d._to_v2_report(
            v1, "test.pdf", len(PDF_CLEAN), sha1="deadbeef", rspamd_digest=rdigest
        )
        assert v2["file"]["rspamd_digest"] == rdigest
        assert len(v2["file"]["rspamd_digest"]) == 128


# ===========================================================================
# UNIT TESTS — load_config
# ===========================================================================


@pytest.mark.skipif(not _HAS_FAKEREDIS, reason="fakeredis not installed")
class TestRedisCache:
    """Tests for get_cached_report / cache_report using a fakeredis backend."""

    @pytest.fixture(autouse=True)
    def _setup(self, daemon):
        self.daemon = daemon
        saved = dict(xspct.config["xspct_redis_cache"])
        xspct.config["xspct_redis_cache"]["enabled"] = True
        xspct.config["xspct_redis_cache"]["expire"] = 3600
        xspct.config["xspct_redis_cache"]["prefix"] = "xspct:"
        xspct.config["xspct_redis_cache"]["max_errors"] = 3
        self.daemon.redis_pool = fakeredis.FakeAsyncRedis(decode_responses=True)
        self.daemon._redis_error_count = 0
        yield
        xspct.config["xspct_redis_cache"].update(saved)
        self.daemon.redis_pool = None

    async def test_cache_miss_returns_none(self):
        result = await self.daemon.get_cached_report("s", "a" * 64)
        assert result is None

    async def test_cache_hit_returns_report(self):
        report = {"hash": "a" * 64, "verdict": "clean"}
        await self.daemon.cache_report("s", "a" * 64, report)
        result = await self.daemon.get_cached_report("s", "a" * 64)
        assert result == report

    async def test_cache_report_sets_ttl(self):
        report = {"hash": "b" * 64}
        await self.daemon.cache_report("s", "b" * 64, report)
        ttl = await self.daemon.redis_pool.ttl("xspct:" + "b" * 64)
        assert 0 < ttl <= 3600

    async def test_cache_report_also_stored_in_tasks(self):
        report = {"hash": "c" * 64}
        await self.daemon.cache_report("s", "c" * 64, report)
        assert "c" * 64 in self.daemon.tasks

    async def test_invalidate_deletes_redis_and_in_memory_report(self):
        file_hash = "l" * 64
        await self.daemon.cache_report("s", file_hash, {"hash": file_hash})

        await self.daemon.invalidate_cached_report("s", file_hash)

        assert file_hash not in self.daemon.tasks
        assert await self.daemon.redis_pool.get("xspct:" + file_hash) is None

    async def test_invalidate_removes_in_memory_report_when_redis_disabled(self):
        file_hash = "m" * 64
        self.daemon._store_terminal_result(file_hash, {"hash": file_hash})
        xspct.config["xspct_redis_cache"]["enabled"] = False

        await self.daemon.invalidate_cached_report("s", file_hash)

        assert file_hash not in self.daemon.tasks

    async def test_invalidated_in_flight_report_cannot_repopulate_cache(self):
        file_hash = "o" * 64
        stale_generation = self.daemon._cache_generations.get(file_hash, 0)

        await self.daemon.invalidate_cached_report("s", file_hash)
        await self.daemon.cache_report(
            "s", file_hash, {"hash": file_hash}, stale_generation
        )

        assert file_hash not in self.daemon.tasks
        assert await self.daemon.redis_pool.get("xspct:" + file_hash) is None
        assert await self.daemon.redis_pool.ttl("xspct:gen:" + file_hash) == -1

    async def test_cache_miss_increments_stat(self):
        initial = xspct.stats["redis_misses"]
        await self.daemon.get_cached_report("s", "d" * 64)
        assert xspct.stats["redis_misses"] == initial + 1

    async def test_cache_hit_increments_stat(self):
        report = {"hash": "e" * 64}
        await self.daemon.cache_report("s", "e" * 64, report)
        initial = xspct.stats["redis_hits"]
        await self.daemon.get_cached_report("s", "e" * 64)
        assert xspct.stats["redis_hits"] == initial + 1

    async def test_disabled_skips_lookup(self):
        xspct.config["xspct_redis_cache"]["enabled"] = False
        result = await self.daemon.get_cached_report("s", "f" * 64)
        assert result is None

    async def test_disabled_skips_store(self):
        xspct.config["xspct_redis_cache"]["enabled"] = False
        await self.daemon.cache_report("s", "g" * 64, {"hash": "g" * 64})
        # key must not exist in fake redis
        raw = await self.daemon.redis_pool.get("xspct:" + "g" * 64)
        assert raw is None

    async def test_circuit_breaker_open_returns_none(self):
        self.daemon._redis_error_count = 10  # exceeds max_errors (3)
        result = await self.daemon.get_cached_report("s", "h" * 64)
        assert result is None

    async def test_circuit_breaker_resets_after_success(self):
        self.daemon._redis_error_count = 1
        report = {"hash": "i" * 64}
        await self.daemon.cache_report("s", "i" * 64, report)
        await self.daemon.get_cached_report("s", "i" * 64)
        assert self.daemon._redis_error_count == 0

    async def test_get_error_increments_error_count(self):
        broken = AsyncMock()
        broken.get = AsyncMock(side_effect=ConnectionError("redis down"))
        self.daemon.redis_pool = broken
        result = await self.daemon.get_cached_report("s", "j" * 64)
        assert result is None
        assert self.daemon._redis_error_count == 1
        assert xspct.stats["redis_errors"] == 1

    async def test_set_error_increments_error_count(self):
        broken = AsyncMock()
        broken.setex = AsyncMock(side_effect=ConnectionError("redis down"))
        self.daemon.redis_pool = broken
        await self.daemon.cache_report("s", "k" * 64, {"hash": "k" * 64})
        assert self.daemon._redis_error_count == 1
        assert xspct.stats["redis_errors"] == 1

    async def test_delete_error_increments_error_count(self):
        broken = AsyncMock()
        broken.eval = AsyncMock(side_effect=ConnectionError("redis down"))
        self.daemon.redis_pool = broken
        await self.daemon.invalidate_cached_report("s", "n" * 64)
        assert self.daemon._redis_error_count == 1
        assert xspct.stats["redis_errors"] == 1

    async def test_cross_process_invalidate_blocks_stale_write(self):
        """A peer daemon process's invalidation must be visible via Redis,
        even though it never touched this process's local generation dict.
        """
        file_hash = "p" * 64
        peer = xspct.InspectorDaemon()
        peer.redis_pool = self.daemon.redis_pool  # shared cache, separate process

        # In-flight scan on self.daemon captures the generation before the
        # peer process invalidates the file.
        stale_generation = await self.daemon.get_cache_generation("s", file_hash)
        assert stale_generation == 0

        await peer.invalidate_cached_report("s", file_hash)
        # self.daemon's local dict never saw the peer's invalidation.
        assert self.daemon._cache_generations.get(file_hash, 0) == 0

        await self.daemon.cache_report(
            "s", file_hash, {"hash": file_hash}, stale_generation
        )

        assert await self.daemon.redis_pool.get("xspct:" + file_hash) is None
        assert file_hash not in self.daemon.tasks

    async def test_cross_process_fresh_write_still_cached(self):
        """A generation captured after the peer's invalidation must still be
        cacheable — the guard must not reject every write once any
        invalidation has ever happened.
        """
        file_hash = "q" * 64
        peer = xspct.InspectorDaemon()
        peer.redis_pool = self.daemon.redis_pool

        await peer.invalidate_cached_report("s", file_hash)
        fresh_generation = await self.daemon.get_cache_generation("s", file_hash)

        await self.daemon.cache_report(
            "s", file_hash, {"hash": file_hash}, fresh_generation
        )

        assert await self.daemon.redis_pool.get("xspct:" + file_hash) is not None

    async def test_run_script_uses_evalsha_when_sha_cached(self):
        """A pre-loaded SHA is used directly, without sending the script body."""
        sha = await self.daemon.redis_pool.script_load(
            xspct.InspectorDaemon._INVALIDATE_SCRIPT
        )
        self.daemon._invalidate_script_sha = sha
        evalsha = self.daemon.redis_pool.evalsha
        self.daemon.redis_pool.evalsha = MagicMock(wraps=evalsha)
        self.daemon.redis_pool.eval = MagicMock(
            side_effect=AssertionError("should not fall back to EVAL")
        )

        file_hash = "r" * 64
        await self.daemon.invalidate_cached_report("s", file_hash)

        assert self.daemon._invalidate_script_sha == sha
        self.daemon.redis_pool.evalsha.assert_called_once()
        self.daemon.redis_pool.eval.assert_not_called()
        assert self.daemon._redis_error_count == 0

    async def test_run_script_falls_back_and_recaches_sha_on_noscript(self):
        """An unrecognised (or never-loaded) SHA transparently falls back to
        EVAL and re-caches a fresh SHA for subsequent calls."""
        self.daemon._invalidate_script_sha = "0" * 40  # bogus/expired SHA
        eval = self.daemon.redis_pool.eval
        script_load = self.daemon.redis_pool.script_load
        self.daemon.redis_pool.eval = MagicMock(wraps=eval)
        self.daemon.redis_pool.script_load = MagicMock(wraps=script_load)

        file_hash = "t" * 64
        await self.daemon.cache_report("s", file_hash, {"hash": file_hash})
        await self.daemon.invalidate_cached_report("s", file_hash)

        assert await self.daemon.redis_pool.get("xspct:" + file_hash) is None
        assert self.daemon._invalidate_script_sha != "0" * 40
        assert self.daemon._invalidate_script_sha
        self.daemon.redis_pool.eval.assert_called_once()
        self.daemon.redis_pool.script_load.assert_called_once_with(
            xspct.InspectorDaemon._INVALIDATE_SCRIPT
        )

    async def test_setup_loads_lua_scripts(self, monkeypatch):
        """Startup loads both script bodies and retains their Redis SHAs."""
        pool = fakeredis.FakeAsyncRedis(decode_responses=True)
        script_load = pool.script_load
        pool.script_load = MagicMock(wraps=script_load)
        redis_module = MagicMock()
        redis_module.from_url.return_value = pool
        monkeypatch.setattr(xspct, "redis", redis_module)
        monkeypatch.setattr(xspct, "HAS_REDIS", True)
        daemon = xspct.InspectorDaemon()

        await daemon.setup()

        assert pool.script_load.call_args_list == [
            ((xspct.InspectorDaemon._INVALIDATE_SCRIPT,), {}),
            ((xspct.InspectorDaemon._CACHE_STORE_SCRIPT,), {}),
        ]
        assert daemon._invalidate_script_sha
        assert daemon._cache_store_script_sha
        await daemon.teardown()


@pytest.mark.skipif(not _HAS_FAKEREDIS, reason="fakeredis not installed")
class TestInvalidateCache:
    """/v1/scan?invalidate_cache=true and metadata.invalidate_cache."""

    @pytest.fixture(autouse=True)
    def _setup_redis(self, client):
        d = client.app["daemon"]
        saved = dict(xspct.config["xspct_redis_cache"])
        xspct.config["xspct_redis_cache"]["enabled"] = True
        xspct.config["xspct_redis_cache"]["expire"] = 3600
        xspct.config["xspct_redis_cache"]["prefix"] = "xspct:"
        xspct.config["xspct_redis_cache"]["max_errors"] = 3
        d.redis_pool = fakeredis.FakeAsyncRedis(decode_responses=True)
        d._redis_error_count = 0
        yield
        xspct.config["xspct_redis_cache"].update(saved)
        d.redis_pool = None

    async def test_query_discards_peer_invalidated_local_report(self, client):
        """A completed local report cannot outlive a peer's Redis deletion."""
        daemon = client.app["daemon"]
        file_hash = "f" * 64
        await daemon.cache_report("s", file_hash, {"hash": file_hash})
        peer = xspct.InspectorDaemon()
        peer.redis_pool = daemon.redis_pool

        await peer.invalidate_cached_report("s", file_hash)
        response = await client.get(f"/v1/query?hash={file_hash}")

        assert response.status == 404
        assert (await response.json())["status"] == "not_found"
        assert file_hash not in daemon.tasks

    async def test_query_discards_redis_rejected_completed_task(self, client):
        """A completed task whose Redis write lost the race is not served."""
        daemon = client.app["daemon"]
        file_hash = "e" * 64
        stale_generation = await daemon.get_cache_generation("s", file_hash)

        async def completed_report():
            return {"hash": file_hash}

        task = asyncio.create_task(completed_report())
        await task
        daemon.tasks[file_hash] = task
        peer = xspct.InspectorDaemon()
        peer.redis_pool = daemon.redis_pool
        await peer.invalidate_cached_report("s", file_hash)
        await daemon.cache_report("s", file_hash, {"hash": file_hash}, stale_generation)

        response = await client.get(f"/v1/query?hash={file_hash}")

        assert response.status == 404
        assert (await response.json())["status"] == "not_found"
        assert file_hash not in daemon.tasks

    async def test_second_request_is_cache_hit(self, client):
        r1 = await client.post("/v1/scan", data=_form(PDF_CLEAN, "inv1.pdf"))
        assert r1.status == 200
        b1 = await r1.json()
        assert "cache_hit" not in b1
        assert b1["scan"]["cache_hit"] is False

        r2 = await client.post("/v1/scan", data=_form(PDF_CLEAN, "inv1.pdf"))
        assert r2.status == 200
        b2 = await r2.json()
        assert b2.get("cache_hit") is True

    async def test_invalidate_cache_query_param_forces_rescan(self, client):
        r1 = await client.post("/v1/scan", data=_form(PDF_CLEAN, "inv2.pdf"))
        assert r1.status == 200

        r2 = await client.post(
            "/v1/scan?invalidate_cache=true", data=_form(PDF_CLEAN, "inv2.pdf")
        )
        assert r2.status == 200
        b2 = await r2.json()
        assert "cache_hit" not in b2
        assert b2["scan"]["cache_hit"] is False

    async def test_invalidate_cache_metadata_field_forces_rescan(self, client):
        r1 = await client.post(
            "/v1/scan", data=_metadata_form(PDF_CLEAN, "inv3.pdf", {})
        )
        assert r1.status == 200

        r2 = await client.post(
            "/v1/scan",
            data=_metadata_form(PDF_CLEAN, "inv3.pdf", {"invalidate_cache": True}),
        )
        assert r2.status == 200
        b2 = await r2.json()
        assert "cache_hit" not in b2
        assert b2["scan"]["cache_hit"] is False

    async def test_invalidate_cache_metadata_field_must_be_boolean(self, client):
        response = await client.post(
            "/v1/scan",
            data=_metadata_form(
                PDF_CLEAN, "invalid.pdf", {"invalidate_cache": "false"}
            ),
        )

        assert response.status == 400
        body = await response.json()
        assert body["error"] == 'metadata field "invalidate_cache" must be a boolean'

    async def test_invalidate_cache_metadata_overrides_query_param(self, client):
        """metadata.invalidate_cache=false must win over ?invalidate_cache=true
        (metadata fields always take precedence over query parameters)."""
        r1 = await client.post(
            "/v1/scan", data=_metadata_form(PDF_CLEAN, "inv4.pdf", {})
        )
        assert r1.status == 200

        r2 = await client.post(
            "/v1/scan?invalidate_cache=true",
            data=_metadata_form(PDF_CLEAN, "inv4.pdf", {"invalidate_cache": False}),
        )
        assert r2.status == 200
        b2 = await r2.json()
        assert b2.get("cache_hit") is True

    async def test_without_invalidate_cache_default_is_cache_hit(self, client):
        """Absence of invalidate_cache must not change existing cache-hit behavior."""
        r1 = await client.post("/v1/scan", data=_form(PDF_CLEAN, "inv5.pdf"))
        assert r1.status == 200
        r2 = await client.post(
            "/v1/scan?invalidate_cache=false", data=_form(PDF_CLEAN, "inv5.pdf")
        )
        assert r2.status == 200
        b2 = await r2.json()
        assert b2.get("cache_hit") is True


# ===========================================================================
# ODF analysis tests
# ===========================================================================
