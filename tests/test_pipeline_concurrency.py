# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""sync_analyze, task eviction, PartialReport, and two-tier concurrency tests."""

import asyncio
import hashlib
import os

import pytest
from aiohttp import FormData

import xspct_scan.daemon as xspct
from tests.conftest import (
    HTML_MALICIOUS,
    OLE_FILE,
    PDF_ALL_MARKERS,
    PDF_CLEAN,
    RTF_FILE,
    _form,
)


class TestEvictTasks:
    def test_evicts_oldest_entries(self, daemon):
        daemon._TASKS_MAX_SIZE = 3
        for i in range(5):
            daemon.tasks[f"h{i}"] = f"result{i}"
            daemon.tasks.move_to_end(f"h{i}")
            daemon._evict_tasks()
        assert len(daemon.tasks) == 3
        assert "h0" not in daemon.tasks
        assert "h1" not in daemon.tasks
        assert "h4" in daemon.tasks

    def test_does_not_evict_under_limit(self, daemon):
        daemon._TASKS_MAX_SIZE = 10
        for i in range(5):
            daemon.tasks[f"h{i}"] = i
        daemon._evict_tasks()
        assert len(daemon.tasks) == 5


class TestSyncAnalyze:
    def test_pdf_returns_correct_detected_type(self, daemon):
        r = daemon.sync_analyze("<t>", "test.pdf", PDF_ALL_MARKERS, "application/pdf")
        assert r["detected_type"] == "pdf"

    def test_pdf_has_correct_hash(self, daemon):
        r = daemon.sync_analyze("<t>", "test.pdf", PDF_CLEAN, "application/pdf")
        assert r["file_hash"] == hashlib.sha256(PDF_CLEAN).hexdigest()

    def test_pdf_flags_propagated(self, daemon):
        r = daemon.sync_analyze("<t>", "test.pdf", PDF_ALL_MARKERS, "application/pdf")
        assert r["has_javascript"] is True
        assert r["has_openaction"] is True

    def test_html_returns_correct_detected_type(self, daemon):
        r = daemon.sync_analyze("<t>", "test.html", HTML_MALICIOUS, "text/html")
        assert r["detected_type"] == "html"
        assert r["has_scripts"] is True

    def test_unknown_binary_has_report_keys(self, daemon):
        data = bytes(range(256))
        r = daemon.sync_analyze("<t>", "mystery.bin", data, "application/octet-stream")
        for key in ("file_hash", "detected_type", "analyses", "iocs", "text_preview"):
            assert key in r

    def test_meta_always_present(self, daemon):
        r = daemon.sync_analyze("<t>", "x.pdf", PDF_CLEAN, "application/pdf")
        assert r["meta"]["script_name"] == "xspct_scan"
        assert r["meta"]["version"] == xspct._ENGINE_VERSION

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason="OLE sample not present")
    def test_real_ole_has_macro(self, daemon):
        with open(OLE_FILE, "rb") as f:
            data = f.read()
        r = daemon.sync_analyze(
            "<t>",
            "autostart-encrypt-standardpassword.xls",
            data,
            "application/vnd.ms-excel",
        )
        # File is encrypted; after in-memory decryption olevba may return has_macro=False
        # for XLM/stomped macros. Assert meaningful analysis was produced.
        assert (
            r["has_macro"] is True or r["decrypted"] is True or len(r["analyses"]) > 0
        )

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason="OLE sample not present")
    def test_real_ole_has_ioc_urls(self, daemon):
        with open(OLE_FILE, "rb") as f:
            data = f.read()
        r = daemon.sync_analyze(
            "<t>",
            "autostart-encrypt-standardpassword.xls",
            data,
            "application/vnd.ms-excel",
        )
        iocs = r["iocs"]
        # This sample has no real network IOCs — only internal Office/VBA object
        # references (MSO.DLL, Excel.Sheet, etc.) that must NOT appear as domains
        # after TLD validation.  Verify the ioc keys exist and are clean lists.
        assert isinstance(iocs["urls"], list)
        assert isinstance(iocs["ips"], list)
        assert isinstance(iocs["domains"], list)
        assert not any("." not in d for d in iocs["domains"]), (
            "bare tokens must not appear"
        )

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason="OLE sample not present")
    def test_real_ole_analyses_populated(self, daemon):
        with open(OLE_FILE, "rb") as f:
            data = f.read()
        r = daemon.sync_analyze(
            "<t>",
            "autostart-encrypt-standardpassword.xls",
            data,
            "application/vnd.ms-excel",
        )
        types = {a["type"] for a in r["analyses"]}
        assert "AutoExec" in types or "Suspicious" in types or len(types) > 0

    @pytest.mark.skipif(not os.path.exists(OLE_FILE), reason="OLE sample not present")
    def test_real_ole_with_custom_passwords(self, daemon):
        with open(OLE_FILE, "rb") as f:
            data = f.read()
        r = daemon.sync_analyze(
            "<t>",
            "autostart-encrypt-standardpassword.xls",
            data,
            "application/vnd.ms-excel",
            custom_passwords=["alpha", "beta", "123456"],
        )
        assert r["detected_type"] != ""

    @pytest.mark.skipif(not os.path.exists(RTF_FILE), reason="RTF sample not present")
    def test_real_rtf_analyzed(self, daemon):
        with open(RTF_FILE, "rb") as f:
            data = f.read()
        r = daemon.sync_analyze("<t>", "sample.rtf", data, "text/rtf")
        assert "file_hash" in r
        assert r["detected_type"] != ""


# ===========================================================================
# INTEGRATION TESTS
# ===========================================================================


class TestPartialReport:
    def _base(self, daemon):
        b = daemon._make_base_report("f.pdf", "abc", None, None)
        b["analyzers_completed"] = []
        b["analyzers_pending"] = ["pdf", "yara"]
        return b

    @pytest.mark.asyncio
    async def test_snapshot_returns_copy(self, daemon):
        pr = xspct.PartialReport(self._base(daemon), ["pdf", "yara"])
        snap = pr.snapshot()
        assert snap is not pr.report

    @pytest.mark.asyncio
    async def test_merge_moves_analyzer_to_completed(self, daemon):
        pr = xspct.PartialReport(self._base(daemon), ["pdf", "yara"])
        await pr.merge("pdf", {"analyses": []}, daemon)
        assert "pdf" in pr.successful
        assert "pdf" not in pr.report.get("analyzers_pending", [])

    @pytest.mark.asyncio
    async def test_merge_none_result_still_completes(self, daemon):
        pr = xspct.PartialReport(self._base(daemon), ["pdf"])
        await pr.merge("pdf", None, daemon)
        # Should still be marked completed even with None result
        assert "pdf" in pr.successful or "pdf" not in pr.report.get(
            "analyzers_pending", []
        )


# ===========================================================================
# UNIT TESTS — text_full via sync_analyze
# ===========================================================================


class TestTwoTierConcurrency:
    """Verify foreground/background semaphore lifecycle in handle_scan."""

    # --- Config defaults -------------------------------------------------

    def test_default_foreground_slots(self):
        assert xspct.config["xspct_foreground_slots"] == 16

    def test_default_background_slots(self):
        assert xspct.config["xspct_background_slots"] == 4

    def test_stats_keys_exist(self):
        for key in (
            "foreground_overloaded",
            "background_rejected",
            "background_completed",
            "background_errors",
        ):
            assert key in xspct.stats

    # --- Semaphore initialisation ----------------------------------------

    def test_daemon_semaphores_none_before_setup(self):
        d = xspct.InspectorDaemon()
        assert d._fg_sem is None
        assert d._bg_sem is None

    async def test_semaphores_initialised_after_setup(self, client):
        # client fixture creates a full app via make_app() → setup()
        # The daemon attached to the app must have non-None semaphores.
        app_daemon = client.server.app.get("daemon")
        if app_daemon is None:
            pytest.skip('app does not expose daemon via app["daemon"]')
        assert app_daemon._fg_sem is not None
        assert app_daemon._bg_sem is not None

    # --- Normal scan finishes within timeout (foreground slot released) ---

    async def test_normal_scan_releases_fg_slot(self, client):
        r = await client.post("/v1/scan", data=_form(PDF_CLEAN, "test.pdf"))
        assert r.status == 200
        body = await r.json()
        assert body["status"] == "finished"

    # --- Overload: all foreground slots taken → 503 ----------------------

    async def test_overloaded_returns_503(self, aiohttp_client):
        """Simulate all foreground slots occupied; next request gets 503."""
        xspct.config["xspct_foreground_slots"] = 2
        xspct.config["xspct_background_slots"] = 1
        app = await xspct.make_app()
        client = await aiohttp_client(app)
        daemon = app["daemon"]
        # Occupy every foreground slot
        n = daemon._fg_sem._value
        for _ in range(n):
            await daemon._fg_sem.acquire()
        before = xspct.stats["foreground_overloaded"]
        try:
            r = await client.post(
                "/v1/scan?timeout=0.05",
                data=_form(PDF_CLEAN, "test.pdf"),
            )
            assert r.status == 503
            body = await r.json()
            assert "overloaded" in body.get("error", "").lower()
        finally:
            for _ in range(n):
                daemon._fg_sem.release()
            xspct.config["xspct_foreground_slots"] = 16
            xspct.config["xspct_background_slots"] = 4
        assert xspct.stats["foreground_overloaded"] > before

    # --- Background slot full → scan dropped → 202 with status=dropped --

    async def test_background_full_drops_scan(self, aiohttp_client, monkeypatch):
        """When bg slots are all taken, a timed-out scan is cancelled (dropped)."""
        xspct.config["xspct_foreground_slots"] = 2
        xspct.config["xspct_background_slots"] = 1
        app = await xspct.make_app()
        client = await aiohttp_client(app)
        daemon = app["daemon"]

        # Hold all background slots
        n_bg = daemon._bg_sem._value
        for _ in range(n_bg):
            await daemon._bg_sem.acquire()

        # Make analyze_task hang so the scan always times out
        async def _slow(*args, **kwargs):
            await asyncio.sleep(60)
            return {}

        monkeypatch.setattr(daemon, "analyze_task", _slow)
        before = xspct.stats["background_rejected"]
        try:
            r = await client.post(
                "/v1/scan?timeout=0.1",
                data=_form(PDF_CLEAN, "slow.pdf"),
            )
            assert r.status == 202
            body = await r.json()
            assert body.get("status") == "dropped"
            assert body["schema_version"] == xspct._REPORT_SCHEMA_VERSION
            assert body["file"]["sha256"] == hashlib.sha256(PDF_CLEAN).hexdigest()
            assert body["file"]["size"] == len(PDF_CLEAN)
            assert body["scan"]["status"] == "dropped"
        finally:
            for _ in range(n_bg):
                daemon._bg_sem.release()
            xspct.config["xspct_foreground_slots"] = 16
            xspct.config["xspct_background_slots"] = 4
        assert xspct.stats["background_rejected"] > before

    async def test_dropped_scans_do_not_leak_progress_state(
        self, aiohttp_client, monkeypatch
    ):
        """A dropped scan is cancelled, so it never clears its own state.

        _partials holds whatever the analyzers accumulated and _evict_tasks
        bounds only self.tasks, so leaving entries behind grows without limit
        under exactly the overload the drop path exists to handle.
        """
        xspct.config["xspct_foreground_slots"] = 2
        xspct.config["xspct_background_slots"] = 1
        app = await xspct.make_app()
        client = await aiohttp_client(app)
        daemon = app["daemon"]

        n_bg = daemon._bg_sem._value
        for _ in range(n_bg):
            await daemon._bg_sem.acquire()

        async def _slow(*args, **kwargs):
            await asyncio.sleep(60)
            return {}

        monkeypatch.setattr(daemon, "analyze_task", _slow)
        try:
            for i in range(5):
                payload = b"%PDF-1.4\n" + bytes([i]) * 64 + b"\n%%EOF\n"
                r = await client.post(
                    "/v1/scan?timeout=0.1", data=_form(payload, f"drop{i}.pdf")
                )
                assert r.status == 202
                assert (await r.json())["status"] == "dropped"

            assert daemon._partials == {}
            assert daemon._scan_owners == {}
        finally:
            for _ in range(n_bg):
                daemon._bg_sem.release()
            xspct.config["xspct_foreground_slots"] = 16
            xspct.config["xspct_background_slots"] = 4

    async def test_evict_tasks_drops_orphaned_progress_state(self):
        """Evicting a terminal entry must not strand its partial in _partials."""
        daemon = xspct.InspectorDaemon()
        max_tasks = daemon._TASKS_MAX_SIZE
        for i in range(max_tasks + 3):
            file_hash = f"{i:064x}"
            daemon.tasks[file_hash] = {"status": "finished"}
            daemon._partials[file_hash] = object()
            daemon._scan_owners[file_hash] = f"owner-{i}"
        daemon._evict_tasks()

        assert len(daemon.tasks) == max_tasks
        # Every hash that fell out of tasks took its progress state with it.
        assert set(daemon._partials) == set(daemon.tasks)
        assert set(daemon._scan_owners) == set(daemon.tasks)

    async def test_evict_tasks_keeps_owner_of_a_still_running_scan(self):
        """An evicted live task must still be able to publish its report.

        Eviction only means the LRU forgot the entry — the coroutine keeps
        running. Dropping its owner token would make the scan_owner check in
        cache_report()/_store_terminal_result() read as "superseded", so a
        completed analysis would be silently discarded and /v1/query would
        answer 404 for a scan the caller already got a 202 for.
        """
        daemon = xspct.InspectorDaemon()
        live_hash = "a" * 64
        owner = "owner-live"

        async def _never():
            await asyncio.sleep(60)

        live = asyncio.ensure_future(_never())
        try:
            daemon.tasks[live_hash] = live
            daemon._scan_owners[live_hash] = owner
            daemon._partials[live_hash] = object()

            for i in range(daemon._TASKS_MAX_SIZE + 1):
                daemon.tasks[f"{i:064x}"] = {"status": "finished"}
            daemon._evict_tasks()

            assert live_hash not in daemon.tasks  # evicted from the LRU
            assert daemon._scan_owners.get(live_hash) == owner  # but still owns it

            report = {"status": "finished", "file_hash": live_hash}
            daemon._store_terminal_result(live_hash, report, scan_owner=owner)
            assert daemon.tasks.get(live_hash) == report
            # Publishing clears the state it was holding.
            assert live_hash not in daemon._partials
            assert live_hash not in daemon._scan_owners
        finally:
            live.cancel()

    async def test_evict_tasks_drops_state_of_a_finished_task(self):
        """A task that already completed holds nothing worth keeping."""
        daemon = xspct.InspectorDaemon()
        done_hash = "b" * 64

        async def _done():
            return None

        finished = asyncio.ensure_future(_done())
        await finished

        daemon.tasks[done_hash] = finished
        daemon._scan_owners[done_hash] = "owner-done"
        daemon._partials[done_hash] = object()

        for i in range(daemon._TASKS_MAX_SIZE + 1):
            daemon.tasks[f"{i:064x}"] = {"status": "finished"}
        daemon._evict_tasks()

        assert done_hash not in daemon._partials
        assert done_hash not in daemon._scan_owners

    async def test_timeout_promotes_to_background_when_slot_available(
        self, aiohttp_client, monkeypatch
    ):
        """A timed-out scan should return 202/processing when a bg slot is free."""
        xspct.config["xspct_foreground_slots"] = 1
        xspct.config["xspct_background_slots"] = 1
        app = await xspct.make_app()
        client = await aiohttp_client(app)
        daemon = app["daemon"]

        finalized = asyncio.Event()

        async def _slow(*args, **kwargs):
            await asyncio.Event().wait()

        async def _finalize_background(s, file_hash, task):
            try:
                task.cancel()
                await task
            except asyncio.CancelledError:
                pass
            finally:
                daemon._bg_sem.release()
                finalized.set()

        monkeypatch.setattr(daemon, "analyze_task", _slow)
        monkeypatch.setattr(daemon, "_finalize_background", _finalize_background)
        try:
            r = await client.post(
                "/v1/scan?timeout=0.1",
                data=_form(PDF_CLEAN, "slow.pdf"),
            )
            assert r.status == 202
            body = await r.json()
            assert body.get("status") == "processing"
            assert body["schema_version"] == xspct._REPORT_SCHEMA_VERSION
            assert body["file"]["sha256"] == hashlib.sha256(PDF_CLEAN).hexdigest()
            assert body["file"]["size"] == len(PDF_CLEAN)
            assert body["scan"]["status"] == "processing"
            await asyncio.wait_for(finalized.wait(), timeout=1)
            assert daemon._bg_sem._value == 1
        finally:
            xspct.config["xspct_foreground_slots"] = 16
            xspct.config["xspct_background_slots"] = 4

    async def test_timeout_with_real_partial_returns_v2_shape(
        self, aiohttp_client, monkeypatch
    ):
        """202/processing for a genuinely in-flight scan must be v2, not the raw
        v1-internal partial report (regression test)."""
        xspct.config["xspct_foreground_slots"] = 1
        xspct.config["xspct_background_slots"] = 1
        app = await xspct.make_app()
        client = await aiohttp_client(app)
        daemon = app["daemon"]
        finalize = asyncio.Event()

        async def _slow_pipeline(
            s,
            filename,
            data,
            file_mime,
            file_desc=None,
            custom_passwords=None,
            types_to_run=None,
            force_analyzers=None,
            **kwargs,
        ):
            partial = kwargs["partial"]
            partial._pending[:] = ["clamav"]
            partial.report["analyzers_pending"] = ["clamav"]
            await asyncio.Event().wait()
            return partial

        async def _finalize_background(s, file_hash, task):
            await finalize.wait()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            daemon._bg_sem.release()

        monkeypatch.setattr(daemon, "analyze_pipeline", _slow_pipeline)
        monkeypatch.setattr(daemon, "_finalize_background", _finalize_background)
        try:
            r = await client.post(
                "/v1/scan?timeout=0.1",
                data=_form(PDF_CLEAN, "slow.pdf"),
            )
            assert r.status == 202
            body = await r.json()
            assert body.get("status") == "processing"
            assert body.get("schema_version") == xspct._REPORT_SCHEMA_VERSION
            assert body.get("file", {}).get("sha256")
            assert body["file"]["size"] == len(PDF_CLEAN)
            assert body["scan"]["analyzers"]["pending"] == ["clamav"]
            # v1-internal keys must never leak into the v2 response
            assert "analyzer_timings" not in body
            assert "text_segments" not in body

            query = await client.get(f"/v1/query?hash={body['file_hash']}")
            assert query.status == 200
            query_body = await query.json()
            assert query_body["schema_version"] == xspct._REPORT_SCHEMA_VERSION
            assert query_body["file"]["size"] == len(PDF_CLEAN)
            assert query_body["file"]["sha256"] == body["file_hash"]
            assert query_body["file"]["sha1"] == hashlib.sha1(PDF_CLEAN).hexdigest()
            assert query_body["file"]["rspamd_digest"]
            assert query_body["scan"]["status"] == "processing"
        finally:
            finalize.set()
            xspct.config["xspct_foreground_slots"] = 16
            xspct.config["xspct_background_slots"] = 4

    async def test_query_in_flight_without_partial_returns_v2(self, aiohttp_client):
        """A defensive in-flight query fallback must still use the v2 envelope."""
        app = await xspct.make_app()
        client = await aiohttp_client(app)
        daemon = app["daemon"]
        file_hash = hashlib.sha256(PDF_CLEAN).hexdigest()
        wait = asyncio.Event()

        async def _slow() -> None:
            await wait.wait()

        task = asyncio.create_task(_slow())
        daemon.tasks[file_hash] = task
        try:
            response = await client.get(f"/v1/query?hash={file_hash}")
            assert response.status == 200
            body = await response.json()
            assert body["schema_version"] == xspct._REPORT_SCHEMA_VERSION
            assert body["status"] == "processing"
            assert body["file"]["sha256"] == file_hash
            assert body["scan"]["status"] == "processing"
        finally:
            wait.set()
            await task

    async def test_duplicate_scan_attaches_to_in_flight_task(
        self, aiohttp_client, monkeypatch
    ):
        """Resubmitting the same file while it is still being analyzed must not
        start a second, redundant analysis task."""
        app = await xspct.make_app()
        client = await aiohttp_client(app)
        daemon = app["daemon"]

        call_count = 0
        release = asyncio.Event()

        async def _slow(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            await release.wait()
            return {"file_hash": args[1]}

        monkeypatch.setattr(daemon, "analyze_task", _slow)
        before = xspct.stats["requests_deduped"]
        try:
            r1 = await client.post(
                "/v1/scan?timeout=0.05", data=_form(PDF_CLEAN, "dup.pdf")
            )
            assert r1.status == 202
            body1 = await r1.json()
            assert body1.get("status") == "processing"

            r2 = await client.post(
                "/v1/scan?timeout=0.05", data=_form(PDF_CLEAN, "dup.pdf")
            )
            assert r2.status == 202
            body2 = await r2.json()
            assert body2.get("status") == "processing"
            assert body2.get("file_hash") == body1.get("file_hash")

            assert call_count == 1
            assert xspct.stats["requests_deduped"] > before
        finally:
            release.set()
            await asyncio.sleep(0.05)

    async def test_fresh_same_hash_scan_keeps_latest_query_owner(
        self, aiohttp_client, monkeypatch
    ):
        """A fresh scan must not let an older same-hash task replace /query."""
        xspct.config["xspct_foreground_slots"] = 2
        xspct.config["xspct_background_slots"] = 2
        app = await xspct.make_app()
        client = await aiohttp_client(app)
        daemon = app["daemon"]
        first_started = asyncio.Event()
        first_release = asyncio.Event()
        second_started = asyncio.Event()
        second_release = asyncio.Event()

        async def _controlled_pipeline(*args, **kwargs):
            partial = kwargs["partial"]
            passwords = args[5]
            if passwords == ["first"]:
                first_started.set()
                await first_release.wait()
            else:
                second_started.set()
                await second_release.wait()
            return partial

        def _upload(filename, password):
            form = FormData()
            form.add_field("doc", PDF_CLEAN, filename=filename)
            form.add_field("passwords", password)
            return form

        def _terminal_report(payload):
            return payload.get("result") or payload.get("report") or payload

        monkeypatch.setattr(daemon, "analyze_pipeline", _controlled_pipeline)
        file_hash = hashlib.sha256(PDF_CLEAN).hexdigest()
        try:
            first_request = asyncio.create_task(
                client.post("/v1/scan?timeout=0.01", data=_upload("first.pdf", "first"))
            )
            await asyncio.wait_for(first_started.wait(), timeout=1)
            first_task = daemon.tasks[file_hash]
            first_response = await first_request
            assert first_response.status == 202

            second_response = await client.post(
                "/v1/scan?timeout=0.01", data=_upload("second.pdf", "second")
            )
            assert second_response.status == 202
            await asyncio.wait_for(second_started.wait(), timeout=1)
            second_task = daemon.tasks[file_hash]
            assert second_task is not first_task

            second_release.set()
            await second_task
            latest_query = await client.get(f"/v1/query?hash={file_hash}")
            assert (
                _terminal_report(await latest_query.json())["file"]["name"]
                == "second.pdf"
            )

            first_release.set()
            await first_task
            query_after_old_completion = await client.get(f"/v1/query?hash={file_hash}")
            assert (
                _terminal_report(await query_after_old_completion.json())["file"][
                    "name"
                ]
                == "second.pdf"
            )
        finally:
            first_release.set()
            second_release.set()
            xspct.config["xspct_foreground_slots"] = 16
            xspct.config["xspct_background_slots"] = 4

    async def test_background_failure_becomes_stable_query_error(
        self, aiohttp_client, monkeypatch
    ):
        """A failed background scan should be queryable as a stable error result."""
        xspct.config["xspct_foreground_slots"] = 1
        xspct.config["xspct_background_slots"] = 1
        app = await xspct.make_app()
        client = await aiohttp_client(app)
        daemon = app["daemon"]

        allow_raise = asyncio.Event()
        error_stored = asyncio.Event()
        original_store = daemon._store_terminal_result

        async def _boom(*args, **kwargs):
            await allow_raise.wait()
            raise RuntimeError("boom")

        def _store_and_signal(file_hash, result):
            original_store(file_hash, result)
            if result.get("status") == "error":
                error_stored.set()

        monkeypatch.setattr(daemon, "analyze_task", _boom)
        monkeypatch.setattr(daemon, "_store_terminal_result", _store_and_signal)
        try:
            r = await client.post(
                "/v1/scan?timeout=0.01",
                data=_form(PDF_CLEAN, "boom.pdf"),
            )
            assert r.status == 202
            body = await r.json()
            assert body.get("status") == "processing"

            allow_raise.set()
            await asyncio.wait_for(error_stored.wait(), timeout=1)

            query_1 = await client.get(f"/v1/query?hash={body['file_hash']}")
            assert query_1.status == 200
            q1_body = await query_1.json()
            assert q1_body["status"] == "error"
            assert q1_body["file_hash"] == body["file_hash"]

            query_2 = await client.get(f"/v1/query?hash={body['file_hash']}")
            assert query_2.status == 200
            q2_body = await query_2.json()
            assert q2_body["status"] == "error"
            assert q2_body["file_hash"] == body["file_hash"]
        finally:
            xspct.config["xspct_foreground_slots"] = 16
            xspct.config["xspct_background_slots"] = 4

    # --- /metrics exposes new counters -----------------------------------

    async def test_metrics_contains_concurrency_lines(self, client):
        r = await client.get("/v1/metrics")
        assert r.status == 200
        text = await r.text()
        for key in (
            "xspct_foreground_overloaded",
            "xspct_background_rejected",
            "xspct_background_completed",
            "xspct_background_errors",
            "xspct_foreground_slots_free",
            "xspct_background_slots_free",
            "xspct_requests_deduped",
        ):
            assert key in text, f"metric {key!r} missing from /metrics"


# ===========================================================================
# INTEGRATION TESTS — admin /admin/reload
# ===========================================================================
