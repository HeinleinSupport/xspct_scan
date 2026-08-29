# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""analyze_yara unit tests."""

import xspct_scan.daemon as xspct


class TestAnalyzeYaraNoEngine:
    def test_returns_none_when_no_rules_loaded(self, daemon):
        # daemon fixture has no YARA rules compiled
        result = daemon.analyze_yara(b"test data")
        assert result is None

    def test_yara_x_rules_none_skipped(self, daemon):
        assert getattr(daemon, "_yara_x_rules", None) is None
        # Should not raise
        result = daemon.analyze_yara(b"\x00" * 64)
        assert result is None


# ===========================================================================
# UNIT TESTS — sync_analyze YARA integration
# ===========================================================================


class TestSyncAnalyzeYara:
    """Verify that sync_analyze calls YARA when rules are available and that the
    result is reflected in the returned report's yara_matches list."""

    def test_no_rules_yara_matches_empty(self, daemon):
        # No rules loaded \u2014 yara_matches must be present but empty
        report = daemon.sync_analyze("s", "file.txt", b"hello world", "text/plain")
        assert "yara_matches" in report
        assert report["yara_matches"] == []

    def test_yara_called_when_rules_loaded(self, daemon, monkeypatch):
        # Patch analyze_yara to return a fake match so we can assert it was called
        hit = {"rule": "TestRule", "engine": "classic", "tags": [], "meta": {}}
        monkeypatch.setattr(daemon, "_yara_rules", object())  # non-None triggers check
        # yara analyzer is disabled by default; enable it for this test
        saved = xspct.config["xspct_analyzers"]["yara"]["enabled"]
        xspct.config["xspct_analyzers"]["yara"]["enabled"] = True
        call_log = []

        def _fake_yara(data, filename="", file_mime="", s=""):
            call_log.append(data)
            return {"yara_matches": [hit]}

        monkeypatch.setattr(daemon, "analyze_yara", _fake_yara)
        try:
            report = daemon.sync_analyze("s", "file.txt", b"hello world", "text/plain")
        finally:
            xspct.config["xspct_analyzers"]["yara"]["enabled"] = saved
        assert call_log, "analyze_yara was not called"
        assert hit in report["yara_matches"]


# ===========================================================================
# UNIT TESTS — analyze_iocsearcher
# ===========================================================================
