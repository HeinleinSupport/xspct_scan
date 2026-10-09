# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""analyze_javascript unit tests."""

import time

import pytest

import xspct_scan.daemon as xspct


class TestAnalyzeJavascript:
    def test_empty_string_returns_empty(self, daemon):
        assert daemon.analyze_javascript("") == []

    def test_whitespace_only_returns_empty(self, daemon):
        assert daemon.analyze_javascript("   \n\t  ") == []

    def test_eval_detected(self, daemon):
        hits = daemon.analyze_javascript('eval("alert(1)")')
        keywords = {h["keyword"] for h in hits}
        assert "eval()" in keywords

    def test_unescape_detected(self, daemon):
        hits = daemon.analyze_javascript('var x = unescape("%41%42")')
        keywords = {h["keyword"] for h in hits}
        assert "unescape()" in keywords

    def test_atob_detected(self, daemon):
        hits = daemon.analyze_javascript('atob("aGVsbG8=")')
        keywords = {h["keyword"] for h in hits}
        assert "atob()" in keywords

    def test_string_from_char_code_detected(self, daemon):
        hits = daemon.analyze_javascript("String.fromCharCode(65,66,67)")
        keywords = {h["keyword"] for h in hits}
        assert "String.fromCharCode" in keywords

    def test_document_write_detected(self, daemon):
        hits = daemon.analyze_javascript('document.write("<b>x</b>")')
        keywords = {h["keyword"] for h in hits}
        assert "document.write()" in keywords

    def test_export_data_object_detected(self, daemon):
        hits = daemon.analyze_javascript('this.exportDataObject({cName:"x"})')
        keywords = {h["keyword"] for h in hits}
        assert "exportDataObject()" in keywords

    def test_launch_url_detected(self, daemon):
        hits = daemon.analyze_javascript('app.launchURL("http://evil.com")')
        keywords = {h["keyword"] for h in hits}
        assert "app.launchURL()" in keywords

    def test_open_doc_detected(self, daemon):
        hits = daemon.analyze_javascript('app.openDoc("/tmp/x.pdf")')
        keywords = {h["keyword"] for h in hits}
        assert "app.openDoc()" in keywords

    def test_util_printf_detected(self, daemon):
        hits = daemon.analyze_javascript('util.printf("%s", x)')
        keywords = {h["keyword"] for h in hits}
        assert "util.printf()" in keywords

    def test_activex_detected(self, daemon):
        hits = daemon.analyze_javascript('new ActiveXObject("WScript.Shell")')
        keywords = {h["keyword"] for h in hits}
        assert "ActiveXObject" in keywords

    def test_wscript_detected(self, daemon):
        hits = daemon.analyze_javascript('WScript.Echo("hello")')
        keywords = {h["keyword"] for h in hits}
        assert "WScript" in keywords

    def test_shell_execute_detected(self, daemon):
        hits = daemon.analyze_javascript('ShellExecute("cmd.exe")')
        keywords = {h["keyword"] for h in hits}
        assert "ShellExecute" in keywords

    def test_source_label_in_description(self, daemon):
        hits = daemon.analyze_javascript('eval("x")', source_label="PDF /OpenAction")
        assert any("PDF /OpenAction" in h["description"] for h in hits)

    def test_clean_js_returns_empty(self, daemon):
        clean = "function add(a, b) { return a + b; }\nvar result = add(1, 2);"
        assert daemon.analyze_javascript(clean) == []

    def test_returns_list(self, daemon):
        result = daemon.analyze_javascript("var x = 1;")
        assert isinstance(result, list)

    def test_no_duplicate_hits(self, daemon):
        # Two eval() calls → still one entry
        hits = daemon.analyze_javascript('eval("a"); eval("b");')
        keywords = [h["keyword"] for h in hits if h["keyword"] == "eval()"]
        assert len(keywords) == 1

    def test_type_field_is_suspiciousjs(self, daemon):
        hits = daemon.analyze_javascript('eval("x")')
        assert hits[0]["type"] == "SuspiciousJS"


@pytest.mark.skipif(not xspct.HAS_QUICKJS, reason="quickjs not installed")
class TestQuickJSEmulation:
    """QuickJS sandbox emulation and output-collector regressions."""

    @pytest.fixture(autouse=True)
    def _enable_quickjs(self):
        js_cfg = xspct.config["xspct_analyzers"]["javascript"]
        saved = js_cfg.get("quickjs", False)
        js_cfg["quickjs"] = True
        yield
        js_cfg["quickjs"] = saved

    def test_setup_stubs_do_not_raise(self, daemon):
        hits = daemon.analyze_javascript("var x = 1 + 1;", source_label="test")
        assert not any(h["type"] == "DynamicJSError" for h in hits)

    def test_console_log_output_is_captured(self, daemon):
        hits = daemon.analyze_javascript(
            'console.log("visit http://evil.example/x");',
            source_label="test",
        )
        keywords = {h["keyword"] for h in hits}
        assert "emulated-url" in keywords

    def test_document_write_output_is_captured(self, daemon):
        hits = daemon.analyze_javascript(
            'document.write("http://evil.example/y");',
            source_label="test",
        )
        keywords = {h["keyword"] for h in hits}
        assert "emulated-url" in keywords

    def test_global_this_shims_capture_output(self, daemon):
        hits = daemon.analyze_javascript(
            'globalThis.console.log("http://evil.example/global"); '
            'globalThis.document.write("http://evil.example/document");',
            source_label="test",
        )
        keywords = {h["keyword"] for h in hits}
        assert "emulated-url" in keywords

    @pytest.fixture
    def collected_output(self, monkeypatch):
        """Record the collector output the host reads back from the sandbox."""
        outputs: list[str] = []
        real_context = xspct._quickjs.Context

        class _RecordingContext:
            def __init__(self):
                self._ctx = real_context()

            def __getattr__(self, name):
                return getattr(self._ctx, name)

            def eval(self, src):
                result = self._ctx.eval(src)
                if src == "__xspct_sandbox.get_output()":
                    outputs.append(xspct._js_unescape(result))
                return result

        monkeypatch.setattr(xspct._quickjs, "Context", _RecordingContext)
        return outputs

    def test_sandbox_global_cannot_be_overwritten(self, daemon):
        # globalThis assignment must not shadow the const sandbox binding that
        # the host reads the collected output back from.
        hits = daemon.analyze_javascript(
            "globalThis.__xspct_sandbox = "
            '{get_output: function(){ return "http://forged.example/"; }, '
            "get_truncated: function(){ return false; }}; "
            'console.log("http://evil.example/z");',
            source_label="test",
        )
        keywords = {h["keyword"] for h in hits}
        assert "emulated-url" in keywords

    @pytest.mark.parametrize(
        "override",
        (
            "JSON.stringify = function() { return '[\"http://forged.example/\", false]'; };",
            'Array.prototype.join = function() { return "http://forged.example/"; };',
            "Array.prototype.toJSON = function() "
            '{ return ["http://forged.example/", false]; };',
            'String.prototype.toJSON = function() { return "http://forged.example/"; };',
            "var stolen; Array.prototype.push = function() { stolen = this; }; "
            'console.log("seed"); delete Array.prototype.push; '
            'if (stolen) { stolen[0] = "http://forged.example/"; }',
        ),
    )
    def test_mutated_intrinsics_cannot_forge_result(self, daemon, override):
        hits = daemon.analyze_javascript(
            override + ' console.log("ht" + "tp://captured.example/");',
            source_label="test",
        )
        emulated = [h for h in hits if h["keyword"] == "emulated-url"]
        assert emulated
        assert "captured.example" in emulated[0]["description"]
        assert "forged.example" not in emulated[0]["description"]

    def test_strict_mode_shim_writes_do_not_abort(self, daemon):
        # The shims stay writable: freezing them makes these common patterns
        # throw under "use strict", discarding every later print.
        hits = daemon.analyze_javascript(
            '"use strict"; window.location.href = "http://one.example/a"; '
            'document.cookie = "a=b"; '
            'console.log("ht" + "tp://two.example/b");',
            source_label="test",
        )
        emulated = [h for h in hits if h["keyword"] == "emulated-url"]
        assert emulated
        assert "two.example" in emulated[0]["description"]

    def test_strict_mode_console_polyfill_does_not_abort(self, daemon):
        hits = daemon.analyze_javascript(
            '"use strict"; if (!console.info) { console.info = console.log; } '
            'console.info("ht" + "tp://three.example/c");',
            source_label="test",
        )
        emulated = [h for h in hits if h["keyword"] == "emulated-url"]
        assert emulated
        assert "three.example" in emulated[0]["description"]

    def test_global_scope_sandbox_cannot_be_forged(self, daemon):
        # The payload runs at global scope, next to the sandbox binding; the
        # frozen object and closure-held output must still resist tampering.
        hits = daemon.analyze_javascript(
            'try { __xspct_sandbox.get_output = function(){ return "http://forged.example/"; }; } '
            "catch (e) {} "
            "try { __xspct_sandbox = null; } catch (e) {} "
            'console.log("ht" + "tp://captured.example/");',
            source_label="test",
        )
        emulated = [h for h in hits if h["keyword"] == "emulated-url"]
        assert emulated
        assert "captured.example" in emulated[0]["description"]
        assert "forged.example" not in emulated[0]["description"]

    @pytest.mark.parametrize(
        "invoke",
        (
            'Function("console.log(destination)")();',
            '(0, eval)("console.log(destination)");',
            'setTimeout = function(s) { Function(s)(); }; setTimeout("console.log(destination)");',
        ),
    )
    def test_top_level_vars_visible_to_nested_code(self, daemon, invoke):
        hits = daemon.analyze_javascript(
            'var destination = "ht" + "tp://captured.example/"; ' + invoke,
            source_label="test",
        )
        emulated = [h for h in hits if h["keyword"] == "emulated-url"]
        assert emulated
        assert "captured.example" in emulated[0]["description"]

    @pytest.mark.parametrize("name", ("console", "document", "window", "app", "print"))
    def test_top_level_lexical_shadowing_of_shims_is_allowed(self, daemon, name):
        # Shims are configurable globals, so a payload's own top-level `let`
        # must not be a redeclaration SyntaxError that discards all emulation.
        hits = daemon.analyze_javascript(
            f"let {name} = 1; "
            'globalThis.__out = "ht" + "tp://captured.example/"; '
            "__xspct_sandbox.print(globalThis.__out);",
            source_label="test",
        )
        assert "emulated-url" in {h["keyword"] for h in hits}

    def test_oversized_print_is_truncated_not_dropped(self, daemon, collected_output):
        # A decoded dropper page larger than the budget must still yield the
        # IOCs in its leading part; only the overflow is discarded.
        hits = daemon.analyze_javascript(
            'document.write("<a href=http://evil.example/>" + "A".repeat(1024 * 1024));',
            source_label="test",
        )
        assert "emulated-url" in {h["keyword"] for h in hits}
        assert len(collected_output[0]) == 65536

    def test_truncation_cannot_use_overridden_slice(self, daemon, collected_output):
        daemon.analyze_javascript(
            "String.prototype.slice = function() { return this + this; }; "
            'console.log("http://evil.example/" + "A".repeat(70000));',
            source_label="test",
        )
        assert len(collected_output[0]) <= 65536

    def test_output_cap_includes_separators(self, daemon, collected_output):
        daemon.analyze_javascript(
            'console.log("A".repeat(65535)); console.log("B");',
            source_label="test",
        )
        assert len(collected_output[0]) <= 65536

    def test_output_cap_counts_utf16_units(self, daemon, collected_output):
        daemon.analyze_javascript(
            'console.log("\\u20ac".repeat(70000));',
            source_label="test",
        )
        assert len(collected_output[0]) == 65536

    def test_truncation_splitting_surrogate_pair_keeps_output(
        self, daemon, collected_output
    ):
        # The cap falls between the halves of an emoji; the dangling high
        # surrogate must not make the host-side conversion discard everything.
        hits = daemon.analyze_javascript(
            'var u = "http://evil.example/"; '
            'console.log(u + "A".repeat(65536 - u.length - 1) + String.fromCodePoint(0x1F600));',
            source_label="test",
        )
        assert "emulated-url" in {h["keyword"] for h in hits}
        assert collected_output[0].endswith("A�")

    def test_lone_surrogate_does_not_discard_output(self, daemon, collected_output):
        hits = daemon.analyze_javascript(
            'console.log("http://evil.example/"); '
            "console.log(String.fromCharCode(0xD800));",
            source_label="test",
        )
        assert "emulated-url" in {h["keyword"] for h in hits}
        assert collected_output[0] == "http://evil.example/ �"

    def test_non_ascii_output_round_trips(self, daemon, collected_output):
        daemon.analyze_javascript(
            'console.log("caf\\u00e9 \\u20ac " + String.fromCodePoint(0x1F600) + " %u0041");',
            source_label="test",
        )
        assert collected_output[0] == "café € \U0001f600 %u0041"

    def test_overridden_escape_cannot_forge_output(self, daemon):
        hits = daemon.analyze_javascript(
            'escape = function() { return "http://forged.example/"; }; '
            'console.log("ht" + "tp://captured.example/");',
            source_label="test",
        )
        emulated = [h for h in hits if h["keyword"] == "emulated-url"]
        assert emulated
        assert "captured.example" in emulated[0]["description"]
        assert "forged.example" not in emulated[0]["description"]

    def test_lone_surrogate_completion_value_keeps_output(self, daemon):
        # The script's last expression is converted to Python by the binding;
        # a failed conversion must not discard the already collected output.
        hits = daemon.analyze_javascript(
            'console.log("http://evil.example/"); String.fromCharCode(0xD800);',
            source_label="test",
        )
        assert "emulated-url" in {h["keyword"] for h in hits}

    def test_all_arguments_are_captured(self, daemon, collected_output):
        daemon.analyze_javascript(
            'var u = "ht" + "tp://evil.example/"; '
            'console.log("fetching", u, 3); '
            'document.write("<a href=", u, ">"); '
            "console.log();",
            source_label="test",
        )
        assert collected_output[0] == (
            "fetching http://evil.example/ 3 <a href=http://evil.example/> "
        )

    def test_reentrant_to_string_in_later_argument_respects_cap(
        self, daemon, collected_output
    ):
        daemon.analyze_javascript(
            'console.log("first", {toString: function() { '
            'for (var i = 0; i < 500; i++) { console.log("x"); } return "OUTER"; }});',
            source_label="test",
        )
        entries = collected_output[0].split(" ")
        assert len(entries) == 500
        assert "OUTER" not in entries

    @pytest.mark.parametrize(
        "src",
        (
            'Promise.resolve("ht" + "tp://evil.example/")'
            ".then(function(u) { console.log(u); });",
            "async function main() { "
            'var u = await Promise.resolve("ht" + "tp://evil.example/"); '
            "document.write(u); } main();",
        ),
    )
    def test_promise_jobs_are_run(self, daemon, src):
        hits = daemon.analyze_javascript(src, source_label="test")
        assert "emulated-url" in {h["keyword"] for h in hits}

    def test_self_requeueing_promise_chain_terminates(self, daemon):
        hits = daemon.analyze_javascript(
            'console.log("http://evil.example/"); '
            "function spin() { Promise.resolve().then(spin); } spin();",
            source_label="test",
        )
        assert "emulated-url" in {h["keyword"] for h in hits}

    def test_promise_jobs_are_bounded_by_deadline(self, daemon):
        # Each job gets its own CPU limit, so a chain of spinning jobs must be
        # stopped by the overall drain deadline rather than run job by job.
        start = time.monotonic()
        hits = daemon.analyze_javascript(
            "function spin() { "
            'console.log("http://evil.example/"); '
            "Promise.resolve().then(spin); while (true) {} } "
            "Promise.resolve().then(spin);",
            source_label="test",
        )
        assert time.monotonic() - start < 6
        assert "emulated-url" in {h["keyword"] for h in hits}

    def test_output_call_cap(self, daemon, collected_output):
        hits = daemon.analyze_javascript(
            'for (var i = 0; i < 100000; i++) { console.log("http://evil.example/" + i); }',
            source_label="test",
        )
        assert "emulated-url" in {h["keyword"] for h in hits}
        assert collected_output[0].count("http://") == 500

    @pytest.mark.parametrize("inner_calls", (499, 500, 1000))
    def test_reentrant_to_string_cannot_exceed_call_cap(
        self, daemon, collected_output, inner_calls
    ):
        # toString() runs inside print(); prints made from there must count
        # against the same cap as the outer call they are nested in.
        daemon.analyze_javascript(
            "console.log({toString: function() { "
            f'for (var i = 0; i < {inner_calls}; i++) {{ console.log("x"); }} '
            'return "OUTER"; }});',
            source_label="test",
        )
        entries = collected_output[0].split(" ")
        assert len(entries) == 500
        assert entries[-1] == ("OUTER" if inner_calls == 499 else "x")

    def test_time_limit_interruption_does_not_raise(self, daemon):
        hits = daemon.analyze_javascript("while (true) {}", source_label="test")
        assert not any(h["type"] == "DynamicJSError" for h in hits)

    def test_syntax_error_in_payload_does_not_raise(self, daemon):
        hits = daemon.analyze_javascript("function( {{{ =", source_label="test")
        assert not any(h["type"] == "DynamicJSError" for h in hits)


# ===========================================================================
# UNIT TESTS — analyze_image
# ===========================================================================
