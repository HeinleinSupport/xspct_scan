# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""analyze_javascript unit tests."""


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


# ===========================================================================
# UNIT TESTS — analyze_image
# ===========================================================================
