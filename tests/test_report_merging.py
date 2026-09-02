# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""Report merging, detected-type routing, and base-report shape tests."""

import pytest

import xspct_scan.daemon as xspct
from tests.conftest import HTML_MALICIOUS, OOXML_DATA


class TestGetDetectedType:
    def test_pdf_by_mime(self, daemon):
        assert daemon.get_detected_type("application/pdf", "", "", b"") == "pdf"

    def test_pdf_by_desc(self, daemon):
        assert daemon.get_detected_type("", "PDF document", "", b"") == "pdf"

    def test_pdf_by_extension(self, daemon):
        assert daemon.get_detected_type("", "", "report.pdf", b"") == "pdf"

    def test_html_by_mime(self, daemon):
        assert daemon.get_detected_type("text/html", "", "", b"") == "html"

    def test_html_by_extension_html(self, daemon):
        assert daemon.get_detected_type("", "", "page.html", b"") == "html"

    def test_html_by_extension_htm(self, daemon):
        assert daemon.get_detected_type("", "", "page.htm", b"") == "html"

    def test_html_by_extension_xhtml(self, daemon):
        assert daemon.get_detected_type("", "", "page.xhtml", b"") == "html"

    def test_html_by_xhtml_mime(self, daemon):
        assert daemon.get_detected_type("application/xhtml+xml", "", "", b"") == "html"

    def test_rtf_by_magic_bytes(self, daemon):
        assert daemon.get_detected_type("", "", "", b"{\\rtf1") == "office"

    def test_office_default(self, daemon):
        assert (
            daemon.get_detected_type(
                "application/octet-stream", "binary", "file.bin", b""
            )
            == "unknown"
        )

    @pytest.mark.parametrize(
        "ext",
        [".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".bat", ".cmd"],
    )
    def test_script_extensions_route_to_script(self, daemon, ext):
        assert daemon.get_detected_type("", "", f"sample{ext}", b"") == "script"

    def test_hta_routes_to_html_not_script(self, daemon):
        assert daemon.get_detected_type("", "", "dropper.hta", b"") == "html"

    def test_lnk_by_extension(self, daemon):
        assert daemon.get_detected_type("", "", "shortcut.lnk", b"") == "lnk"

    def test_lnk_by_mime(self, daemon):
        assert (
            daemon.get_detected_type("application/x-ms-shortcut", "", "", b"") == "lnk"
        )

    def test_lnk_by_magic_desc(self, daemon):
        assert daemon.get_detected_type("", "MS Windows shortcut", "", b"") == "lnk"

    def test_lnk_by_magic_bytes(self, daemon):
        header = (
            b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00"
            b"\xc0\x00\x00\x00\x00\x00\x00\x46"
        )
        assert daemon.get_detected_type("", "", "", header) == "lnk"

    def test_lnk_ambiguous_mime_with_extension_routes_to_lnk(self, daemon):
        """application/x-ms-application is Rspamd's lua_magic content-type
        for .lnk, but it's also used for PE executables — confirmed by the
        .lnk extension, it must still route to "lnk"."""
        assert (
            daemon.get_detected_type(
                "application/x-ms-application", "", "shortcut.lnk", b""
            )
            == "lnk"
        )

    def test_lnk_ambiguous_mime_with_magic_bytes_routes_to_lnk(self, daemon):
        header = (
            b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00"
            b"\xc0\x00\x00\x00\x00\x00\x00\x46"
        )
        assert (
            daemon.get_detected_type("application/x-ms-application", "", "", header)
            == "lnk"
        )

    def test_lnk_ambiguous_mime_alone_does_not_route_to_lnk(self, daemon):
        """Without a confirming extension or magic-byte signature, the
        ambiguous MIME alone (e.g. an actual PE executable reported with
        the same content-type by some detectors) must not be misrouted."""
        assert (
            daemon.get_detected_type("application/x-ms-application", "", "app.exe", b"")
            != "lnk"
        )

    @pytest.mark.parametrize(
        "mime",
        ["application/x-bzip", "application/x-iso", "application/x-compress"],
    )
    def test_rspamd_lua_magic_archive_mime_variants_recognized(self, daemon, mime):
        """Rspamd's lua_magic reports these content-types (types.lua) for
        bzip2/ISO9660/Unix-compress content; xspct's own libmagic-derived
        variants ("x-bzip2", "x-iso9660-image") were already recognized but
        these weren't."""
        assert daemon.get_detected_type(mime, "", "", b"") == "archive"

    def test_unix_compress_extension_routes_to_archive(self, daemon):
        assert daemon.get_detected_type("", "", "archive.Z", b"") == "archive"


class TestGetDetectedTypeExtended:
    """Cover image and archive detection added in Phase 8."""

    def test_image_by_mime_jpeg(self, daemon):
        assert daemon.get_detected_type("image/jpeg", None, None, None) == "image"

    def test_image_by_mime_png(self, daemon):
        assert daemon.get_detected_type("image/png", None, None, None) == "image"

    def test_image_by_mime_gif(self, daemon):
        assert daemon.get_detected_type("image/gif", None, None, None) == "image"

    def test_image_by_extension(self, daemon):
        assert daemon.get_detected_type(None, None, "photo.jpg", None) == "image"

    def test_image_png_magic_bytes(self, daemon):
        # PNG header without MIME/extension — get_detected_type relies on MIME
        # or extension for image detection; raw magic bytes alone → unknown
        png_header = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        result = daemon.get_detected_type(None, None, None, png_header)
        assert result in ("image", "unknown")  # depends on libmagic availability

    def test_archive_by_mime_zip(self, daemon):
        assert (
            daemon.get_detected_type("application/zip", None, None, None) == "archive"
        )

    def test_archive_by_extension_zip(self, daemon):
        assert daemon.get_detected_type(None, None, "payload.zip", None) == "archive"

    def test_archive_by_extension_7z(self, daemon):
        assert daemon.get_detected_type(None, None, "payload.7z", None) == "archive"

    def test_text_by_mime(self, daemon):
        assert daemon.get_detected_type("text/plain", None, None, None) == "text"


# ===========================================================================
# UNIT TESTS — _make_base_report (new fields present)
# ===========================================================================


class TestMergeReports:
    def _base_target(self):
        return {
            "analyses": [],
            "iocs": {"urls": [], "ips": [], "domains": []},
            "rtf_objects": [],
        }

    def test_analyses_deduplication(self, daemon):
        item = {"type": "AutoExec", "keyword": "kw", "description": "desc"}
        t = self._base_target()
        t["analyses"].append(item)
        daemon.merge_reports(t, {"analyses": [item]})
        assert len(t["analyses"]) == 1

    def test_analyses_new_item_added(self, daemon):
        t = self._base_target()
        daemon.merge_reports(
            t, {"analyses": [{"type": "A", "keyword": "x", "description": "d"}]}
        )
        assert len(t["analyses"]) == 1

    def test_iocs_deduplication(self, daemon):
        t = self._base_target()
        t["iocs"]["urls"] = ["http://a.com"]
        daemon.merge_reports(
            t,
            {
                "iocs": {
                    "urls": ["http://a.com", "http://b.com"],
                    "ips": [],
                    "domains": [],
                }
            },
        )
        assert t["iocs"]["urls"].count("http://a.com") == 1
        assert "http://b.com" in t["iocs"]["urls"]

    def test_boolean_fields_ored(self, daemon):
        t = self._base_target()
        t["has_macro"] = False
        daemon.merge_reports(t, {"has_macro": True})
        assert t["has_macro"] is True

    def test_boolean_false_does_not_override_true(self, daemon):
        t = self._base_target()
        t["has_macro"] = True
        daemon.merge_reports(t, {"has_macro": False})
        assert t["has_macro"] is True

    def test_meta_key_is_skipped(self, daemon):
        t = self._base_target()
        t["meta"] = {"version": "original"}
        daemon.merge_reports(t, {"meta": {"version": "overwrite"}})
        assert t["meta"]["version"] == "original"

    def test_none_source_is_noop(self, daemon):
        t = self._base_target()
        daemon.merge_reports(t, None)
        assert t["analyses"] == []


class TestMergeReportsNewFields:
    def _base(self, daemon):
        return daemon._make_base_report("f", "h", None, None)

    def test_yara_matches_merged_no_duplicates(self, daemon):
        base = self._base(daemon)
        hit = {
            "engine": "classic",
            "rule": "Eicar",
            "namespace": "",
            "tags": [],
            "meta": {},
            "strings": [],
        }
        base["yara_matches"] = [hit]
        daemon.merge_reports(
            base,
            {
                "yara_matches": [
                    hit,
                    {
                        "engine": "yara-x",
                        "rule": "Other",
                        "namespace": "",
                        "tags": [],
                        "meta": {},
                        "strings": [],
                    },
                ]
            },
        )
        rules = [m["rule"] for m in base["yara_matches"]]
        assert rules.count("Eicar") == 1
        assert "Other" in rules

    def test_iocs_extended_deep_merged(self, daemon):
        base = self._base(daemon)
        base["iocs_extended"] = {"url": ["http://a.example"]}
        daemon.merge_reports(
            base,
            {
                "iocs_extended": {
                    "url": ["http://b.example"],
                    "email": ["x@example.com"],
                }
            },
        )
        assert "http://a.example" in base["iocs_extended"]["url"]
        assert "http://b.example" in base["iocs_extended"]["url"]
        assert "x@example.com" in base["iocs_extended"]["email"]

    def test_archive_files_appended(self, daemon):
        base = self._base(daemon)
        base["archive_files"] = [{"name": "a.txt", "size": 10}]
        daemon.merge_reports(base, {"archive_files": [{"name": "b.pdf", "size": 20}]})
        names = [f["name"] for f in base["archive_files"]]
        assert "a.txt" in names
        assert "b.pdf" in names

    def test_archive_files_no_duplicates(self, daemon):
        base = self._base(daemon)
        item = {"name": "x.doc", "size": 5}
        base["archive_files"] = [item]
        daemon.merge_reports(base, {"archive_files": [item]})
        assert len(base["archive_files"]) == 1

    def test_exif_first_wins(self, daemon):
        base = self._base(daemon)
        base["exif"] = {"Make": "Canon"}
        daemon.merge_reports(base, {"exif": {"Make": "Nikon"}})
        assert base["exif"]["Make"] == "Canon"

    def test_exif_empty_replaced(self, daemon):
        base = self._base(daemon)
        daemon.merge_reports(base, {"exif": {"Make": "Sony"}})
        assert base["exif"]["Make"] == "Sony"

    def test_text_full_segments_accumulate(self, daemon):
        base = self._base(daemon)
        daemon.merge_reports(base, {"text_full": [{"source": "a", "text": "alpha"}]})
        daemon.merge_reports(base, {"text_full": [{"source": "b", "text": "beta"}]})
        texts = {s["text"] for s in base.get("text_segments", [])}
        assert "alpha" in texts and "beta" in texts

    def test_text_segments_dedup(self, daemon):
        base = self._base(daemon)
        daemon.merge_reports(base, {"text_segments": [{"source": "a", "text": "x"}]})
        daemon.merge_reports(base, {"text_segments": [{"source": "a", "text": "x"}]})
        assert sum(1 for s in base["text_segments"] if s["text"] == "x") == 1


# ===========================================================================
# UNIT TESTS — analyze_yara (no engine installed path)
# ===========================================================================


class TestMakeBaseReport:
    def test_all_new_fields_present(self, daemon):
        r = daemon._make_base_report("f.pdf", "abc123", "application/pdf", "PDF doc")
        for field in (
            "yara_matches",
            "iocs_extended",
            "pdfid_keywords",
            "pdfid_meta",
            "archive_files",
            "exif",
            "text_full",
        ):
            assert field in r, f"Missing field: {field}"

    def test_yara_matches_is_list(self, daemon):
        r = daemon._make_base_report("f.pdf", "abc", None, None)
        assert isinstance(r["yara_matches"], list)

    def test_iocs_extended_is_dict(self, daemon):
        r = daemon._make_base_report("f.pdf", "abc", None, None)
        assert isinstance(r["iocs_extended"], dict)

    def test_archive_files_is_list(self, daemon):
        r = daemon._make_base_report("f.pdf", "abc", None, None)
        assert isinstance(r["archive_files"], list)

    def test_exif_is_dict(self, daemon):
        r = daemon._make_base_report("f.pdf", "abc", None, None)
        assert isinstance(r["exif"], dict)

    def test_text_full_is_empty_list_by_default(self, daemon):
        r = daemon._make_base_report("f.pdf", "abc", None, None)
        assert r["text_full"] == []


# ===========================================================================
# UNIT TESTS — merge_reports (new fields)
# ===========================================================================


# ===========================================================================
# CONTRACT TESTS — the v2 payload never contains a JSON null
# ===========================================================================


def _null_paths(node, path=""):
    """Yield the dotted path of every ``None`` value inside *node*."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _null_paths(value, f"{path}.{key}" if path else str(key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _null_paths(value, f"{path}[{index}]")
    elif node is None:
        yield path or "<root>"


def _report_matrix(daemon):
    """Build v2 reports across the analyzer types, as ``{label: report}``.

    Covers the branches of ``_to_v2_report`` that populate optional sections
    (content, document, engines, iocs, findings) plus the paths where the
    source values are missing entirely.
    """
    inputs = {
        "pdf": (
            b"%PDF-1.4\n/JS /JavaScript /OpenAction /Launch\n"
            b"/URI (http://evil.example.com/stage2)\n%%EOF\n",
            "invoice.pdf",
            "application/pdf",
        ),
        "html": (HTML_MALICIOUS, "phish.html", "text/html"),
        "office": (OOXML_DATA, "doc.docx", None),
        "text": (
            b"contact 10.0.0.1 or http://good.example.org/p\n",
            "n.txt",
            "text/plain",
        ),
        "script": (
            b'Set o = CreateObject("WScript.Shell")\no.Run "calc"\n',
            "s.vbs",
            None,
        ),
        "empty": (b"", "empty.bin", None),
        # No mime, no magic, no analyzer output — the path that used to emit
        # file.mime = null and file.magic = null.
        "unknown": (b"\x00\x01\x02\x03" * 32, "blob.bin", None),
    }
    reports = {}
    for label, (data, filename, mime) in inputs.items():
        v1 = daemon.sync_analyze("s", filename, data, mime)
        reports[label] = daemon._to_v2_report(
            v1, filename, len(data), "a" * 40, "b" * 64
        )
    # Same builder with the optional digests absent.
    v1 = daemon.sync_analyze("s", "blob.bin", b"\x00" * 64, None)
    reports["no-digests"] = daemon._to_v2_report(v1, "blob.bin", 64, None, None)
    return reports


class _StubPartial:
    """Minimal PartialReport stand-in for the in-flight envelopes."""

    filesize = 4096
    sha1 = "a" * 40
    rspamd_digest = "b" * 64

    def __init__(self, daemon, pending):
        self._daemon = daemon
        self._pending = pending

    def snapshot(self):
        report = self._daemon._make_base_report(
            "held.pdf", "application/pdf", None, None
        )
        report["file_hash"] = "c" * 64
        report["analyzers_completed"] = []
        report["analyzers_pending"] = list(self._pending)
        return report

    def successful(self):
        return []


class TestV2NullContract:
    """Consumers must never have to guard a field against JSON null.

    A null decodes to a truthy sentinel in some clients (Rspamd's ucl.null),
    so ``if report.field then`` silently takes the wrong branch. The contract
    is therefore: present with a meaningful value, or absent.
    """

    @pytest.mark.parametrize(
        "label",
        [
            "pdf",
            "html",
            "office",
            "text",
            "script",
            "empty",
            "unknown",
            "no-digests",
        ],
    )
    def test_finished_report_has_no_nulls(self, daemon, label):
        report = _report_matrix(daemon)[label]
        nulls = sorted(_null_paths(report))
        assert not nulls, f"{label}: null-valued fields {nulls}"

    @pytest.mark.parametrize("status", ["processing", "dropped"])
    def test_in_flight_envelope_has_no_nulls(self, daemon, status):
        """The 202 and /v1/query still-running bodies share the same builder."""
        partial = _StubPartial(daemon, ["clamav", "yara"])
        envelope = daemon._to_v2_partial_report(partial, status)
        nulls = sorted(_null_paths(envelope))
        assert not nulls, f"{status}: null-valued fields {nulls}"

    def test_in_flight_envelope_with_message_has_no_nulls(self, daemon):
        partial = _StubPartial(daemon, ["yara"])
        envelope = daemon._to_v2_partial_report(
            partial, "processing", 1.5, message="still going"
        )
        assert not sorted(_null_paths(envelope))

    def test_capabilities_has_no_nulls(self, daemon):
        nulls = sorted(_null_paths(daemon.build_capabilities()))
        assert not nulls, f"capabilities: null-valued fields {nulls}"

    def test_flags_are_present_and_true_never_false(self, daemon):
        """Clients read flags with plain truthiness; a false would be a trap."""
        for label, report in _report_matrix(daemon).items():
            for key, value in report.get("flags", {}).items():
                if key == "decryption_password":
                    assert isinstance(value, str) and value, f"{label}.{key}"
                else:
                    assert value is True, f"{label}: flags.{key} is {value!r}"

    def test_verdict_severity_always_present(self, daemon):
        """score/summary are omitted until scoring exists; severity carries it."""
        for label, report in _report_matrix(daemon).items():
            verdict = report["verdict"]
            assert verdict["severity"], label
            assert "score" not in verdict, label
            assert "summary" not in verdict, label


class TestV2ModelContract:
    """The pydantic models are the published contract — keep them true.

    Nothing validates the hand-built dicts at runtime, so without these the
    models are documentation with no mechanism to stay correct.
    """

    @pytest.mark.parametrize(
        "label",
        ["pdf", "html", "office", "text", "script", "empty", "unknown"],
    )
    def test_report_validates_against_model(self, daemon, label):
        if not xspct.HAS_PYDANTIC:
            pytest.skip("pydantic not installed")
        xspct._V2ScanReport.model_validate(_report_matrix(daemon)[label])

    @pytest.mark.parametrize(
        "label",
        ["pdf", "html", "office", "text", "script", "empty", "unknown"],
    )
    def test_report_emits_no_undeclared_keys(self, daemon, label):
        """model_validate ignores extras, so check the key sets directly.

        A builder key the model never declared is a field clients cannot
        discover from the OpenAPI spec.
        """
        if not xspct.HAS_PYDANTIC:
            pytest.skip("pydantic not installed")

        undeclared = []

        def _check(payload, model, path):
            for key, value in payload.items():
                field = model.model_fields.get(key)
                if field is None:
                    undeclared.append(f"{path}.{key}" if path else key)
                    continue
                nested = _nested_model(field.annotation)
                if nested is not None and isinstance(value, dict):
                    _check(value, nested, f"{path}.{key}" if path else key)
                elif nested is not None and isinstance(value, list):
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            _check(item, nested, f"{path}.{key}[{i}]")

        def _nested_model(annotation):
            """Return the BaseModel behind a (possibly Optional/list) annotation."""
            import typing

            if isinstance(annotation, type) and issubclass(
                annotation, xspct._pydantic.BaseModel
            ):
                return annotation
            for arg in typing.get_args(annotation) or ():
                found = _nested_model(arg)
                if found is not None:
                    return found
            return None

        _check(_report_matrix(daemon)[label], xspct._V2ScanReport, "")
        assert not undeclared, f"{label}: keys absent from the models: {undeclared}"

    # Named here rather than read from daemon._NON_NULLABLE_MODELS: the test
    # must not share its oracle with the code under test, or emptying that
    # constant would silently disable this check.
    V2_SCHEMA_NAMES = (
        "V2Engine",
        "V2File",
        "V2AnalyzerInfo",
        "V2Scan",
        "V2Verdict",
        "V2IocEntry",
        "V2Iocs",
        "V2Finding",
        "V2ScanReport",
        "ProcessingResponse",
        "QueryResponse",
    )

    def test_published_v2_schema_declares_no_nullable(self, daemon):
        """anyOf: [T, null] would tell clients to guard a null we never send."""
        if not xspct.HAS_PYDANTIC:
            pytest.skip("pydantic not installed")
        import json

        schemas = xspct._get_openapi_spec()["components"]["schemas"]
        missing = [n for n in self.V2_SCHEMA_NAMES if n not in schemas]
        assert not missing, f"v2 schemas absent from the spec: {missing}"
        offenders = [
            name
            for name in self.V2_SCHEMA_NAMES
            if '"type": "null"' in json.dumps(schemas[name])
        ]
        assert not offenders, f"v2 schemas still declare null: {sorted(offenders)}"
