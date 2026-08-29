# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""Report merging, detected-type routing, and base-report shape tests."""

import pytest


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
