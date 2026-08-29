# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""IOC extraction, domain-exclusion, and iocsearcher tests."""

import pytest

import xspct_scan.daemon as xspct


class TestExtractIocs:
    def test_empty_bytes(self, daemon):
        r = daemon.extract_iocs(b"")
        assert r == {"urls": [], "ips": [], "domains": []}

    def test_url_detected(self, daemon):
        r = daemon.extract_iocs(b"payload at https://evil.example.com/drop?x=1")
        assert any("evil.example.com" in u for u in r["urls"])

    def test_ip_detected(self, daemon):
        r = daemon.extract_iocs(b"C2 at 10.20.30.40")
        assert "10.20.30.40" in r["ips"]

    def test_invalid_octet_rejected(self, daemon):
        r = daemon.extract_iocs(b"bogus 999.999.999.999")
        assert "999.999.999.999" not in r["ips"]

    def test_url_deduplication(self, daemon):
        r = daemon.extract_iocs(b"https://evil.com https://evil.com https://evil.com")
        assert r["urls"].count("https://evil.com") == 1

    def test_utf16le_url_detected(self, daemon):
        payload = "https://hidden.example.com".encode("utf-16le")
        r = daemon.extract_iocs(payload)
        assert any("hidden.example.com" in u for u in r["urls"])

    def test_multiple_ips(self, daemon):
        r = daemon.extract_iocs(b"hosts: 1.2.3.4 and 5.6.7.8")
        assert "1.2.3.4" in r["ips"]
        assert "5.6.7.8" in r["ips"]

    def test_domain_with_valid_tld_kept(self, daemon):
        r = daemon.extract_iocs(b"see evil.example.com for details")
        assert "evil.example.com" in r["domains"]

    def test_domain_with_file_ext_tld_filtered(self, daemon):
        # Windows file names like MSO.DLL or Normal.dotm must not appear as domains
        r = daemon.extract_iocs(b"MSO.DLL VBE7.DLL Normal.dotm stdole2.tlb")
        assert not any(
            d.lower().endswith((".dll", ".dotm", ".tlb")) for d in r["domains"]
        )

    def test_vba_internal_names_filtered(self, daemon):
        # VBA object paths extracted from OLE streams must not appear as domains
        r = daemon.extract_iocs(b"BzqPKManager.sqW PROJECT.NLHWEHWJ.AVVKQDABDFCIT")
        assert "BzqPKManager.sqW" not in r["domains"]
        assert "PROJECT.NLHWEHWJ.AVVKQDABDFCIT" not in r["domains"]

    def test_pdf_internal_refs_filtered(self, daemon):
        # Short PDF internal object references must not appear as domains,
        # including fragments with valid ccTLDs but 1-2-char SLDs (Jy.gY, o.MA)
        r = daemon.extract_iocs(b"JNWs.oO g.xJ i.yZ xf.jx y.MDO Jy.gY o.MA")
        assert not r["domains"]

    def test_short_sld_with_valid_cctld_filtered(self, daemon):
        # 1–2-char SLDs before real ccTLDs are binary-internal artefacts, not IOCs
        r = daemon.extract_iocs(b"Jy.gY o.MA xf.jx")
        assert not r["domains"]

    def test_min_sld_length_keeps_real_domains(self, daemon):
        # bit.ly (3-char SLD) and longer SLDs must not be filtered
        r = daemon.extract_iocs(b"see bit.ly and krittv.ru for context")
        assert "bit.ly" in r["domains"]
        assert "krittv.ru" in r["domains"]


# ===========================================================================
# UNIT TESTS — _ioc_excluded helper
# ===========================================================================


class TestIocExcluded:
    def test_exact_match(self):
        assert xspct.InspectorDaemon._ioc_excluded("w3.org", ("w3.org",))

    def test_subdomain_match(self):
        assert xspct.InspectorDaemon._ioc_excluded("www.w3.org", ("w3.org",))

    def test_deep_subdomain_match(self):
        assert xspct.InspectorDaemon._ioc_excluded("a.b.w3.org", ("w3.org",))

    def test_no_match(self):
        assert not xspct.InspectorDaemon._ioc_excluded("evil.com", ("w3.org",))

    def test_partial_suffix_not_matched(self):
        # 'w3.org' should NOT match 'notw3.org'
        assert not xspct.InspectorDaemon._ioc_excluded("notw3.org", ("w3.org",))

    def test_empty_suffixes(self):
        assert not xspct.InspectorDaemon._ioc_excluded("anything.com", ())


# ===========================================================================
# UNIT TESTS — extract_iocs domain exclusion
# ===========================================================================


class TestExtractIocsExcludeDomains:
    def test_excluded_url_dropped(self, daemon):
        saved = xspct.config.get("xspct_ioc_url_exclude_domains")
        xspct.config["xspct_ioc_url_exclude_domains"] = ["w3.org"]
        try:
            r = daemon.extract_iocs(b"see http://www.w3.org/1999/xhtml for details")
            assert all("w3.org" not in u for u in r["urls"])
        finally:
            xspct.config["xspct_ioc_url_exclude_domains"] = saved

    def test_excluded_domain_dropped(self, daemon):
        saved = xspct.config.get("xspct_ioc_url_exclude_domains")
        xspct.config["xspct_ioc_url_exclude_domains"] = ["w3.org"]
        try:
            r = daemon.extract_iocs(b"namespace http://www.w3.org/TR/xhtml1/")
            assert all("w3.org" not in d for d in r["domains"])
        finally:
            xspct.config["xspct_ioc_url_exclude_domains"] = saved

    def test_non_excluded_url_kept(self, daemon):
        saved = xspct.config.get("xspct_ioc_url_exclude_domains")
        xspct.config["xspct_ioc_url_exclude_domains"] = ["w3.org"]
        try:
            r = daemon.extract_iocs(b"payload at https://evil.example.com/drop")
            assert any("evil.example.com" in u for u in r["urls"])
        finally:
            xspct.config["xspct_ioc_url_exclude_domains"] = saved

    def test_empty_exclusion_list_keeps_all(self, daemon):
        saved = xspct.config.get("xspct_ioc_url_exclude_domains")
        xspct.config["xspct_ioc_url_exclude_domains"] = []
        try:
            r = daemon.extract_iocs(
                b"see http://www.w3.org/TR/xhtml1/ and https://evil.com"
            )
            assert any("w3.org" in u for u in r["urls"])
        finally:
            xspct.config["xspct_ioc_url_exclude_domains"] = saved


# ===========================================================================
# UNIT TESTS — analyze_iocsearcher domain exclusion
# ===========================================================================


class TestAnalyzeIocsearcherExclude:
    def test_excluded_fqdn_dropped(self, daemon):
        if not xspct.HAS_IOCSEARCHER:
            pytest.skip("iocsearcher not installed")
        saved = xspct.config.get("xspct_ioc_url_exclude_domains")
        xspct.config["xspct_ioc_url_exclude_domains"] = ["w3.org"]
        try:
            result = daemon.analyze_iocsearcher(
                "namespace http://www.w3.org/1999/xhtml something", "test"
            )
            if result and "iocs_extended" in result:
                for ioc_list in result["iocs_extended"].values():
                    assert all("w3.org" not in v for v in ioc_list)
        finally:
            xspct.config["xspct_ioc_url_exclude_domains"] = saved

    def test_non_excluded_kept(self, daemon):
        if not xspct.HAS_IOCSEARCHER:
            pytest.skip("iocsearcher not installed")
        saved = xspct.config.get("xspct_ioc_url_exclude_domains")
        xspct.config["xspct_ioc_url_exclude_domains"] = ["w3.org"]
        try:
            result = daemon.analyze_iocsearcher(
                "contact info@evil.example.com for payload", "test"
            )
            # evil.example.com is NOT excluded — email or fqdn should survive
            if result and "iocs_extended" in result:
                all_vals = [v for lst in result["iocs_extended"].values() for v in lst]
                assert any("evil.example.com" in v for v in all_vals)
        finally:
            xspct.config["xspct_ioc_url_exclude_domains"] = saved


class TestAnalyzeIocsearcher:
    def test_returns_none_when_not_installed(self, daemon):
        if xspct.HAS_IOCSEARCHER:
            pytest.skip("iocsearcher is installed; skipping no-engine path")
        result = daemon.analyze_iocsearcher("some text with http://example.com", "test")
        assert result is None

    def test_returns_dict_when_installed(self, daemon):
        if not xspct.HAS_IOCSEARCHER:
            pytest.skip("iocsearcher not installed")
        result = daemon.analyze_iocsearcher(
            "Visit http://example.com for details", "test"
        )
        # Returns None if no hits, or dict with iocs_extended key
        assert result is None or ("iocs_extended" in result)

    def test_empty_text_returns_none(self, daemon):
        if not xspct.HAS_IOCSEARCHER:
            pytest.skip("iocsearcher not installed")
        result = daemon.analyze_iocsearcher("", "test")
        assert result is None


# ===========================================================================
# UNIT TESTS — analyze_archive
# ===========================================================================
