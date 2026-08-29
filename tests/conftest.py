# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""
Pytest configuration for the xspct_scan test suite.

Provides:
  - session-scoped logging setup
  - FIXTURES_DIR / OLE_FILE / RTF_FILE / PASSWD_FILE constants
  - reset_global_state / client / auth_client / daemon fixtures
  - synthetic byte-level fixtures (PDF_CLEAN, HTML_MALICIOUS, OOXML_DATA, ...)
    and helpers (_form, _keywords, _make_png, _make_lnk, _metadata_form, ...)
    shared across the per-analyzer test modules

CLI options:
  --oletools-testdata PATH
      Path to the oletools tests/test-data directory.
      When given, OLE_FILE and RTF_FILE are resolved from that tree instead
      of the local tests/fixtures/ copies.
      Example:
          pytest --oletools-testdata /home/cr/git/oletools/tests/test-data
"""

import io
import json
import struct
import zipfile
from pathlib import Path

import aiohttp
import pytest

import xspct_scan.daemon as xspct

# ---------------------------------------------------------------------------
# Logging — configure once for the whole test session
# ---------------------------------------------------------------------------
xspct.configure_logging()

# ---------------------------------------------------------------------------
# Fixture file locations (populated by pytest_configure below)
# ---------------------------------------------------------------------------
FIXTURES_DIR = Path(__file__).parent / "fixtures"
OLE_FILE: str = ""
RTF_FILE: str = ""
PASSWD_FILE: str = ""

# Generated fixtures (created by tests/create_fixtures.py)
PDF_JS_FILE: str = str(FIXTURES_DIR / "pdf_javascript.pdf")
PDF_EMBEDDED_FILE: str = str(FIXTURES_DIR / "pdf_embedded.pdf")
PDF_URI_FILE: str = str(FIXTURES_DIR / "pdf_uri.pdf")
HTML_PHISHING_FILE: str = str(FIXTURES_DIR / "html_phishing.html")
ARCHIVE_MIXED_FILE: str = str(FIXTURES_DIR / "archive_mixed.zip")
EML_FILE: str = str(FIXTURES_DIR / "email_with_attachment.eml")
QR_FILE: str = str(FIXTURES_DIR / "qr_code.png")


def pytest_addoption(parser):
    parser.addoption(
        "--oletools-testdata",
        metavar="PATH",
        default=None,
        help="Path to oletools tests/test-data directory (overrides local fixture copies)",
    )


def pytest_configure(config):
    global OLE_FILE, RTF_FILE, PASSWD_FILE
    td = config.getoption("--oletools-testdata", default=None)
    if td:
        base = Path(td)
        OLE_FILE = str(base / "encrypted" / "autostart-encrypt-standardpassword.xls")
        RTF_FILE = str(base / "msodde" / "RTF-Spec-1.7.rtf")
    else:
        OLE_FILE = str(FIXTURES_DIR / "autostart-encrypt-standardpassword.xls")
        RTF_FILE = str(FIXTURES_DIR / "RTF-Spec-1.7.rtf")
    PASSWD_FILE = str(FIXTURES_DIR / "passwords.txt")


try:
    import pymupdf as _pymupdf

    _HAS_PYMUPDF = True
except ImportError:
    _pymupdf = None
    _HAS_PYMUPDF = False


try:
    import msgpack as _msgpack_test  # noqa: F401  # re-exported for other test modules

    _HAS_MSGPACK_TEST = True
except ImportError:
    _msgpack_test = None
    _HAS_MSGPACK_TEST = False


try:
    import zstandard as _zstd_test

    _HAS_ZSTD_TEST = True
except ImportError:
    _zstd_test = None
    _HAS_ZSTD_TEST = False


PDF_CLEAN = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
    b"xref\n0 1\n0000000000 65535 f \n"
    b"trailer\n<< /Size 1 >>\n"
    b"startxref\n9\n%%EOF\n"
)


PDF_ALL_MARKERS = (
    b"%PDF-1.4\n"
    b"/JS /JavaScript /OpenAction /Launch /EmbeddedFiles /Encrypt /XFA\n"
    b"%%EOF\n"
)


PDF_WITH_URI = b"%PDF-1.4\n/URI (https://malware.example.com/stage2)\n%%EOF"


_PDF_ENC_PASSWORD = "TestPwd42"


def _make_encrypted_pdf(user_pw: str) -> bytes:
    """Return a minimal AES-256-encrypted PDF protected by *user_pw*."""
    if not _HAS_PYMUPDF:
        return b""  # tests that need this are skipped via _HAS_PYMUPDF guard
    doc = _pymupdf.open()
    page = doc.new_page()
    page.insert_text((50, 50), "Encrypted test document")
    buf = doc.tobytes(
        encryption=_pymupdf.PDF_ENCRYPT_AES_256,
        owner_pw="owner",
        user_pw=user_pw,
    )
    doc.close()
    return buf


PDF_ENCRYPTED: bytes = _make_encrypted_pdf(_PDF_ENC_PASSWORD) if _HAS_PYMUPDF else b""


HTML_CLEAN = (
    b"<html><body><p>Hello world. Visit https://example.com for more.</p></body></html>"
)


HTML_MALICIOUS = (
    b"<html><head>"
    b'<meta http-equiv="refresh" content="0;url=http://evil.example.com">'
    b"</head><body>"
    b"<script>"
    b'eval(atob("YWxlcnQoMSk="));'
    b'document.write("<b>");'
    b'unescape("%3Cscript%3E");'
    b'atob("dGVzdA==");'
    b"String.fromCharCode(60);"
    b"</script>"
    b'<form action="http://phishing.example.com"><input type="password"></form>'
    b'<iframe src="http://hidden.example.com"></iframe>'
    b"</body></html>"
)


HTML_NO_TAGS = b"Just some plain text without any angle brackets at all."


def _make_ooxml() -> bytes:
    """Minimal valid OOXML (docx) zip with word/document.xml."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            "</Types>",
        )
        z.writestr(
            "word/document.xml",
            '<?xml version="1.0"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            "<w:body><w:p><w:r><w:t>Hello from OOXML test document</w:t></w:r></w:p></w:body>"
            "</w:document>",
        )
    return buf.getvalue()


OOXML_DATA = _make_ooxml()


def _form(data: bytes, filename: str, **extra_fields) -> aiohttp.FormData:
    """Build a multipart form with a 'doc' part and optional extra fields."""
    form = aiohttp.FormData()
    form.add_field("doc", data, filename=filename)
    for name, value in extra_fields.items():
        form.add_field(name, value)
    return form


def _keywords(hits):
    return {h["keyword"] for h in hits}


def _zstd_compress(data: bytes) -> bytes:
    return _zstd_test.ZstdCompressor().compress(data)


def _zstd_stream_decompress(data: bytes) -> bytes:
    dctx = _zstd_test.ZstdDecompressor()
    with dctx.stream_reader(io.BytesIO(data)) as reader:
        return reader.read()


@pytest.fixture(autouse=True)
def reset_global_state():
    """Reset module-level mutable state before and after every test."""
    saved_keys = list(xspct.config["xspct_api_key"])
    saved_fail = xspct.config["xspct_api_key_verify_fail"]
    saved_stats = dict(xspct.stats)
    saved_pw_file = xspct.config["xspct_password_file"]
    saved_stats_en = xspct.config["xspct_stats_enabled"]
    saved_ocr_preload = xspct.config["xspct_analyzers"]["image"][
        "ocr_preload_at_startup"
    ]

    xspct.config["xspct_api_key"] = []
    xspct.config["xspct_api_key_verify_fail"] = True
    xspct.config["xspct_password_file"] = PASSWD_FILE
    xspct.config["xspct_stats_enabled"] = False  # no background tasks in tests
    # Don't block every test's daemon.setup() on an EasyOCR model load/download;
    # tests that exercise OCR call analyze_image directly (lazy-init path).
    xspct.config["xspct_analyzers"]["image"]["ocr_preload_at_startup"] = False
    for k, v in xspct.stats.items():
        xspct.stats[k] = {} if isinstance(v, dict) else 0

    yield

    xspct.config["xspct_api_key"] = saved_keys
    xspct.config["xspct_api_key_verify_fail"] = saved_fail
    xspct.config["xspct_password_file"] = saved_pw_file
    xspct.config["xspct_stats_enabled"] = saved_stats_en
    xspct.config["xspct_analyzers"]["image"]["ocr_preload_at_startup"] = (
        saved_ocr_preload
    )
    for k, val in saved_stats.items():
        xspct.stats[k] = val


@pytest.fixture
async def client(aiohttp_client):
    """Full daemon TestClient with no API key required."""
    app = await xspct.make_app()
    return await aiohttp_client(app)


@pytest.fixture
async def auth_client(aiohttp_client):
    """Full daemon TestClient with API key enforcement."""
    xspct.config["xspct_api_key"] = ["test-secret-key"]
    xspct.config["xspct_api_key_verify_fail"] = True
    app = await xspct.make_app()
    return await aiohttp_client(app)


@pytest.fixture
def daemon():
    """Bare InspectorDaemon with a small, known password list."""
    d = xspct.InspectorDaemon()
    d.passwords = ["VelvetSweatshop", "test123", "123456", "password"]
    return d


# ===========================================================================
# UNIT TESTS
# ===========================================================================


def _make_lnk(
    target="", arguments="", working_dir="", icon_location="", description=""
):
    """Build a minimal, valid Windows shortcut (.lnk) file for testing.

    Only the ShellLinkHeader + StringData sections are populated (no
    LinkTargetIDList, no LinkInfo) — sufficient for LnkParse3 to expose
    relative_path()/command_line_arguments()/working_directory()/
    icon_location()/description() via `string_data`.
    """
    flags = 0x80  # IsUnicode
    if description:
        flags |= 0x04  # HasName
    if target:
        flags |= 0x08  # HasRelativePath
    if working_dir:
        flags |= 0x10  # HasWorkingDir
    if arguments:
        flags |= 0x20  # HasArguments
    if icon_location:
        flags |= 0x40  # HasIconLocation

    clsid = bytes(
        [
            0x01,
            0x14,
            0x02,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0xC0,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x46,
        ]
    )
    header = struct.pack("<I", 76) + clsid
    header += struct.pack("<I", flags)
    header += struct.pack("<I", 0x20)  # FILE_ATTRIBUTE_ARCHIVE
    header += b"\x00" * 8 * 3  # creation/access/write FILETIMEs
    header += struct.pack("<I", 0)  # target file size
    header += struct.pack("<i", 0)  # icon index
    header += struct.pack("<I", 1)  # show command (SW_SHOWNORMAL)
    header += b"\x00" * 2  # hotkey
    header += b"\x00" * 2  # reserved1
    header += b"\x00" * 4  # reserved2
    header += b"\x00" * 4  # reserved3
    assert len(header) == 76

    def _sd(s, limit=False):
        count = min(len(s), 260) if limit else len(s)
        return struct.pack("<H", count) + s[:count].encode("utf-16-le")

    body = b""
    if description:
        body += _sd(description, limit=True)
    if target:
        body += _sd(target, limit=True)
    if working_dir:
        body += _sd(working_dir, limit=True)
    if arguments:
        body += _sd(arguments)
    if icon_location:
        body += _sd(icon_location)

    return header + body + b"\x00\x00\x00\x00"  # empty terminal ExtraData block


try:
    from PIL import Image as _TestPIL

    _HAS_PIL_FOR_TESTS = True
except ImportError:
    _TestPIL = None
    _HAS_PIL_FOR_TESTS = False


def _make_png(width: int = 50, height: int = 50, color: str = "white") -> bytes:
    """Create a minimal in-memory PNG for testing."""
    buf = io.BytesIO()
    img = _TestPIL.new("RGB", (width, height), color=color)
    img.save(buf, format="PNG")
    return buf.getvalue()


def _metadata_form(
    filedata: bytes,
    filename: str,
    metadata: object,
    *,
    metadata_content_type: "str | None" = "application/json",
) -> aiohttp.FormData:
    """Build a multipart form with "metadata" + "file" parts."""
    form = aiohttp.FormData()
    if metadata_content_type in ("application/x-msgpack", "application/msgpack"):
        raw_metadata = _msgpack_test.packb(metadata, use_bin_type=True)
    else:
        raw_metadata = json.dumps(metadata).encode()
    if metadata_content_type:
        form.add_field(
            "metadata",
            io.BytesIO(raw_metadata),
            content_type=metadata_content_type,
        )
    else:
        form.add_field("metadata", io.BytesIO(raw_metadata))
    form.add_field("file", filedata, filename=filename)
    return form
