# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""
xspct-scan Daemon
=================
Async HTTP service for analyzing Office/PDF/HTML documents for malware indicators.

Public API
----------
    load_config(path)       -- load and merge a YAML config file into `config`
    configure_logging()     -- configure the 'xspct-scan' logger from current `config`
    make_app()              -- coroutine returning a configured aiohttp.web.Application
    config                  -- module-level dict with current configuration
    stats                   -- module-level dict with runtime counters
    InspectorDaemon         -- the analysis engine class
"""

import asyncio
import concurrent.futures
import contextvars
import hashlib
import hmac
import io
import json
import logging
import math
import os
import re
import secrets
import sys
import time
import timeit
import urllib.parse
import zipfile
from collections import OrderedDict

import yaml
from aiohttp import web

# ---------------------------------------------------------------------------
# Schema version exposed in every v2 report
# ---------------------------------------------------------------------------
_REPORT_SCHEMA_VERSION = "2.0"
# Derived from pyproject.toml via importlib.metadata — do not hardcode here.
from xspct_scan import __version__ as _ENGINE_VERSION  # noqa: E402

# Maximum upload size enforced by make_app() and reported via /v1/capabilities.
MAX_UPLOAD_BYTES: int = 50 * 1024 * 1024  # 50 MB

# Default scan timeout (seconds) for the ``timeout`` query parameter.
DEFAULT_SCAN_TIMEOUT: int = 10

# ---------------------------------------------------------------------------
# MIME-routing tables consumed by get_detected_type() and build_capabilities()
# ---------------------------------------------------------------------------
#: Per-type routing metadata.  Each entry holds:
#:   mime_exact     – exact MIME strings for this type.
#:   mime_prefixes  – MIME prefix strings (startswith check).
#:   mime_fragments – substring fragments matched against the MIME string;
#:                    also rendered as ``fragment*`` glob patterns in the
#:                    capabilities response.
#:   extensions     – lower-case filename extensions (with leading dot).
#:   magic_keywords – substrings matched against the libmagic description.
TYPE_ROUTING: "dict[str, dict]" = {
    "pdf": {
        "mime_exact": ("application/pdf",),
        "mime_prefixes": (),
        # 'pdf' is a router-only substring, not a glob-prefix fragment;
        # keep mime_fragments empty so capabilities.mime_types.patterns stays clean.
        "mime_fragments": (),
        "extensions": (".pdf",),
        "magic_keywords": ("pdf",),
    },
    "html": {
        "mime_exact": ("text/html", "application/xhtml+xml", "image/svg+xml"),
        "mime_prefixes": (),
        # same reasoning as pdf above — 'html' is a substring check, not a prefix glob.
        "mime_fragments": (),
        "extensions": (".html", ".htm", ".xhtml", ".svg"),
        "magic_keywords": ("html",),
    },
    "office": {
        # text/rtf and application/rtf are exact RTF MIME types; additional
        # RTF detection happens via 'rtf' substring and magic-byte check.
        "mime_exact": ("text/rtf", "application/rtf"),
        "mime_prefixes": (),
        "mime_fragments": (
            "application/msword",
            "application/vnd.ms-",
            "application/vnd.openxmlformats",
            "application/vnd.oasis.opendocument",
        ),
        "extensions": (
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".xlsm",
            ".xlsb",
            ".ppt",
            ".pptx",
            ".odt",
            ".ods",
            ".odp",
            ".odg",
            ".odf",
        ),
        "magic_keywords": ("composite document", "ole", "compound", "cdfv2"),
    },
    "image": {
        "mime_exact": (),
        "mime_prefixes": ("image/",),
        "mime_fragments": (),
        "extensions": (
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".bmp",
            ".tiff",
            ".tif",
            ".webp",
            ".ico",
        ),
        "magic_keywords": (),
    },
    "archive": {
        # message/rfc822 and application/vnd.ms-outlook are the mail MIMEs
        # that must be routed to the archive analyzer (sflock2 unpacks them).
        "mime_exact": (
            "message/rfc822",
            "application/vnd.ms-outlook",
            "application/zip",
            "application/x-7z-compressed",
            "application/x-tar",
            "application/gzip",
            "application/x-gzip",
            "application/x-bzip2",
            "application/x-xz",
            "application/x-rar-compressed",
            "application/vnd.rar",
            "application/x-rar",
            "application/x-cab",
            "application/vnd.ms-cab-compressed",
            "application/x-ace",
            "application/x-lzh",
            "application/x-lzh-compressed",
            "application/x-iso9660-image",
            "application/x-lzip",
        ),
        "mime_prefixes": (),
        "mime_fragments": (),
        "extensions": (
            ".zip",
            ".7z",
            ".tar",
            ".gz",
            ".bz2",
            ".xz",
            ".rar",
            ".tgz",
            ".tbz2",
            ".cab",
            ".ace",
            ".lzh",
            ".lha",
            ".iso",
            ".lz",
            ".zpaq",
            ".msg",
            ".eml",
            ".mso",
        ),
        "magic_keywords": ("zip archive", "7-zip", "rar archive", "tar archive"),
    },
    "text": {
        "mime_exact": (),
        "mime_prefixes": ("text/",),
        "mime_fragments": (),
        "extensions": (
            ".txt",
            ".csv",
            ".log",
            ".md",
            ".rst",
            ".ini",
            ".cfg",
            ".conf",
            ".sh",
            ".bash",
            ".zsh",
            ".fish",
            ".py",
            ".rb",
            ".pl",
            ".php",
            ".js",
            ".ts",
            ".jsx",
            ".tsx",
            ".json",
            ".xml",
            ".yaml",
            ".yml",
            ".toml",
            ".bat",
            ".ps1",
            ".vbs",
            ".sql",
        ),
        "magic_keywords": ("ascii", "utf-8", "unicode"),
    },
}

# Rspamd-compatible attachment digest key.
# Rspamd computes keyed BLAKE2b-512 over decoded MIME-part content, keyed
# with the 64-byte BLAKE2b hash of the literal string b"rspamd".
# (see rspamd/src/libmime/mime_parser.c, Blake2b applied to string 'rspamd')
_RSPAMD_BLAKE2_KEY = hashlib.blake2b(b"rspamd").digest()  # 64 bytes, computed once


def _rspamd_digest(data: bytes) -> str:
    """Return the Rspamd-compatible keyed BLAKE2b-512 digest of *data*.

    This matches the ``part->digest`` value Rspamd stores for every decoded
    MIME part, enabling direct correlation between Rspamd scan tasks and
    xspct-scan reports.

    Returns:
        128-character lowercase hex string.
    """
    return hashlib.blake2b(data, key=_RSPAMD_BLAKE2_KEY).hexdigest()


def _normalize_pdf_date(date_str: str) -> "str | None":
    """Convert a PDF date string to ISO-8601.

    Handles the ``D:YYYYMMDDHHmmSSOHH'mm'`` format produced by Acrobat and
    most PDF generators.  Returns the input unchanged when the pattern does
    not match, and ``None`` when *date_str* is empty.

    Examples::

        "D:20260430041451Z"  →  "2026-04-30T04:14:51Z"
        "D:20260430041451+02'00'"  →  "2026-04-30T04:14:51+02:00"
    """
    if not date_str:
        return None
    s = date_str.strip()
    if s.startswith("D:"):
        s = s[2:]
    m = re.match(
        r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(Z|[+-]\d{2}\'?\d{2}\'?)?",
        s,
    )
    if not m:
        return date_str or None
    y, mo, d, h, mi, sec = m.groups()[:6]
    tz = m.group(7) or "Z"
    if tz == "Z":
        return f"{y}-{mo}-{d}T{h}:{mi}:{sec}Z"
    sign = tz[0]
    digits = re.sub(r"[^0-9]", "", tz[1:])
    if len(digits) >= 4:
        return f"{y}-{mo}-{d}T{h}:{mi}:{sec}{sign}{digits[:2]}:{digits[2:4]}"
    return f"{y}-{mo}-{d}T{h}:{mi}:{sec}{tz}"


try:
    import olefile as _olefile

    HAS_OLEFILE = True
except ImportError:
    _olefile = None  # type: ignore[assignment]
    HAS_OLEFILE = False

try:
    import magic as _magic

    HAS_MAGIC = True
except ImportError:
    _magic = None  # type: ignore[assignment]
    HAS_MAGIC = False

try:
    import msoffcrypto as _msoffcrypto

    HAS_MSOFFCRYPTO = True
except ImportError:
    _msoffcrypto = None  # type: ignore[assignment]
    HAS_MSOFFCRYPTO = False

try:
    from oletools.olevba import VBA_Parser as _VBA_Parser
    from oletools.rtfobj import RtfObjParser as _RtfObjParser
    from oletools.rtfobj import RtfParser as _RtfParser

    HAS_OLETOOLS = True
except ImportError:
    _VBA_Parser = None  # type: ignore[assignment,misc]
    _RtfObjParser = None  # type: ignore[assignment]
    _RtfParser = object  # fallback base so TextExtractorRtf can still be defined
    HAS_OLETOOLS = False

try:
    import redis.asyncio as redis

    HAS_REDIS = True
except ImportError:
    try:
        import aioredis as redis  # type: ignore[no-redef]

        HAS_REDIS = True
    except ImportError:
        HAS_REDIS = False

try:
    import fitz  # PyMuPDF

    HAS_PYMUPDF = True
except ImportError:
    HAS_PYMUPDF = False

try:
    import jsbeautifier as _jsbeautifier

    HAS_JSBEAUTIFIER = True
except ImportError:
    HAS_JSBEAUTIFIER = False

try:
    import quickjs as _quickjs

    HAS_QUICKJS = True
except ImportError:
    HAS_QUICKJS = False

try:
    import tree_sitter_javascript as _ts_js
    from tree_sitter import (
        Language as _TSLanguage,
    )
    from tree_sitter import (
        Parser as _TSParser,
    )
    from tree_sitter import (
        Query as _TSQuery,
    )
    from tree_sitter import (
        QueryCursor as _TSQueryCursor,
    )

    _TS_JS_LANGUAGE = _TSLanguage(_ts_js.language())
    _TS_JS_PARSER = _TSParser(_TS_JS_LANGUAGE)
    HAS_TREESITTER = True
except Exception:
    HAS_TREESITTER = False

try:
    import clamd as _clamd

    HAS_CLAMD = True
except ImportError:
    HAS_CLAMD = False

try:
    import pytesseract as _pytesseract
    from PIL import Image as _PILImage

    HAS_OCR = True
except ImportError:
    HAS_OCR = False

try:
    import easyocr as _easyocr

    HAS_EASYOCR = True
except ImportError:
    HAS_EASYOCR = False

try:
    from pyzbar import pyzbar as _pyzbar

    HAS_PYZBAR = True
except ImportError:
    HAS_PYZBAR = False

try:
    import pydantic as _pydantic

    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False

try:
    import yara as _yara

    HAS_YARA = True
    HAS_YARA_HYPERSCAN = getattr(_yara, "HAVE_HYPERSCAN", False)
except ImportError:
    _yara = None  # type: ignore[assignment]
    HAS_YARA = False
    HAS_YARA_HYPERSCAN = False

try:
    import yara_x as _yara_x  # yara-x Rust rewrite

    HAS_YARA_X = True
except ImportError:
    _yara_x = None  # type: ignore[assignment]
    HAS_YARA_X = False

try:
    from iocsearcher.searcher import Searcher as _IocSearcher

    _IOCSEARCHER: "_IocSearcher | None" = _IocSearcher()
    HAS_IOCSEARCHER = True
except Exception:
    _IOCSEARCHER = None
    HAS_IOCSEARCHER = False

try:
    import tldextract as _tldextract

    # Bundled PSL only — no runtime network requests.
    _TLDEXT = _tldextract.TLDExtract(suffix_list_urls=())
    HAS_TLDEXTRACT = True
except ImportError:
    _TLDEXT = None
    HAS_TLDEXTRACT = False

try:
    from odfdo import Document as _OdfDocument

    HAS_ODFDO = True
except ImportError:
    _OdfDocument = None  # type: ignore[assignment,misc]
    HAS_ODFDO = False

try:
    import importlib.util as _ilu

    _vendor_dir = os.path.join(os.path.dirname(__file__), "vendor")
    _pdfid_path = os.path.join(_vendor_dir, "pdfid.py")
    if os.path.isfile(_pdfid_path):
        _spec = _ilu.spec_from_file_location("_vendored_pdfid", _pdfid_path)
        _vendored_pdfid = _ilu.module_from_spec(_spec)  # type: ignore[arg-type]
        _spec.loader.exec_module(_vendored_pdfid)  # type: ignore[union-attr]
        HAS_PDFID = True
    else:
        _vendored_pdfid = None
        HAS_PDFID = False
except Exception:
    _vendored_pdfid = None
    HAS_PDFID = False

try:
    import sflock as _sflock

    HAS_SFLOCK = True
except ImportError:
    _sflock = None  # type: ignore[assignment]
    HAS_SFLOCK = False

try:
    import msgpack as _msgpack

    HAS_MSGPACK = True
except ImportError:
    _msgpack = None  # type: ignore[assignment]
    HAS_MSGPACK = False

try:
    import cbor2 as _cbor2

    HAS_CBOR2 = True
except ImportError:
    _cbor2 = None  # type: ignore[assignment]
    HAS_CBOR2 = False

try:
    import zstandard as _zstd

    HAS_ZSTD = True
except ImportError:
    _zstd = None  # type: ignore[assignment]
    HAS_ZSTD = False

# Zstandard frame magic (little-endian 0xFD2FB528)
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_MAX_ZSTD_DECOMPRESSED_BYTES = 64 * 1024 * 1024


class _ClientRequestError(Exception):
    """Raised when the client sends a malformed or oversized request payload."""

    def __init__(self, message: str, *, status: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


# ---------------------------------------------------------------------------
# Per-request timer (ContextVar — isolated per async task)
# ---------------------------------------------------------------------------
_time_start_var: contextvars.ContextVar[float] = contextvars.ContextVar(
    "time_start", default=0.0
)


class _LazyTimer:
    """Deferred timer whose __str__ is only evaluated when the log record fires."""

    __slots__ = ()

    def __str__(self) -> str:
        return str(round(timeit.default_timer() - _time_start_var.get(), 5))

    __repr__ = __str__


_LAZY_TIMER = _LazyTimer()


def timer(action: str = "") -> object:
    """Start or read a per-request wall-clock timer.

    A :class:`contextvars.ContextVar` keeps one start timestamp per
    asyncio task so concurrent requests don't interfere with each other.

    Args:
        action: Pass ``'start'`` to snapshot the current time; omit (or
            pass any other value) to get the elapsed-time token.

    Returns:
        ``0`` when starting the timer, otherwise a
        :class:`_LazyTimer` whose :meth:`__str__` returns the elapsed
        seconds as a string (evaluated lazily at log-record format time).
    """
    if action == "start":
        _time_start_var.set(timeit.default_timer())
        return 0
    return _LAZY_TIMER


# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------
config: dict = {
    "xspct_listen_address": ["0.0.0.0"],
    "xspct_listen_port": 8080,
    "xspct_listen_backlog": 256,
    "xspct_log_level": 20,
    "xspct_log_prefix": "xspct-scan",
    "xspct_api_header": "X-Api-Key",
    "xspct_api_key": [],
    "xspct_api_key_verify_fail": True,
    "xspct_admin_api_key": [],
    "xspct_rspamd_header": "X-Rspamd-ID",
    "xspct_tls": {
        "tls_enabled": False,
        "tls_cert": "",
        "tls_key": "",
    },
    "xspct_redis_cache": {
        "enabled": False,
        "host": "localhost",
        "port": 6379,
        "user": "",
        "password": "",
        "prefix": "xspct:",
        "expire": 3600,
        "max_errors": 3,
    },
    "xspct_clamav": {
        "enabled": False,
        "socket": "/var/run/clamav/clamd.ctl",  # non-empty → Unix socket; else TCP
        "host": "127.0.0.1",
        "port": 3310,
        "timeout": 60,  # per-scan timeout in seconds
        "max_size": 26214400,  # 25 MB — skip larger files
        "scan_members": True,  # also scan archive members individually
    },
    "xspct_stats_enabled": True,
    "xspct_stats_interval": 60,
    "xspct_password_file": "10k-most-common.txt",
    # Per-analyzer enable/disable flags and analyzer-specific settings.
    # Each key is an analyzer name; 'enabled' controls whether it runs.
    "xspct_analyzers": {
        "pdf": {"enabled": True},
        "html": {"enabled": True},
        "office": {"enabled": True},
        "yara": {"enabled": False, "rules_path": ""},
        "yara_x": {"enabled": False, "rules_path": ""},
        "image": {
            "enabled": True,
            # --- OCR exclusion gates ---
            # Set to 0 to disable a gate; use force_analyzers to override per-request.
            "ocr_max_bytes": 2
            * 1024
            * 1024,  # skip OCR when file > 2 MB (camera JPEGs)
            "ocr_max_pixels": 4_000_000,  # skip OCR when W×H > 4 MP
            "ocr_skip_camera": True,  # skip OCR when EXIF Make/Model present
            # When False (default), raw byte-level text extraction is skipped for
            # image files, preventing EXIF/XMP namespace fragments from feeding
            # the IOC extractors and producing noisy results.
            "raw_text_fallback": False,
        },
        "archive": {"enabled": True},
        "iocs": {"enabled": True},
        "javascript": {"enabled": True, "quickjs": False},
        "text": {"enabled": True},
    },
    # When True, 'text_preview' (a list of {source, text} truncated excerpts,
    # one per extractor) is included in the report. Enabled by default.
    "xspct_include_text_preview": True,
    # When True, 'text_full' (a list of {source, text} segments, one per
    # extractor, at full length) is included in the report.
    "xspct_include_text_full": False,
    # Maximum characters per 'text_preview' segment (the short excerpt sent in
    # every response). Independent of xspct_text_max_length.
    "xspct_text_preview_length": 2000,
    # Maximum characters per extracted-text segment, used by iocsearcher and for
    # the 'text_full' report field.
    "xspct_text_max_length": 50000,
    # Maximum archive recursion depth (0 = no extraction).
    "xspct_archive_max_depth": 2,
    # Maximum total bytes extracted from a single archive (default 50 MB).
    "xspct_archive_max_size": 52428800,
    # When True, fall back to stdlib zipfile/py7zr when sflock2 is unavailable
    # or raises an error. Disabled by default for security (no sandbox).
    "xspct_archive_stdlib_fallback": False,
    # When True, partial (timeout) reports are also stored in the cache.
    "xspct_cache_partial": False,
    # Concurrency limits for the two-tier scan lifecycle.
    # Foreground slots: requests actively waiting for a Rspamd/client response.
    # Background slots: scans that have already returned 202 and continue running.
    # Total concurrent analyses = foreground + background.
    "xspct_foreground_slots": 16,
    "xspct_background_slots": 4,
    # Domain suffix exclusion list for IOC URL/domain extraction.
    # Any URL whose hostname ends with one of these suffixes (or matches exactly)
    # is silently dropped from 'urls' and 'domains' in every report.
    # Useful for filtering out W3C schema references, CDN boilerplate, etc.
    "xspct_ioc_url_exclude_domains": [
        "w3.org",
        "schema.org",
        "schemas.microsoft.com",
        "schemas.openxmlformats.org",
        "purl.org",
        "dublincore.org",
        "xmlsoap.org",
        "ns.adobe.com",
        "ns.google.com",  # XMP/EXIF namespace URIs embedded in JPEG/image metadata
        "creativecommons.org",
        "opengis.net",
        "xhtml1-transitional.dtd",
    ],
}
"""Module-level configuration dictionary.

Populated by :func:`load_config`. Keys mirror the YAML configuration file;
see the :doc:`configuration` page for the full reference.
"""

# ---------------------------------------------------------------------------
# Runtime stats
# ---------------------------------------------------------------------------
stats: dict = {
    "requests_total": 0,
    "requests_finished": 0,
    "requests_timeout": 0,
    "redis_hits": 0,
    "redis_misses": 0,
    "redis_errors": 0,
    # Two-tier concurrency stats
    "foreground_overloaded": 0,  # requests rejected because fg slots were full
    "background_rejected": 0,  # timed-out scans dropped (no bg slot available)
    "background_completed": 0,  # background scans that finished successfully
    "background_errors": 0,  # background scans that raised an exception
    # ClamAV engine stats
    "clamav_clean": 0,
    "clamav_infected": 0,
    "clamav_errors": 0,
    "clamav_timeouts": 0,
    # Per-analyzer timing/hit stats — populated lazily on first call.
    # Each entry: {calls, hits, ms_total, ms_min, ms_max}
    "analyzer_stats": {},
}
"""Module-level runtime counters.

All values are integers incremented by the request handlers.
Exposed as Prometheus metrics via ``GET /v1/metrics``.
"""

# ---------------------------------------------------------------------------
# Logger — NullHandler so we don't warn when used as a library.
# Call configure_logging() to attach a real handler.
# ---------------------------------------------------------------------------
logger = logging.getLogger("xspct-scan")
logger.addHandler(logging.NullHandler())


def _is_analyzer_hit(name: str, result: "dict | None") -> bool:
    """Return True when *result* contains at least one actionable finding."""
    if not result:
        return False
    if result.get("analyses"):
        return True
    if result.get("yara_matches"):
        return True
    if name == "clamav" and result.get("clamav", {}).get("status") == "infected":
        return True
    return False


def _record_analyzer_stats(name: str, elapsed_ms: int, result: "dict | None") -> None:
    """Update the per-analyzer timing/hit counters in :data:`stats`."""
    entry = stats["analyzer_stats"].setdefault(
        name,
        {
            "calls": 0,
            "hits": 0,
            "ms_total": 0,
            "ms_min": None,
            "ms_max": 0,
        },
    )
    entry["calls"] += 1
    entry["ms_total"] += elapsed_ms
    entry["ms_min"] = (
        elapsed_ms if entry["ms_min"] is None else min(entry["ms_min"], elapsed_ms)
    )
    entry["ms_max"] = max(entry["ms_max"], elapsed_ms)
    if _is_analyzer_hit(name, result):
        entry["hits"] += 1


# ---------------------------------------------------------------------------
# Public init helpers
# ---------------------------------------------------------------------------


def load_config(path: "str | None" = None) -> None:
    """Load *path* (YAML) and deep-merge it into the module-level ``config`` dict.

    Sub-dicts ``xspct_tls`` and ``xspct_redis_cache`` are merged key-by-key so
    callers only need to specify the keys they want to override.

    Raises ``SystemExit(1)`` if the file is missing or contains invalid YAML.
    """
    if path is None:
        _normalise_api_key()
        _normalise_admin_key()
        return
    if not os.path.isfile(path):
        print(f"Config file not found: {path}", file=sys.stderr)
        sys.exit(1)
    try:
        with open(path) as fh:
            extra = yaml.safe_load(fh)
        if extra:
            for sub in ("xspct_tls", "xspct_redis_cache", "xspct_clamav"):
                if sub in extra:
                    merged = config[sub].copy()
                    merged.update(extra.pop(sub))
                    extra[sub] = merged
            # Two-level merge for xspct_analyzers: preserve defaults for
            # unmentioned analyzers and unmentioned keys within each analyzer.
            if "xspct_analyzers" in extra:
                merged_a: dict = {
                    k: v.copy() for k, v in config["xspct_analyzers"].items()
                }
                for name, override in (extra.pop("xspct_analyzers") or {}).items():
                    if name in merged_a:
                        merged_a[name].update(override or {})
                    else:
                        merged_a[name] = dict(override or {})
                extra["xspct_analyzers"] = merged_a
            config.update(extra)
    except yaml.YAMLError as exc:
        print(f"YAML error in {path}: {exc}", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"Cannot read {path}: {exc}", file=sys.stderr)
        sys.exit(1)
    _normalise_api_key()
    _normalise_admin_key()


def _normalise_api_key() -> None:
    key = config["xspct_api_key"]
    if isinstance(key, str):
        config["xspct_api_key"] = [key] if key else []


def _normalise_admin_key() -> None:
    key = config["xspct_admin_api_key"]
    if isinstance(key, str):
        config["xspct_admin_api_key"] = [key] if key else []


class _SessionLogFormatter(logging.Formatter):
    """Log formatter that places the session-ID token *before* the function name.

    Output format::

        prefix LEVEL <sid> funcName rest-of-message

    When the message does not start with a ``<hex>`` session ID (e.g. startup
    lines) the function name is still prepended::

        prefix LEVEL funcName rest-of-message
    """

    _SID_RE = re.compile(r"^(<[0-9a-f]{6,8}>)\s?")

    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        msg = record.getMessage()
        m = self._SID_RE.match(msg)
        if m:
            composed = f"{m.group(1)} {record.funcName} {msg[m.end() :]}"
        else:
            composed = f"{record.funcName} {msg}"
        saved_msg, saved_args = record.msg, record.args
        record.msg, record.args = composed, None
        result = super().format(record)
        record.msg, record.args = saved_msg, saved_args
        return result


def configure_logging() -> None:
    """Attach a ``StreamHandler`` to the *xspct-scan* logger using current ``config``.

    Safe to call multiple times; existing non-NullHandler handlers are removed
    first so reconfiguration works correctly.
    """
    logger.setLevel(int(config["xspct_log_level"]))
    # Remove any real handlers added by a previous call, keep NullHandler
    for h in list(logger.handlers):
        if not isinstance(h, logging.NullHandler):
            logger.removeHandler(h)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        _SessionLogFormatter(config["xspct_log_prefix"] + " %(levelname)s %(message)s")
    )
    logger.addHandler(handler)


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------


def generate_session_id() -> str:
    """Generate a short random hex string used as a per-request session ID.

    Returns:
        Six-character lowercase hex string.
    """
    return secrets.token_hex(3)


def make_session(request: web.Request, session_id: "str | None" = None) -> str:
    """Build a short session tag used as a log prefix for a single request.

    Combines a random session ID with the Rspamd correlation header value
    (if present) to make log lines traceable across systems.

    Args:
        request: The incoming aiohttp request.
        session_id: Optional pre-generated session ID; one is created if omitted.

    Returns:
        A bracketed tag such as ``<a3f2c1>`` or ``<a3f2c1-rspamd>``.
    """
    sid = session_id or generate_session_id()
    rspamd_id = (
        request.headers.get(config["xspct_rspamd_header"], "") if request else ""
    )
    if rspamd_id:
        return f"<{sid[:6]}-{rspamd_id[:6]}>"
    return f"<{sid[:6]}>"


# ---------------------------------------------------------------------------
# API key verification (timing-safe, multi-key)
# ---------------------------------------------------------------------------


def verify_api_key(s: str, request: web.Request) -> bool:
    """Check the API key supplied in the request header.

    Uses :func:`hmac.compare_digest` for all comparisons to prevent
    timing-based key enumeration. When multiple keys are configured
    all are checked regardless of which one matches.

    Args:
        s: Session tag for log messages.
        request: The incoming aiohttp request.

    Returns:
        ``True`` if authentication passes (including when auth is disabled),
        ``False`` when a key is required but the provided value is wrong.
    """
    keys = config["xspct_api_key"]
    if not keys:
        return True
    provided = str(request.headers.get(config["xspct_api_header"], "") or "")
    valid = False
    for k in keys:
        valid |= hmac.compare_digest(provided, str(k))
    if valid:
        logger.debug("%s - api key verification success", s)
        return True
    if not config["xspct_api_key_verify_fail"]:
        logger.debug("%s - api key failed but not fatal", s)
        return True
    logger.warning("%s - api key verification failed", s)
    return False


def verify_admin_key(s: str, request: web.Request) -> bool:
    """Check the admin API key supplied in ``X-Admin-Api-Key`` header.

    Uses :func:`hmac.compare_digest` for timing-safe comparison.
    Returns ``False`` when no admin keys are configured (admin endpoints
    are disabled) or when the supplied key does not match any configured key.

    Args:
        s: Session tag for log messages.
        request: The incoming aiohttp request.

    Returns:
        ``True`` only when at least one admin key is configured and the
        request supplies a matching value.
    """
    keys = config["xspct_admin_api_key"]
    if not keys:
        logger.warning(
            "%s - admin endpoint accessed but xspct_admin_api_key not configured", s
        )
        return False
    provided = str(request.headers.get("X-Admin-Api-Key", "") or "")
    valid = False
    for k in keys:
        valid |= hmac.compare_digest(provided, str(k))
    if valid:
        logger.debug("%s - admin key verification success", s)
        return True
    logger.warning("%s - admin key verification failed", s)
    return False


# ---------------------------------------------------------------------------
# RTF text extractor
# ---------------------------------------------------------------------------


class TextExtractorRtf(_RtfParser):
    """Extract plain text from an RTF document.

    Subclasses :class:`oletools.thirdparty.rtfparse.rtfparse.RtfParser`
    and collects all text tokens into a list for later retrieval.

    Args:
        data: Raw RTF bytes passed directly to the parent parser.
    """

    def __init__(self, data: bytes) -> None:
        """Initialise the parser and allocate the text accumulator.

        Args:
            data: Raw RTF bytes.
        """
        super().__init__(data)
        self.all_text: list[str] = []

    def text(self, matchobject, text) -> None:  # type: ignore[override]
        """Callback invoked by the RTF parser for each text token.

        Decodes *text* as ASCII (ignoring unrecognised bytes) and
        appends it to :attr:`all_text`.

        Args:
            matchobject: Regex match object provided by the parent parser.
            text: Raw bytes of the decoded RTF text token.
        """
        try:
            self.all_text.append(text.decode("ascii", errors="ignore"))
        except Exception:
            pass

    def get_text(self) -> str:
        """Parse the document and return all extracted text.

        Returns:
            A single string made up of all collected text tokens.
        """
        self.parse()
        return "".join(self.all_text)


# ---------------------------------------------------------------------------
# OpenAPI schema models (pydantic v2)
# ---------------------------------------------------------------------------
#
# These models serve two purposes:
#   1. Documentation: their JSON schema is embedded in the OpenAPI spec.
#   2. (optional) Runtime validation: not enforced automatically — handlers
#      produce dicts that match the schema; pydantic is used only for schema
#      generation so that the [openapi] extra is optional.
# ---------------------------------------------------------------------------

if HAS_PYDANTIC:
    from typing import Any, Optional

    class _AnalysisHit(_pydantic.BaseModel):
        type: str
        keyword: str
        description: str
        confidence: Optional[str] = None

    class _IocReport(_pydantic.BaseModel):
        urls: list[str] = []
        ips: list[str] = []
        domains: list[str] = []

    class _TextSegment(_pydantic.BaseModel):
        source: str
        module: Optional[str] = None
        text: str

    class _MetaInfo(_pydantic.BaseModel):
        script_name: str
        version: str
        type: str

    # ── v2 models ─────────────────────────────────────────────────────
    class _V2Engine(_pydantic.BaseModel):
        name: str
        version: str

    class _V2File(_pydantic.BaseModel):
        name: str
        sha256: str
        sha1: str
        rspamd_digest: str  # keyed BLAKE2b-512, Rspamd-compatible
        size: int
        mime: Optional[str] = None
        magic: Optional[str] = None
        type: str
        resolution: Optional[str] = None  # 'WxH' for image/video files

    class _V2AnalyzerInfo(_pydantic.BaseModel):
        completed: list[str] = []
        pending: list[str] = []
        timings_s: dict = _pydantic.Field(default_factory=dict)
        errors: Optional[dict] = None

    class _V2Scan(_pydantic.BaseModel):
        status: str
        duration_s: float
        cache_hit: bool = False
        analyzers: "_V2AnalyzerInfo" = _pydantic.Field(
            default_factory=lambda: _V2AnalyzerInfo()
        )

    class _V2Verdict(_pydantic.BaseModel):
        score: Optional[int] = None
        severity: str = "unknown"
        labels: list[str] = []
        summary: Optional[str] = None
        contributors: dict = _pydantic.Field(default_factory=dict)

    class _V2IocEntry(_pydantic.BaseModel):
        value: str
        source: str
        module: Optional[str] = None  # 'regex' | 'iocsearcher'
        confidence: str  # 'high' | 'medium' | 'low'
        defanged: Optional[str] = None
        context: Optional[str] = None

    class _V2Iocs(_pydantic.BaseModel):
        urls: list["_V2IocEntry"] = []
        domains: list["_V2IocEntry"] = []
        ips: list["_V2IocEntry"] = []
        emails: list["_V2IocEntry"] = []
        hashes: list["_V2IocEntry"] = []
        cves: list["_V2IocEntry"] = []
        wallets: list["_V2IocEntry"] = []
        onions: list["_V2IocEntry"] = []
        phones: list["_V2IocEntry"] = []

    class _V2Finding(_pydantic.BaseModel):
        type: str
        keyword: str
        description: str
        severity: str  # 'info' | 'low' | 'medium' | 'high' | 'critical'
        source: str
        confidence: Optional[str] = None

    class _V2ScanReport(_pydantic.BaseModel):
        """v2 scan report — the structure returned by ``/v1/scan``."""

        schema_version: str
        engine: "_V2Engine"
        file: "_V2File"
        scan: "_V2Scan"
        verdict: "_V2Verdict" = _pydantic.Field(default_factory=_V2Verdict)
        flags: dict = _pydantic.Field(default_factory=dict)
        iocs: "_V2Iocs" = _pydantic.Field(default_factory=_V2Iocs)
        findings: list["_V2Finding"] = []
        content: Optional[dict] = None
        document: Optional[dict] = None
        engines: Optional[dict] = None

    # ── (legacy model kept for internal OpenAPI spec generation only) ──
    class _ScanReport(_pydantic.BaseModel):
        filename: str
        file_hash: str
        file_type: Optional[str] = None
        file_description: Optional[str] = None
        detected_type: str
        has_macro: bool = False
        has_javascript: bool = False
        has_openaction: bool = False
        has_embedded_files: bool = False
        has_launch: bool = False
        has_forms: bool = False
        is_encrypted: bool = False
        decrypted: bool = False
        decryption_password: Optional[str] = None
        has_scripts: bool = False
        has_iframes: bool = False
        has_meta_refresh: bool = False
        analyses: list[_AnalysisHit] = []
        rtf_objects: list[Any] = []
        iocs: _IocReport = _pydantic.Field(default_factory=_IocReport)
        text_preview: list[_TextSegment] = []
        text_full: list[_TextSegment] = []
        meta_document: Optional[dict] = None
        meta: _MetaInfo
        analyzers_completed: list[str] = []
        analyzers_pending: list[str] = []
        yara_matches: list[dict] = []
        iocs_extended: dict = _pydantic.Field(default_factory=dict)
        pdfid_keywords: Optional[dict] = None
        pdfid_meta: Optional[dict] = None
        archive_files: list[dict] = []
        exif: dict = _pydantic.Field(default_factory=dict)

    class _ScanResponse(_pydantic.BaseModel):
        """Response body for ``POST /scan`` (finished)."""

        status: str  # 'finished'
        time_taken: float
        cache_hit: bool = False
        report: Optional[_ScanReport] = None
        # Scan report fields are inlined at the top level for finished responses.

    class _ProcessingResponse(_pydantic.BaseModel):
        """Response body for ``POST /scan`` (202 partial / timeout)."""

        status: str  # 'processing'
        file_hash: str
        message: str
        time_taken: float
        analyzers_completed: list[str] = []
        analyzers_pending: list[str] = []

    class _QueryResponse(_pydantic.BaseModel):
        """Response body for ``GET|POST /query``."""

        status: str  # 'finished' | 'processing' | 'not_found' | 'error'
        report: Optional[_ScanReport] = None
        error: Optional[str] = None

    class _ErrorResponse(_pydantic.BaseModel):
        error: str

    def _build_openapi_spec() -> dict:
        """Build and return the OpenAPI 3.0 spec dict."""
        schemas = {}
        for model in (
            _AnalysisHit,
            _IocReport,
            _TextSegment,
            _MetaInfo,
            _V2Engine,
            _V2File,
            _V2AnalyzerInfo,
            _V2Scan,
            _V2Verdict,
            _V2IocEntry,
            _V2Iocs,
            _V2Finding,
            _V2ScanReport,
            _ScanResponse,
            _ProcessingResponse,
            _QueryResponse,
            _ErrorResponse,
        ):
            s = model.model_json_schema()
            # pydantic embeds $defs for nested models — hoist them
            for k, v in s.pop("$defs", {}).items():
                schemas[k] = v
            schemas[model.__name__.lstrip("_")] = s

        def _ref(name: str) -> dict:
            return {"$ref": f"#/components/schemas/{name}"}

        spec: dict = {
            "openapi": "3.0.3",
            "info": {
                "title": "xspct-scan API",
                "version": _ENGINE_VERSION,
                "description": (
                    "HTTP API for scanning Office, PDF, and HTML files "
                    "for malware indicators."
                ),
            },
            "paths": {
                "/v1/scan": {
                    "post": {
                        "summary": "Submit a file for analysis",
                        "operationId": "scan",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "oneOf": [
                                            {
                                                "type": "object",
                                                "description": "Legacy shape",
                                                "properties": {
                                                    "doc": {
                                                        "type": "string",
                                                        "format": "binary",
                                                        "description": "File to analyse (legacy shape)",
                                                    },
                                                    "passwords": {
                                                        "type": "string",
                                                        "description": "Comma/newline-separated decryption passwords",
                                                    },
                                                    "file_mime": {"type": "string"},
                                                    "file_type": {"type": "string"},
                                                },
                                                "required": ["doc"],
                                            },
                                            {
                                                "type": "object",
                                                "description": "Structured shape",
                                                "properties": {
                                                    "file": {
                                                        "type": "string",
                                                        "format": "binary",
                                                        "description": "File to analyse (structured shape, paired with metadata)",
                                                    },
                                                    "metadata": {
                                                        "type": "string",
                                                        "format": "binary",
                                                        "description": (
                                                            "JSON or msgpack object: filename, "
                                                            "declared_content_type, detected_type, "
                                                            "rspamd_uid, queue_id, message_id, "
                                                            "passwords[], force_analyzers[], timeout_s. "
                                                            "Overrides query parameters when present. "
                                                            "rspamd_uid/queue_id/message_id are "
                                                            "echoed back in the response's request "
                                                            "block."
                                                        ),
                                                    },
                                                },
                                                "required": ["file", "metadata"],
                                            },
                                        ],
                                    },
                                },
                                "application/octet-stream": {
                                    "schema": {
                                        "type": "string",
                                        "format": "binary",
                                        "description": "Raw file bytes",
                                    },
                                },
                            },
                        },
                        "parameters": [
                            {
                                "in": "query",
                                "name": "timeout",
                                "schema": {"type": "number", "default": 10},
                                "description": "Max wait seconds before returning 202",
                            },
                            {
                                "in": "query",
                                "name": "rtf",
                                "schema": {"type": "boolean", "default": False},
                                "description": "Enable RTF object extraction",
                            },
                            {
                                "in": "query",
                                "name": "filename",
                                "schema": {"type": "string"},
                                "description": "Filename hint (octet-stream only)",
                            },
                        ],
                        "responses": {
                            "200": {
                                "description": "Analysis complete",
                                "content": {
                                    "application/json": {"schema": _ref("V2ScanReport")}
                                },
                            },
                            "202": {
                                "description": "Analysis in progress (partial report)",
                                "content": {
                                    "application/json": {
                                        "schema": _ref("ProcessingResponse")
                                    }
                                },
                            },
                            "400": {
                                "description": "Bad request",
                                "content": {
                                    "application/json": {
                                        "schema": _ref("ErrorResponse")
                                    }
                                },
                            },
                            "401": {"description": "Unauthorized"},
                            "415": {"description": "Unsupported Content-Type"},
                            "500": {"description": "Internal server error"},
                        },
                        "security": [{"ApiKeyAuth": []}],
                    },
                },
                "/v1/query": {
                    "get": {
                        "summary": "Poll scan result by file hash",
                        "operationId": "queryGet",
                        "parameters": [
                            {
                                "in": "query",
                                "name": "hash",
                                "required": True,
                                "schema": {"type": "string"},
                                "description": "SHA-256 hex digest",
                            },
                        ],
                        "responses": {
                            "200": {
                                "description": "Query result",
                                "content": {
                                    "application/json": {
                                        "schema": _ref("QueryResponse")
                                    }
                                },
                            },
                            "400": {"description": "No hash provided"},
                            "404": {"description": "Not found"},
                        },
                        "security": [{"ApiKeyAuth": []}],
                    },
                    "post": {
                        "summary": "Poll scan result by file hash (JSON body)",
                        "operationId": "queryPost",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"hash": {"type": "string"}},
                                        "required": ["hash"],
                                    }
                                }
                            },
                        },
                        "responses": {
                            "200": {
                                "description": "Query result",
                                "content": {
                                    "application/json": {
                                        "schema": _ref("QueryResponse")
                                    }
                                },
                            },
                        },
                        "security": [{"ApiKeyAuth": []}],
                    },
                },
                "/v1/metrics": {
                    "get": {
                        "summary": "Prometheus metrics",
                        "operationId": "metrics",
                        "responses": {
                            "200": {
                                "description": "Prometheus exposition text",
                                "content": {
                                    "text/plain": {"schema": {"type": "string"}}
                                },
                            },
                        },
                        "security": [{"ApiKeyAuth": []}],
                    },
                },
                "/v1/health": {
                    "get": {
                        "summary": "Health check",
                        "operationId": "health",
                        "responses": {
                            "200": {
                                "description": "OK",
                                "content": {
                                    "text/plain": {
                                        "schema": {"type": "string", "example": "OK"}
                                    }
                                },
                            }
                        },
                    },
                },
                "/v1/capabilities": {
                    "get": {
                        "summary": "Query active analyzers, MIME routing, and limits",
                        "operationId": "capabilities",
                        "responses": {
                            "200": {
                                "description": "Capabilities payload",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "engine": {"type": "object"},
                                                "limits": {"type": "object"},
                                                "response_formats": {
                                                    "type": "array",
                                                    "items": {"type": "string"},
                                                },
                                                "analyzers": {"type": "object"},
                                                "mime_types": {"type": "object"},
                                            },
                                        },
                                    },
                                },
                            },
                            "304": {"description": "Not Modified (ETag matched)"},
                            "401": {"description": "Unauthorized"},
                        },
                        "security": [{"ApiKeyAuth": []}],
                    },
                },
            },
            "components": {
                "schemas": schemas,
                "securitySchemes": {
                    "ApiKeyAuth": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "X-Api-Key",
                    },
                },
            },
        }
        return spec

    _OPENAPI_SPEC: "dict | None" = None

    def _get_openapi_spec() -> dict:
        global _OPENAPI_SPEC
        if _OPENAPI_SPEC is None:
            _OPENAPI_SPEC = _build_openapi_spec()
        return _OPENAPI_SPEC

else:

    def _get_openapi_spec() -> dict:  # type: ignore[misc]
        return {"error": "pydantic not installed; install xspct-scan[openapi]"}


# ---------------------------------------------------------------------------
# Partial report accumulator
# ---------------------------------------------------------------------------


class PartialReport:
    """Thread-safe accumulator for concurrent per-analyzer results.

    One instance is created per in-flight scan request.  Each analyzer
    coroutine calls :meth:`merge` when it finishes; the asyncio lock ensures
    the underlying report dict is never mutated from two coroutines at once.

    :attr:`analyzers_completed` and :attr:`analyzers_pending` are updated
    automatically by :meth:`merge`.  :meth:`snapshot` returns a shallow copy
    safe to serialise while the scan is still running.

    Args:
        base: Initial report skeleton (all fields pre-populated with defaults).
        pending: Names of analyzers that are expected to run.
    """

    __slots__ = ("_report", "_lock", "_completed", "_pending", "_successful")

    def __init__(self, base: dict, pending: "list[str]") -> None:
        self._report: dict = base
        self._lock: asyncio.Lock = asyncio.Lock()
        self._completed: list[str] = []
        self._pending: list[str] = list(pending)
        self._successful: list[str] = []  # analyzers that returned non-None
        self._report["analyzers_completed"] = self._completed
        self._report["analyzers_pending"] = self._pending

    async def merge(
        self, analyzer_name: str, result: "dict | None", daemon: "InspectorDaemon"
    ) -> None:
        """Merge *result* into the report under the asyncio lock.

        Args:
            analyzer_name: Name of the analyzer (e.g. ``'pdf'``).
            result: Report fragment returned by the analyzer, or ``None`` if the
                analyzer found nothing or the file type did not match.
            daemon: :class:`InspectorDaemon` instance whose
                :meth:`~InspectorDaemon.merge_reports` does the actual merging.
        """
        async with self._lock:
            if result:
                daemon.merge_reports(self._report, result)
                if analyzer_name not in self._successful:
                    self._successful.append(analyzer_name)
            if analyzer_name in self._pending:
                self._pending.remove(analyzer_name)
            if analyzer_name not in self._completed:
                self._completed.append(analyzer_name)
            # Keep the live lists in the report up to date so that a snapshot()
            # taken at any point reflects the current state.
            self._report["analyzers_completed"] = list(self._completed)
            self._report["analyzers_pending"] = list(self._pending)

    def snapshot(self) -> dict:
        """Return a shallow copy of the current partial report.

        Safe to call from the event loop while analyzers are still running.
        The copy prevents callers from accidentally mutating the live report.

        Returns:
            Shallow-copied report dict including up-to-date
            ``analyzers_completed`` and ``analyzers_pending`` lists.
        """
        snap = dict(self._report)
        snap["analyzers_completed"] = list(self._completed)
        snap["analyzers_pending"] = list(self._pending)
        return snap

    @property
    def report(self) -> dict:
        """The live (mutable) report dict."""
        return self._report

    @property
    def successful(self) -> "list[str]":
        """Analyzers that returned a non-None result."""
        return list(self._successful)


# ---------------------------------------------------------------------------
# InspectorDaemon
# ---------------------------------------------------------------------------


class InspectorDaemon:
    """Async HTTP daemon that analyses Office, PDF, and HTML files for malware.

    A single long-lived instance is created by :func:`make_app`. It owns the
    Redis connection pool, the in-memory task/report cache, and the password
    list used for encrypted-Office decryption.  All heavy work is dispatched
    to a thread-pool executor via :meth:`analyze_task` so the event loop
    stays responsive.

    The four HTTP endpoints are implemented as bound methods:

    * :meth:`handle_scan`     — ``POST /v1/scan``
    * :meth:`handle_query`    — ``GET|POST /v1/query``
    * :meth:`handle_metrics`  — ``GET /v1/metrics``
    """

    _TASKS_MAX_SIZE = 512
    _URL_RE = re.compile(r"https?://[a-zA-Z0-9\-\.\/\_\?\&\=\%\#\:]+")
    _IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    _DOM_RE = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    )

    # IANA root zone TLD snapshot — used to filter spurious domain matches that
    # arise when _DOM_RE runs over binary Office/PDF streams.  Covers all ccTLDs
    # (ISO 3166-1 alpha-2 delegated entries) and the most widely used gTLDs /
    # new-gTLDs as of 2025.  False-negatives on very obscure new gTLDs are
    # acceptable; false-positives from binary internals are not.
    _VALID_TLDS: "frozenset[str]" = frozenset(
        {
            # ccTLDs — ISO 3166-1 alpha-2
            "ac",
            "ad",
            "ae",
            "af",
            "ag",
            "ai",
            "al",
            "am",
            "ao",
            "aq",
            "ar",
            "as",
            "at",
            "au",
            "aw",
            "ax",
            "az",
            "ba",
            "bb",
            "bd",
            "be",
            "bf",
            "bg",
            "bh",
            "bi",
            "bj",
            "bm",
            "bn",
            "bo",
            "bq",
            "br",
            "bs",
            "bt",
            "bv",
            "bw",
            "by",
            "bz",
            "ca",
            "cc",
            "cd",
            "cf",
            "cg",
            "ch",
            "ci",
            "ck",
            "cl",
            "cm",
            "cn",
            "co",
            "cr",
            "cu",
            "cv",
            "cw",
            "cx",
            "cy",
            "cz",
            "de",
            "dj",
            "dk",
            "dm",
            "do",
            "dz",
            "ec",
            "ee",
            "eg",
            "eh",
            "er",
            "es",
            "et",
            "eu",
            "fi",
            "fj",
            "fk",
            "fm",
            "fo",
            "fr",
            "ga",
            "gb",
            "gd",
            "ge",
            "gf",
            "gg",
            "gh",
            "gi",
            "gl",
            "gm",
            "gn",
            "gp",
            "gq",
            "gr",
            "gs",
            "gt",
            "gu",
            "gw",
            "gy",
            "hk",
            "hm",
            "hn",
            "hr",
            "ht",
            "hu",
            "id",
            "ie",
            "il",
            "im",
            "in",
            "io",
            "iq",
            "ir",
            "is",
            "it",
            "je",
            "jm",
            "jo",
            "jp",
            "ke",
            "kg",
            "kh",
            "ki",
            "km",
            "kn",
            "kp",
            "kr",
            "kw",
            "ky",
            "kz",
            "la",
            "lb",
            "lc",
            "li",
            "lk",
            "lr",
            "ls",
            "lt",
            "lu",
            "lv",
            "ly",
            "ma",
            "mc",
            "md",
            "me",
            "mf",
            "mg",
            "mh",
            "mk",
            "ml",
            "mm",
            "mn",
            "mo",
            "mp",
            "mq",
            "mr",
            "ms",
            "mt",
            "mu",
            "mv",
            "mw",
            "mx",
            "my",
            "mz",
            "na",
            "nc",
            "ne",
            "nf",
            "ng",
            "ni",
            "nl",
            "no",
            "np",
            "nr",
            "nu",
            "nz",
            "om",
            "pa",
            "pe",
            "pf",
            "pg",
            "ph",
            "pk",
            "pl",
            "pm",
            "pn",
            "pr",
            "ps",
            "pt",
            "pw",
            "py",
            "qa",
            "re",
            "ro",
            "rs",
            "ru",
            "rw",
            "sa",
            "sb",
            "sc",
            "sd",
            "se",
            "sg",
            "sh",
            "si",
            "sj",
            "sk",
            "sl",
            "sm",
            "sn",
            "so",
            "sr",
            "ss",
            "st",
            "su",
            "sv",
            "sx",
            "sy",
            "sz",
            "tc",
            "td",
            "tf",
            "tg",
            "th",
            "tj",
            "tk",
            "tl",
            "tm",
            "tn",
            "to",
            "tr",
            "tt",
            "tv",
            "tw",
            "tz",
            "ua",
            "ug",
            "uk",
            "um",
            "us",
            "uy",
            "uz",
            "va",
            "vc",
            "ve",
            "vg",
            "vi",
            "vn",
            "vu",
            "wf",
            "ws",
            "ye",
            "yt",
            "za",
            "zm",
            "zw",
            # Original / sponsored gTLDs
            "com",
            "net",
            "org",
            "edu",
            "gov",
            "mil",
            "int",
            "arpa",
            "info",
            "biz",
            "name",
            "pro",
            "aero",
            "coop",
            "museum",
            "jobs",
            "mobi",
            "tel",
            "travel",
            "cat",
            "xxx",
            "post",
            # Popular new gTLDs (ICANN delegated)
            "app",
            "ai",
            "cloud",
            "co",
            "dev",
            "digital",
            "email",
            "io",
            "live",
            "media",
            "news",
            "online",
            "shop",
            "site",
            "store",
            "tech",
            "web",
            "academy",
            "accountant",
            "accountants",
            "actor",
            "adult",
            "agency",
            "airforce",
            "apartments",
            "art",
            "associates",
            "attorney",
            "auction",
            "audio",
            "auto",
            "band",
            "bank",
            "bar",
            "bargains",
            "beer",
            "best",
            "bid",
            "bike",
            "bingo",
            "black",
            "blog",
            "blue",
            "boutique",
            "broker",
            "build",
            "builders",
            "business",
            "buzz",
            "cab",
            "camera",
            "camp",
            "capital",
            "cards",
            "care",
            "careers",
            "cash",
            "casino",
            "catering",
            "center",
            "chat",
            "cheap",
            "christmas",
            "church",
            "city",
            "claims",
            "cleaning",
            "clinic",
            "clothing",
            "coach",
            "codes",
            "coffee",
            "college",
            "community",
            "company",
            "computer",
            "condos",
            "construction",
            "consulting",
            "contact",
            "contractors",
            "cooking",
            "cool",
            "credit",
            "creditcard",
            "cruises",
            "dating",
            "deals",
            "degree",
            "delivery",
            "democrat",
            "dental",
            "design",
            "diamonds",
            "diet",
            "direct",
            "directory",
            "discount",
            "dog",
            "domains",
            "education",
            "energy",
            "engineering",
            "enterprises",
            "equipment",
            "estate",
            "events",
            "exchange",
            "expert",
            "exposed",
            "fail",
            "farm",
            "finance",
            "financial",
            "fitness",
            "florist",
            "football",
            "foundation",
            "fun",
            "fund",
            "furniture",
            "gallery",
            "gifts",
            "glass",
            "global",
            "gold",
            "graphics",
            "gripe",
            "group",
            "guide",
            "guitars",
            "guru",
            "haus",
            "healthcare",
            "help",
            "hockey",
            "holdings",
            "holiday",
            "homes",
            "host",
            "hosting",
            "house",
            "immo",
            "industries",
            "info",
            "institute",
            "insure",
            "international",
            "investments",
            "jewelry",
            "kitchen",
            "land",
            "lawyer",
            "lease",
            "legal",
            "life",
            "lighting",
            "limited",
            "limo",
            "link",
            "loans",
            "management",
            "marketing",
            "mba",
            "moda",
            "money",
            "mortgage",
            "network",
            "ninja",
            "one",
            "partners",
            "parts",
            "photography",
            "photos",
            "pictures",
            "pink",
            "pizza",
            "place",
            "plumbing",
            "plus",
            "press",
            "productions",
            "properties",
            "property",
            "recipes",
            "red",
            "rehab",
            "reise",
            "reisen",
            "rentals",
            "repair",
            "report",
            "republican",
            "restaurant",
            "reviews",
            "rich",
            "rocks",
            "run",
            "sale",
            "salon",
            "school",
            "services",
            "singles",
            "social",
            "software",
            "solar",
            "solutions",
            "space",
            "studio",
            "style",
            "supplies",
            "supply",
            "support",
            "surgery",
            "systems",
            "tax",
            "team",
            "technology",
            "tips",
            "today",
            "tools",
            "tours",
            "town",
            "training",
            "university",
            "ventures",
            "video",
            "villas",
            "vision",
            "voyage",
            "watch",
            "website",
            "wiki",
            "works",
            "world",
            "wtf",
            "zone",
        }
    )

    @staticmethod
    def _has_valid_tld(domain: str) -> bool:
        """Return True when *domain* looks like a real hostname.

        When ``tldextract`` is installed (recommended, part of the
        ``advanced`` extras) the Mozilla Public Suffix List is used for
        TLD recognition — it stays current with new gTLDs without code
        changes.  Otherwise the built-in ``_VALID_TLDS`` snapshot is
        used as a fallback.

        Either way a minimum SLD length of 3 characters is enforced to
        drop 1–2-char SLD fragments that appear in binary file internals
        (e.g. PDF object refs like ``Jy.gY``, ``o.MA``) while keeping
        real short-SLD domains such as ``bit.ly`` intact.
        """
        if HAS_TLDEXTRACT:
            result = _TLDEXT(domain)
            # The suffix must be all-lowercase — mixed-case TLDs (e.g. ".gT",
            # ".cOm") are text fragments, not real DNS labels.
            return (
                bool(result.suffix)
                and result.suffix == result.suffix.lower()
                and len(result.domain) >= 3
            )
        # Fallback: static IANA TLD snapshot
        parts = domain.rsplit(".", 2)
        tld = parts[-1].lower()
        if tld not in InspectorDaemon._VALID_TLDS:
            return False
        sld = parts[-2] if len(parts) >= 2 else ""
        return len(sld) >= 3

    # External variables pre-defined so that rule sets like signature-base
    # (which reference filepath/filename/extension/filetype) compile without
    # error.  Actual values are injected per-scan in analyze_yara().
    _YARA_EXTERNALS: "dict[str, str]" = {
        "filepath": "",
        "filename": "",
        "extension": "",
        "filetype": "",
    }

    def __init__(self) -> None:
        """Create a new daemon instance with empty state.

        Attributes are fully initialised by :meth:`setup`; do not use
        the instance before calling it.
        """
        self.passwords: list[str] = []
        self.redis_pool = None
        self._redis_error_count = 0
        self.tasks: OrderedDict = OrderedDict()
        # In-flight PartialReport objects keyed by file_hash.
        # Populated by analyze_pipeline(); removed when the scan finishes.
        self._partials: dict = {}
        # Two-tier concurrency semaphores.
        # Initialised in setup() so they are bound to the running event loop.
        self._fg_sem: "asyncio.Semaphore | None" = None
        self._bg_sem: "asyncio.Semaphore | None" = None
        # Compiled YARA rules (None when YARA is unavailable or not configured).
        self._yara_rules = None  # yara-python compiled rules
        self._yara_x_rules = None  # yara-x compiled rules
        # ClamAV client (None when disabled or library unavailable).
        self._clamd = None
        self._clamav_version: str = ""  # cached VERSION response
        # EasyOCR reader — lazily initialised on first use (slow to load).
        self._easyocr_reader = None
        # Dedicated thread pool for CPU-bound analyzer work.
        self._executor: "concurrent.futures.ThreadPoolExecutor | None" = None
        # Cached config-derived values (rebuilt on reload).
        self._exclude_suffixes: tuple[str, ...] = ()
        self._exclude_suffixes_source: "list | None" = None  # identity-check
        self._rebuild_cached_config()

    # ------------------------------------------------------------------
    # Redis helpers
    # ------------------------------------------------------------------

    def _redis_enabled(self, s: str) -> bool:
        if not config["xspct_redis_cache"]["enabled"] or not self.redis_pool:
            return False
        if self._redis_error_count > int(config["xspct_redis_cache"]["max_errors"]):
            logger.debug(
                "%s - Redis circuit-breaker open (%d errors)",
                s,
                self._redis_error_count,
            )
            return False
        return True

    def _redis_record_error(self, s: str, exc: Exception) -> None:
        self._redis_error_count += 1
        logger.error("%s - Redis error (#%d): %s", s, self._redis_error_count, exc)
        stats["redis_errors"] += 1

    def _redis_reset_errors(self, s: str) -> None:
        if self._redis_error_count > 0:
            logger.info("%s - Redis recovered, resetting circuit-breaker", s)
            self._redis_error_count = 0

    async def get_cached_report(self, s: str, file_hash: str) -> "dict | None":
        """Look up a previously computed report in Redis.

        Falls back gracefully when Redis is disabled or the circuit-breaker
        is open. Cache misses (including errors) are counted in
        :data:`stats`.

        Args:
            s: Session tag for log messages.
            file_hash: SHA-256 hex digest of the file.

        Returns:
            The cached report dict, or ``None`` on a miss.
        """
        if not self._redis_enabled(s):
            stats["redis_misses"] += 1
            return None
        key = config["xspct_redis_cache"]["prefix"] + file_hash
        try:
            raw = await self.redis_pool.get(key)
            self._redis_reset_errors(s)
        except Exception as exc:
            self._redis_record_error(s, exc)
            return None
        if raw:
            stats["redis_hits"] += 1
            logger.debug("%s - Redis hit: %s", s, file_hash)
            return json.loads(raw)
        stats["redis_misses"] += 1
        return None

    async def cache_report(self, s: str, file_hash: str, report: dict) -> None:
        """Store a finished report in the in-memory LRU cache and Redis.

        Always writes to the in-memory :attr:`tasks` dict and evicts the
        oldest entries if the cache exceeds :attr:`_TASKS_MAX_SIZE`.  The
        Redis write is skipped when Redis is disabled or unreachable.

        Args:
            s: Session tag for log messages.
            file_hash: SHA-256 hex digest used as the cache key.
            report: Finished analysis report dict to store.
        """
        self._store_terminal_result(file_hash, report)
        if not self._redis_enabled(s):
            return
        key = config["xspct_redis_cache"]["prefix"] + file_hash
        expire = int(config["xspct_redis_cache"]["expire"])
        try:
            await self.redis_pool.setex(key, expire, json.dumps(report))
            self._redis_reset_errors(s)
            logger.info("%s - cached report for %s (TTL %ds)", s, file_hash, expire)
        except Exception as exc:
            self._redis_record_error(s, exc)

    def _store_terminal_result(self, file_hash: str, result: dict) -> None:
        """Persist a terminal in-memory result for subsequent /query lookups."""
        self.tasks[file_hash] = result
        self.tasks.move_to_end(file_hash)
        self._evict_tasks()
        self._partials.pop(file_hash, None)  # partial no longer needed

    def _make_terminal_error_result(
        self, file_hash: str, message: str = "Internal server error"
    ) -> dict:
        """Build a stable error payload for failed background/query lookups."""
        return {
            "status": "error",
            "file_hash": file_hash,
            "error": message,
        }

    def _evict_tasks(self) -> None:
        while len(self.tasks) > self._TASKS_MAX_SIZE:
            self.tasks.popitem(last=False)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def setup(self) -> None:
        """Initialise the daemon: load passwords and connect to Redis.

        Called once during application startup via the aiohttp
        ``on_startup`` signal.
        """
        self._read_passwords()

        # Build cached config-derived values.
        self._rebuild_cached_config()

        # Create dedicated thread pool for CPU-bound analyzer work.
        import concurrent.futures

        pool_size = int(config.get("xspct_foreground_slots", 16)) + int(
            config.get("xspct_background_slots", 4)
        )
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=pool_size,
            thread_name_prefix="xspct-analyzer",
        )

        # Log availability of every optional engine at startup so operators
        # can see at a glance what is installed and what is active.
        for _cat, _name, _avail, _enabled, _pip in self._engine_matrix():
            if _avail and _enabled:
                _status = "available + enabled"
            elif _avail and not _enabled:
                _status = "available, disabled in config"
            elif not _avail and _enabled:
                _status = "NOT INSTALLED — enabled in config but will not run"
            else:
                _status = "not installed"
            logger.info("engine - %-10s - %-16s  %s", _cat, _name, _status)
            if not _avail:
                logger.info("engine - %-10s - %-16s    install: %s", _cat, _name, _pip)

        self._compile_yara_rules()
        # Semaphores must be created inside the running event loop.
        self._fg_sem = asyncio.Semaphore(int(config.get("xspct_foreground_slots", 16)))
        self._bg_sem = asyncio.Semaphore(int(config.get("xspct_background_slots", 4)))
        logger.info(
            "Concurrency: %d foreground + %d background slots",
            config.get("xspct_foreground_slots", 16),
            config.get("xspct_background_slots", 4),
        )
        if HAS_CLAMD and config["xspct_clamav"]["enabled"]:
            cv = config["xspct_clamav"]
            timeout = int(cv.get("timeout", 60))
            try:
                if cv.get("socket"):
                    self._clamd = _clamd.ClamdUnixSocket(cv["socket"], timeout=timeout)
                else:
                    self._clamd = _clamd.ClamdNetworkSocket(
                        cv.get("host", "127.0.0.1"),
                        int(cv.get("port", 3310)),
                        timeout=timeout,
                    )
                self._clamd.ping()
                self._clamav_version = self._clamd.version()
                logger.info("Connected to ClamAV: %s", self._clamav_version)
            except Exception as exc:
                logger.error(
                    "ClamAV connection failed: %s — ClamAV engine disabled", exc
                )
                self._clamd = None
        elif config["xspct_clamav"]["enabled"] and not HAS_CLAMD:
            logger.warning(
                "ClamAV requested but clamd library not found. Engine disabled."
            )

        if HAS_REDIS and config["xspct_redis_cache"]["enabled"]:
            rc = config["xspct_redis_cache"]
            url = f"redis://{rc['host']}:{rc['port']}"
            try:
                if hasattr(redis, "from_url"):
                    self.redis_pool = redis.from_url(
                        url,
                        username=rc["user"] or None,
                        password=rc["password"] or None,
                        decode_responses=True,
                    )
                else:
                    self.redis_pool = await redis.create_redis_pool(
                        url, encoding="utf-8"
                    )
                logger.info("Connected to Redis at %s", url)
            except Exception as exc:
                logger.error("Failed to connect to Redis: %s", exc)
                self.redis_pool = None
        elif config["xspct_redis_cache"]["enabled"] and not HAS_REDIS:
            logger.warning("Redis requested but library not found. Caching disabled.")

    async def teardown(self) -> None:
        """Gracefully close the Redis connection pool.

        Called once during application shutdown via the aiohttp
        ``on_cleanup`` signal.
        """
        if self._executor:
            self._executor.shutdown(wait=False)
        if self.redis_pool:
            try:
                await self.redis_pool.aclose()
            except Exception:
                pass

    def _read_passwords(self) -> None:
        defaults = ["VelvetSweatshop", "123", "1234", "12345", "123456", "4321"]
        pw_config = config["xspct_password_file"]
        files = [pw_config] if isinstance(pw_config, str) else list(pw_config)
        all_passwords: list[str] = []
        for pw_file in files:
            try:
                with open(pw_file) as fh:
                    all_passwords.extend(fh.read().splitlines())
            except FileNotFoundError:
                logger.warning("Password file %s not found. Using defaults.", pw_file)
        self.passwords = (all_passwords + defaults) if all_passwords else defaults
        logger.info("Loaded %d passwords.", len(self.passwords))

    def _archive_backend_available(self) -> bool:
        """Return whether archive extraction has a usable backend."""
        return HAS_SFLOCK or bool(config.get("xspct_archive_stdlib_fallback", False))

    def _engine_matrix(self) -> "list[tuple]":
        """Return the engine availability matrix used for startup logging and capabilities.

        Each entry is a 5-tuple:
        ``(category, display_name, available, enabled, pip_hint)``

        The list is sorted lexicographically by ``(category, display_name)``.

        Returns:
            Sorted list of 5-tuples describing every optional engine.
        """
        _az = config.get("xspct_analyzers", {})
        _cv = config.get("xspct_clamav", {})
        return sorted(
            [
                # (category, display-name, available, enabled, pip-hint)
                (
                    "archive",
                    "sflock2",
                    HAS_SFLOCK,
                    _az.get("archive", {}).get("enabled", True),
                    'pip install "xspct-scan[advanced]"',
                ),
                (
                    "cache",
                    "redis",
                    HAS_REDIS,
                    config.get("xspct_redis_cache", {}).get("enabled", False),
                    'pip install "xspct-scan[redis]"',
                ),
                (
                    "clamav",
                    "clamav",
                    HAS_CLAMD,
                    _cv.get("enabled", False),
                    'pip install "xspct-scan[enrichment]"',
                ),
                ("core", "python-magic", HAS_MAGIC, True, "pip install python-magic"),
                (
                    "office",
                    "msoffcrypto",
                    HAS_MSOFFCRYPTO,
                    _az.get("office", {}).get("enabled", True),
                    "pip install msoffcrypto-tool",
                ),
                (
                    "office",
                    "olefile",
                    HAS_OLEFILE,
                    _az.get("office", {}).get("enabled", True),
                    "pip install olefile",
                ),
                (
                    "office",
                    "odfdo",
                    HAS_ODFDO,
                    _az.get("office", {}).get("enabled", True),
                    'pip install "xspct-scan[advanced]"',
                ),
                (
                    "office",
                    "oletools",
                    HAS_OLETOOLS,
                    _az.get("office", {}).get("enabled", True),
                    "pip install oletools",
                ),
                (
                    "iocs",
                    "iocsearcher",
                    HAS_IOCSEARCHER,
                    _az.get("iocs", {}).get("enabled", True),
                    'pip install "xspct-scan[advanced]"',
                ),
                (
                    "image",
                    "pyzbar",
                    HAS_PYZBAR,
                    _az.get("image", {}).get("enabled", True),
                    'pip install "xspct-scan[enrichment]"  # also: apt install libzbar0',
                ),
                (
                    "image",
                    "tesseract-ocr",
                    HAS_OCR,
                    _az.get("image", {}).get("enabled", True),
                    'pip install "xspct-scan[enrichment]"  # also: apt install tesseract-ocr',
                ),
                (
                    "image",
                    "easyocr",
                    HAS_EASYOCR,
                    _az.get("image", {}).get("enabled", True),
                    "pip install easyocr",
                ),
                (
                    "javascript",
                    "jsbeautifier",
                    HAS_JSBEAUTIFIER,
                    _az.get("javascript", {}).get("enabled", True),
                    'pip install "xspct-scan[enrichment]"',
                ),
                (
                    "javascript",
                    "quickjs",
                    HAS_QUICKJS,
                    _az.get("javascript", {}).get("enabled", True)
                    and _az.get("javascript", {}).get("quickjs", False),
                    'pip install "xspct-scan[enrichment]"',
                ),
                (
                    "javascript",
                    "tree-sitter-js",
                    HAS_TREESITTER,
                    _az.get("javascript", {}).get("enabled", True),
                    'pip install "xspct-scan[enrichment]"',
                ),
                (
                    "pdf",
                    "pymupdf",
                    HAS_PYMUPDF,
                    _az.get("pdf", {}).get("enabled", True),
                    "pip install pymupdf",
                ),
                (
                    "yara",
                    "yara-python",
                    HAS_YARA,
                    _az.get("yara", {}).get("enabled", False),
                    'pip install "xspct-scan[advanced]"',
                ),
                (
                    "yara",
                    "yara-x",
                    HAS_YARA_X,
                    _az.get("yara_x", {}).get("enabled", False),
                    'pip install "xspct-scan[advanced]"',
                ),
            ]
        )

    def _resolve_enabled_analyzers(self) -> list[str]:
        """Return the list of analyzer names that are currently enabled.

        Reads ``xspct_analyzers`` from the module config and returns the names
        of all analyzers whose ``enabled`` flag is truthy.

        Returns:
            Ordered list of enabled analyzer name strings.
        """
        return [
            name
            for name, cfg in config["xspct_analyzers"].items()
            if cfg.get("enabled", True)
            and (name != "archive" or self._archive_backend_available())
        ]

    def _rebuild_cached_config(self) -> None:
        """Rebuild cached config-derived values from current module config."""
        src = config.get("xspct_ioc_url_exclude_domains") or []
        self._exclude_suffixes = tuple(s.lower() for s in src if s)
        self._exclude_suffixes_source = src

    def _get_exclude_suffixes(self) -> tuple:
        """Return cached exclude suffixes, refreshing if config changed."""
        src = config.get("xspct_ioc_url_exclude_domains") or []
        if src is not self._exclude_suffixes_source:
            self._exclude_suffixes = tuple(s.lower() for s in src if s)
            self._exclude_suffixes_source = src
        return self._exclude_suffixes

    def _try_acquire_background_slot(self) -> bool:
        """Attempt to take one background semaphore slot without waiting.

        Uses the semaphore's internal counter via acquire_nowait() pattern.
        Background promotion needs an immediate yes/no decision so foreground
        requests can release their slot promptly instead of waiting for
        background capacity.

        Returns:
            ``True`` when a slot was claimed, otherwise ``False``.
        """
        sem = self._bg_sem
        if sem is None:
            return False
        if sem.locked():
            return False
        # locked() returns True when value is 0; if not locked, acquire is
        # guaranteed to succeed immediately on the next await.  We still need
        # a synchronous decrement — the internal _value is the only option in
        # CPython's asyncio.Semaphore, but we guard with locked() first.
        sem._value -= 1
        return True

    # ------------------------------------------------------------------
    # YARA rules
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_yara_files(rules_path: str) -> list:
        """Return a list of ``*.yar``/``*.yara`` file paths under *rules_path*.

        If *rules_path* is a file, returns ``[rules_path]``.  If it is a
        directory, returns all matching files inside it (non-recursive).
        Returns an empty list when the path does not exist.
        """
        if os.path.isfile(rules_path):
            return [rules_path]
        if os.path.isdir(rules_path):
            return [
                os.path.join(rules_path, f)
                for f in os.listdir(rules_path)
                if f.endswith((".yar", ".yara"))
            ]
        return []

    # Pattern that extracts the undefined identifier name from yara-python and
    # yara-x error messages so we can add it as an external and retry.
    _YARA_UNDEF_RE = re.compile(
        r'undefined identifier ["\`](\w+)["\`]'  # yara-python
        r"|unknown identifier `(\w+)`"  # yara-x
    )

    def _compile_yara_classic(self, files: list):
        """Compile *files* with yara-python, auto-adding unknown externals.

        Retries up to 32 times, each time extracting the undefined identifier
        from the error message and adding it with an empty-string default.
        Raises on non-external errors or when the retry limit is reached.
        """
        ext = dict(self._YARA_EXTERNALS)
        fps = {os.path.basename(f): f for f in files}
        for _ in range(32):
            try:
                if len(files) == 1:
                    return _yara.compile(filepath=files[0], externals=ext)
                return _yara.compile(filepaths=fps, externals=ext)
            except Exception as exc:
                m = self._YARA_UNDEF_RE.search(str(exc))
                if m:
                    var = m.group(1) or m.group(2)
                    if var and var not in ext:
                        logger.debug('YARA (classic): adding external %r = ""', var)
                        ext[var] = ""
                        continue
                raise
        raise RuntimeError("YARA (classic): too many undefined external variables")

    def _compile_yara_x(self, files: list):
        """Compile *files* with yara-x, auto-adding unknown externals.

        Same retry logic as :meth:`_compile_yara_classic`.
        """
        ext = dict(self._YARA_EXTERNALS)
        for _ in range(32):
            try:
                compiler = _yara_x.Compiler()
                for k, v in ext.items():
                    compiler.define_global(k, v)
                for fpath in files:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                        compiler.add_source(fh.read())
                return compiler.build()
            except Exception as exc:
                m = self._YARA_UNDEF_RE.search(str(exc))
                if m:
                    var = m.group(1) or m.group(2)
                    if var and var not in ext:
                        logger.debug('YARA-X: adding external %r = ""', var)
                        ext[var] = ""
                        continue
                raise
        raise RuntimeError("YARA-X: too many undefined external variables")

    def _compile_yara_rules(self) -> None:
        """Compile YARA rules for both the classic (yara-python) and modern
        (yara-x) engines based on ``xspct_analyzers.yara`` /
        ``xspct_analyzers.yara_x`` config blocks.

        Results are stored in:
            - ``self._yara_rules``   — compiled yara-python ruleset or ``None``
            - ``self._yara_x_rules`` — compiled yara-x ruleset or ``None``

        Both engines can be active simultaneously, which enables side-by-side
        comparison of match results in ``analyze_yara()``.
        """
        self._yara_rules = None
        self._yara_x_rules = None

        # --- classic yara-python ---
        yara_cfg = config["xspct_analyzers"].get("yara", {})
        if yara_cfg.get("enabled", False):
            if not HAS_YARA:
                logger.warning(
                    "YARA (classic) enabled in config but yara-python is not installed — no rules loaded"
                )
            else:
                rules_path = os.path.expandvars(
                    os.path.expanduser(yara_cfg.get("rules_path", ""))
                )
                if not rules_path:
                    logger.warning(
                        "YARA (classic) enabled but rules_path is not set — no rules loaded"
                    )
                else:
                    files = self._collect_yara_files(rules_path)
                    if not files:
                        logger.warning(
                            "YARA (classic): no *.yar/*.yara files found at %s",
                            rules_path,
                        )
                    else:
                        try:
                            self._yara_rules = self._compile_yara_classic(files)
                            logger.info(
                                "YARA (classic): compiled %d file(s) from %s%s",
                                len(files),
                                rules_path,
                                " [Hyperscan]" if HAS_YARA_HYPERSCAN else "",
                            )
                        except Exception as exc:
                            logger.error("YARA (classic) compilation failed: %s", exc)

        # --- yara-x ---
        yara_x_cfg = config["xspct_analyzers"].get("yara_x", {})
        if yara_x_cfg.get("enabled", False):
            if not HAS_YARA_X:
                logger.warning(
                    "YARA-X enabled in config but yara-x is not installed — no rules loaded"
                )
            else:
                rules_path = os.path.expandvars(
                    os.path.expanduser(yara_x_cfg.get("rules_path", ""))
                )
                if not rules_path:
                    logger.warning(
                        "YARA-X enabled but rules_path is not set — no rules loaded"
                    )
                else:
                    files = self._collect_yara_files(rules_path)
                    if not files:
                        logger.warning(
                            "YARA-X: no *.yar/*.yara files found at %s", rules_path
                        )
                    else:
                        try:
                            self._yara_x_rules = self._compile_yara_x(files)
                            logger.info(
                                "YARA-X: compiled %d file(s) from %s",
                                len(files),
                                rules_path,
                            )
                        except Exception as exc:
                            logger.error("YARA-X compilation failed: %s", exc)

    def analyze_yara(
        self, data: bytes, filename: str = "", file_mime: str = "", s: str = ""
    ) -> "dict | None":
        """Run compiled YARA rules against *data* using any loaded engine(s).

        When both classic (yara-python) and modern (yara-x) engines are
        configured, both scan the same bytes and their results are merged
        into a single ``yara_matches`` list.  Each entry is tagged with an
        ``engine`` key (``'classic'`` or ``'yara-x'``) so callers can
        compare results.

        Args:
            data: Raw file bytes to scan.
            filename: Original filename — populates the ``filename``,
                ``filepath``, and ``extension`` external variables so that
                rules from sets like ``signature-base`` that reference them
                compile and match correctly.
            file_mime: MIME type string — populates the ``filetype`` external.

        Returns:
            A dict with key ``yara_matches`` (list of match dicts), or
            ``None`` when no engines are loaded or nothing matches.

            Each match dict has keys:
                - **engine** (str): ``'classic'`` or ``'yara-x'``.
                - **rule** (str): Rule name.
                - **namespace** (str): Rule namespace.
                - **tags** (list[str]): Rule tags.
                - **meta** (dict): Rule metadata.
                - **strings** (list[str]): Matched string identifiers.
        """
        results: list = []
        ext = {
            "filepath": filename,
            "filename": os.path.basename(filename),
            "extension": os.path.splitext(filename)[1].lstrip(".").lower(),
            "filetype": file_mime or "",
        }

        # --- classic yara-python ---
        if HAS_YARA and getattr(self, "_yara_rules", None):
            _t0 = time.monotonic()
            classic_hits: list = []
            try:
                for m in self._yara_rules.match(data=data, externals=ext):
                    classic_hits.append(
                        {
                            "engine": "classic",
                            "rule": m.rule,
                            "namespace": m.namespace,
                            "tags": list(m.tags),
                            "meta": dict(m.meta),
                            "strings": [str(s) for s in m.strings],
                        }
                    )
            except Exception as exc:
                logger.error("%s YARA (classic) scan error: %s", s, exc)
            _ms = int((time.monotonic() - _t0) * 1000)
            _rules = [h["rule"] for h in classic_hits]
            logger.debug(
                "%s yara-classic file=%s bytes=%d time=%dms hits=%d%s",
                s,
                filename,
                len(data),
                _ms,
                len(classic_hits),
                " rules=" + ",".join(_rules) if _rules else "",
            )
            results.extend(classic_hits)

        # --- yara-x ---
        if HAS_YARA_X and getattr(self, "_yara_x_rules", None):
            _t0 = time.monotonic()
            yarax_hits: list = []
            try:
                scanner = _yara_x.Scanner(self._yara_x_rules)
                for k, v in ext.items():
                    scanner.set_global(k, v)
                for m in scanner.scan(data).matching_rules:
                    yarax_hits.append(
                        {
                            "engine": "yara-x",
                            "rule": m.identifier,
                            "namespace": m.namespace,
                            "tags": list(m.tags),
                            "meta": {k: v for k, v in m.metadata},
                            "strings": [
                                p.identifier for p in m.patterns if list(p.matches)
                            ],
                        }
                    )
            except Exception as exc:
                logger.error("%s YARA-X scan error: %s", s, exc)
            _ms = int((time.monotonic() - _t0) * 1000)
            _rules = [h["rule"] for h in yarax_hits]
            logger.debug(
                "%s yara-x     file=%s bytes=%d time=%dms hits=%d%s",
                s,
                filename,
                len(data),
                _ms,
                len(yarax_hits),
                " rules=" + ",".join(_rules) if _rules else "",
            )
            results.extend(yarax_hits)

        return {"yara_matches": results} if results else None

    # ------------------------------------------------------------------
    # IOC extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _ioc_excluded(host: str, exclude_suffixes: tuple) -> bool:
        """Return True when *host* matches or is a subdomain of any excluded suffix."""
        host = host.lower().rstrip(".")
        for suffix in exclude_suffixes:
            suffix = suffix.lower()
            if host == suffix or host.endswith("." + suffix):
                return True
        return False

    def extract_iocs(self, data: bytes) -> dict:
        """Extract indicators of compromise (IOCs) from raw document bytes.

        Decodes the data as both UTF-8 and UTF-16 LE and scans the combined
        text with regular expressions for URLs, IP addresses, and domain names.
        URLs and domains whose hostname matches ``xspct_ioc_url_exclude_domains``
        (or is a subdomain thereof) are silently filtered out.

        Args:
            data: Raw file bytes to scan.

        Returns:
            A dict with keys ``urls``, ``ips``, and ``domains``, each
            containing a sorted list of unique strings.
        """
        try:
            text_utf8 = data.decode("utf-8", "ignore")
            text_utf16 = data.decode("utf-16le", "ignore")
        except Exception:
            text_utf8 = data.decode("ascii", "ignore")
            text_utf16 = ""

        exclude_suffixes = self._get_exclude_suffixes()

        def _host_from_url(url: str) -> str:
            """Best-effort hostname extraction without a full URL parser."""
            try:
                # strip scheme
                after_scheme = url.split("://", 1)[1] if "://" in url else url
                # strip path / query / fragment
                return after_scheme.split("/")[0].split("?")[0].split("#")[0].lower()
            except Exception:
                return ""

        # Scan each encoding separately to avoid concatenating two large strings.
        raw_urls: set[str] = set()
        raw_urls.update(self._URL_RE.findall(text_utf8))
        if text_utf16:
            raw_urls.update(self._URL_RE.findall(text_utf16))
        if exclude_suffixes:
            urls = sorted(
                u
                for u in raw_urls
                if not self._ioc_excluded(_host_from_url(u), exclude_suffixes)
            )
        else:
            urls = sorted(raw_urls)

        raw_ips: set[str] = set()
        raw_ips.update(self._IP_RE.findall(text_utf8))
        if text_utf16:
            raw_ips.update(self._IP_RE.findall(text_utf16))
        ips = sorted(
            ip for ip in raw_ips if all(0 <= int(p) <= 255 for p in ip.split("."))
        )

        raw_domains: set[str] = set()
        raw_domains.update(self._DOM_RE.findall(text_utf8))
        if text_utf16:
            raw_domains.update(self._DOM_RE.findall(text_utf16))
        domains = sorted(
            d
            for d in raw_domains
            if self._has_valid_tld(d)
            and (not exclude_suffixes or not self._ioc_excluded(d, exclude_suffixes))
        )

        return {"urls": urls, "ips": ips, "domains": domains}

    def analyze_iocsearcher(self, text: str, label: str = "") -> "dict | None":
        """Extract extended IOCs from *text* using ``iocsearcher``.

        Supplements :meth:`extract_iocs` with additional indicator types that
        regex-only extraction misses: e-mail addresses, CVE identifiers,
        cryptocurrency wallet addresses, onion addresses, and more.

        Args:
            text: Decoded document text to search.
            label: Source label for log messages.

        Returns:
            A dict with key ``iocs_extended`` whose value is a sub-dict
            mapping IOC type strings to sorted lists of unique values.
            Returns ``None`` when iocsearcher is unavailable or ``text``
            is empty.
        """
        if not HAS_IOCSEARCHER or not _IOCSEARCHER or not text:
            return None
        try:
            hits = _IOCSEARCHER.search_raw(text)
        except Exception as exc:
            logger.debug("iocsearcher failed (%s): %s", label, exc)
            return None

        exclude_suffixes = self._get_exclude_suffixes()

        # IOC types whose value is a hostname or URL — apply the exclude list.
        _HOST_TYPES = frozenset({"fqdn", "domain", "url", "ip", "ipv6"})

        result: dict = {}
        for ioc_type, normalized, _pos, _raw in hits:
            if exclude_suffixes and ioc_type in _HOST_TYPES:
                # For URL-type values extract the host first; for host-type
                # values use the value directly.
                if "://" in normalized:
                    try:
                        host = (
                            normalized.split("://", 1)[1]
                            .split("/")[0]
                            .split("?")[0]
                            .lower()
                        )
                    except Exception:
                        host = normalized.lower()
                else:
                    host = normalized.lower()
                if self._ioc_excluded(host, exclude_suffixes):
                    continue
            # Filter low-quality FQDN/domain hits:
            #   - TLD must be all-lowercase alpha (mixed-case TLDs are text
            #     fragments, not real domains, e.g. "2HPZuVNKY.gT")
            #   - SLD must be at least 2 characters (single-char SLDs like
            #     "o.ma" are almost always false positives)
            if ioc_type in ("fqdn", "domain"):
                _parts = normalized.rstrip(".").rsplit(".", 2)
                _tld = _parts[-1]
                _sld = _parts[-2] if len(_parts) >= 2 else ""
                if not _tld.isalpha() or _tld != _tld.lower() or len(_sld) < 2:
                    continue
            result.setdefault(ioc_type, set()).add(normalized)
        if not result:
            return None
        return {"iocs_extended": {k: sorted(v) for k, v in result.items()}}

    # ------------------------------------------------------------------
    # ClamAV engine
    # ------------------------------------------------------------------

    _CLAMAV_VERSION_RE = re.compile(r"ClamAV\s+([^\s/]+)(?:/(\d+)/([^\n]+))?")

    def _parse_clamav_version(self) -> "tuple[str, str, str]":
        """Parse the cached VERSION string into (engine, db_version, db_date)."""
        m = self._CLAMAV_VERSION_RE.search(self._clamav_version)
        if m:
            return m.group(1) or "", m.group(2) or "", (m.group(3) or "").strip()
        return self._clamav_version, "", ""

    def analyze_clamav(self, data: bytes, filename: str = "", s: str = "") -> dict:
        """Scan *data* with ClamAV via the clamd INSTREAM protocol.

        Always returns a dict with a ``clamav`` key so the field is present
        in the report whenever the engine is enabled — even on errors or
        when the file is skipped.  Possible ``clamav.status`` values:

        - ``clean``       — scan completed, no threat found
        - ``infected``    — one or more detections; names in ``viruses``
        - ``skipped``     — file exceeds ``xspct_clamav.max_size``
        - ``unavailable`` — client not connected (startup connection failed)
        - ``error``       — scan-time exception

        Runs synchronously (intended for
        :meth:`~asyncio.loop.run_in_executor`).
        """
        engine_ver, db_ver, db_date = self._parse_clamav_version()

        def _meta(status: str, **extra) -> dict:
            return {
                "clamav": {
                    "status": status,
                    "viruses": [],
                    "engine_version": engine_ver,
                    "db_version": db_ver,
                    "db_date": db_date,
                    "scan_time_s": 0.0,
                    **extra,
                }
            }

        if self._clamd is None:
            stats["clamav_errors"] += 1
            return _meta("unavailable")

        max_size = int(config["xspct_clamav"].get("max_size", 26214400))
        if len(data) > max_size:
            logger.debug(
                "%s ClamAV scan skipped for %s: %d bytes > %d",
                s,
                filename,
                len(data),
                max_size,
            )
            return _meta("skipped")

        t0 = time.monotonic()
        try:
            result = self._clamd.instream(io.BytesIO(data))
        except (_clamd.ConnectionError, _clamd.ClamdError) as exc:
            logger.error("%s ClamAV unreachable: %s", s, exc)
            stats["clamav_errors"] += 1
            return _meta("error", scan_time_s=round(time.monotonic() - t0, 3))
        except Exception as exc:
            logger.error("%s ClamAV scan error for %s: %s", s, filename, exc)
            stats["clamav_errors"] += 1
            return _meta("error", scan_time_s=round(time.monotonic() - t0, 3))

        scan_time_s = round(time.monotonic() - t0, 3)
        # result: {'stream': ('OK', None)} or {'stream': ('FOUND', 'Virus.Name')}
        status_str, virus_name = result.get("stream", ("ERROR", None))

        if status_str == "ERROR":
            stats["clamav_errors"] += 1
            return _meta("error", scan_time_s=scan_time_s)

        viruses = [virus_name] if status_str == "FOUND" and virus_name else []
        if viruses:
            stats["clamav_infected"] += 1
            logger.info(
                "%s ClamAV FOUND in %s: %s (%.3f s)", s, filename, viruses, scan_time_s
            )
        else:
            stats["clamav_clean"] += 1
            logger.debug("%s ClamAV clean: %s (%.3f s)", s, filename, scan_time_s)

        partial: dict = {
            "clamav": {
                "status": "infected" if viruses else "clean",
                "viruses": viruses,
                "engine_version": engine_ver,
                "db_version": db_ver,
                "db_date": db_date,
                "scan_time_s": scan_time_s,
            }
        }
        if viruses:
            partial["analyses"] = [
                {
                    "type": "ClamAV",
                    "keyword": v,
                    "description": f"ClamAV detected: {v}"
                    + (f" [in {filename}]" if filename else ""),
                }
                for v in viruses
            ]
        return partial

    # ------------------------------------------------------------------
    # JavaScript static analysis + sandbox
    # ------------------------------------------------------------------

    # tree-sitter queries — compiled once at class definition time (tree-sitter >= 0.25).
    # Each entry: (Query, keyword, description)
    if HAS_TREESITTER:
        _TS_QUERIES: list[tuple] = [
            # Direct calls: eval(), unescape(), atob(), Function(), escape()
            (
                _TSQuery(
                    _TS_JS_LANGUAGE,
                    """
                    (call_expression
                        function: (identifier) @match
                        (#match? @match "^(eval|unescape|atob|escape|Function)$"))
                """,
                ),
                "ts-eval-call",
                "Direct call to dangerous function (AST)",
            ),
            # Member calls: document.write(), String.fromCharCode(),
            #               app.launchURL(), app.openDoc(), app.launchApp(),
            #               util.printf(), execScript()
            (
                _TSQuery(
                    _TS_JS_LANGUAGE,
                    """
                    (call_expression
                        function: (member_expression
                            property: (property_identifier) @match)
                        (#match? @match
                            "^(write|fromCharCode|launchURL|openDoc|launchApp|execScript)$"))
                """,
                ),
                "ts-member-call",
                "Dangerous member-function call (AST)",
            ),
            # Bracket/computed property access: window["eval"], this["atob"], …
            (
                _TSQuery(
                    _TS_JS_LANGUAGE,
                    """
                    (subscript_expression
                        index: (string (string_fragment) @match)
                        (#match? @match
                            "^(eval|Function|atob|unescape|escape|write|execScript)$"))
                """,
                ),
                "bracket-eval",
                "Dangerous function accessed via bracket notation — obfuscation pattern (AST)",
            ),
        ]
        # String-literal extractor — all static string values in the AST
        _TS_STRING_QUERY: "_TSQuery | None" = _TSQuery(
            _TS_JS_LANGUAGE,
            """
            (string (string_fragment) @s)
        """,
        )
    else:
        _TS_QUERIES = []
        _TS_STRING_QUERY = None

    # Patterns that indicate a script is worth looking at more closely
    _JS_SUSPICIOUS = [
        (
            r"\beval\s*\(",
            "SuspiciousJS",
            "eval()",
            "Use of eval() for dynamic code execution",
        ),
        (
            r"\bunescape\s*\(",
            "SuspiciousJS",
            "unescape()",
            "Use of unescape() — common obfuscation",
        ),
        (r"\batob\s*\(", "SuspiciousJS", "atob()", "Use of atob() for Base64 decoding"),
        (
            r"String\.fromCharCode\s*\(",
            "SuspiciousJS",
            "String.fromCharCode",
            "Character-code obfuscation",
        ),
        (
            r"document\.write\s*\(",
            "SuspiciousJS",
            "document.write()",
            "Dynamic content injection",
        ),
        (
            r"this\.exportDataObject\b",
            "SuspiciousJS",
            "exportDataObject()",
            "PDF exportDataObject — can write files to disk",
        ),
        (
            r"app\.launchURL\b",
            "SuspiciousJS",
            "app.launchURL()",
            "Launches external URLs from PDF",
        ),
        (
            r"app\.openDoc\b",
            "SuspiciousJS",
            "app.openDoc()",
            "Opens external documents from PDF",
        ),
        (
            r"util\.printf\b",
            "SuspiciousJS",
            "util.printf()",
            "Used in heap-spray exploits",
        ),
        (
            r"ActiveXObject\b",
            "SuspiciousJS",
            "ActiveXObject",
            "ActiveX object instantiation",
        ),
        (r"WScript\b", "SuspiciousJS", "WScript", "Windows Script Host reference"),
        (r"ShellExecute\b", "SuspiciousJS", "ShellExecute", "Shell execution attempt"),
    ]

    def analyze_javascript(self, js_src: str, source_label: str = "") -> list[dict]:
        """Analyse a JavaScript snippet for suspicious patterns and optionally emulate it.

        First beautifies the source with ``jsbeautifier`` (if available) and
        input ≤ 512 KB to defeat trivial minification.  Then runs static regex
        checks for known dangerous patterns.  Finally, when ``quickjs`` is
        available and the input is ≤ 512 KB, executes the snippet in a
        sandboxed QuickJS engine with a 32 MB heap cap, 256 KB stack cap, and
        a 2-second CPU time limit.  Output collected via ``print()`` /
        ``console.log()`` is further limited to 500 calls / 64 KB to prevent
        Python-side memory exhaustion.

        ``source_label`` is sanitised (control characters stripped, capped at
        80 chars) before being embedded in any report string.

        Args:
            js_src: JavaScript source code as a string.
            source_label: Human-readable label for log / analysis entries
                (e.g. ``'PDF /OpenAction'`` or ``'HTML <script>'``).

        Returns:
            List of analysis dicts with keys ``type``, ``keyword``,
            ``description``, and (for ``DynamicJS`` hits) ``confidence``.

            Notable ``type`` values:

            - **SuspiciousJS**: Static match against a known-dangerous pattern.
            - **DynamicJS**: Finding from QuickJS emulation output
              (``confidence: 'low'`` — attacker controls the printed text).
            - **DynamicJSError**: Host-level exception during emulation setup
              or eval (unexpected; may indicate an engine issue).
        """
        if not js_src or not js_src.strip():
            return []

        # Sanitise the caller-supplied label before it is embedded in any
        # report description string: strip control characters and cap length
        # so a crafted filename/object-label cannot inject newlines, JSON
        # special characters, or log-injection sequences.
        if source_label:
            source_label = re.sub(r"[\x00-\x1f\x7f]", "", source_label)[:80]

        hits: list[dict] = []

        # -- 1. Beautify -------------------------------------------------------
        _JS_BEAUTIFY_LIMIT = 512 * 1024  # 512 KB — pure-Python parser; no time guard
        if HAS_JSBEAUTIFIER and len(js_src) <= _JS_BEAUTIFY_LIMIT:
            try:
                opts = _jsbeautifier.default_options()
                opts.unescape_strings = True
                js_src = _jsbeautifier.beautify(js_src, opts)
            except Exception as exc:
                logger.debug("jsbeautifier failed (%s): %s", source_label, exc)
        elif HAS_JSBEAUTIFIER:
            logger.debug(
                "jsbeautifier skipped for %s: input too large (%d bytes > %d)",
                source_label,
                len(js_src),
                _JS_BEAUTIFY_LIMIT,
            )

        # -- 2. tree-sitter AST scan ------------------------------------------
        _JS_TS_LIMIT = 512 * 1024  # 512 KB — parse overhead guard (same as beautifier)
        if HAS_TREESITTER and len(js_src) <= _JS_TS_LIMIT:
            try:
                _ts_tree = _TS_JS_PARSER.parse(bytes(js_src, "utf-8"))
                _ts_root = _ts_tree.root_node
                for _ts_q, keyword, desc in self._TS_QUERIES:
                    if any(True for _ in _TSQueryCursor(_ts_q).matches(_ts_root)):
                        entry = {
                            "type": "SuspiciousJS",
                            "keyword": keyword,
                            "description": f"{desc} [in {source_label}]"
                            if source_label
                            else desc,
                        }
                        if entry not in hits:
                            hits.append(entry)
                # Extract static string literals and scan for URLs / IOCs.
                # QueryCursor.matches() yields (pattern_idx, {capture_name: [Node, ...]}).
                if self._TS_STRING_QUERY is not None:
                    _seen_urls: set[str] = set()
                    for _, _cap in _TSQueryCursor(self._TS_STRING_QUERY).matches(
                        _ts_root
                    ):
                        for _node in _cap.get("s", []):
                            _val = _node.text.decode("utf-8", errors="replace")
                            if re.search(r"https?://", _val):
                                _safe = re.sub(r"[\x00-\x1f\x7f]", " ", _val)[:120]
                                if _safe not in _seen_urls:
                                    _seen_urls.add(_safe)
                                    hits.append(
                                        {
                                            "type": "SuspiciousJS",
                                            "keyword": "static-url",
                                            "description": (
                                                f"URL in static JS string literal"
                                                f"{' [in ' + source_label + ']' if source_label else ''}"
                                                f": {_safe}"
                                            ),
                                        }
                                    )
            except Exception as exc:
                logger.debug("tree-sitter JS parse failed (%s): %s", source_label, exc)
        elif HAS_TREESITTER:
            logger.debug(
                "tree-sitter JS scan skipped for %s: input too large (%d bytes > %d)",
                source_label,
                len(js_src),
                _JS_TS_LIMIT,
            )

        # -- 3. Static pattern scan -------------------------------------------
        for pattern, a_type, keyword, desc in self._JS_SUSPICIOUS:
            if re.search(pattern, js_src):
                entry = {
                    "type": a_type,
                    "keyword": keyword,
                    "description": f"{desc} [in {source_label}]"
                    if source_label
                    else desc,
                }
                if entry not in hits:
                    hits.append(entry)

        # -- 3. QuickJS sandbox emulation --------------------------------------
        _JS_EMULATE_LIMIT = 512 * 1024  # 512 KB — parse/compile overhead guard
        _quickjs_enabled = (
            config.get("xspct_analyzers", {})
            .get("javascript", {})
            .get("quickjs", False)
        )
        if HAS_QUICKJS and _quickjs_enabled and len(js_src) <= _JS_EMULATE_LIMIT:
            try:
                ctx = _quickjs.Context()

                # Stub out browser/PDF globals that the sandbox doesn't have
                ctx.eval("""
                    var document = {write: function(s){ print(s); }, cookie: '', location: {href:''}};
                    var window = {location: {href:''}, navigator: {}};
                    var app = {launchURL: print, openDoc: print};
                    var console = {log: print, warn: print, error: print};
                """)

                # Capture print() output
                ctx.set_memory_limit(32 * 1024 * 1024)  # 32 MB heap cap
                ctx.set_max_stack_size(
                    256 * 1024
                )  # 256 KB stack — limits deep recursion
                ctx.set_time_limit(2)  # 2-second CPU hard limit
                # Replace print with a collector
                # Caps: max 500 individual calls and 64 KB of total text so that a
                # tight print-loop cannot grow the Python-side list unboundedly
                # (QuickJS heap is capped separately via set_memory_limit/set_time_limit,
                # but that does not constrain the host-Python memory used here).
                _COLLECT_MAX_CALLS = 500
                _COLLECT_MAX_BYTES = 64 * 1024
                collected: list[str] = []
                _collect_bytes = 0
                _collect_truncated = False

                def _collect(s=""):
                    nonlocal _collect_bytes, _collect_truncated
                    if _collect_truncated:
                        return
                    chunk = str(s)
                    _collect_bytes += len(chunk)
                    if (
                        len(collected) >= _COLLECT_MAX_CALLS
                        or _collect_bytes > _COLLECT_MAX_BYTES
                    ):
                        _collect_truncated = True
                        return
                    collected.append(chunk)

                ctx.add_callable("print", _collect)
                _js_runtime_error = False
                try:
                    ctx.eval(js_src)
                except _quickjs.JSException as exc:
                    _js_runtime_error = True
                    logger.debug("QuickJS JSException (%s): %s", source_label, exc)
                    # JSException is expected when stubs are incomplete; suppress the hit
                    # to avoid false positives on clean scripts that reference browser APIs.
                except Exception:
                    pass

                if collected:
                    combined_output = " ".join(collected)
                    logger.debug(
                        "QuickJS output from %s (%s): %r",
                        source_label,
                        "truncated" if _collect_truncated else "complete",
                        combined_output[:200],
                    )
                    # Sanitise attacker-controlled output before embedding in the report:
                    # replace control characters (including newlines) with a space so that
                    # log-injection and JSON-breaking sequences cannot pass through.
                    _safe_output = re.sub(r"[\x00-\x1f\x7f]", " ", combined_output)[
                        :120
                    ]
                    # Scan emulated output for IOCs / suspicious strings
                    if re.search(r"https?://", combined_output):
                        hits.append(
                            {
                                "type": "DynamicJS",
                                "keyword": "emulated-url",
                                # confidence:low because the script itself controls what is
                                # printed — decoy URLs can be injected to pollute the report.
                                "confidence": "low",
                                "description": (
                                    f"Dynamic JS emulation produced URL(s) "
                                    f"[{source_label}]: {_safe_output}"
                                ),
                            }
                        )
                    if re.search(r"eval\(|unescape\(|atob\(", combined_output):
                        hits.append(
                            {
                                "type": "DynamicJS",
                                "keyword": "emulated-obfuscation",
                                # confidence:low for the same reason as emulated-url.
                                "confidence": "low",
                                "description": (
                                    f"Emulated JS output contains obfuscation calls "
                                    f"[{source_label}]"
                                ),
                            }
                        )
            except _quickjs.JSException as exc:
                # JSException from the setup phase (e.g. stubs referencing undefined
                # globals) — expected, same policy as the inner handler.
                logger.debug("QuickJS setup JSException (%s): %s", source_label, exc)
            except Exception as exc:
                # A host-level (non-JS) exception during emulation setup or eval is
                # genuinely unexpected and may mask errors in a malicious payload.
                logger.debug("QuickJS emulation failed (%s): %s", source_label, exc)
                hits.append(
                    {
                        "type": "DynamicJSError",
                        "keyword": "js-emulation-error",
                        "description": (
                            f"JS emulation raised a host-level error [{source_label}]: "
                            f"{type(exc).__name__}"
                        ),
                    }
                )
        elif HAS_QUICKJS and _quickjs_enabled:
            logger.debug(
                "QuickJS emulation skipped for %s: input too large (%d bytes > %d)",
                source_label,
                len(js_src),
                _JS_EMULATE_LIMIT,
            )

        return hits

    # ------------------------------------------------------------------
    # Image analysis — OCR + QR/barcode
    # ------------------------------------------------------------------

    def analyze_image(
        self,
        image_data: bytes,
        label: str = "",
        s: str = "",
        force_analyzers: "frozenset | None" = None,
    ) -> dict:
        """Run OCR and QR/barcode decoding on raw image bytes.

        Uses ``pytesseract`` for OCR (English + German) and ``pyzbar`` for
        QR codes and barcodes.  Falls back gracefully when either library is
        unavailable.

        Args:
            image_data:       Raw image bytes (PNG, JPEG, BMP, TIFF, …).
            label:            Human-readable source label for log messages.
            force_analyzers:  Set of analyzer names whose exclusion gates are
                              bypassed (e.g. ``frozenset({'image.ocr'})``).

        Returns:
            A dict with keys:

            - **ocr_text** (list[dict]): OCR engine results with ``engine``,
              ``time_s``, and ``text`` keys. Empty when OCR is unavailable or
              skipped.
            - **qr_codes** (list[str]): Decoded QR/barcode values.
            - **analyses** (list[dict]): Suspicious findings from OCR text.
            - **iocs** (dict): URLs/IPs/domains extracted from OCR text.
            - **exclusions** (dict): Gates that blocked an analyzer for this image.
        """
        result: dict = {
            "ocr_text": [],
            "qr_codes": [],
            "analyses": [],
            "iocs": {"urls": [], "ips": [], "domains": []},
            "exif": {},
        }
        if not image_data:
            return result

        # Byte-size OCR gate runs before PIL — no image open required.
        _force_analyzers = force_analyzers or frozenset()
        _img_cfg = config.get("xspct_analyzers", {}).get("image", {})
        _ocr_max_bytes = int(_img_cfg.get("ocr_max_bytes", 0))
        if (
            "image.ocr" not in _force_analyzers
            and _ocr_max_bytes
            and len(image_data) > _ocr_max_bytes
        ):
            result["exclusions"] = {
                "image.ocr": (
                    f"file exceeds ocr_max_bytes "
                    f"({len(image_data):,} > {_ocr_max_bytes:,})"
                )
            }
            logger.debug(
                "%s OCR gate (%s): %s", s, label, result["exclusions"]["image.ocr"]
            )

        img = None
        if HAS_OCR or HAS_PYZBAR:
            try:
                img = _PILImage.open(io.BytesIO(image_data))
                # Store pixel dimensions for the file section.
                result["image_size"] = f"{img.width}x{img.height}"
            except Exception as exc:
                logger.debug("PIL cannot open image (%s): %s", label, exc)
                return result

        # -- QR / barcode decoding -------------------------------------------
        if HAS_PYZBAR and img is not None:
            try:
                decoded = _pyzbar.decode(img)
                for sym in decoded:
                    try:
                        value = sym.data.decode("utf-8", "ignore").strip()
                    except Exception:
                        value = repr(sym.data)
                    if value:
                        result["qr_codes"].append(value)
                        self._add_text_segment(
                            result, "image-qr", value, module="pyzbar"
                        )
                        result["analyses"].append(
                            {
                                "type": "QRCode",
                                "keyword": sym.type,
                                "description": f"{sym.type} decoded: {value[:120]}",
                            }
                        )
                        # Extract IOCs from QR content
                        qr_iocs = self.extract_iocs(sym.data)
                        for k in ("urls", "ips", "domains"):
                            result["iocs"][k] = sorted(
                                set(result["iocs"][k] + qr_iocs[k])
                            )
            except Exception as exc:
                logger.debug("pyzbar decoding failed (%s): %s", label, exc)

        # -- OCR gate: resolution and camera EXIF (requires PIL) -------------
        # Byte-size gate was already applied above (before PIL open).
        # Pixel/EXIF gates run here after we know the image dimensions.
        class _OcrSkipped(Exception):
            pass

        _ocr_exclusion: str = result.get("exclusions", {}).get("image.ocr", "")
        if (
            not _ocr_exclusion
            and "image.ocr" not in _force_analyzers
            and img is not None
        ):
            _w, _h = img.width, img.height
            _ocr_max_px = int(_img_cfg.get("ocr_max_pixels", 0))
            if _ocr_max_px and _w * _h > _ocr_max_px:
                _ocr_exclusion = (
                    f"image exceeds ocr_max_pixels ({_w * _h:,} > {_ocr_max_px:,})"
                )
            elif _img_cfg.get("ocr_skip_camera", True):
                # Quick camera check: EXIF tag 271=Make, 272=Model.
                try:
                    _raw_exif = img._getexif() or {}
                    if _raw_exif.get(271) or _raw_exif.get(272):
                        _make = str(_raw_exif.get(271, "")).strip()
                        _model = str(_raw_exif.get(272, "")).strip()
                        _ocr_exclusion = (
                            f"camera photo detected via EXIF"
                            f"{' (' + _make + '/' + _model + ')' if _make or _model else ''}"
                        )
                except Exception:
                    pass
            if _ocr_exclusion:
                result["exclusions"] = {"image.ocr": _ocr_exclusion}
                logger.debug("%s OCR gate (%s): %s", s, label, _ocr_exclusion)

        # -- OCR -------------------------------------------------------------
        if (HAS_OCR or HAS_EASYOCR) and img is not None and not _ocr_exclusion:
            try:
                import numpy as _np

                # Step 1: greyscale for Tesseract; RGB array for EasyOCR.
                ocr_img = img.convert("L")

                # Step 2: upscale — both engines work better with ≥150 DPI.
                #         Target 1200 px on the long side.
                w, h = ocr_img.size
                min_side = 1200
                if max(w, h) < min_side:
                    scale = min_side / max(w, h)
                    new_size = (int(w * scale), int(h * scale))
                    ocr_img = ocr_img.resize(new_size, _PILImage.LANCZOS)

                # Step 3: Pre-screen — skip OCR on images that cannot contain
                #         readable text.  Two cheap numpy signals are computed on
                #         a small thumbnail to keep this under ~1 ms:
                #
                #   pixel_std  — std-dev of pixel values.  Near-zero means a
                #                solid-colour image (blank slide, transparent PNG).
                #                Threshold: < 8  → skip.
                #
                #   edge_var   — variance of a Laplacian edge map.  Low variance
                #                means smooth gradients / photos with no sharp
                #                transitions; text always has sharp strokes.
                #                Threshold: < 20 → skip.
                #
                # Both values are logged so thresholds can be tuned.
                import PIL.ImageFilter as _ImageFilter

                _thumb = ocr_img.resize((256, 256), _PILImage.LANCZOS)
                _arr = _np.array(_thumb, dtype=_np.float32)
                _pixel_std = float(_arr.std())
                _edge_arr = _np.array(
                    _thumb.filter(
                        _ImageFilter.Kernel(
                            size=(3, 3),
                            kernel=[-1, -1, -1, -1, 8, -1, -1, -1, -1],
                            scale=1,
                        )
                    ),
                    dtype=_np.float32,
                )
                _edge_var = float(_edge_arr.var())
                logger.debug(
                    "%s OCR pre-screen (%s): pixel_std=%.1f edge_var=%.1f",
                    s,
                    label,
                    _pixel_std,
                    _edge_var,
                )
                if _pixel_std < 8 or _edge_var < 20:
                    logger.debug(
                        "%s OCR skipped (%s): image unlikely to contain text", s, label
                    )
                    result["ocr_text"] = []
                    raise _OcrSkipped()

                _ocr_texts: list[dict] = []
                _ocr_timings: dict[str, float] = {}

                # Prepare shared inputs up front so both engines can start
                # as soon as they are submitted to the thread pool.
                _rgb_img = img.resize(ocr_img.size, _PILImage.LANCZOS).convert("RGB")
                import concurrent.futures as _cf
                import warnings as _warnings

                from PIL import ImageOps as _ImageOps

                def _run_tesseract() -> "tuple[float, str]":
                    t0 = time.monotonic()
                    raw = _pytesseract.image_to_string(
                        ocr_img,
                        lang="eng+deu",
                        config="--oem 1 --psm 11 --dpi 300",
                    ).strip()
                    return round(time.monotonic() - t0, 3), raw

                def _run_easyocr() -> "tuple[float, str]":
                    # Lazy-init is not thread-safe, so initialise before
                    # submitting to the executor (we are still on the
                    # caller thread at that point).
                    _easy_variants = [
                        ("normal", _np.array(_rgb_img)),
                        ("inverted", _np.array(_ImageOps.invert(_rgb_img))),
                    ]
                    all_text: list[str] = []
                    t0 = time.monotonic()
                    for _vname, _easy_arr in _easy_variants:
                        logger.debug(
                            "%s easyocr starting (%s) variant=%s shape=%s",
                            s,
                            label,
                            _vname,
                            _easy_arr.shape,
                        )
                        with _warnings.catch_warnings():
                            _warnings.filterwarnings(
                                "ignore", message=".*pin_memory.*", category=UserWarning
                            )
                            res = self._easyocr_reader.readtext(
                                _easy_arr,
                                detail=0,
                                paragraph=False,
                                contrast_ths=0.05,
                                adjust_contrast=0.8,
                            )
                        logger.debug(
                            "%s easyocr variant=%s detections=%d raw=%r",
                            s,
                            _vname,
                            len(res),
                            res[:5],
                        )
                        all_text.extend(t.strip() for t in res if t.strip())
                        if all_text:
                            break  # normal variant found text — skip inverted
                    elapsed = round(time.monotonic() - t0, 3)
                    seen: set[str] = set()
                    deduped: list[str] = []
                    for t in all_text:
                        if t.lower() not in seen:
                            seen.add(t.lower())
                            deduped.append(t)
                    return elapsed, "\n".join(deduped)

                # Ensure EasyOCR reader is initialised on THIS thread before
                # we hand off to the executor (Reader.__init__ is not reentrant).
                if HAS_EASYOCR and self._easyocr_reader is None:
                    with _warnings.catch_warnings():
                        _warnings.filterwarnings(
                            "ignore", message=".*pin_memory.*", category=UserWarning
                        )
                        self._easyocr_reader = _easyocr.Reader(
                            ["en", "de"],
                            gpu=False,
                            verbose=False,
                        )

                # Submit both engines in parallel; collect results.
                _futures: dict[str, "_cf.Future"] = {}
                with _cf.ThreadPoolExecutor(max_workers=2) as _pool:
                    if HAS_OCR:
                        _futures["tesseract"] = _pool.submit(_run_tesseract)
                    if HAS_EASYOCR:
                        _futures["easyocr"] = _pool.submit(_run_easyocr)

                for _eng, _fut in _futures.items():
                    try:
                        _elapsed, _text = _fut.result()
                        _ocr_timings[_eng] = _elapsed
                        if _text:
                            _ocr_texts.append(
                                {"engine": _eng, "time_s": _elapsed, "text": _text}
                            )
                    except Exception as _e:
                        logger.debug("%s %s failed (%s): %s", s, _eng, label, _e)

                result["ocr_text"] = _ocr_texts
                _timing_str = ", ".join(
                    f"{eng}={t}s" for eng, t in _ocr_timings.items()
                )
                logger.debug("%s OCR timings (%s): %s", s, label, _timing_str or "none")
                # Expose OCR text as a text segment for report-level text fields.
                for _e in _ocr_texts:
                    self._add_text_segment(
                        result, "image-ocr", _e.get("text", ""), module=_e.get("engine")
                    )
                # Extract IOCs from all engine results combined.
                _all_ocr_text = "\n".join(e["text"] for e in _ocr_texts)
                if _all_ocr_text:
                    ocr_iocs = self.extract_iocs(
                        _all_ocr_text.encode("utf-8", "ignore")
                    )
                    for k in ("urls", "ips", "domains"):
                        result["iocs"][k] = sorted(set(result["iocs"][k] + ocr_iocs[k]))
                    # Detect URL-only images (common in phishing PDFs)
                    if ocr_iocs["urls"]:
                        result["analyses"].append(
                            {
                                "type": "OCRUrl",
                                "keyword": "ocr-url",
                                "description": (
                                    f"URL found in image via OCR ({label}): "
                                    + ", ".join(ocr_iocs["urls"][:3])
                                ),
                            }
                        )
            except _OcrSkipped:
                pass  # pre-screen decided OCR is not useful for this image
            except Exception as exc:
                logger.debug("%s OCR failed (%s): %s", s, label, exc)

        # -- EXIF metadata extraction ----------------------------------------
        if HAS_OCR and img is not None:
            try:
                from PIL import ExifTags as _ExifTags

                exif_raw = img._getexif() if hasattr(img, "_getexif") else None
                if exif_raw:

                    def _safe_exif(v) -> str:
                        if isinstance(v, bytes):
                            return v.decode("utf-8", "ignore")[:256]
                        return re.sub(r"[\x00-\x1f\x7f]", "", str(v))[:256]

                    result["exif"] = {
                        _ExifTags.TAGS.get(k, str(k)): _safe_exif(v)
                        for k, v in exif_raw.items()
                        if k in _ExifTags.TAGS
                    }
                    # GPS data in EXIF may be a privacy concern
                    if "GPSInfo" in result["exif"] or any(
                        "GPS" in str(k) for k in result["exif"]
                    ):
                        result["analyses"].append(
                            {
                                "type": "EXIFGps",
                                "keyword": "gps-metadata",
                                "description": f"GPS coordinates found in image EXIF ({label})",
                            }
                        )
            except Exception as exc:
                logger.debug("EXIF extraction failed (%s): %s", label, exc)

        return result

    # ------------------------------------------------------------------
    # Archive analysis
    # ------------------------------------------------------------------

    def analyze_archive(
        self, s: str, filename: str, data: bytes, depth: int = 0
    ) -> "dict | None":
        """Recursively extract and analyse files inside an archive.

        When sflock2 is installed (``HAS_SFLOCK=True``) extraction runs inside
        the zipjail usermode sandbox, giving coverage for ZIP, 7z, RAR, TAR,
        TAR.GZ, CAB, ACE, ISO, EML, MSG, MSO, and more.  Without sflock2 the
        fallback uses :mod:`zipfile` (stdlib) and :mod:`py7zr` (optional).

        Password-protected archives are tried with the daemon password list;
        sflock is called once per candidate password until ``children`` is
        non-empty.  The fallback loop mirrors the same behaviour.

        Each extracted member is passed through
        :meth:`get_detected_type` → :meth:`sync_analyze` (documents) /
        :meth:`analyze_image` / :meth:`analyze_yara` so that YARA, iocsearcher,
        and type-specific analysers run on every member.

        Args:
            s: Session tag for log messages.
            filename: Original archive filename (used for log/report only).
            data: Raw archive bytes.
            depth: Current recursion depth (callers should pass 0).

        Returns:
            A merged report dict or ``None`` when the archive cannot be opened,
            depth/size limits are exceeded, or the analyzer is disabled.
        """
        max_depth = int(config["xspct_archive_max_depth"])
        max_size = int(config["xspct_archive_max_size"])
        if max_depth == 0 or depth >= max_depth:
            return None

        enabled = self._resolve_enabled_analyzers()
        if "archive" not in enabled:
            return None

        report: dict = {
            "archive_files": [],
            "analyses": [],
            "rtf_objects": [],
            "iocs": {"urls": [], "ips": [], "domains": []},
            "yara_matches": [],
            "iocs_extended": {},
        }
        total_extracted = 0

        def _analyse_member(name: str, member_data: bytes) -> None:
            nonlocal total_extracted
            total_extracted += len(member_data)
            _yara_ok = (
                "yara" in enabled and getattr(self, "_yara_rules", None) is not None
            ) or (
                "yara_x" in enabled and getattr(self, "_yara_x_rules", None) is not None
            )
            _clamav_members = (
                HAS_CLAMD
                and config["xspct_clamav"]["enabled"]
                and config["xspct_clamav"].get("scan_members", True)
            )
            detected = self.get_detected_type(None, None, name, member_data[:4096])
            analyzers_run: list[str] = []
            member_errors: dict = {}
            findings_before = len(report["analyses"])

            def _run_member(analyzer_name: str, fn, *args):
                try:
                    return fn(*args)
                except Exception as exc:
                    logger.info(
                        "%s - archive member %s: analyzer %s error: %s",
                        s,
                        name,
                        analyzer_name,
                        exc,
                    )
                    member_errors[analyzer_name] = type(exc).__name__
                    return None

            if detected == "archive" and depth + 1 < max_depth:
                sub = _run_member(
                    "archive", self.analyze_archive, s, name, member_data, depth + 1
                )
                if sub:
                    self.merge_reports(report, sub)
                    analyzers_run.append("archive")
            elif detected in ("pdf", "html", "office", "text"):
                sub = _run_member(
                    detected, self.sync_analyze, s, name, member_data, None
                )
                if sub:
                    self.merge_reports(report, sub)
                    analyzers_run.append(detected)
                    if HAS_IOCSEARCHER and "iocs" in enabled:
                        analyzers_run.append("iocs")
                    if _yara_ok:
                        analyzers_run.append("yara")
                    if _clamav_members:
                        analyzers_run.append("clamav")
            elif detected == "image":
                sub = _run_member("image", self.analyze_image, member_data, name)
                if sub:
                    self.merge_reports(report, sub)
                    analyzers_run.append("image")
                if _yara_ok:
                    yr = _run_member("yara", self.analyze_yara, member_data)
                    if yr:
                        self.merge_reports(report, yr)
                    analyzers_run.append("yara")
                if _clamav_members:
                    cv_res = _run_member(
                        "clamav", self.analyze_clamav, member_data, name
                    )
                    if cv_res:
                        self.merge_reports(report, cv_res)
                    analyzers_run.append("clamav")
            else:
                if _yara_ok:
                    yr = _run_member("yara", self.analyze_yara, member_data)
                    if yr:
                        self.merge_reports(report, yr)
                    analyzers_run.append("yara")
                if _clamav_members:
                    cv_res = _run_member(
                        "clamav", self.analyze_clamav, member_data, name
                    )
                    if cv_res:
                        self.merge_reports(report, cv_res)
                    analyzers_run.append("clamav")

            if member_errors:
                report.setdefault("analyzer_errors", {}).update(
                    {f"{name}:{k}": v for k, v in member_errors.items()}
                )

            report["archive_files"].append(
                {
                    "name": name,
                    "size": len(member_data),
                    "sha256": hashlib.sha256(member_data).hexdigest(),
                    "rspamd_digest": _rspamd_digest(member_data),
                    "detected_type": detected,
                    "analyzers_run": analyzers_run,
                    "findings": len(report["analyses"]) - findings_before,
                }
            )

        if HAS_SFLOCK:
            # ---- sflock path: sandboxed extraction via zipjail ----------------
            if len(data) > max_size:
                logger.warning(
                    "%s - archive %s exceeds max_size (%d), skipping",
                    s,
                    filename,
                    max_size,
                )
                return None

            # Try without password first, then the daemon wordlist.
            # sflock accepts one password per call; we iterate until children
            # is non-empty or we exhaust the list.
            passwords_to_try: list = [None] + list(self.passwords[:50])
            f = None
            _sflock_hard_error = False
            for pwd in passwords_to_try:
                try:
                    f = _sflock.unpack(
                        contents=data,
                        filename=filename.encode()
                        if isinstance(filename, str)
                        else filename,
                        password=pwd,
                    )
                    if getattr(f, "children", None):
                        break
                    # No children: check whether error hints at wrong password
                    err = str(getattr(f, "error", "") or "").lower()
                    if not err or (
                        "decrypt" not in err
                        and "password" not in err
                        and "wrong" not in err
                        and "bad" not in err
                    ):
                        break  # error is not password-related — stop retrying
                except Exception as exc:
                    logger.debug(
                        "%s - sflock unpack error for %s: %s — falling back to stdlib",
                        s,
                        filename,
                        exc,
                    )
                    f = None
                    _sflock_hard_error = True
                    break

            if not _sflock_hard_error:
                if f is None or not getattr(f, "children", None):
                    return None

            if getattr(f, "password", None):
                report["decryption_password"] = str(f.password)

            def _walk_sflock(file_obj: object, current_depth: int) -> None:
                nonlocal total_extracted
                for child in getattr(file_obj, "children", None) or []:
                    _raw_name = (
                        getattr(child, "filename", None)
                        or getattr(child, "relapath", None)
                        or b"unknown"
                    )
                    child_name = (
                        _raw_name.decode("utf-8", errors="replace")
                        if isinstance(_raw_name, bytes)
                        else str(_raw_name)
                    )
                    child_contents = getattr(child, "contents", None) or b""
                    if getattr(child, "children", None):
                        # Container node (nested archive sflock already opened)
                        if current_depth + 1 < max_depth:
                            _walk_sflock(child, current_depth + 1)
                        else:
                            logger.debug(
                                "%s - sflock depth limit at %s/%s",
                                s,
                                filename,
                                child_name,
                            )
                    else:
                        # Leaf file — respect size budget
                        if total_extracted + len(child_contents) > max_size:
                            logger.warning(
                                "%s - archive %s: size limit reached", s, filename
                            )
                            return
                        _analyse_member(child_name, child_contents)

            if not _sflock_hard_error:
                _walk_sflock(f, depth)

        if (not HAS_SFLOCK or _sflock_hard_error) and config.get(
            "xspct_archive_stdlib_fallback", False
        ):
            # ---- Fallback: stdlib zipfile + optional py7zr ------------------
            # Disabled by default (no sandbox). Enable via xspct_archive_stdlib_fallback: true.
            is_zip = zipfile.is_zipfile(io.BytesIO(data))
            is_7z = data[:6] == b"7z\xbc\xaf\x27\x1c"

            if not is_zip and not is_7z:
                return None

            try:
                if is_zip:
                    with zipfile.ZipFile(io.BytesIO(data)) as zf:
                        for info in zf.infolist():
                            if info.is_dir():
                                continue
                            if total_extracted + info.file_size > max_size:
                                logger.warning(
                                    "%s - archive %s: size limit reached", s, filename
                                )
                                break
                            for pwd in [None] + [
                                p.encode() for p in self.passwords[:50]
                            ]:
                                try:
                                    member_data = zf.read(info, pwd=pwd)
                                    _analyse_member(info.filename, member_data)
                                    break
                                except RuntimeError:
                                    continue
                                except Exception as exc:
                                    logger.debug(
                                        "%s - zip member %s failed: %s",
                                        s,
                                        info.filename,
                                        exc,
                                    )
                                    break
                elif is_7z:
                    try:
                        import py7zr as _py7zr

                        with _py7zr.SevenZipFile(io.BytesIO(data), mode="r") as zf:
                            members = zf.readall()
                            for name, bio in (members or {}).items():
                                if bio is None:
                                    continue
                                member_data = bio.read()
                                if total_extracted + len(member_data) > max_size:
                                    logger.warning(
                                        "%s - 7z %s: size limit reached", s, filename
                                    )
                                    break
                                _analyse_member(name, member_data)
                    except ImportError:
                        logger.debug("py7zr not installed — 7z archive not extracted")
                        return None
            except Exception as exc:
                logger.error("%s - archive analysis error for %s: %s", s, filename, exc)

        return report if report["archive_files"] else None

    # ------------------------------------------------------------------
    # Plain-text analysis
    # ------------------------------------------------------------------

    def analyze_text(
        self, data: bytes, filename: str, file_mime: "str | None" = None
    ) -> "dict | None":
        """Analyse a plain-text or script file.

        Decodes the raw bytes (UTF-8 with fallback to latin-1), extracts
        ``text_preview`` and ``iocs``, and returns a minimal report dict
        compatible with :meth:`merge_reports`.  YARA and iocsearcher run
        separately on the same data — this method only handles baseline
        IOC extraction and text population.

        Args:
            data: Raw file bytes.
            filename: Original filename (for log messages).
            file_mime: MIME type hint (unused currently, reserved for future
                encoding heuristics).

        Returns:
            A report dict with ``text_preview``, ``iocs``, and ``analyses``
            keys, or ``None`` when the data is empty.
        """
        if not data:
            return None
        text_max = int(config.get("xspct_text_max_length", 50000))
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = data.decode("latin-1", errors="replace")
        report: dict = {
            "analyses": [],
            "iocs": self.extract_iocs(data),
        }
        self._add_text_segment(report, "text", text[:text_max], module="builtin")
        logger.debug("analyze_text: %s — %d chars", filename, len(text))
        return report

    # ------------------------------------------------------------------
    # PDF analysis
    # ------------------------------------------------------------------

    def analyze_pdf(
        self, data: bytes, custom_passwords: "list | None" = None
    ) -> "dict | None":
        """Analyse a PDF document for malware indicators.

        When PyMuPDF (``fitz``) is available the PDF object graph is walked
        directly: JavaScript actions, URI/Launch/GoToR/SubmitForm link
        annotations, embedded files, OpenAction, AcroForm/XFA fields, and
        document-level JavaScript are all inspected via the parsed object
        model rather than raw byte scanning.  A plain byte-scan fallback is
        used when PyMuPDF is not installed.

        Encrypted PDFs are decrypted automatically: *custom_passwords* are
        tried first, followed by the daemon-wide :attr:`passwords` list.

        Args:
            data: Raw PDF bytes. Must start with ``%PDF``.
            custom_passwords: Extra passwords to try before the built-in
                list (same semantics as for Office decryption).

        Returns:
            A report dict on success, or ``None`` if *data* is not a PDF.

            Report keys:
                - **has_javascript** (bool)
                - **has_openaction** (bool)
                - **has_embedded_files** (bool)
                - **has_launch** (bool)
                - **has_forms** (bool)
                - **is_encrypted** (bool)
                - **decrypted** (bool): ``True`` when an encrypted PDF was
                  successfully decrypted with a password.
                - **decryption_password** (str | None): The password that
                  unlocked the PDF, or ``None``.
                - **analyses** (list[dict]): Detected indicators.
                - **iocs** (dict): Extracted URLs, IPs, and domains.
                - **text_preview** (str)
                - **meta_document** (dict | None): Document properties
                  extracted via PyMuPDF (``title``, ``author``, ``subject``,
                  ``keywords``, ``creator``, ``producer``, ``creation_date``,
                  ``mod_date``, ``encryption``).  ``None`` when PyMuPDF is
                  unavailable or the PDF carries no metadata.
        """
        if not data.startswith(b"%PDF"):
            return None
        passwords = list(custom_passwords or []) + self.passwords
        report: dict = {
            "has_javascript": False,
            "has_openaction": False,
            "has_embedded_files": False,
            "has_launch": False,
            "has_forms": False,
            "is_encrypted": False,
            "decrypted": False,
            "decryption_password": None,
            "analyses": [],
            "iocs": {"urls": [], "ips": [], "domains": []},
        }

        if HAS_PYMUPDF:
            self._analyze_pdf_pymupdf(data, report, passwords)
        else:
            logger.debug(
                "PyMuPDF not available — falling back to byte-scan PDF analysis"
            )
            self._analyze_pdf_bytescan(data, report)

        body_iocs = self.extract_iocs(data)
        for k in ("urls", "ips", "domains"):
            report["iocs"][k] = sorted(set(report["iocs"][k] + body_iocs[k]))
        _text_max = int(config.get("xspct_text_max_length", 50000))
        self._add_text_segment(
            report,
            "pdf",
            self.extract_text_preview(data, "application/pdf", _text_max),
            module="pymupdf",
        )
        # OCR text from embedded images is added as segments during
        # _analyze_pdf_pymupdf via _merge_image_result.
        # Supplement with pdfid keyword-count heuristics when available.
        self._analyze_pdf_pdfid(data, report)
        return report

    def _analyze_pdf_pymupdf(self, data: bytes, report: dict, passwords: list) -> None:
        """Deep PDF inspection using the PyMuPDF object graph.

        Populates *report* in-place.  Called by :meth:`analyze_pdf` when
        ``fitz`` is available.

        Args:
            data: Raw PDF bytes.
            report: Accumulator dict to populate.
            passwords: Ordered list of passwords to try when the PDF is
                encrypted (custom passwords first, then the daemon-wide list).
        """

        def _add(a_type: str, keyword: str, desc: str) -> None:
            entry = {"type": a_type, "keyword": keyword, "description": desc}
            if entry not in report["analyses"]:
                report["analyses"].append(entry)

        def _add_url(url: str) -> None:
            url = url.strip()
            if url and url not in report["iocs"]["urls"]:
                report["iocs"]["urls"].append(url)

        try:
            doc = fitz.open(stream=data, filetype="pdf")
        except Exception as exc:
            logger.warning("PyMuPDF could not open PDF: %s", exc)
            self._analyze_pdf_bytescan(data, report)
            return

        try:
            # -- Encryption / password decryption --------------------------
            if doc.needs_pass:
                report["is_encrypted"] = True
                for pwd in passwords:
                    if doc.authenticate(pwd):
                        report["decrypted"] = True
                        report["decryption_password"] = pwd
                        logger.info("PDF decrypted with password: %s", pwd)
                        break
                else:
                    _add(
                        "Encryption",
                        "/Encrypt",
                        "PDF is encrypted — no matching password found",
                    )
                    return
            elif doc.is_encrypted:
                # Opened with the empty/owner password (no password needed)
                report["is_encrypted"] = True
                _add("Encryption", "/Encrypt", "PDF is encrypted")

            # -- Document-level metadata / trailer -------------------------
            # pdf_trailer() returns a raw-object string in PyMuPDF ≥ 1.25.
            trailer_str = doc.pdf_trailer()
            if isinstance(trailer_str, str) and "/Encrypt" in trailer_str:
                report["is_encrypted"] = True
                _add("Encryption", "/Encrypt", "PDF is encrypted")

            # -- Document-level JavaScript + OpenAction / AA / AcroForm -----
            # PyMuPDF ≥ 1.25 changed pdf_catalog() to return an xref int.
            # Use xref_get_keys/xref_get_key to walk the catalog dictionary.
            try:
                cat_xref = doc.pdf_catalog()
                cat_keys = doc.xref_get_keys(cat_xref)

                # /Names/JavaScript — standard JS registry used by Acrobat
                if "Names" in cat_keys:
                    names_ref = doc.xref_get_key(cat_xref, "Names")
                    if names_ref[0] == "xref":
                        names_xref = int(names_ref[1].split()[0])
                        if "JavaScript" in doc.xref_get_keys(names_xref):
                            report["has_javascript"] = True
                            _add(
                                "JavaScript",
                                "/JavaScript",
                                "JavaScript in /Names/JavaScript dictionary",
                            )
                            # Extract string values from the names-tree leaves
                            js_ref = doc.xref_get_key(names_xref, "JavaScript")
                            js_obj_str = ""
                            if js_ref[0] == "xref":
                                js_obj_str = doc.xref_object(int(js_ref[1].split()[0]))
                            else:
                                js_obj_str = doc.xref_object(names_xref)
                            # Pull plain-string values (JS code) out of the tree
                            js_strings = re.findall(r"\(([^()]{20,})\)", js_obj_str)
                            for i, js_src in enumerate(js_strings):
                                for hit in self.analyze_javascript(
                                    js_src, f"PDF /JavaScript #{i + 1}"
                                ):
                                    if hit not in report["analyses"]:
                                        report["analyses"].append(hit)

                # /OpenAction
                if "OpenAction" in cat_keys:
                    report["has_openaction"] = True
                    oa_ref = doc.xref_get_key(cat_xref, "OpenAction")
                    action_type = ""
                    js_src_oa = ""
                    if oa_ref[0] == "xref":
                        act_xref = int(oa_ref[1].split()[0])
                        act_keys = doc.xref_get_keys(act_xref)
                        if "S" in act_keys:
                            s_ref = doc.xref_get_key(act_xref, "S")
                            # value is ('name', '/JavaScript')
                            action_type = s_ref[1].lstrip("/")
                        if "JS" in act_keys:
                            js_ref2 = doc.xref_get_key(act_xref, "JS")
                            if js_ref2[0] == "string":
                                js_src_oa = js_ref2[1]
                    _add(
                        "AutoExecute",
                        "/OpenAction",
                        f"OpenAction found (type: {action_type or 'unknown'})",
                    )
                    if action_type == "JavaScript":
                        report["has_javascript"] = True
                        _add("JavaScript", "/OpenAction/JS", "JavaScript in OpenAction")
                        if js_src_oa:
                            for hit in self.analyze_javascript(
                                js_src_oa, "PDF /OpenAction"
                            ):
                                if hit not in report["analyses"]:
                                    report["analyses"].append(hit)

                # /AA (Additional Actions at document level)
                if "AA" in cat_keys:
                    _add(
                        "AutoExecute",
                        "/AA",
                        "Additional Actions (AA) on document level found",
                    )

                # /AcroForm
                if "AcroForm" in cat_keys:
                    acro_ref = doc.xref_get_key(cat_xref, "AcroForm")
                    if acro_ref[0] == "xref":
                        acro_keys = doc.xref_get_keys(int(acro_ref[1].split()[0]))
                        if "XFA" in acro_keys:
                            report["has_forms"] = True
                            _add(
                                "XFA",
                                "/XFA",
                                "XML Forms Architecture (XFA) found — can contain scripts",
                            )
                        else:
                            report["has_forms"] = True
                            _add("AcroForm", "/AcroForm", "PDF AcroForm found")
                    else:
                        report["has_forms"] = True
                        _add("AcroForm", "/AcroForm", "PDF AcroForm found")

            except Exception as exc:
                logger.debug("PDF catalog inspection failed: %s", exc)

            # -- Embedded files --------------------------------------------
            try:
                ef_count = doc.embfile_count()
                if ef_count > 0:
                    report["has_embedded_files"] = True
                    names = []
                    for i in range(ef_count):
                        info = doc.embfile_info(i)
                        names.append(info.get("filename", f"file{i}"))
                    embedded_names = ", ".join(names[:5])
                    _add(
                        "EmbeddedFile",
                        "/EmbeddedFiles",
                        f"{ef_count} embedded file(s): {embedded_names}",
                    )
            except Exception as exc:
                logger.debug("PDF embedded file check failed: %s", exc)

            # -- Page-level: links, annotations, actions -------------------
            for page in doc:
                try:
                    for link in page.get_links():
                        uri = link.get("uri", "")
                        kind = link.get("kind", 0)
                        # kind 2 = external URI
                        if uri:
                            _add_url(uri)
                        # kind 4 = launch action
                        if kind == fitz.LINK_LAUNCH:
                            report["has_launch"] = True
                            _add(
                                "Execution",
                                "/Launch",
                                f"Launch action found: {uri or '(no URI)'}",
                            )
                        # kind 5 = named action  (e.g. GoToR)
                        if kind == fitz.LINK_NAMED:
                            _add(
                                "AutoExecute",
                                "/Named",
                                f"Named action on page {page.number}: {uri}",
                            )

                    for annot in page.annots():
                        adict = annot.info
                        # URI annotations
                        uri = adict.get("uri") or ""
                        if uri:
                            _add_url(uri)
                        # Subtype-level checks
                        subtype = annot.type[1] if annot.type else ""
                        if subtype == "FileAttachment":
                            report["has_embedded_files"] = True
                            fname = adict.get("file", "unknown")
                            _add(
                                "EmbeddedFile",
                                "/FileAttachment",
                                f"File attachment annotation: {fname}",
                            )
                        if subtype == "Screen":
                            _add(
                                "Execution",
                                "/Screen",
                                "Screen annotation found (can trigger media/scripts)",
                            )

                    # Widget annotations (form fields with JS)
                    for widget in page.widgets() or []:
                        widget_js_found = False
                        for attr in (
                            "script",
                            "script_stroke",
                            "script_format",
                            "script_change",
                            "script_calc",
                        ):
                            js = getattr(widget, attr, None)
                            if js:
                                report["has_javascript"] = True
                                if not widget_js_found:
                                    _add(
                                        "JavaScript",
                                        "/Widget/JS",
                                        f"JavaScript in form widget ({attr})",
                                    )
                                    widget_js_found = True
                                for hit in self.analyze_javascript(
                                    js, f"PDF widget/{attr} page {page.number}"
                                ):
                                    if hit not in report["analyses"]:
                                        report["analyses"].append(hit)

                except Exception as exc:
                    logger.debug("PDF page %d inspection failed: %s", page.number, exc)

            # -- Image extraction + OCR / QR scan -------------------------
            if HAS_OCR or HAS_PYZBAR:
                try:
                    for page in doc:
                        for img_info in page.get_images():
                            xref = img_info[0]
                            base_image = doc.extract_image(xref)
                            img_bytes = base_image.get("image", b"")
                            if img_bytes:
                                img_result = self.analyze_image(
                                    img_bytes,
                                    label=f"PDF page {page.number} xref {xref}",
                                )
                                self._merge_image_result(
                                    report, img_result, "pdf-image"
                                )
                except Exception as exc:
                    logger.debug("PDF image extraction failed: %s", exc)

            # -- Document metadata ------------------------------------------
            try:
                raw_meta = doc.metadata or {}

                def _clean(v: str) -> str:
                    return re.sub(r"[\x00-\x1f\x7f]", "", str(v or ""))[:256]

                report["meta_document"] = {
                    "title": _clean(raw_meta.get("title")),
                    "author": _clean(raw_meta.get("author")),
                    "subject": _clean(raw_meta.get("subject")),
                    "keywords": _clean(raw_meta.get("keywords")),
                    "creator": _clean(raw_meta.get("creator")),
                    "producer": _clean(raw_meta.get("producer")),
                    "creation_date": _clean(raw_meta.get("creationDate")),
                    "mod_date": _clean(raw_meta.get("modDate")),
                    "encryption": _clean(raw_meta.get("encryption")),
                }
            except Exception as exc:
                logger.debug("PDF metadata extraction failed: %s", exc)

        finally:
            doc.close()

    def _analyze_pdf_bytescan(self, data: bytes, report: dict) -> None:
        """Byte-scan PDF fallback used when PyMuPDF is unavailable.

        Searches for dangerous keyword markers directly in the raw byte
        stream and extracts ``/URI`` values with a regex.

        Args:
            data: Raw PDF bytes.
            report: Accumulator dict to populate.
        """
        markers = {
            b"/JS": ("JavaScript", "Embedded JavaScript code found"),
            b"/JavaScript": ("JavaScript", "Embedded JavaScript code found"),
            b"/OpenAction": ("AutoExecute", "Automatic action on open found"),
            b"/AA": ("AutoExecute", "Additional Action (auto-execute) found"),
            b"/EmbeddedFiles": ("EmbeddedFile", "Embedded files found in PDF"),
            b"/Launch": (
                "Execution",
                "Launch action found (can execute external programs)",
            ),
            b"/Encrypt": ("Encryption", "PDF is encrypted"),
            b"/XFA": ("XFA", "XML Forms Architecture (can contain scripts) found"),
        }
        for marker, (m_type, desc) in markers.items():
            if marker in data:
                entry = {
                    "type": m_type,
                    "keyword": marker.decode("ascii"),
                    "description": desc,
                }
                if entry not in report["analyses"]:
                    report["analyses"].append(entry)
                if m_type == "JavaScript":
                    report["has_javascript"] = True
                if m_type == "AutoExecute":
                    report["has_openaction"] = True
                if m_type == "EmbeddedFile":
                    report["has_embedded_files"] = True
                if m_type == "Execution":
                    report["has_launch"] = True
                if m_type == "Encryption":
                    report["is_encrypted"] = True
        for uri in re.findall(rb"/URI\s*\((https?://[^\)]+)\)", data):
            try:
                url = uri.decode("utf-8", "ignore").strip()
                if url and url not in report["iocs"]["urls"]:
                    report["iocs"]["urls"].append(url)
            except Exception:
                pass

    def _analyze_pdf_pdfid(self, data: bytes, report: dict) -> None:
        """Supplement PDF analysis with pdfid keyword-count heuristics.

        pdfid counts occurrences of named PDF keywords (``/JS``,
        ``/OpenAction``, ``/Encrypt``, etc.) directly in the raw byte
        stream.  Results are added to *report* under ``pdfid_keywords``
        (a ``{keyword: count}`` dict) and any suspicious keywords produce
        additional ``analyses`` entries prefixed with ``pdfid-``.

        This analysis runs **in addition to** :meth:`_analyze_pdf_pymupdf` /
        :meth:`_analyze_pdf_bytescan` and is skipped when the vendored
        ``pdfid.py`` is not present.

        Args:
            data: Raw PDF bytes.
            report: Report dict to enrich in-place.
        """
        if not HAS_PDFID or _vendored_pdfid is None:
            return
        import tempfile

        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                suffix=".pdf", delete=False, mode="wb"
            ) as fh:
                os.fchmod(fh.fileno(), 0o600)
                fh.write(data)
                tmp_path = fh.name
            result = _vendored_pdfid.PDFiD(
                tmp_path, allNames=False, extraData=False, disarm=False, force=False
            )
            json_str = _vendored_pdfid.PDFiD2JSON(result, "")
            pdfid_data = json.loads(json_str)[0]["pdfid"]
            keywords = {
                kw["name"]: kw["count"]
                for kw in pdfid_data.get("keywords", {}).get("keyword", [])
            }
            report["pdfid_keywords"] = keywords
            # Flag keywords that indicate suspicious content
            _SUSPICIOUS_PDFID: dict = {
                "/JS": ("JavaScript", "JavaScript keyword count"),
                "/JavaScript": ("JavaScript", "JavaScript keyword count"),
                "/AA": ("AutoExecute", "Additional Actions keyword count"),
                "/OpenAction": ("AutoExecute", "OpenAction keyword count"),
                "/Launch": ("Execution", "Launch action keyword count"),
                "/EmbeddedFile": ("EmbeddedFile", "EmbeddedFile keyword count"),
                "/Encrypt": ("Encryption", "Encrypt keyword count"),
                "/XFA": ("XFA", "XFA keyword count"),
                "/JBIG2Decode": ("JBIG2", "JBIG2Decode — CVE-2009-0658 related"),
                "/RichMedia": ("RichMedia", "RichMedia — Flash/3D embedding"),
            }
            for kw, (a_type, desc_prefix) in _SUSPICIOUS_PDFID.items():
                count = keywords.get(kw, 0)
                if count > 0:
                    entry = {
                        "type": f"pdfid-{a_type}",
                        "keyword": kw,
                        "description": f"pdfid: {desc_prefix} ({count})",
                    }
                    if entry not in report["analyses"]:
                        report["analyses"].append(entry)
            # Extra metadata from pdfid
            report.setdefault("pdfid_meta", {}).update(
                {
                    "count_eof": pdfid_data.get("countEof", 0),
                    "count_chat_after_eof": pdfid_data.get("countChatAfterLastEof", 0),
                    "total_entropy": pdfid_data.get("totalEntropy", 0.0),
                    "stream_entropy": pdfid_data.get("streamEntropy", 0.0),
                    "non_stream_entropy": pdfid_data.get("nonStreamEntropy", 0.0),
                }
            )
        except Exception as exc:
            logger.debug("pdfid analysis failed: %s", exc)
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    # ------------------------------------------------------------------
    # HTML analysis
    # ------------------------------------------------------------------

    def _analyze_css_hiding(self, text: str) -> list[dict]:
        """Detect CSS-based techniques used to hide content from human readers.

        Inspects all ``<style>`` block content and ``style=""`` attribute
        values for patterns that make elements invisible or move them off
        screen, and flags remote stylesheet loading that prevents static
        inspection of the final rendered appearance.

        Args:
            text: The full decoded HTML document as a string.

        Returns:
            A (possibly empty) list of analysis-hit dicts, each with
            ``type``, ``keyword``, and ``description`` keys.
        """
        hits: list[dict] = []

        # Collect CSS text from <style> blocks and inline style= attributes.
        style_blocks = re.findall(r"<style[^>]*>(.*?)</style>", text, re.I | re.S)
        inline_styles = re.findall(r'style=["\']([^"\']{1,2000})["\']', text, re.I)
        all_css = "\n".join(style_blocks + inline_styles)

        # --- Invisible/collapsed element patterns ---
        _HIDING: list[tuple[str, str, str]] = [
            (
                r"display\s*:\s*none",
                "display:none",
                "CSS display:none hides element from view",
            ),
            (
                r"visibility\s*:\s*hidden",
                "visibility:hidden",
                "CSS visibility:hidden hides element without collapsing it",
            ),
            (
                r"opacity\s*:\s*0(?:[^.]|$)",
                "opacity:0",
                "CSS opacity:0 makes element fully transparent",
            ),
            (
                r"font-size\s*:\s*0",
                "font-size:0",
                "CSS font-size:0 collapses text to zero height",
            ),
            (
                r"(?:width|height)\s*:\s*0\s*(?:px\b|;|$)",
                "width/height:0",
                "CSS zero-dimension collapses element to invisible sliver",
            ),
            (
                r"(?:max-width|max-height)\s*:\s*0\s*(?:px\b|;|$)",
                "max-width/height:0",
                "CSS max-dimension:0 collapses element",
            ),
            (
                r"overflow\s*:\s*hidden",
                "overflow:hidden",
                "CSS overflow:hidden (possible clipping of phishing content)",
            ),
            (
                # position:absolute|fixed with a large negative top or left offset
                r"position\s*:\s*(?:absolute|fixed)",
                "position:absolute/fixed",
                "CSS absolute/fixed positioning (check for off-screen placement)",
            ),
            (
                r"(?:top|left)\s*:\s*-\d{3,}",
                "top/left negative offset",
                "CSS off-screen negative offset (content moved far outside viewport)",
            ),
            (
                r"color\s*:\s*(?:#(?:fff(?:fff)?|ffffff)|white\b|rgba?\(\s*255\s*,\s*255\s*,\s*255)",
                "color:white",
                "CSS white text colour (possible white-on-white steganographic hiding)",
            ),
            (
                r"background(?:-color)?\s*:\s*(?:#(?:000(?:000)?|ffffff|fff\b)|black\b|white\b)",
                "background:black/white",
                "CSS solid black or white background (combined with matching text = invisible)",
            ),
            (
                r"clip(?:-path)?\s*:\s*rect\(\s*0",
                "clip:rect(0)",
                "CSS clip:rect(0,0,0,0) collapses visible area to nothing",
            ),
        ]
        for pattern, keyword, desc in _HIDING:
            if re.search(pattern, all_css, re.I):
                hits.append(
                    {
                        "type": "CSSHiding",
                        "keyword": keyword,
                        "description": desc,
                    }
                )

        # --- Remote CSS loading (hides effective styles from static analysis) ---
        # <link rel="stylesheet" href="https://...">  (attribute order may vary)
        external_links = re.findall(
            r'<link\b[^>]*\brel=["\']stylesheet["\'][^>]*\bhref=["\'](\s*https?://[^"\']+)["\']'
            r'|<link\b[^>]*\bhref=["\'](\s*https?://[^"\']+)["\'][^>]*\brel=["\']stylesheet["\']',
            text,
            re.I,
        )
        n_links = sum(1 for pair in external_links if any(pair))
        if n_links:
            hits.append(
                {
                    "type": "ExternalCSS",
                    "keyword": "<link rel=stylesheet>",
                    "description": (
                        f"Remote CSS stylesheet loaded via <link> ({n_links} URL(s)) — "
                        "rendered appearance cannot be determined without fetching the URL"
                    ),
                }
            )

        # @import url("https://...") or @import "https://..." inside <style> blocks
        css_imports = re.findall(
            r'@import\s+(?:url\s*\(\s*)?["\']?(https?://[^"\')\s]+)',
            all_css,
            re.I,
        )
        if css_imports:
            hits.append(
                {
                    "type": "ExternalCSS",
                    "keyword": "@import",
                    "description": (
                        f"CSS @import of remote stylesheet ({len(css_imports)} URL(s)) — "
                        "allows server-side injection of hiding rules at render time"
                    ),
                }
            )

        return hits

    def analyze_html(self, data: bytes) -> "dict | None":
        """Analyse an HTML document for phishing and malware indicators.

        Detects suspicious JavaScript functions, HTML forms, iframes,
        meta-refresh redirects, large Base64-encoded blobs that may
        indicate HTML smuggling, and injected tracker/affiliate redirect
        scripts (``<script src="…?u=…">`` pattern used in spam campaigns).

        Args:
            data: Raw HTML bytes.

        Returns:
            A report dict on success, or ``None`` if *data* does not look
            like HTML.

            Report keys:
                - **has_scripts** (bool)
                - **has_forms** (bool)
                - **has_iframes** (bool)
                - **has_meta_refresh** (bool)
                - **analyses** (list[dict]): Detected indicators.
                - **iocs** (dict): Extracted URLs, IPs, and domains.
                - **text_preview** (str)
        """
        header = data[:4096]
        if b"<" not in header and b"http-equiv" not in header.lower():
            return None
        report: dict = {
            "has_scripts": False,
            "has_forms": False,
            "has_iframes": False,
            "has_meta_refresh": False,
            "analyses": [],
            "iocs": {"urls": [], "ips": [], "domains": []},
        }
        try:
            text = data.decode("utf-8", "ignore")
        except Exception:
            text = data.decode("ascii", "ignore")
        if re.search(r"<script", text, re.I):
            report["has_scripts"] = True
            for func, desc in {
                "eval(": "Use of eval() for dynamic code execution",
                "unescape(": "Use of unescape() (often used for obfuscation)",
                "document.write(": "Use of document.write() for dynamic content",
                "atob(": "Use of atob() for Base64 decoding",
                "String.fromCharCode(": "Use of String.fromCharCode() for obfuscation",
            }.items():
                if func in text:
                    report["analyses"].append(
                        {
                            "type": "SuspiciousJS",
                            "keyword": func,
                            "description": desc,
                        }
                    )
        if re.search(r"<form", text, re.I):
            report["has_forms"] = True
            report["analyses"].append(
                {
                    "type": "HTMLForm",
                    "keyword": "form",
                    "description": "HTML form found (potential phishing)",
                }
            )
        if re.search(r"<iframe", text, re.I):
            report["has_iframes"] = True
            report["analyses"].append(
                {
                    "type": "HTMLIframe",
                    "keyword": "iframe",
                    "description": "HTML iframe found (potential hidden content)",
                }
            )
        if re.search(r'http-equiv=["\']refresh["\']', text, re.I):
            report["has_meta_refresh"] = True
            report["analyses"].append(
                {
                    "type": "HTMLRedirect",
                    "keyword": "meta-refresh",
                    "description": "Automatic redirect via meta-refresh found",
                }
            )
        blobs = re.findall(r"[a-zA-Z0-9+/]{1000,}", text)
        if blobs:
            report["analyses"].append(
                {
                    "type": "HTMLSmuggling",
                    "keyword": "base64-blob",
                    "description": f"Large Base64-like blob found ({len(blobs)} blobs > 1000 chars)",
                }
            )
        # External script injection: <script src="https://...">
        # Two sub-patterns:
        #   1. Tracker/affiliate URLs with a ?u= token (original narrow pattern)
        #   2. Any external HTTP(S) script src — remote script injection is
        #      inherently suspicious regardless of query parameter name.
        tracker_scripts = re.findall(
            r'<script[^>]+src=["\']([^"\']*\?u=[a-zA-Z0-9]{8,}[^"\']*)["\']',
            text,
            re.I,
        )
        if tracker_scripts:
            report["analyses"].append(
                {
                    "type": "SpamRedirect",
                    "keyword": "script-tracker-url",
                    "description": (
                        f"Injected tracker/affiliate redirect script found "
                        f"({len(tracker_scripts)} URL(s) with ?u= parameter)"
                    ),
                }
            )
        # Any external <script src="http(s)://..."> not already caught above
        all_external_scripts = re.findall(
            r'<script[^>]+src=["\'](\s*https?://[^"\']+)["\']',
            text,
            re.I,
        )
        extra_external = [u for u in all_external_scripts if u not in tracker_scripts]
        if extra_external:
            report["analyses"].append(
                {
                    "type": "ExternalScript",
                    "keyword": "external-script-src",
                    "description": (
                        f'External <script src="http…"> found '
                        f"({len(extra_external)} URL(s)) — remote code execution risk"
                    ),
                }
            )
        # Detect CSS-based content-hiding techniques
        for hit in self._analyze_css_hiding(text):
            if hit not in report["analyses"]:
                report["analyses"].append(hit)
        report["iocs"] = self.extract_iocs(data)
        # Analyse inline JavaScript blocks
        for script_body in re.findall(
            r"<script[^>]*>(.*?)</script>", text, re.I | re.S
        ):
            if script_body.strip():
                for hit in self.analyze_javascript(script_body, "HTML <script>"):
                    if hit not in report["analyses"]:
                        report["analyses"].append(hit)
        # Analyse inline base64-encoded images (data URIs)
        if HAS_OCR or HAS_PYZBAR:
            for i, (mime_hint, b64data) in enumerate(
                re.findall(
                    r'<img[^>]+src=["\']data:(image/[^;]+);base64,([A-Za-z0-9+/=\s]{100,})["\']',
                    text,
                    re.I,
                )
            ):
                try:
                    img_bytes = __import__("base64").b64decode(
                        b64data.replace(" ", "").replace("\n", "").replace("\r", "")
                    )
                    img_result = self.analyze_image(
                        img_bytes, label=f"HTML data-URI image {i + 1} ({mime_hint})"
                    )
                    self._merge_image_result(report, img_result, "html-image")
                except Exception as exc:
                    logger.debug("HTML inline image %d decode failed: %s", i + 1, exc)
        _text_max = int(config.get("xspct_text_max_length", 50000))
        self._add_text_segment(
            report,
            "html",
            self.extract_text_preview(data, "text/html", _text_max),
            module="builtin",
        )
        return report

    # ------------------------------------------------------------------
    # Text preview
    # ------------------------------------------------------------------

    def extract_text_preview(
        self, data: bytes, file_mime: "str | None", limit: int = 2000
    ) -> str:
        """Extract a human-readable text preview from document bytes.

        Handles HTML (tag stripping), RTF (via :class:`TextExtractorRtf`),
        OOXML (XML extraction), and falls back to printable-ASCII filtering
        for all other formats.

        Args:
            data: Raw document bytes.
            file_mime: MIME type hint used to choose the extraction strategy.
            limit: Maximum number of characters to return.

        Returns:
            A whitespace-normalised string of at most *limit* characters.
        """
        mime_lower = (file_mime or "").lower()
        if "html" in mime_lower or mime_lower == "application/xhtml+xml":
            try:
                text = data.decode("utf-8", "ignore")
                text = re.sub(
                    r"<(script|style)[^>]*>.*?</\1>", " ", text, flags=re.I | re.S
                )
                text = re.sub(r"<[^>]+>", " ", text)
                return re.sub(r"\s+", " ", text)[:limit].strip()
            except Exception:
                pass
        if "rtf" in mime_lower or data.startswith(b"{\\rt"):
            try:
                te = TextExtractorRtf(data)
                return re.sub(r"\s+", " ", te.get_text())[:limit].strip()
            except Exception as exc:
                logger.warning("RTF text extraction failed: %s", exc)
        if "pdf" in mime_lower or data.startswith(b"%PDF"):
            if HAS_PYMUPDF:
                try:
                    doc = fitz.open(stream=data, filetype="pdf")
                    parts = []
                    for page in doc:
                        parts.append(page.get_text())
                        if sum(len(p) for p in parts) >= limit * 2:
                            break
                    doc.close()
                    return re.sub(r"\s+", " ", " ".join(parts))[:limit].strip()
                except Exception as exc:
                    logger.debug("PyMuPDF text extraction failed: %s", exc)
        if "openxmlformats" in mime_lower:
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    for xml_path in ("word/document.xml", "xl/worksheets/sheet1.xml"):
                        if xml_path in z.namelist():
                            content = z.read(xml_path).decode("utf-8", "ignore")
                            text = re.sub(r"<[^>]+>", " ", content)
                            return re.sub(r"\s+", " ", text)[:limit].strip()
            except Exception:
                pass
        printable = "".join(
            chr(c) if 32 <= c <= 126 or c in (9, 10, 13) else " " for c in data
        )
        return re.sub(r"\s+", " ", printable)[:limit].strip()

    # ------------------------------------------------------------------
    # File type detection
    # ------------------------------------------------------------------

    def get_detected_type(
        self,
        mime: "str | None",
        desc: "str | None",
        filename: "str | None",
        data: "bytes | None",
    ) -> str:
        """Determine the analysis type to run for a given file.

        Checks MIME type, magic description string, filename extension, and
        (for RTF) the magic bytes ``{\\rt`` in that order.

        Args:
            mime: MIME type string (e.g. ``application/pdf``).
            desc: Human-readable magic description (e.g. ``PDF document``).
            filename: Original filename (used for extension matching).
            data: First few bytes of the file (used for RTF magic detection).

        Returns:
            One of ``'pdf'``, ``'html'``, ``'office'``, ``'image'``,
            ``'archive'``, ``'text'``, or ``'unknown'``.
        """
        mime = (mime or "").lower()
        desc = (desc or "").lower()
        filename = (filename or "").lower()

        _t = TYPE_ROUTING

        # PDF: substring 'pdf' in mime/desc handled explicitly (not via mime_fragments
        # which are reserved for real glob-prefix patterns like application/vnd.ms-*).
        _pdf = _t["pdf"]
        if (
            "pdf" in mime
            or any(kw in desc for kw in _pdf["magic_keywords"])
            or any(filename.endswith(e) for e in _pdf["extensions"])
        ):
            return "pdf"

        # HTML / XHTML (SVG handled separately after office checks)
        _html = _t["html"]
        if (
            "html" in mime
            or any(kw in desc for kw in _html["magic_keywords"])
            or mime == "application/xhtml+xml"
            or any(filename.endswith(e) for e in (".html", ".htm", ".xhtml"))
        ):
            return "html"

        # RTF → processed as office
        _off = _t["office"]
        if (
            mime in _off["mime_exact"]
            or "rtf" in mime
            or "rtf" in desc
            or (data and data.startswith(b"{\\rt"))
        ):
            return "office"

        # EML / MSG: treat as archive so sflock2 can extract attachments in-sandbox.
        # These checks must come before the broad vnd.ms-* office MIME fragment so
        # that application/vnd.ms-outlook is not mistakenly classified as office.
        _arc = _t["archive"]
        _MAIL_MIMES = ("message/rfc822", "application/vnd.ms-outlook")
        _MAIL_EXTS = (".eml", ".mso")
        if mime in _MAIL_MIMES or any(filename.endswith(e) for e in _MAIL_EXTS):
            return "archive"

        # OLE2 / Compound Document / generic binary → office
        if any(kw in desc for kw in _off["magic_keywords"]):
            return "office"

        # MS-Office and ODF MIME types → office
        if any(f in mime for f in _off["mime_fragments"]):
            return "office"

        # Office filename extensions → office
        if any(filename.endswith(e) for e in _off["extensions"]):
            return "office"

        # SVG is XML-based and can contain <script>, event handlers, and external
        # references — treat it like HTML rather than a binary image.
        if mime == "image/svg+xml" or filename.endswith(".svg"):
            return "html"

        # Raster images
        _img = _t["image"]
        if any(mime.startswith(p) for p in _img["mime_prefixes"]) or any(
            filename.endswith(e) for e in _img["extensions"]
        ):
            return "image"

        # Archives
        if (
            mime in _arc["mime_exact"]
            or any(filename.endswith(e) for e in _arc["extensions"])
            or any(kw in desc for kw in _arc["magic_keywords"])
        ):
            return "archive"

        # Plain text / scripts — check both MIME/magic and common file extensions
        _txt = _t["text"]
        if (
            any(mime.startswith(p) for p in _txt["mime_prefixes"])
            or any(kw in desc for kw in _txt["magic_keywords"])
            or any(filename.endswith(e) for e in _txt["extensions"])
        ):
            return "text"

        return "unknown"

    # ------------------------------------------------------------------
    # Report merging
    # ------------------------------------------------------------------

    def merge_reports(self, target: dict, source: "dict | None") -> None:
        """Merge a partial analysis report into an accumulator dict in-place.

        Rules:
            - ``analyses`` and ``rtf_objects`` lists are appended without
              duplicates.
            - ``iocs`` sub-dicts are union-merged and sorted.
            - Boolean indicator flags are OR-ed together.
            - ``text_segments`` (and ``text_full`` from finalized sub-reports)
              accumulate deduplicated ``{source, text}`` entries; ``text_preview``
              is derived at finalize time and never merged directly.
              ``decryption_password`` keeps the longest non-empty value.
            - ``meta_document``: the first non-``None`` value wins (PDF and
              OLE never both produce metadata for the same file).
            - The ``meta`` key is never overwritten.

        Args:
            target: The accumulator report dict to merge *source* into.
            source: A partial report dict returned by one of the
                ``analyze_*`` methods. Ignored if ``None``.
        """
        if not source:
            return
        # Use a set of hashable keys for O(1) deduplication of list items.
        _analyses_seen: set[tuple] = (
            {(d["type"], d["keyword"], d["description"]) for d in target["analyses"]}
            if target.get("analyses")
            else set()
        )
        for key, value in source.items():
            if key == "analyses":
                for item in value:
                    _key = (item["type"], item["keyword"], item["description"])
                    if _key not in _analyses_seen:
                        _analyses_seen.add(_key)
                        target["analyses"].append(item)
            elif key == "iocs":
                for ik in ("urls", "ips", "domains"):
                    target["iocs"][ik] = sorted(
                        set(target["iocs"][ik] + value.get(ik, []))
                    )
            elif key == "rtf_objects":
                for item in value:
                    if item not in target["rtf_objects"]:
                        target["rtf_objects"].append(item)
            elif key == "yara_matches":
                existing = target.setdefault("yara_matches", [])
                for item in value:
                    if item not in existing:
                        existing.append(item)
            elif key == "iocs_extended":
                # Deep-merge extended IOC sub-dicts (each value is a list[str])
                existing_ext = target.setdefault("iocs_extended", {})
                for ioc_type, values in value.items():
                    existing_ext[ioc_type] = sorted(
                        set(existing_ext.get(ioc_type, [])) | set(values)
                    )
            elif key in ("pdfid_keywords", "pdfid_meta"):
                # First non-empty value wins (a file is only parsed once by pdfid)
                if value and not target.get(key):
                    target[key] = value
            elif key == "archive_files":
                existing_af = target.setdefault("archive_files", [])
                for item in value:
                    if item not in existing_af:
                        existing_af.append(item)
            elif key == "exif":
                if value and not target.get("exif"):
                    target["exif"] = value
            elif key == "clamav":
                if value is not None:
                    target["clamav"] = value
            elif key == "analyzer_errors":
                target.setdefault("analyzer_errors", {}).update(value)
            elif key == "exclusions":
                # Per-image OCR-gate reasons → aggregate into scan_exclusions.
                target.setdefault("scan_exclusions", {}).update(value)
            elif key == "analyzer_timings":
                target.setdefault("analyzer_timings", {}).update(value)
            elif key == "text_segments":
                for seg in value or []:
                    if isinstance(seg, dict):
                        self._add_text_segment(
                            target,
                            seg.get("source", ""),
                            seg.get("text", ""),
                            module=seg.get("module"),
                        )
            elif key == "text_full":
                # Finalized sub-reports (e.g. archive members) expose text as a
                # list of {source, text}; fold it back into the accumulator so
                # the parent's text_preview/text_full include the member text.
                for seg in value or []:
                    if isinstance(seg, dict):
                        self._add_text_segment(
                            target,
                            seg.get("source", ""),
                            seg.get("text", ""),
                            module=seg.get("module"),
                        )
            elif key == "text_preview":
                continue  # derived from text_segments; never merged directly
            elif key in (
                "has_macro",
                "has_javascript",
                "has_openaction",
                "has_embedded_files",
                "has_launch",
                "is_encrypted",
                "has_scripts",
                "has_forms",
                "has_iframes",
                "has_meta_refresh",
                "decrypted",
            ):
                if isinstance(value, bool):
                    target[key] = target.get(key, False) or value
            elif key == "decryption_password":
                if value and (
                    not target.get(key)
                    or len(str(value)) > len(str(target.get(key, "")))
                ):
                    target[key] = value
            elif key == "meta":
                continue
            elif key == "meta_document":
                # Keep the first non-None metadata block; PDF and OLE each
                # produce at most one, and they are never both present.
                if value and not target.get("meta_document"):
                    target["meta_document"] = value
            elif key not in target:
                target[key] = value

    # ------------------------------------------------------------------
    # Office / OLE / RTF analysis
    # ------------------------------------------------------------------

    _ODF_MIMES = (
        "application/vnd.oasis.opendocument.text",
        "application/vnd.oasis.opendocument.spreadsheet",
        "application/vnd.oasis.opendocument.presentation",
        "application/vnd.oasis.opendocument.graphics",
        "application/vnd.oasis.opendocument.formula",
    )
    _ODF_EXTS = (".odt", ".ods", ".odp", ".odg", ".odf")

    @staticmethod
    def _is_odf(data: bytes, file_mime: "str | None", filename: str) -> bool:
        """Return True if the file is an OpenDocument Format (ODF) document.

        Checks MIME type prefix, filename extension, and the ``mimetype``
        entry inside the ZIP archive (the most reliable indicator).

        Args:
            data: Raw file bytes.
            file_mime: MIME type string, or None.
            filename: Original filename (used for extension check).

        Returns:
            True when the file is identified as ODF, False otherwise.
        """
        mime = (file_mime or "").lower()
        if mime.startswith("application/vnd.oasis.opendocument"):
            return True
        name = filename.lower()
        if any(name.endswith(e) for e in InspectorDaemon._ODF_EXTS):
            return True
        # Check the ZIP mimetype entry — the most authoritative indicator.
        # All conformant ODF files store their MIME type as the first entry
        # in the ZIP archive (uncompressed) at path "mimetype".
        if data[:2] == b"PK":
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    if "mimetype" in z.namelist():
                        mt = (
                            z.read("mimetype").strip().decode("ascii", "ignore").lower()
                        )
                        if mt.startswith("application/vnd.oasis.opendocument"):
                            return True
            except Exception:
                pass
        return False

    def _analyze_odf(
        self, s: str, filename: str, data: bytes, file_mime: "str | None"
    ) -> dict:
        """Analyse an ODF document for malware indicators.

        Extracts plain text, hyperlinks, metadata, and StarBasic macros from
        OpenDocument Format files (.odt, .ods, .odp, .odg).  Uses
        :mod:`odfdo` when available; falls back to raw ZIP + XML parsing.

        Args:
            s: Session tag for log messages.
            filename: Original filename.
            data: Raw file bytes.
            file_mime: MIME type of the file.

        Returns:
            A report dict with the same keys as :meth:`analyze_office`:
            ``has_macro``, ``analyses``, ``rtf_objects``, ``decrypted``,
            ``decryption_password``, ``iocs``, ``text_preview``,
            ``meta_document``.
        """
        report: dict = {
            "has_macro": False,
            "analyses": [],
            "rtf_objects": [],
            "decrypted": False,
            "decryption_password": None,
            "iocs": {"urls": [], "ips": [], "domains": []},
        }

        def _sclean(v: object) -> str:
            if v is None:
                return ""
            raw = str(v)
            return re.sub(r"[\x00-\x1f\x7f]", "", raw)[:256]

        # ----------------------------------------------------------------
        # Primary path: odfdo
        # ----------------------------------------------------------------
        if HAS_ODFDO:
            try:
                doc = _OdfDocument(io.BytesIO(data))

                # --- Text extraction ---
                try:
                    body_text = doc.get_formatted_text()
                except Exception:
                    body_text = ""

                # --- Hyperlink extraction ---
                try:
                    body = doc.body
                    links = body.get_links() if hasattr(body, "get_links") else []
                    for lnk in links:
                        url = getattr(lnk, "url", None)
                        if url and "://" in url:
                            if url not in report["iocs"]["urls"]:
                                report["iocs"]["urls"].append(url)
                except Exception as exc:
                    logger.debug("%s - ODF link extraction error: %s", s, exc)

                # --- Metadata ---
                try:
                    m = doc.meta
                    creation_dt = m.creation_date
                    mod_dt = getattr(m, "date", None)
                    report["meta_document"] = {
                        "title": _sclean(m.title),
                        "author": _sclean(m.initial_creator),
                        "subject": _sclean(m.subject),
                        "keywords": _sclean(m.keywords),
                        "last_saved_by": _sclean(getattr(m, "creator", None)),
                        "company": "",
                        "app_name": _sclean(m.generator),
                        "revision_num": str(m.editing_cycles or ""),
                        "creation_date": str(creation_dt or ""),
                        "mod_date": str(mod_dt or ""),
                    }
                except Exception as exc:
                    logger.debug("%s - ODF metadata extraction error: %s", s, exc)

                # --- IOC scan on extracted text ---
                if body_text:
                    iocs = self.extract_iocs(body_text.encode("utf-8", "ignore"))
                    for k in ("urls", "ips", "domains"):
                        report["iocs"][k] = sorted(set(report["iocs"][k] + iocs[k]))
                    self._add_text_segment(report, "odf", body_text, module="odfdo")

            except Exception as exc:
                logger.error("%s - odfdo parsing error for %s: %s", s, filename, exc)
                # fall through to ZIP fallback below

        # ----------------------------------------------------------------
        # Raw ZIP parsing — always runs.
        # Macro scanning and broad hyperlink extraction have no odfdo
        # equivalent; text/metadata extraction here also fills gaps when
        # odfdo is unavailable or returned nothing.
        # ----------------------------------------------------------------
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                names = z.namelist()

                # Read content.xml once and reuse for text + hyperlink scans.
                content_xml = b""
                if "content.xml" in names:
                    try:
                        content_xml = z.read("content.xml")
                    except Exception as exc:
                        logger.debug("%s - ODF content.xml read error: %s", s, exc)

                # --- Text extraction (fill gap when odfdo produced no text) ---
                _have_body = any(
                    seg.get("source") == "odf"
                    for seg in report.get("text_segments", [])
                )
                if content_xml and not _have_body:
                    try:
                        # Strip XML tags to get plain text
                        plain = re.sub(rb"<[^>]+>", b" ", content_xml)
                        plain = re.sub(rb"\s+", b" ", plain).strip()
                        iocs = self.extract_iocs(plain)
                        for k in ("urls", "ips", "domains"):
                            report["iocs"][k] = sorted(set(report["iocs"][k] + iocs[k]))
                        self._add_text_segment(
                            report,
                            "odf",
                            plain.decode("utf-8", "ignore"),
                            module="zip-xml",
                        )
                    except Exception as exc:
                        logger.debug("%s - ODF content.xml text error: %s", s, exc)

                # --- Hyperlink extraction (always) ---
                # doc.get_links() in the odfdo path only returns text:a links;
                # scanning every xlink:href additionally covers draw:a
                # (shape/image links), form control actions, and
                # office:event-listeners URLs that odfdo would otherwise miss.
                if content_xml:
                    try:
                        for m_url in re.finditer(
                            rb'xlink:href=["\']([^"\']+)["\']', content_xml
                        ):
                            url = m_url.group(1).decode("utf-8", "ignore").strip()
                            if "://" in url and url not in report["iocs"]["urls"]:
                                report["iocs"]["urls"].append(url)
                    except Exception as exc:
                        logger.debug("%s - ODF hyperlink scan error: %s", s, exc)

                # --- Metadata fallback (when odfdo did not populate it) ---
                if not report.get("meta_document") and "meta.xml" in names:
                    try:
                        meta_xml = z.read("meta.xml")

                        # Regex extraction (not an XML parser) avoids
                        # entity-expansion DoS (billion-laughs / quadratic
                        # blowup) on hostile meta.xml input.
                        def _mget(tag: str) -> str:
                            tb = re.escape(tag).encode()
                            mm = re.search(
                                rb"<" + tb + rb"[^>]*>(.*?)</" + tb + rb">",
                                meta_xml,
                                re.DOTALL,
                            )
                            return (
                                _sclean(mm.group(1).decode("utf-8", "ignore"))
                                if mm
                                else ""
                            )

                        report["meta_document"] = {
                            "title": _mget("dc:title"),
                            "author": _mget("meta:initial-creator"),
                            "subject": _mget("dc:subject"),
                            "keywords": _mget("meta:keyword"),
                            "last_saved_by": _mget("dc:creator"),
                            "company": "",
                            "app_name": _mget("meta:generator"),
                            "revision_num": _mget("meta:editing-cycles"),
                            "creation_date": _mget("meta:creation-date"),
                            "mod_date": _mget("dc:date"),
                        }
                    except Exception as exc:
                        logger.debug("%s - ODF meta.xml fallback error: %s", s, exc)

                # --- Macro detection (always via ZIP, odfdo has no macro API) ---
                macro_entries = [n for n in names if n.startswith("Basic/")]
                if macro_entries:
                    report["has_macro"] = True
                    report["analyses"].append(
                        {
                            "type": "AutoExec",
                            "keyword": "StarBasic macro",
                            "description": (
                                "ODF document contains StarBasic macros "
                                f"({len(macro_entries)} entries in Basic/)"
                            ),
                        }
                    )
                    # Extract macro source from XML module files and scan for IOCs
                    macro_text_parts: list[str] = []
                    for entry in macro_entries:
                        if not entry.endswith(".xml"):
                            continue
                        try:
                            raw = z.read(entry)
                            # Extract text content from <script:module> elements
                            for m_mod in re.finditer(
                                rb"<script:module[^>]*>(.*?)</script:module>",
                                raw,
                                re.DOTALL,
                            ):
                                code = m_mod.group(1).decode("utf-8", "ignore")
                                macro_text_parts.append(code)
                        except Exception:
                            continue
                    if macro_text_parts:
                        macro_combined = "\n".join(macro_text_parts)
                        self._add_text_segment(
                            report, "odf-macro", macro_combined, module="oletools"
                        )
                        macro_iocs = self.extract_iocs(
                            macro_combined.encode("utf-8", "ignore")
                        )
                        for k in ("urls", "ips", "domains"):
                            report["iocs"][k] = sorted(
                                set(report["iocs"][k] + macro_iocs[k])
                            )
                        # Feed to VBA_Scanner for keyword analysis if available
                        if HAS_OLETOOLS:
                            try:
                                from oletools.olevba import (
                                    VBA_Scanner as _VBA_Scanner_cls,
                                )

                                scanner = _VBA_Scanner_cls(macro_combined)
                                vba_results = scanner.scan(
                                    include_decoded_strings=False
                                )
                                vba_string_count = 0
                                for kw_type, keyword, description in vba_results:
                                    if kw_type == "VBA string":
                                        vba_string_count += 1
                                    elif kw_type != "IOC":
                                        entry_item = {
                                            "type": kw_type,
                                            "keyword": keyword,
                                            "description": description,
                                        }
                                        if entry_item not in report["analyses"]:
                                            report["analyses"].append(entry_item)
                                if vba_string_count:
                                    report["analyses"].append(
                                        {
                                            "type": "VBA string",
                                            "keyword": f"{vba_string_count} obfuscated string(s)",
                                            "description": (
                                                f"{vba_string_count} VBA obfuscated string "
                                                "expression(s) detected"
                                            ),
                                        }
                                    )
                            except Exception as exc:
                                logger.debug("%s - ODF VBA_Scanner error: %s", s, exc)

                # --- Embedded OLE objects ---
                obj_entries = [n for n in names if re.match(r"Object \d+/", n)]
                unique_objs = {n.split("/")[0] for n in obj_entries}
                if unique_objs:
                    report["analyses"].append(
                        {
                            "type": "Suspicious",
                            "keyword": "EmbeddedObject",
                            "description": (
                                f"ODF document contains {len(unique_objs)} "
                                "embedded object(s)"
                            ),
                        }
                    )

        except zipfile.BadZipFile:
            logger.warning("%s - ODF file is not a valid ZIP archive: %s", s, filename)
        except Exception as exc:
            logger.error("%s - ODF ZIP analysis error for %s: %s", s, filename, exc)

        # Final IOC sort/dedup
        for k in ("urls", "ips", "domains"):
            report["iocs"][k] = sorted(set(report["iocs"][k]))

        return report

    def analyze_office(
        self,
        s: str,
        filename: str,
        data: bytes,
        file_mime: "str | None",
        rtf_eval: bool = False,
        custom_passwords: "list | None" = None,
    ) -> "dict | None":
        """Analyse an Office document (OLE2, OOXML, RTF) for malware indicators.

        Uses :mod:`oletools.olevba` to detect and analyse VBA/XLM macros.
        Encrypted files are decrypted automatically via
        :mod:`msoffcrypto` and the oletools decryption helpers using the
        password list from :attr:`passwords`.  For OLE2 files, document
        properties are extracted from the SummaryInformation stream via
        :mod:`olefile` and stored as ``meta_document``.

        Args:
            s: Session tag for log messages.
            filename: Original filename passed to oletools.
            data: Raw file bytes.
            file_mime: MIME type of the file.
            rtf_eval: When ``True``, also run RTF object extraction via
                :mod:`oletools.rtfobj`.
            custom_passwords: Additional passwords to try before the
                built-in list.

        Returns:
            A report dict, or ``None`` if oletools cannot recognise the file
            and no RTF objects were found.

            Report keys:
                - **has_macro** (bool)
                - **analyses** (list[dict]): Keyword analysis results.
                - **rtf_objects** (list[dict]): RTF embedded objects.
                - **decrypted** (bool)
                - **decryption_password** (str | None)
                - **iocs** (dict): Extracted URLs, IPs, and domains.
                - **text_preview** (str)
                - **meta_document** (dict | None): OLE2 document properties
                  (``title``, ``author``, ``subject``, ``keywords``,
                  ``last_saved_by``, ``company``, ``app_name``,
                  ``revision_num``, ``creation_date``, ``mod_date``).
                  ``None`` for non-OLE2 formats (OOXML, RTF).
        """
        # ODF files share the .odt/.ods/.odp extensions and MIME prefix with the
        # office analyzer, but oletools cannot parse them.  Dispatch early to the
        # dedicated ODF path before attempting VBA_Parser.
        if self._is_odf(data, file_mime, filename):
            return self._analyze_odf(s, filename, data, file_mime)

        office_report: dict = {
            "has_macro": False,
            "analyses": [],
            "rtf_objects": [],
            "decrypted": False,
            "decryption_password": None,
            "iocs": {"urls": [], "ips": [], "domains": []},
        }
        if (
            HAS_OLETOOLS
            and rtf_eval
            and (
                file_mime in ("text/rtf", "application/rtf")
                or data.startswith(b"{\\rt")
            )
        ):
            try:
                rtfp = _RtfObjParser(data)
                rtfp.parse()
                for rtfobj in rtfp.objects:
                    office_report["rtf_objects"].append(
                        {
                            "is_ole": rtfobj.is_ole,
                            "class_name": rtfobj.class_name,
                            "oledata_md5": rtfobj.oledata_md5
                            if rtfobj.is_ole
                            else None,
                            "is_package": rtfobj.is_package,
                        }
                    )
            except Exception as exc:
                logger.error("%s - RTF analysis error: %s", s, exc)

        passwords = (custom_passwords or []) + self.passwords
        working_data = data
        vba_parser = None
        if not HAS_OLETOOLS:
            logger.warning(
                "%s - oletools not installed, skipping macro/VBA analysis", s
            )
            return office_report if office_report["rtf_objects"] else None
        try:
            vba_parser = _VBA_Parser(filename, data=data)
            if vba_parser.type is None:
                vba_parser.close()
                vba_parser = None
                return office_report if office_report["rtf_objects"] else None

            vba_parser.no_xlm = False
            office_report["has_macro"] = vba_parser.detect_vba_macros()

            if vba_parser.detect_is_encrypted():
                logger.info("%s - %s is encrypted. Trying msoffcrypto...", s, filename)
                ms_file_io = io.BytesIO(data)
                if not HAS_MSOFFCRYPTO:
                    logger.warning(
                        "%s - msoffcrypto not installed, falling back to oletools decrypt",
                        s,
                    )
                    working_data, vba_parser, office_report = (
                        self._try_oletools_decrypt(
                            s, filename, passwords, vba_parser, office_report
                        )
                    )
                else:
                    try:
                        ms_file = _msoffcrypto.OfficeFile(ms_file_io)
                        decrypted_data = None
                        for password in passwords:
                            try:
                                ms_file.load_key(password=password)
                                dec_io = io.BytesIO()
                                ms_file.decrypt(dec_io)
                                decrypted_data = dec_io.getvalue()
                                office_report["decryption_password"] = password
                                logger.info("%s - decrypted with msoffcrypto", s)
                                break
                            except Exception:
                                continue
                        if decrypted_data:
                            vba_parser.close()
                            working_data = decrypted_data
                            vba_parser = _VBA_Parser(filename, data=working_data)
                            vba_parser.no_xlm = False
                            office_report["has_macro"] = vba_parser.detect_vba_macros()
                            office_report["decrypted"] = True
                        else:
                            logger.warning(
                                "%s - msoffcrypto failed, trying oletools...", s
                            )
                            working_data, vba_parser, office_report = (
                                self._try_oletools_decrypt(
                                    s, filename, passwords, vba_parser, office_report
                                )
                            )
                    except Exception as exc:
                        logger.error(
                            "%s - msoffcrypto setup error: %s, falling back to oletools",
                            s,
                            exc,
                        )
                        working_data, vba_parser, office_report = (
                            self._try_oletools_decrypt(
                                s, filename, passwords, vba_parser, office_report
                            )
                        )

            results = vba_parser.analyze_macros(False, True)
            if results:
                vba_string_count = 0
                for kw_type, keyword, description in results:
                    if kw_type == "IOC":
                        if "://" in keyword:
                            if keyword not in office_report["iocs"]["urls"]:
                                office_report["iocs"]["urls"].append(keyword)
                        elif re.match(
                            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", keyword
                        ):
                            if keyword not in office_report["iocs"]["ips"]:
                                office_report["iocs"]["ips"].append(keyword)
                        else:
                            # Apply the same quality filter used for iocs_extended:
                            # TLD must be all-lowercase alpha; SLD must be ≥ 2 chars.
                            _kparts = keyword.rstrip(".").rsplit(".", 2)
                            _ktld = _kparts[-1]
                            _ksld = _kparts[-2] if len(_kparts) >= 2 else ""
                            if (
                                _ktld.isalpha()
                                and _ktld == _ktld.lower()
                                and len(_ksld) >= 2
                            ):
                                if keyword not in office_report["iocs"]["domains"]:
                                    office_report["iocs"]["domains"].append(keyword)
                    elif kw_type == "VBA string":
                        vba_string_count += 1
                    else:
                        office_report["analyses"].append(
                            {
                                "type": kw_type,
                                "keyword": keyword,
                                "description": description,
                            }
                        )
                if vba_string_count:
                    office_report["analyses"].append(
                        {
                            "type": "VBA string",
                            "keyword": f"{vba_string_count} obfuscated string(s)",
                            "description": f"{vba_string_count} VBA obfuscated string expression(s) detected",
                        }
                    )

            effective = working_data if working_data is not None else data
            body_iocs = self.extract_iocs(effective)
            for k in ("urls", "ips", "domains"):
                office_report["iocs"][k] = sorted(
                    set(office_report["iocs"][k] + body_iocs[k])
                )
            _office_text_max = int(config.get("xspct_text_max_length", 50000))
            self._add_text_segment(
                office_report,
                "office",
                self.extract_text_preview(effective, file_mime, _office_text_max),
                module="oletools",
            )
            # Full VBA/XLM macro source as a text segment (IOC-scanned + reported).
            try:
                _macro_src = "\n".join(
                    code
                    for (_fn, _sp, _vf, code) in vba_parser.extract_all_macros()
                    if code
                )
                self._add_text_segment(
                    office_report, "office-macro", _macro_src, module="oletools"
                )
            except Exception:
                pass

            # -- OLE2 document properties (SummaryInformation stream) -------
            if HAS_OLEFILE and _olefile.isOleFile(io.BytesIO(effective)):
                try:
                    ole = _olefile.OleFileIO(io.BytesIO(effective))
                    m = ole.get_metadata()

                    def _oclean(v) -> str:
                        if v is None:
                            return ""
                        s_val = (
                            v.decode("utf-8", "ignore")
                            if isinstance(v, bytes)
                            else str(v)
                        )
                        return re.sub(r"[\x00-\x1f\x7f]", "", s_val)[:256]

                    office_report["meta_document"] = {
                        "title": _oclean(getattr(m, "title", None)),
                        "author": _oclean(getattr(m, "author", None)),
                        "subject": _oclean(getattr(m, "subject", None)),
                        "keywords": _oclean(getattr(m, "keywords", None)),
                        "last_saved_by": _oclean(getattr(m, "last_saved_by", None)),
                        "company": _oclean(getattr(m, "company", None)),
                        "app_name": _oclean(getattr(m, "app_name", None)),
                        "revision_num": str(getattr(m, "revision_num", None) or ""),
                        "creation_date": str(getattr(m, "create_time", None) or ""),
                        "mod_date": str(getattr(m, "last_saved", None) or ""),
                    }
                    ole.close()
                except Exception as exc:
                    logger.debug("%s - OLE metadata extraction failed: %s", s, exc)

        except Exception as exc:
            logger.error("%s - OLE analysis error for %s: %s", s, filename, exc)
            effective = working_data if working_data is not None else data
            office_report["iocs"] = self.extract_iocs(effective)
            self._add_text_segment(
                office_report,
                "office",
                self.extract_text_preview(
                    effective,
                    file_mime,
                    int(config.get("xspct_text_max_length", 50000)),
                ),
                module="oletools",
            )
        finally:
            if vba_parser is not None:
                try:
                    vba_parser.close()
                except Exception:
                    pass
        return office_report

    def _try_oletools_decrypt(
        self, s: str, filename: str, passwords: list, vba_parser, office_report: dict
    ):
        decrypted_file = None
        for pw in passwords:
            try:
                res = vba_parser.decrypt_file([pw])
                if res:
                    decrypted_file = res
                    office_report["decryption_password"] = pw
                    break
            except Exception:
                continue
        if decrypted_file:
            logger.info("%s - decrypted with oletools", s)
            vba_parser.close()
            try:
                with open(decrypted_file, "rb") as fh:
                    working_data = fh.read()
            finally:
                try:
                    os.unlink(decrypted_file)
                except OSError:
                    pass
            vba_parser = _VBA_Parser(filename, data=working_data)
            vba_parser.no_xlm = False
            office_report["has_macro"] = vba_parser.detect_vba_macros()
            office_report["decrypted"] = True
            return working_data, vba_parser, office_report
        logger.warning("%s - decryption failed with all tools", s)
        return None, vba_parser, office_report

    # ------------------------------------------------------------------
    # Full analysis pipeline
    # ------------------------------------------------------------------

    def sync_analyze(
        self,
        s: str,
        filename: str,
        data: bytes,
        file_mime: "str | None",
        file_desc: "str | None" = None,
        rtf_eval: bool = False,
        custom_passwords: "list | None" = None,
        types_to_run: "list | None" = None,
        force_analyzers: "frozenset | None" = None,
    ) -> dict:
        """Run the full analysis pipeline synchronously and return a report.

        Detects the file type, dispatches to the appropriate
        ``analyze_*`` method(s), merges the results, and attaches a text
        preview and metadata. Intended to be called from a thread-pool
        executor to avoid blocking the event loop.

        Args:
            s: Session tag for log messages.
            filename: Original filename.
            data: Raw file bytes.
            file_mime: MIME type (from magic or caller-supplied).
            file_desc: Human-readable magic description (optional).
            rtf_eval: Enable RTF object extraction.
            custom_passwords: Extra passwords to prepend to the built-in list.
            types_to_run: Override auto-detection by providing an explicit
                list of analysis type strings (``'pdf'``, ``'html'``,
                ``'office'``).

        Returns:
            A complete report dict with keys: ``filename``, ``file_hash``,
            ``file_type``, ``file_description``, ``detected_type``,
            ``has_macro``, ``analyses``, ``iocs``, ``rtf_objects``,
            ``decrypted``, ``decryption_password``, ``text_preview``,
            ``meta``, and ``meta_document``.
        """
        file_hash = hashlib.sha256(data).hexdigest()
        if not types_to_run:
            types_to_run = [
                self.get_detected_type(file_mime, file_desc, filename, data)
            ]
        enabled = self._resolve_enabled_analyzers()
        report: dict = self._make_base_report(filename, file_hash, file_mime, file_desc)
        successful_types = []
        for t in types_to_run:
            res = None
            if t == "pdf" and "pdf" in enabled:
                res = self.analyze_pdf(data, custom_passwords=custom_passwords)
            elif t == "html" and "html" in enabled:
                res = self.analyze_html(data)
            elif t == "office" and "office" in enabled:
                res = self.analyze_office(
                    s, filename, data, file_mime, rtf_eval, custom_passwords
                )
            elif t == "image" and "image" in enabled:
                res = self.analyze_image(
                    data,
                    label=filename,
                    s=s,
                    force_analyzers=force_analyzers or frozenset(),
                )
            elif t == "archive" and "archive" in enabled:
                res = self.analyze_archive(s, filename, data, 0)
            elif t == "text" and "text" in enabled:
                res = self.analyze_text(data, filename, file_mime)
            # 'unknown' — no dedicated method; YARA/iocsearcher run separately
            if res:
                successful_types.append(t)
                self.merge_reports(report, res)
        report["detected_type"] = (
            ",".join(sorted(successful_types)) if successful_types else "unknown"
        )
        _text_max = int(config.get("xspct_text_max_length", 50000))
        # Embedded-image OCR/QR text (adds segments) — before iocsearcher.
        if (
            (HAS_OCR or HAS_PYZBAR)
            and file_mime
            and "openxmlformats" in file_mime.lower()
        ):
            self._extract_ooxml_images(s, data, report)
        if (HAS_OCR or HAS_PYZBAR) and self._is_odf(data, file_mime, filename):
            self._extract_odf_images(s, data, report)
        # Ensure at least one text segment exists (unknown/empty extractions).
        # Skip for image files when raw_text_fallback is disabled (default) to
        # prevent EXIF/XMP fragments from feeding the IOC extractors.
        _img_raw_fb = (
            config.get("xspct_analyzers", {})
            .get("image", {})
            .get("raw_text_fallback", False)
        )
        if not report.get("text_segments") and not (
            report.get("detected_type") == "image" and not _img_raw_fb
        ):
            self._add_text_segment(
                report,
                report.get("detected_type") or "raw",
                self.extract_text_preview(data, file_mime, _text_max),
                module="builtin",
            )
        # YARA — always scan raw bytes when rules are loaded, regardless of file type
        _yara_ok = (
            "yara" in enabled and getattr(self, "_yara_rules", None) is not None
        ) or ("yara_x" in enabled and getattr(self, "_yara_x_rules", None) is not None)
        if _yara_ok:
            yara_res = self.analyze_yara(data, filename, file_mime or "", s)
            if yara_res:
                self.merge_reports(report, yara_res)
        # iocsearcher — extended IOC extraction over ALL accumulated text.
        if HAS_IOCSEARCHER and "iocs" in enabled:
            # For HTML, use raw decoded source so href/src/action attributes are visible
            if "html" in report.get("detected_type", ""):
                try:
                    _ios_text = data.decode("utf-8", "ignore")[:_text_max]
                except Exception:
                    _ios_text = self._aggregate_text(report)[:_text_max]
            else:
                _ios_text = self._aggregate_text(report)[:_text_max]
            if _ios_text:
                iocs_res = self.analyze_iocsearcher(_ios_text, filename)
                if iocs_res:
                    self.merge_reports(report, iocs_res)
        # ClamAV — scan raw bytes when engine is connected.
        # Skip when called for archive members and scan_members is False
        # (the parent archive scan already passes the whole archive to clamd).
        _cv_cfg = config["xspct_clamav"]
        if HAS_CLAMD and _cv_cfg["enabled"] and _cv_cfg.get("scan_members", True):
            cv_res = self.analyze_clamav(data, filename, s)
            if cv_res:
                self.merge_reports(report, cv_res)
        # Derive text_preview/text_full lists from accumulated segments.
        self._finalize_text_fields(report)
        return report

    # ------------------------------------------------------------------
    # Parallel analysis pipeline
    # ------------------------------------------------------------------

    def _make_base_report(
        self,
        filename: str,
        file_hash: str,
        file_mime: "str | None",
        file_desc: "str | None",
    ) -> dict:
        """Return the skeleton report dict used by both sync and async pipelines."""
        return {
            "filename": filename,
            "file_hash": file_hash,
            "file_type": file_mime,
            "file_description": file_desc,
            "detected_type": "",
            "has_macro": False,
            "analyses": [],
            "meta": {
                "script_name": "xspct-scan",
                "version": _ENGINE_VERSION,
                "type": "MetaInformation",
            },
            "rtf_objects": [],
            "decrypted": False,
            "decryption_password": None,
            "iocs": {"urls": [], "ips": [], "domains": []},
            "text_preview": [],
            "text_full": [],
            "text_segments": [],
            "meta_document": None,
            "yara_matches": [],
            "iocs_extended": {},
            "pdfid_keywords": None,
            "pdfid_meta": None,
            "archive_files": [],
            "exif": {},
            "analyzer_errors": {},
            "analyzer_timings": {},
            "scan_exclusions": {},
        }

    # ------------------------------------------------------------------
    # Extracted-text accumulation
    # ------------------------------------------------------------------

    @staticmethod
    def _add_text_segment(
        report: dict, source: str, text: "str | None", module: "str | None" = None
    ) -> None:
        """Append an extracted-text segment to *report* (deduplicated).

        Segments accumulate under the internal ``text_segments`` key. The
        pipeline later derives ``text_preview`` and ``text_full`` (both
        lists of ``{source, module?, text}``) from them via
        :meth:`_finalize_text_fields`, and feeds the aggregated text to the
        IOC catchers.  Empty/whitespace-only text is ignored.
        """
        if not text:
            return
        text = text.strip()
        if not text:
            return
        segs = report.setdefault("text_segments", [])
        for seg in segs:
            if seg.get("source") == source and seg.get("text") == text:
                return
        seg: dict = {"source": source, "text": text}
        if module:
            seg["module"] = module
        segs.append(seg)

    @staticmethod
    def _aggregate_text(report: dict) -> str:
        """Return all accumulated segment text joined for IOC scanning."""
        return "\n".join(
            seg["text"] for seg in report.get("text_segments", []) if seg.get("text")
        )

    def _finalize_text_fields(self, report: dict) -> None:
        """Derive ``text_preview``/``text_full`` lists from ``text_segments``.

        ``text_preview`` truncates each segment to
        ``xspct_text_preview_length``; ``text_full`` truncates to
        ``xspct_text_max_length``.  The internal ``text_segments`` key is
        removed so it never leaks into the response.
        """
        segs = report.pop("text_segments", None) or []
        preview_limit = int(config.get("xspct_text_preview_length", 2000))
        text_max = int(config.get("xspct_text_max_length", 50000))

        def _seg_out(seg: dict, limit: int) -> dict:
            out = {"source": seg["source"], "text": seg["text"][:limit]}
            if seg.get("module"):
                out["module"] = seg["module"]
            return out

        report["text_preview"] = [
            _seg_out(seg, preview_limit) for seg in segs if seg.get("text")
        ]
        report["text_full"] = [
            _seg_out(seg, text_max) for seg in segs if seg.get("text")
        ]

    def _merge_image_result(self, report: dict, img_result: dict, source: str) -> None:
        """Merge an :meth:`analyze_image` result (analyses, IOCs, and text).

        OCR/QR text is added as ``text_segments`` under *source* so it reaches
        both ``text_preview``/``text_full`` and the IOC catchers.
        """
        for hit in img_result.get("analyses", []):
            if hit not in report["analyses"]:
                report["analyses"].append(hit)
        _img_iocs = img_result.get("iocs", {})
        for k in ("urls", "ips", "domains"):
            report["iocs"][k] = sorted(
                set(report["iocs"].get(k, []) + _img_iocs.get(k, []))
            )
        for seg in img_result.get("text_segments", []):
            self._add_text_segment(
                report, source, seg.get("text", ""), module=seg.get("module")
            )

    # ------------------------------------------------------------------
    # v2 report transformer
    # ------------------------------------------------------------------

    def _to_v2_report(
        self,
        v1: dict,
        filename: str,
        filesize: int,
        sha1: "str | None" = None,
        rspamd_digest: "str | None" = None,
    ) -> dict:
        """Transform a finalized v1-internal report dict into the v2 schema.

        This is the single serialization boundary: all internal accumulation
        stays in v1 format; this method is called once in
        :meth:`analyze_task` before caching and returning.

        Args:
            v1:             Completed v1 report dict (after _finalize_text_fields).
            filename:       Original filename (URL-decoded in the output).
            filesize:       Raw byte length of the scanned file.
            sha1:           Pre-computed SHA-1 hex digest (optional).
            rspamd_digest:  Rspamd-compatible keyed BLAKE2b-512 digest (optional).

        Returns:
            A v2 report dict ready for serialization and caching.
        """
        # engine
        v2: dict = {
            "schema_version": _REPORT_SCHEMA_VERSION,
            "engine": {"name": "xspct-scan", "version": _ENGINE_VERSION},
        }

        # file
        _file: dict = {
            "name": urllib.parse.unquote(filename or ""),
            "sha256": v1.get("file_hash", ""),
            "sha1": sha1 or "",
            "rspamd_digest": rspamd_digest or "",
            "size": filesize,
            "mime": v1.get("file_type") or None,
            "magic": v1.get("file_description") or None,
            "type": v1.get("detected_type") or "unknown",
        }
        # Resolution from image analysis (image_size key set by analyze_image).
        _img_size = v1.get("image_size")
        if _img_size:
            _file["resolution"] = _img_size
        v2["file"] = _file

        # scan
        analyzers: dict = {
            "completed": v1.get("analyzers_completed", []),
            "pending": v1.get("analyzers_pending", []),
            "timings_s": v1.get("analyzer_timings", {}),
        }
        if v1.get("analyzer_errors"):
            analyzers["errors"] = v1["analyzer_errors"]
        _scan = {
            "status": v1.get("status", "finished"),
            "duration_s": v1.get("time_taken", 0.0),
            "cache_hit": bool(v1.get("cache_hit", False)),
            "analyzers": analyzers,
        }
        _scan_excl = dict(v1.get("scan_exclusions", {}))
        # Surface unavailable/skipped engine statuses in scan.exclusions so
        # consumers don't have to dig into engines.* to understand the gap.
        _clamav_v1 = v1.get("clamav", {})
        if isinstance(_clamav_v1, dict) and _clamav_v1.get("status") in (
            "unavailable",
            "skipped",
            "error",
        ):
            _scan_excl.setdefault("clamav", _clamav_v1["status"])
        if _scan_excl:
            _scan["exclusions"] = _scan_excl
        v2["scan"] = _scan

        # verdict  (scoring/labels populated in a later iteration)
        v2["verdict"] = {
            "score": None,
            "severity": "unknown",
            "labels": [],
            "summary": None,
            "contributors": {},
        }

        # flags  — only keys that are True (plus decryption info when set)
        _flag_map = [
            ("encrypted", "is_encrypted"),
            ("decrypted", "decrypted"),
            ("macros", "has_macro"),
            ("javascript", "has_javascript"),
            ("open_action", "has_openaction"),
            ("launch", "has_launch"),
            ("embedded_files", "has_embedded_files"),
            ("forms", "has_forms"),
            ("scripts", "has_scripts"),
            ("iframes", "has_iframes"),
            ("meta_refresh", "has_meta_refresh"),
        ]
        flags: dict = {}
        for v2_key, v1_key in _flag_map:
            if v1.get(v1_key):
                flags[v2_key] = True
        if v1.get("decryption_password"):
            flags["decryption_password"] = v1["decryption_password"]
        v2["flags"] = flags

        # iocs — rich {value, source, module, confidence} objects, deduped
        v2_iocs: dict = {}
        basic = v1.get("iocs", {})
        ext = v1.get("iocs_extended", {})

        # If all text segments came from the raw-bytes fallback (module='builtin')
        # iocsearcher results are less reliable — downgrade confidence to medium.
        _text_segs = v1.get("text_preview", []) or []
        _has_reliable_text = any(seg.get("module") != "builtin" for seg in _text_segs)
        _ext_conf = "high" if _has_reliable_text else "medium"

        def _append_unique(
            bucket: list, value: str, source: str, confidence: str, module: str = ""
        ) -> None:
            if not any(e["value"] == value for e in bucket):
                entry: dict = {
                    "value": value,
                    "source": source,
                    "confidence": confidence,
                }
                if module:
                    entry["module"] = module
                bucket.append(entry)

        urls: list = []
        for u in basic.get("urls", []):
            _append_unique(urls, u, "scanner", "high", module="regex")
        for u in ext.get("url", []):
            if not any(e["value"] == u for e in urls):
                _append_unique(urls, u, "iocsearcher", _ext_conf, module="iocsearcher")
        if urls:
            v2_iocs["urls"] = urls

        domains: list = []
        for d in basic.get("domains", []):
            _append_unique(domains, d, "scanner", "medium", module="regex")
        for d in ext.get("fqdn", []):
            existing = next((e for e in domains if e["value"] == d), None)
            if existing:
                existing["confidence"] = _ext_conf
                existing["source"] = "iocsearcher"
                existing["module"] = "iocsearcher"
            else:
                _append_unique(
                    domains, d, "iocsearcher", _ext_conf, module="iocsearcher"
                )
        if domains:
            v2_iocs["domains"] = domains

        ips: list = []
        for ip in basic.get("ips", []):
            _append_unique(ips, ip, "scanner", "high", module="regex")
        for ip in ext.get("ip", []) + ext.get("ipv6", []):
            _append_unique(ips, ip, "iocsearcher", _ext_conf, module="iocsearcher")
        if ips:
            v2_iocs["ips"] = ips

        _ext_type_map = [
            ("email", "emails"),
            ("md5", "hashes"),
            ("sha1", "hashes"),
            ("sha256", "hashes"),
            ("cve", "cves"),
            ("cryptocurrency", "wallets"),
            ("onion", "onions"),
            ("phone", "phones"),
        ]
        for ext_type, v2_type in _ext_type_map:
            for val in ext.get(ext_type, []):
                bucket = v2_iocs.setdefault(v2_type, [])
                _append_unique(
                    bucket, val, "iocsearcher", _ext_conf, module="iocsearcher"
                )

        v2["iocs"] = v2_iocs

        # findings  (was analyses; enrich with severity + source)
        findings: list = []
        for a in v1.get("analyses", []):
            f: dict = {
                "type": a.get("type", ""),
                "keyword": a.get("keyword", ""),
                "description": a.get("description", ""),
                "severity": "medium",
                "source": "scanner",
            }
            if a.get("confidence"):
                f["confidence"] = a["confidence"]
            findings.append(f)
        if findings:
            v2["findings"] = findings

        # content  (text segments; controlled by config flags)
        content: dict = {}
        preview = v1.get("text_preview", [])
        if preview and config.get("xspct_include_text_preview", True):
            content["preview"] = preview
        full = v1.get("text_full", [])
        if full and config.get("xspct_include_text_full", False):
            content["full"] = full
        if content:
            v2["content"] = content

        # document  (was meta_document; ISO-8601 dates, empty keys omitted)
        meta_doc = v1.get("meta_document") or {}
        doc: dict = {}
        for v1_k, v2_k in [
            ("title", "title"),
            ("author", "author"),
            ("subject", "subject"),
            ("keywords", "keywords"),
            ("creator", "creator"),
            ("producer", "producer"),
            ("last_saved_by", "last_saved_by"),
            ("company", "company"),
            ("app_name", "app_name"),
            ("revision_num", "revision"),
            ("encryption", "encryption"),
        ]:
            val = str(meta_doc.get(v1_k, "") or "").strip()
            if val:
                doc[v2_k] = val
        for v1_k, v2_k in [("creation_date", "created"), ("mod_date", "modified")]:
            iso = _normalize_pdf_date(str(meta_doc.get(v1_k, "") or ""))
            if iso:
                doc[v2_k] = iso
        if doc:
            v2["document"] = doc

        # engines  (per-engine raw output; section omitted when empty)
        engines: dict = {}

        clamav = v1.get("clamav")
        if clamav is not None:
            cv: dict = {"status": clamav.get("status", "unavailable")}
            if clamav.get("viruses"):
                cv["viruses"] = clamav["viruses"]
            for fld in ("engine_version", "db_version", "db_date"):
                val = clamav.get(fld)
                if val:
                    cv[fld] = val
            cv["scan_time_s"] = clamav.get("scan_time_s", 0.0)
            engines["clamav"] = cv

        yara_matches = v1.get("yara_matches", [])
        if yara_matches:
            engines["yara"] = {"matches": yara_matches}

        pdfid_kw = v1.get("pdfid_keywords") or {}
        pdfid_meta = v1.get("pdfid_meta") or {}
        pdfid_kw_nz = {k: v for k, v in pdfid_kw.items() if v}
        pdfid_meta_nz = {k: v for k, v in pdfid_meta.items() if v}
        if pdfid_kw_nz or pdfid_meta_nz:
            pdfid: dict = {}
            if pdfid_kw_nz:
                pdfid["keywords"] = pdfid_kw_nz
            if pdfid_meta_nz:
                pdfid["meta"] = pdfid_meta_nz
            engines["pdfid"] = pdfid

        archive_files = v1.get("archive_files", [])
        if archive_files:
            engines["archive"] = {"files": archive_files}

        exif = v1.get("exif") or {}
        if exif:
            engines["image"] = {"exif": exif}

        rtf_objects = v1.get("rtf_objects", [])
        if rtf_objects:
            engines["rtf"] = {"objects": rtf_objects}

        if engines:
            v2["engines"] = engines

        return v2

    async def analyze_pipeline(
        self,
        s: str,
        filename: str,
        data: bytes,
        file_mime: "str | None",
        file_desc: "str | None" = None,
        rtf_eval: bool = False,
        custom_passwords: "list | None" = None,
        types_to_run: "list | None" = None,
        force_analyzers: "frozenset | None" = None,
    ) -> PartialReport:
        """Run analyzers in parallel and return a populated :class:`PartialReport`.

        Dispatches each applicable analyzer to the thread-pool executor as
        an independent asyncio task and awaits them all with
        :func:`asyncio.gather`.  The :class:`PartialReport` accumulates
        results under an asyncio lock as each analyzer finishes.

        After all analyzers complete the method finalises ``detected_type``
        and, if needed, runs a text-preview extraction.

        Args:
            s: Session tag for log messages.
            filename: Original filename.
            data: Raw file bytes.
            file_mime: MIME type (from magic or caller-supplied).
            file_desc: Human-readable magic description (optional).
            rtf_eval: Enable RTF object extraction.
            custom_passwords: Extra decryption passwords.
            types_to_run: Override auto-detection by providing explicit
                analysis type strings (``'pdf'``, ``'html'``, ``'office'``).

        Returns:
            A fully-populated :class:`PartialReport`.  Access ``.report``
            for the final dict or call ``.snapshot()`` for a safe copy.
        """
        file_hash = hashlib.sha256(data).hexdigest()
        if not types_to_run:
            types_to_run = [
                self.get_detected_type(file_mime, file_desc, filename, data)
            ]
        enabled = self._resolve_enabled_analyzers()

        # Determine which analyzers will actually run so the pending list is accurate.
        pending: list[str] = []
        for t in types_to_run:
            if t == "pdf" and "pdf" in enabled:
                pending.append("pdf")
            elif t == "html" and "html" in enabled:
                pending.append("html")
            elif t == "office" and "office" in enabled:
                pending.append("office")
            elif t == "image" and "image" in enabled:
                pending.append("image")
            elif t == "archive" and "archive" in enabled:
                pending.append("archive")
            elif t == "text" and "text" in enabled:
                pending.append("text")
            # 'unknown': no dedicated analyzer; text_preview extracted in pre-Group-2 block
        # YARA runs regardless of file type (always on raw bytes).
        # Either or both engines may be active simultaneously.
        yara_enabled = (
            "yara" in enabled
            and (HAS_YARA and getattr(self, "_yara_rules", None) is not None)
        ) or (
            "yara_x" in enabled
            and (HAS_YARA_X and getattr(self, "_yara_x_rules", None) is not None)
        )
        if yara_enabled:
            pending.append("yara")
        # ClamAV runs regardless of file type.
        # Task always runs when enabled so 'clamav' is always present in the report
        # (analyze_clamav returns status='unavailable' when the client isn't connected).
        clamav_enabled = HAS_CLAMD and config["xspct_clamav"]["enabled"]
        if clamav_enabled:
            pending.append("clamav")

        base = self._make_base_report(filename, file_hash, file_mime, file_desc)
        base["analyzers_completed"] = []
        base["analyzers_pending"] = list(pending)
        partial = PartialReport(base, pending)

        # Register so handle_scan() can read the partial on timeout.
        self._partials[file_hash] = partial

        loop = asyncio.get_running_loop()

        async def _run(name: str, sync_fn, *args) -> None:
            """Run *sync_fn* in the thread pool, record timing, and merge."""
            t0 = time.monotonic()
            try:
                result = await loop.run_in_executor(self._executor, sync_fn, *args)
            except Exception as exc:
                logger.error("%s - analyzer %s raised: %s", s, name, exc)
                result = {"analyzer_errors": {name: type(exc).__name__}}
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            _record_analyzer_stats(name, elapsed_ms, result)
            logger.debug(
                "%s [%s] analyzer=%s time=%dms hit=%s",
                s,
                filename,
                name,
                elapsed_ms,
                _is_analyzer_hit(name, result),
            )
            # Inject timing without mutating the analyzer's result dict
            merge_payload = dict(result) if result else {}
            merge_payload["analyzer_timings"] = {name: round(elapsed_ms / 1000, 3)}
            await partial.merge(name, merge_payload, self)

        tasks: list = []
        for t in types_to_run:
            if t == "pdf" and "pdf" in enabled:
                tasks.append(
                    asyncio.create_task(
                        _run("pdf", self.analyze_pdf, data, custom_passwords)
                    )
                )
            elif t == "html" and "html" in enabled:
                tasks.append(asyncio.create_task(_run("html", self.analyze_html, data)))
            elif t == "office" and "office" in enabled:
                tasks.append(
                    asyncio.create_task(
                        _run(
                            "office",
                            self.analyze_office,
                            s,
                            filename,
                            data,
                            file_mime,
                            rtf_eval,
                            custom_passwords,
                        )
                    )
                )
            elif t == "image" and "image" in enabled:
                tasks.append(
                    asyncio.create_task(
                        _run(
                            "image",
                            __import__("functools").partial(
                                self.analyze_image,
                                s=s,
                                force_analyzers=force_analyzers or frozenset(),
                            ),
                            data,
                            filename,
                        )
                    )
                )
            elif t == "archive" and "archive" in enabled:
                tasks.append(
                    asyncio.create_task(
                        _run("archive", self.analyze_archive, s, filename, data, 0)
                    )
                )
            elif t == "text" and "text" in enabled:
                tasks.append(
                    asyncio.create_task(
                        _run("text", self.analyze_text, data, filename, file_mime)
                    )
                )
            # 'unknown': no dedicated Group-1 analyzer; iocsearcher + YARA
            # still run via the pre-Group-2 block and the yara task.
        if yara_enabled:
            tasks.append(
                asyncio.create_task(
                    _run("yara", self.analyze_yara, data, filename, file_mime or "", s)
                )
            )
        if clamav_enabled:
            tasks.append(
                asyncio.create_task(
                    _run("clamav", self.analyze_clamav, data, filename, s)
                )
            )

        if tasks:
            await asyncio.gather(*tasks)

        # --- Post-analyzer: embedded-image text + aggregated IOC search ---
        _text_max = int(config.get("xspct_text_max_length", 50000))
        report = partial.report
        # OOXML/ODF embedded images (adds OCR/QR text segments) — run before
        # iocsearcher so image text also reaches the extended IOC catcher.
        if (
            (HAS_OCR or HAS_PYZBAR)
            and file_mime
            and "openxmlformats" in file_mime.lower()
        ):
            await loop.run_in_executor(
                self._executor, self._extract_ooxml_images, s, data, report
            )
        if (HAS_OCR or HAS_PYZBAR) and self._is_odf(data, file_mime, filename):
            await loop.run_in_executor(
                self._executor, self._extract_odf_images, s, data, report
            )
        # Fallback: if no analyzer produced text (unknown/text types, or a
        # document with no extractable text layer), extract byte-level text.
        # Skip for image files when raw_text_fallback is disabled (default) to
        # prevent EXIF/XMP fragments from feeding the IOC extractors.
        _img_raw_fb = (
            config.get("xspct_analyzers", {})
            .get("image", {})
            .get("raw_text_fallback", False)
        )
        _detected_fb = (
            self.get_detected_type(file_mime, file_desc, filename, data) or "raw"
        )
        if not report.get("text_segments") and not (
            _detected_fb == "image" and not _img_raw_fb
        ):
            _fallback = await loop.run_in_executor(
                self._executor, self.extract_text_preview, data, file_mime, _text_max
            )
            self._add_text_segment(report, _detected_fb, _fallback, module="builtin")

        # --- Group 2: iocsearcher over ALL accumulated text ---
        # For HTML files we pass the raw decoded source rather than the
        # tag-stripped preview so URLs/FQDNs in href/src/action attributes
        # are visible to iocsearcher.
        iocs_enabled = HAS_IOCSEARCHER and "iocs" in enabled
        if iocs_enabled:
            if file_mime and "html" in file_mime.lower():
                try:
                    _iocsearcher_text = data.decode("utf-8", "ignore")[:_text_max]
                except Exception:
                    _iocsearcher_text = self._aggregate_text(report)[:_text_max]
            else:
                _iocsearcher_text = self._aggregate_text(report)[:_text_max]
            if _iocsearcher_text:
                _iocs_t0 = time.monotonic()
                try:
                    iocs_result = await loop.run_in_executor(
                        self._executor,
                        self.analyze_iocsearcher,
                        _iocsearcher_text,
                        filename,
                    )
                except Exception as exc:
                    logger.error("%s - analyzer iocs raised: %s", s, exc)
                    iocs_result = {"analyzer_errors": {"iocs": type(exc).__name__}}
                _iocs_ms = int((time.monotonic() - _iocs_t0) * 1000)
                _record_analyzer_stats("iocs", _iocs_ms, iocs_result)
                if iocs_result:
                    iocs_payload = dict(iocs_result)
                    iocs_payload["analyzer_timings"] = {
                        "iocs": round(_iocs_ms / 1000, 3)
                    }
                    await partial.merge("iocs", iocs_payload, self)

        # --- Finalise ---
        # detected_type reflects only primary content-type analyzers
        # (pdf/html/office/image/archive); supplementary analyzers excluded.
        _SUPPLEMENTARY = frozenset({"iocs", "yara", "javascript", "clamav"})
        successful = [a for a in partial.successful if a not in _SUPPLEMENTARY]
        report["detected_type"] = (
            ",".join(sorted(successful)) if successful else "unknown"
        )
        # Derive text_preview/text_full lists from accumulated segments.
        self._finalize_text_fields(report)
        return partial

    def _extract_ooxml_images(self, s: str, data: bytes, report: dict) -> None:
        """Extract and analyse images embedded in an OOXML ZIP archive.

        Mutates *report* in-place.  Called from :meth:`analyze_pipeline`
        via :meth:`~asyncio.loop.run_in_executor`.

        Args:
            s: Session tag for log messages.
            data: Raw OOXML file bytes.
            report: Report dict to merge image analysis results into.
        """
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for name in z.namelist():
                    if re.match(r"(?:word|xl|ppt)/media/", name, re.I):
                        img_bytes = z.read(name)
                        img_result = self.analyze_image(
                            img_bytes, label=f"OOXML {name}", s=s
                        )
                        self._merge_image_result(report, img_result, "ooxml-image")
        except Exception as exc:
            logger.debug("%s - OOXML image extraction failed: %s", s, exc)

    def _extract_odf_images(self, s: str, data: bytes, report: dict) -> None:
        """Extract and analyse images embedded in an ODF ZIP archive.

        Iterates the ``Pictures/`` directory inside the ODF ZIP container,
        passing each image to :meth:`analyze_image` and merging the results
        into *report* in-place.  Called from :meth:`analyze_pipeline` via
        :meth:`~asyncio.loop.run_in_executor`.

        Args:
            s: Session tag for log messages.
            data: Raw ODF file bytes.
            report: Report dict to merge image analysis results into.
        """
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for name in z.namelist():
                    if re.match(r"Pictures/", name, re.I) and not name.endswith("/"):
                        img_bytes = z.read(name)
                        img_result = self.analyze_image(
                            img_bytes, label=f"ODF {name}", s=s
                        )
                        self._merge_image_result(report, img_result, "odf-image")
        except Exception as exc:
            logger.debug("%s - ODF image extraction failed: %s", s, exc)

    async def analyze_task(
        self,
        s: str,
        file_hash: str,
        filename: str,
        data: bytes,
        file_mime: "str | None",
        file_desc: "str | None" = None,
        rtf_eval: bool = False,
        custom_passwords: "list | None" = None,
        types_to_run: "list | None" = None,
        force_analyzers: "frozenset | None" = None,
    ) -> dict:
        """Run :meth:`analyze_pipeline` and cache the final report.

        Drives the parallel analyzer pipeline via :meth:`analyze_pipeline`,
        then persists the finished report via :meth:`cache_report`.

        Args:
            s: Session tag for log messages.
            file_hash: SHA-256 hex digest (used as cache key).
            filename: Original filename.
            data: Raw file bytes.
            file_mime: MIME type string.
            file_desc: Human-readable magic description.
            rtf_eval: Enable RTF object extraction.
            custom_passwords: Extra decryption passwords.
            types_to_run: Explicit list of analysis types to run.

        Returns:
            The finished report dict.
        """
        logger.info("%s - starting analysis for %s (%s)", s, filename, file_hash)
        _t0 = time.monotonic()
        partial = await self.analyze_pipeline(
            s,
            filename,
            data,
            file_mime,
            file_desc,
            rtf_eval,
            custom_passwords,
            types_to_run,
            force_analyzers,
        )
        report = partial.report
        _elapsed = time.monotonic() - _t0
        report["time_taken"] = round(_elapsed, 4)

        # --- compact scan summary ---
        _iocs = report.get("iocs", {})
        _flags = []
        if report.get("has_macro"):
            _flags.append("macro")
        if report.get("decrypted"):
            _flags.append("decrypted")
        if report.get("is_encrypted") and not report.get("decrypted"):
            _flags.append("encrypted")
        _clamav = next(
            (
                a["keyword"]
                for a in report.get("analyses", [])
                if a.get("type") == "ClamAV"
            ),
            None,
        )
        _yara_rules = sorted({m["rule"] for m in report.get("yara_matches", [])})
        _analysis_hits = [
            a for a in report.get("analyses", []) if a.get("type") not in ("ClamAV",)
        ]
        # Condensed hit tokens: type:keyword (VBA string collapsed to count only)
        _hit_tokens: list[str] = []
        for a in _analysis_hits:
            kw = a.get("keyword", "")
            atype = a.get("type", "")
            if atype == "VBA string":
                # already collapsed to "N obfuscated string(s)" — extract count
                _hit_tokens.append(f"VBA_strings:{kw}")
            else:
                _hit_tokens.append(f"{atype}:{kw}")
        logger.info(
            "%s file=%s hash=%s type=%s time=%.3fs"
            " analyses=%d urls=%d ips=%d domains=%d yara=%d%s%s%s%s",
            s,
            filename,
            file_hash[:12],
            report.get("detected_type", "?"),
            _elapsed,
            len(report.get("analyses", [])),
            len(_iocs.get("urls", [])),
            len(_iocs.get("ips", [])),
            len(_iocs.get("domains", [])),
            len(_yara_rules),
            (" " + " ".join(_flags)) if _flags else "",
            (" clamav=" + _clamav) if _clamav else "",
            (" hits=[" + ", ".join(_hit_tokens) + "]") if _hit_tokens else "",
            (" yara=[" + ", ".join(_yara_rules) + "]") if _yara_rules else "",
        )

        # Transform v1 internal report → v2 output schema before caching.
        _sha1 = hashlib.sha1(data).hexdigest()  # noqa: S324  (non-security use)
        _rdigest = _rspamd_digest(data)
        v2_report = self._to_v2_report(
            report, filename, len(data), sha1=_sha1, rspamd_digest=_rdigest
        )
        v2_report["status"] = "finished"
        await self.cache_report(s, file_hash, v2_report)
        return v2_report

    # ------------------------------------------------------------------
    # HTTP request handlers
    # ------------------------------------------------------------------

    async def _finalize_background(
        self, s: str, file_hash: str, scan_task: asyncio.Task
    ) -> None:
        """Await a timed-out scan task in the background and cache the result.

        Called as a fire-and-forget ``asyncio.create_task`` by
        :meth:`handle_scan` after transferring ownership of the background
        semaphore slot.  Always releases ``_bg_sem`` in the ``finally``
        block so the slot is guaranteed to be returned regardless of outcome.

        Args:
            s: Session tag for log messages.
            file_hash: SHA-256 hex digest (cache key).
            scan_task: The still-running analysis task created by
                :meth:`handle_scan`.
        """
        try:
            report = await scan_task
            report["status"] = "finished"
            await self.cache_report(s, file_hash, report)
            stats["background_completed"] += 1
            logger.info("%s - background scan finished for %s", s, file_hash)
        except asyncio.CancelledError:
            logger.debug("%s - background scan cancelled for %s", s, file_hash)
        except Exception as exc:
            stats["background_errors"] += 1
            self._store_terminal_result(
                file_hash,
                self._make_terminal_error_result(file_hash),
            )
            logger.exception(
                "%s - background scan raised for %s: %s", s, file_hash, exc
            )
        finally:
            self._bg_sem.release()

    # ------------------------------------------------------------------
    # Response serialization helpers
    # ------------------------------------------------------------------

    _SERIALIZE_FORMAT_WARN_LOGGED: dict[str, bool] = {}
    _MAX_ZSTD_DECOMPRESSED_BYTES = _MAX_ZSTD_DECOMPRESSED_BYTES

    # ------------------------------------------------------------------
    # Zstd request decompression / response compression helpers
    # ------------------------------------------------------------------

    def _decompress_zstd_part(self, data: bytes, label: str) -> bytes:
        """Transparently decompress *data* if zstd magic bytes are detected.

        Detection is based entirely on the Zstandard frame magic bytes
        (``\\x28\\xb5\\x2f\\xfd``) at the start of the data.  This is
        reliable and immune to HTTP pipeline behaviour that may have
        already consumed the ``Content-Encoding`` header.

        If the ``zstandard`` library is not installed and zstd data is
        detected, data is returned unchanged and a one-time warning is logged.
        """
        if len(data) < 4 or data[:4] != _ZSTD_MAGIC:
            return data
        if not HAS_ZSTD:
            if not self._SERIALIZE_FORMAT_WARN_LOGGED.get("zstd_decompress"):
                logger.warning(
                    "zstd-compressed %s received but zstandard library not installed; "
                    "passing raw bytes. Install xspct-scan[compression].",
                    label,
                )
                self._SERIALIZE_FORMAT_WARN_LOGGED["zstd_decompress"] = True
            return data
        limit = getattr(
            self, "_MAX_ZSTD_DECOMPRESSED_BYTES", _MAX_ZSTD_DECOMPRESSED_BYTES
        )
        dctx = _zstd.ZstdDecompressor()
        chunks: list[bytes] = []
        total = 0
        try:
            with dctx.stream_reader(io.BytesIO(data)) as reader:
                while True:
                    chunk = reader.read(131072)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise _ClientRequestError(
                            f"Zstd-compressed upload expands beyond limit "
                            f"({limit} bytes)",
                            status=413,
                        )
                    chunks.append(chunk)
        except _ClientRequestError:
            raise
        except Exception as exc:
            zstd_error = getattr(_zstd, "ZstdError", None)
            if zstd_error and isinstance(exc, zstd_error):
                raise _ClientRequestError("Invalid zstd-compressed upload") from exc
            raise
        decompressed = b"".join(chunks)
        logger.debug(
            "zstd decompressed %s: %d → %d bytes", label, len(data), len(decompressed)
        )
        return decompressed

    def _parse_metadata_part(self, data: bytes, content_type: str) -> dict:
        """Decode a multipart ``metadata`` part body as JSON or msgpack.

        An explicit ``application/json`` or ``application/x-msgpack`` part
        Content-Type takes precedence. Otherwise (missing or generic
        Content-Type) msgpack is tried first and JSON is used as a fallback.
        """
        ct = (content_type or "").split(";")[0].strip().lower()
        if ct in ("application/x-msgpack", "application/msgpack"):
            if not HAS_MSGPACK:
                raise _ClientRequestError(
                    "metadata part is msgpack but msgpack support is not installed",
                    status=415,
                )
            try:
                metadata = _msgpack.unpackb(data, raw=False)
            except Exception as exc:
                raise _ClientRequestError("Invalid msgpack in metadata part") from exc
        elif ct == "application/json":
            try:
                metadata = json.loads(data)
            except Exception as exc:
                raise _ClientRequestError("Invalid JSON in metadata part") from exc
        else:
            metadata = None
            if HAS_MSGPACK:
                try:
                    metadata = _msgpack.unpackb(data, raw=False)
                except Exception:
                    pass
            if metadata is None:
                try:
                    metadata = json.loads(data)
                except Exception as exc:
                    raise _ClientRequestError(
                        "metadata part is neither valid JSON nor msgpack"
                    ) from exc

        if not isinstance(metadata, dict):
            raise _ClientRequestError("metadata part must contain an object")

        string_fields = (
            "filename",
            "declared_content_type",
            "detected_type",
            "rspamd_uid",
            "queue_id",
            "message_id",
        )
        for field in string_fields:
            value = metadata.get(field)
            if value is None:
                continue
            if not isinstance(value, str):
                raise _ClientRequestError(f'metadata field "{field}" must be a string')
            # Strip control characters and cap length before this value can
            # reach log lines or the session tag (log injection / DoS).
            metadata[field] = re.sub(r"[\x00-\x1f\x7f]", "", value)[:256]

        for field in ("passwords", "force_analyzers"):
            if field not in metadata:
                continue
            value = metadata[field]
            if not isinstance(value, list) or not all(
                isinstance(item, str) for item in value
            ):
                raise _ClientRequestError(
                    f'metadata field "{field}" must be a list of strings'
                )

        if metadata.get("timeout_s") is not None:
            timeout_hint = metadata["timeout_s"]
            if (
                isinstance(timeout_hint, bool)
                or not isinstance(timeout_hint, (int, float))
                or not math.isfinite(timeout_hint)
                or timeout_hint <= 0
            ):
                raise _ClientRequestError(
                    'metadata field "timeout_s" must be a positive finite number'
                )

        return metadata

    def _should_compress_response(self, request: web.Request) -> bool:
        """Return True if the client accepts zstd-encoded responses."""
        if not HAS_ZSTD:
            return False

        weighted = self._parse_weighted_header(
            request.headers.get("Accept-Encoding", "")
        )
        zstd_q: float | None = None
        wildcard_q: float | None = None
        for token, q, _specificity, _index in weighted:
            if token == "zstd":
                zstd_q = q
                break
            if token == "*":
                wildcard_q = q
        accepted_q = zstd_q if zstd_q is not None else wildcard_q
        return bool(accepted_q and accepted_q > 0)

    @staticmethod
    def _parse_weighted_header(header_value: str) -> list[tuple[str, float, int, int]]:
        """Parse an RFC-style weighted header into sortable tokens.

        Returns tuples of ``(token, q, specificity, index)`` where higher
        specificity means a more exact match and lower index preserves
        original order for equally weighted tokens.
        """
        weighted: list[tuple[str, float, int, int]] = []
        for index, raw_token in enumerate(header_value.split(",")):
            raw_token = raw_token.strip()
            if not raw_token:
                continue
            parts = [part.strip() for part in raw_token.split(";") if part.strip()]
            token = parts[0].lower()
            q = 1.0
            for param in parts[1:]:
                if not param.startswith("q="):
                    continue
                try:
                    q = float(param[2:])
                except ValueError:
                    q = 0.0
                break
            q = max(0.0, min(1.0, q))
            specificity = 2
            if token in {"*", "*/*"}:
                specificity = 0
            elif token.endswith("/*"):
                specificity = 1
            weighted.append((token, q, specificity, index))
        weighted.sort(key=lambda item: (-item[1], -item[2], item[3]))
        return weighted

    def _negotiate_format(self, request: web.Request) -> str:
        """Return the wire format to use for this response.

        Priority:
        1. ``xspct_response_format`` config key (if not ``'auto'``).
        2. ``Accept`` request header (first recognised MIME wins).
        3. ``Content-Type`` of the incoming request (for msgpack/cbor
           bodies on ``/v1/query`` POST).
        4. Fall back to ``'json'``.
        """
        forced = config.get("xspct_response_format", "auto")
        if forced and forced != "auto":
            return str(forced).lower()

        accept = self._parse_weighted_header(request.headers.get("Accept", ""))
        for mime, q, _specificity, _index in accept:
            if q <= 0:
                continue
            if mime == "application/json":
                return "json"
            if mime == "application/x-msgpack":
                return "msgpack"
            if mime == "application/cbor":
                return "cbor"

        ct = request.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if ct == "application/x-msgpack":
            return "msgpack"
        if ct == "application/cbor":
            return "cbor"

        return "json"

    def _build_response(
        self,
        data: dict,
        request: web.Request,
        *,
        status: int = 200,
    ) -> web.Response:
        """Serialise *data* in the negotiated wire format and return a Response.

        If the negotiated format's library is not installed the response falls
        back to JSON and logs a one-time warning.
        """
        fmt = self._negotiate_format(request)
        compress = self._should_compress_response(request)

        if fmt == "msgpack":
            if HAS_MSGPACK:
                body = _msgpack.packb(data, use_bin_type=True)
                return self._make_response(
                    body, "application/x-msgpack", status, compress
                )
            if not self._SERIALIZE_FORMAT_WARN_LOGGED.get("msgpack"):
                logger.warning(
                    "msgpack requested but msgpack library not installed; "
                    "falling back to JSON. Install xspct-scan[serialization]."
                )
                self._SERIALIZE_FORMAT_WARN_LOGGED["msgpack"] = True

        elif fmt == "cbor":
            if HAS_CBOR2:
                body = _cbor2.dumps(data)
                return self._make_response(body, "application/cbor", status, compress)
            if not self._SERIALIZE_FORMAT_WARN_LOGGED.get("cbor"):
                logger.warning(
                    "cbor requested but cbor2 library not installed; "
                    "falling back to JSON. Install xspct-scan[serialization]."
                )
                self._SERIALIZE_FORMAT_WARN_LOGGED["cbor"] = True

        body = json.dumps(data).encode()
        return self._make_response(body, "application/json", status, compress)

    def _make_response(
        self,
        body: bytes,
        content_type: str,
        status: int,
        compress: bool,
    ) -> web.Response:
        """Build a Response, optionally zstd-compressing the body."""
        vary = ["Accept-Encoding"]
        forced = config.get("xspct_response_format", "auto")
        if not forced or forced == "auto":
            vary.insert(0, "Accept")
        headers = {"Vary": ", ".join(vary)}
        if compress:
            body = _zstd.ZstdCompressor().compress(body)
            headers["Content-Encoding"] = "zstd"
        return web.Response(
            body=body,
            status=status,
            content_type=content_type,
            headers=headers,
        )

    async def handle_scan(self, request: web.Request) -> web.Response:
        """Handle ``POST /v1/scan`` — accept a file and return an analysis report.

        Supports three upload shapes, all under ``multipart/form-data`` except
        the raw octet-stream one:

        **Multipart, legacy** (``doc`` part):
            - ``doc`` (required): the file to analyse.
            - ``passwords``: comma- or newline-separated extra decryption passwords.
            - ``file_mime``: override MIME type hint.
            - ``file_type``: override description hint.

        **Multipart, structured metadata** (``metadata`` + ``file`` parts):
            - ``file`` (required): the file to analyse. ``Content-Encoding``-style
              zstd compression is auto-detected the same way as the ``doc`` part.
            - ``metadata`` (required): JSON or msgpack object with keys
              ``filename``, ``declared_content_type``, ``detected_type``,
              ``rspamd_uid``, ``queue_id``, ``message_id``, ``passwords``
              (list), ``force_analyzers`` (list), ``timeout_s``. Fields here
              take precedence over query parameters. Structured and legacy
              multipart parts cannot be mixed.
              ``timeout_s`` may only tighten the effective timeout, never
              loosen it. ``rspamd_uid``/``queue_id``/``message_id`` are
              folded into the session log tag and echoed back in the
              response's ``request`` block for cross-system correlation;
              never persisted into the cached report.

        **Octet-stream** (``application/octet-stream``):
            The raw file bytes are the request body.  Options are supplied via
            query parameters: ``timeout``, ``rtf``, ``filename``, ``file_mime``,
            ``file_type``, ``passwords`` (comma-separated).

        Query parameters (all modes):
            - ``timeout`` (float, default 10): seconds to wait before returning
              HTTP 202.
            - ``rtf`` (bool, default false): enable RTF object extraction.
            - ``force_analyzers`` (comma-separated): force-run specific
              analyzers, bypassing their normal skip heuristics.

        Args:
            request: Incoming aiohttp request.

        Returns:
            JSON :class:`aiohttp.web.Response` containing the report dict
            (HTTP 200), a partial ``processing`` snapshot (HTTP 202), or an
            error response (HTTP 400 / 401 / 500).
        """
        timer("start")
        s = make_session(request)
        stats["requests_total"] += 1
        if not verify_api_key(s, request):
            return self._build_response({"error": "Unauthorized"}, request, status=401)
        start_time = time.monotonic()
        filename = None
        try:
            timeout = float(request.query.get("timeout", DEFAULT_SCAN_TIMEOUT))
            rtf_eval = request.query.get("rtf", "false").lower() == "true"
            _fa_param = request.query.get("force_analyzers", "")
            force_analyzers: "frozenset | None" = (
                frozenset(a.strip() for a in _fa_param.split(",") if a.strip())
                if _fa_param
                else None
            )

            content_type = request.headers.get("Content-Type", "")
            filedata: "bytes | None" = None
            custom_passwords: list = []
            file_mime_provided: "str | None" = None
            file_type_provided: "str | None" = None
            metadata: "dict | None" = None
            rspamd_uid: "str | None" = None
            queue_id: "str | None" = None
            message_id: "str | None" = None
            declared_content_type: "str | None" = None
            detected_type_hint: "str | None" = None

            if "multipart/form-data" in content_type:
                # ---- Multipart upload ----------------------------------------
                legacy_parts: set[str] = set()
                structured_parts: set[str] = set()
                reader = await request.multipart()
                async for part in reader:
                    if part.name == "doc":
                        legacy_parts.add("doc")
                        filename = part.filename
                        filedata = bytes(await part.read())
                        filedata = self._decompress_zstd_part(
                            filedata, filename or "doc"
                        )
                        if filename and filename.lower().endswith(".zst"):
                            filename = filename[:-4]
                        logger.info(
                            "%s (%s) - read %d bytes from %s",
                            s,
                            timer(),
                            len(filedata),
                            filename,
                        )
                    elif part.name == "passwords":
                        legacy_parts.add("passwords")
                        raw = await part.text()
                        custom_passwords = [
                            p.strip()
                            for p in raw.replace(",", "\n").split("\n")
                            if p.strip()
                        ]
                        logger.info(
                            "%s (%s) - received %d custom passwords",
                            s,
                            timer(),
                            len(custom_passwords),
                        )
                    elif part.name == "file_mime":
                        legacy_parts.add("file_mime")
                        file_mime_provided = (await part.text()).strip()
                    elif part.name == "file_type":
                        legacy_parts.add("file_type")
                        file_type_provided = (await part.text()).strip()
                    elif part.name == "metadata":
                        structured_parts.add("metadata")
                        raw_metadata = await part.read()
                        metadata = self._parse_metadata_part(
                            raw_metadata, part.headers.get("Content-Type", "")
                        )
                        # Fold rspamd_uid/queue_id into the session tag as soon
                        # as they're known so later log lines in this request
                        # (including the "read N bytes" line below, if the
                        # file part follows metadata) carry the correlation
                        # tag too.
                        rspamd_uid = metadata.get("rspamd_uid") or None
                        queue_id = metadata.get("queue_id") or None
                        if rspamd_uid or queue_id:
                            tag_bits = []
                            if rspamd_uid:
                                tag_bits.append(f"uid={rspamd_uid[:12]}")
                            if queue_id:
                                tag_bits.append(f"qid={queue_id[:12]}")
                            s = f"{s[:-1]} {' '.join(tag_bits)}>"
                    elif part.name == "file":
                        structured_parts.add("file")
                        filename = part.filename
                        chunks: list = []
                        while True:
                            chunk = await part.read_chunk(size=262144)
                            if not chunk:
                                break
                            chunks.append(part.decode(chunk))
                        filedata = b"".join(chunks)
                        filedata = self._decompress_zstd_part(
                            filedata, filename or "file"
                        )
                        if filename and filename.lower().endswith(".zst"):
                            filename = filename[:-4]
                        logger.info(
                            "%s (%s) - read %d bytes from %s",
                            s,
                            timer(),
                            len(filedata),
                            filename,
                        )
                if legacy_parts and structured_parts:
                    raise _ClientRequestError(
                        "legacy and structured multipart fields cannot be mixed"
                    )
                if structured_parts:
                    missing_parts = {"metadata", "file"} - structured_parts
                    if missing_parts:
                        missing = sorted(missing_parts)[0]
                        raise _ClientRequestError(
                            f'No multipart part named "{missing}"'
                        )
                elif "doc" not in legacy_parts:
                    raise _ClientRequestError('No file part named "doc"')
                if not filedata:
                    raise _ClientRequestError("Uploaded file is empty")
                if structured_parts:
                    # Metadata part fields take precedence over query params
                    # (see docs/guide/api-http.md). rspamd_uid/queue_id were
                    # already extracted (and folded into the session tag `s`)
                    # as soon as the metadata part was parsed, above.
                    if metadata.get("filename"):
                        filename = metadata["filename"]
                    message_id = metadata.get("message_id") or None
                    declared_content_type = (
                        metadata.get("declared_content_type") or None
                    )
                    detected_type_hint = metadata.get("detected_type") or None
                    if "passwords" in metadata:
                        custom_passwords = [
                            password.strip()
                            for password in metadata["passwords"]
                            if password.strip()
                        ]
                    if "force_analyzers" in metadata:
                        force_analyzers = frozenset(
                            analyzer.strip()
                            for analyzer in metadata["force_analyzers"]
                            if analyzer.strip()
                        )
                    if metadata.get("timeout_s") is not None:
                        # A caller-supplied timeout hint may only tighten the
                        # server's timeout, never loosen it.
                        timeout = min(timeout, float(metadata["timeout_s"]))
                    logger.info(
                        "%s (%s) - metadata part: rspamd_uid=%s queue_id=%s "
                        "message_id=%s declared_content_type=%s detected_type=%s",
                        s,
                        timer(),
                        rspamd_uid,
                        queue_id,
                        message_id,
                        declared_content_type,
                        detected_type_hint,
                    )
            elif "application/octet-stream" in content_type:
                # ---- Raw octet-stream upload ---------------------------------
                filedata = bytes(await request.read())
                if not filedata:
                    return self._build_response(
                        {"error": "Empty request body"}, request, status=400
                    )
                filename = request.query.get("filename", "upload.bin")
                filedata = self._decompress_zstd_part(filedata, filename)
                if filename and filename.lower().endswith(".zst"):
                    filename = filename[:-4]
                file_mime_provided = request.query.get("file_mime") or None
                file_type_provided = request.query.get("file_type") or None
                pw_param = request.query.get("passwords", "")
                if pw_param:
                    custom_passwords = [
                        p.strip() for p in pw_param.split(",") if p.strip()
                    ]
                logger.info(
                    "%s (%s) - read %d bytes (octet-stream) from %s",
                    s,
                    timer(),
                    len(filedata),
                    filename,
                )
            else:
                return self._build_response(
                    {
                        "error": "Unsupported Content-Type — use multipart/form-data "
                        "or application/octet-stream"
                    },
                    request,
                    status=415,
                )
            # Per-request correlation IDs (never persisted into the cached
            # report — they belong to this request, not to the file content).
            correlation: dict = {}
            if rspamd_uid:
                correlation["rspamd_uid"] = rspamd_uid
            if queue_id:
                correlation["queue_id"] = queue_id
            if message_id:
                correlation["message_id"] = message_id

            def _attach_correlation(payload: dict) -> dict:
                if correlation:
                    payload["request"] = correlation
                return payload

            file_hash = hashlib.sha256(filedata).hexdigest()
            cached = await self.get_cached_report(s, file_hash)
            if cached:
                if cached.get("decrypted") or not custom_passwords:
                    logger.info("%s (%s) - cache hit for %s", s, timer(), file_hash)
                    cached["cache_hit"] = True
                    return self._build_response(_attach_correlation(cached), request)
                logger.info("%s - cache hit but re-analyzing (custom passwords)", s)
            if HAS_MAGIC:
                file_magic_mime = _magic.Magic(mime=True)
                magic_mime = file_magic_mime.from_buffer(filedata[:2048])
                file_magic_desc = _magic.Magic()
                magic_desc = file_magic_desc.from_buffer(filedata[:2048])
            else:
                magic_mime = ""
                magic_desc = ""
            # Sanitise libmagic output before storing in the report: strip control
            # characters and cap length so a crafted file cannot inject misleading
            # content into file_type / file_description response fields.
            magic_mime = re.sub(r"[\x00-\x1f\x7f]", "", magic_mime or "")[:256]
            magic_desc = re.sub(r"[\x00-\x1f\x7f]", "", magic_desc or "")[:256]
            types_to_run: set = set()
            types_to_run.add(
                self.get_detected_type(magic_mime, magic_desc, None, filedata)
            )
            if file_mime_provided or file_type_provided:
                types_to_run.add(
                    self.get_detected_type(
                        file_mime_provided, file_type_provided, filename, filedata
                    )
                )
            else:
                types_to_run.add(
                    self.get_detected_type(magic_mime, magic_desc, filename, filedata)
                )
            file_mime = file_mime_provided or magic_mime
            file_desc = file_type_provided or magic_desc
            logger.info(
                "%s (%s) - file=%s mime=%s types=%s",
                s,
                timer(),
                filename,
                file_mime,
                types_to_run,
            )

            # ----------------------------------------------------------
            # Two-tier concurrency lifecycle
            # ----------------------------------------------------------
            # 1. Acquire a foreground slot (with per-request timeout).
            #    If the slot queue is full for the entire deadline the
            #    daemon is overloaded — return 503 immediately so
            #    Rspamd/clients aren't left hanging.
            fg_acquired = False
            try:
                await asyncio.wait_for(self._fg_sem.acquire(), timeout=timeout)
                fg_acquired = True
            except asyncio.TimeoutError:
                stats["foreground_overloaded"] += 1
                logger.warning(
                    "%s - overloaded: no foreground slot within %.1fs", s, timeout
                )
                return self._build_response(
                    {"error": "Service overloaded, retry later"}, request, status=503
                )

            bg_acquired = False
            try:
                # 2. Launch analysis task while holding the foreground slot.
                task = asyncio.create_task(
                    self.analyze_task(
                        s,
                        file_hash,
                        filename,
                        filedata,
                        file_mime,
                        file_desc,
                        rtf_eval,
                        custom_passwords,
                        list(types_to_run),
                        force_analyzers,
                    )
                )
                self.tasks[file_hash] = task
                self.tasks.move_to_end(file_hash)
                self._evict_tasks()

                try:
                    report = await asyncio.wait_for(
                        asyncio.shield(task), timeout=timeout
                    )
                    # Finished within deadline — release fg slot, return result.
                    self._fg_sem.release()
                    fg_acquired = False
                    report["status"] = "finished"
                    report["time_taken"] = round(time.monotonic() - start_time, 4)
                    stats["requests_finished"] += 1
                    return self._build_response(_attach_correlation(report), request)

                except asyncio.TimeoutError:
                    # Deadline exceeded — attempt non-blocking transition to background.
                    stats["requests_timeout"] += 1
                    logger.info(
                        "%s (%s) - timeout for %s, attempting background promotion",
                        s,
                        timer(),
                        filename,
                    )

                    # Try to grab a background slot immediately.
                    # If none are free we drop the scan to protect foreground capacity.
                    bg_acquired = self._try_acquire_background_slot()

                    if not bg_acquired:
                        # No background capacity — cancel and report dropped.
                        task.cancel()
                        stats["background_rejected"] += 1
                        logger.warning(
                            "%s - background slots full, scan dropped for %s",
                            s,
                            filename,
                        )
                        partial = self._partials.get(file_hash)
                        resp: dict = {
                            "status": "dropped",
                            "file_hash": file_hash,
                            "message": "Analysis dropped: background queue full",
                            "time_taken": round(time.monotonic() - start_time, 4),
                        }
                        if partial:
                            snap = partial.snapshot()
                            snap.update(resp)
                            return self._build_response(
                                _attach_correlation(snap), request, status=202
                            )
                        return self._build_response(
                            _attach_correlation(resp), request, status=202
                        )

                    # Background slot acquired — release foreground slot now.
                    self._fg_sem.release()
                    fg_acquired = False

                    # Kick off background finalization; ownership of bg_sem
                    # transfers to _finalize_background — do NOT release it here.
                    asyncio.create_task(self._finalize_background(s, file_hash, task))
                    bg_acquired = False  # ownership transferred

                    partial = self._partials.get(file_hash)
                    snap_resp: dict = {
                        "status": "processing",
                        "file_hash": file_hash,
                        "message": "Analysis is continuing in background",
                        "time_taken": round(time.monotonic() - start_time, 4),
                    }
                    if partial:
                        snap = partial.snapshot()
                        snap.update(snap_resp)
                        return self._build_response(
                            _attach_correlation(snap), request, status=202
                        )
                    return self._build_response(
                        _attach_correlation(snap_resp), request, status=202
                    )

            finally:
                if fg_acquired:
                    self._fg_sem.release()
                if bg_acquired:
                    self._bg_sem.release()

        except _ClientRequestError as exc:
            logger.warning(
                "%s - invalid upload for %s: %s", s, filename or "unknown", exc.message
            )
            return self._build_response(
                {"error": exc.message}, request, status=exc.status
            )
        except Exception as exc:
            logger.exception(
                "%s - error handling scan for %s: %s", s, filename or "unknown", exc
            )
            return self._build_response(
                {"error": "Internal server error"}, request, status=500
            )

    async def handle_query(self, request: web.Request) -> web.Response:
        """Handle ``GET|POST /v1/query`` — look up a report by file hash.

        Accepts the hash via query-string (``?hash=…``) or in a JSON
        request body (``{"hash": "…"}``).  Checks the in-memory task
        dict first, then falls back to Redis.

        Args:
            request: Incoming aiohttp request.

        Returns:
            JSON response with ``status`` set to ``'finished'``,
            ``'processing'``, ``'error'``, or ``'not_found'`` (HTTP 404).
        """
        timer("start")
        s = make_session(request)
        if not verify_api_key(s, request):
            return self._build_response({"error": "Unauthorized"}, request, status=401)
        try:
            if request.method == "POST":
                ct = (
                    request.headers.get("Content-Type", "")
                    .split(";")[0]
                    .strip()
                    .lower()
                )
                if ct == "application/x-msgpack":
                    raw = await request.read()
                    body = _msgpack.unpackb(raw, raw=False) if HAS_MSGPACK else {}
                elif ct == "application/cbor":
                    raw = await request.read()
                    body = _cbor2.loads(raw) if HAS_CBOR2 else {}
                else:
                    body = await request.json()
                file_hash = body.get("hash")
            else:
                file_hash = request.query.get("hash")
        except Exception:
            file_hash = request.query.get("hash")
        if not file_hash:
            return self._build_response(
                {"error": "No hash provided"}, request, status=400
            )
        if not re.fullmatch(r"[0-9a-f]{64}", file_hash):
            return self._build_response(
                {"error": "Invalid hash format"}, request, status=400
            )
        if file_hash in self.tasks:
            result = self.tasks[file_hash]
            if isinstance(result, asyncio.Task):
                if result.done():
                    if result.cancelled():
                        error = self._make_terminal_error_result(
                            file_hash, "Analysis was cancelled"
                        )
                        self._store_terminal_result(file_hash, error)
                        return self._build_response(error, request)
                    try:
                        report = result.result()
                        return self._build_response(
                            {"status": "finished", "report": report}, request
                        )
                    except Exception as exc:
                        error = self._make_terminal_error_result(file_hash)
                        self._store_terminal_result(file_hash, error)
                        logger.exception(
                            "%s - background task for %s raised: %s", s, file_hash, exc
                        )
                        return self._build_response(error, request)
                # Task still running — return partial report if available.
                partial = self._partials.get(file_hash)
                if partial:
                    snap = partial.snapshot()
                    snap["status"] = "processing"
                    return self._build_response(snap, request)
                return self._build_response({"status": "processing"}, request)
            if isinstance(result, dict) and result.get("status") == "error":
                return self._build_response(result, request)
            return self._build_response(
                {"status": "finished", "report": result}, request
            )
        report = await self.get_cached_report(s, file_hash)
        if report:
            return self._build_response(
                {"status": "finished", "report": report}, request
            )
        return self._build_response({"status": "not_found"}, request, status=404)

    def build_capabilities(self) -> dict:
        """Build the capabilities response payload from live module config.

        The result reflects the current config and installed dependencies,
        so it automatically picks up changes made by ``POST /v1/admin/reload``.

        Returns:
            Dict matching the ``GET /v1/capabilities`` response schema.
        """
        _az = config.get("xspct_analyzers", {})
        _cv = config.get("xspct_clamav", {})

        # --- engine block -----------------------------------------------
        engine = {
            "name": "xspct-scan",
            "version": _ENGINE_VERSION,
            "schema_version": _REPORT_SCHEMA_VERSION,
        }

        # --- limits block ------------------------------------------------
        limits = {
            "archive_max_depth": int(config.get("xspct_archive_max_depth", 2)),
            "archive_max_size": int(
                config.get("xspct_archive_max_size", MAX_UPLOAD_BYTES)
            ),
            "default_timeout": DEFAULT_SCAN_TIMEOUT,
            "max_file_size": MAX_UPLOAD_BYTES,
        }

        # --- response_formats block --------------------------------------
        _fmt = config.get("xspct_response_format", "auto")
        if _fmt == "auto":
            response_formats: list[str] = ["json"]
            if HAS_MSGPACK:
                response_formats.append("msgpack")
            if HAS_CBOR2:
                response_formats.append("cbor")
        elif _fmt == "msgpack" and HAS_MSGPACK:
            response_formats = ["msgpack"]
        elif _fmt == "cbor" and HAS_CBOR2:
            response_formats = ["cbor"]
        else:
            response_formats = ["json"]

        # --- per-analyzer active flags -----------------------------------
        enabled = self._resolve_enabled_analyzers()

        def _az_active(name: str, prereq: bool) -> bool:
            return name in enabled and prereq

        analyzers: dict = {
            "archive": {
                "active": _az_active("archive", self._archive_backend_available()),
                "detected_type": "archive",
                "extensions": sorted(TYPE_ROUTING["archive"]["extensions"]),
                "mime_patterns": [],
                "mime_types": sorted(TYPE_ROUTING["archive"]["mime_exact"]),
                "scope": "type-routed",
            },
            "clamav": {
                "active": (
                    HAS_CLAMD and _cv.get("enabled", False) and self._clamd is not None
                ),
                "scope": "global",
            },
            "html": {
                "active": _az_active("html", True),
                "detected_type": "html",
                "extensions": sorted(TYPE_ROUTING["html"]["extensions"]),
                "mime_patterns": [],
                "mime_types": sorted(TYPE_ROUTING["html"]["mime_exact"]),
                "scope": "type-routed",
            },
            "image": {
                "active": _az_active("image", HAS_OCR or HAS_PYZBAR),
                "detected_type": "image",
                "extensions": sorted(TYPE_ROUTING["image"]["extensions"]),
                # image/* coverage is via mime_prefixes in the top-level mime_types
                # aggregate; per-analyzer mime_patterns lists only fragment-based globs.
                "mime_patterns": [],
                "mime_types": sorted(TYPE_ROUTING["image"]["mime_exact"]),
                "scope": "type-routed",
            },
            "iocs": {
                "active": _az_active("iocs", HAS_IOCSEARCHER),
                "scope": "post-processing",
            },
            "javascript": {
                "active": _az_active("javascript", True),
                "scope": "post-processing",
            },
            "office": {
                "active": _az_active("office", HAS_OLETOOLS or HAS_OLEFILE),
                "detected_type": "office",
                "extensions": sorted(TYPE_ROUTING["office"]["extensions"]),
                "mime_patterns": sorted(
                    f + "*" for f in TYPE_ROUTING["office"]["mime_fragments"]
                ),
                "mime_types": sorted(TYPE_ROUTING["office"]["mime_exact"]),
                "scope": "type-routed",
            },
            "pdf": {
                "active": _az_active("pdf", HAS_PYMUPDF),
                "detected_type": "pdf",
                "extensions": sorted(TYPE_ROUTING["pdf"]["extensions"]),
                "mime_patterns": [],
                "mime_types": sorted(TYPE_ROUTING["pdf"]["mime_exact"]),
                "scope": "type-routed",
            },
            "text": {
                "active": _az_active("text", True),
                "detected_type": "text",
                "extensions": sorted(TYPE_ROUTING["text"]["extensions"]),
                # text/* coverage is via mime_prefixes in the top-level mime_types
                # aggregate; per-analyzer mime_patterns lists only fragment-based globs.
                "mime_patterns": [],
                "mime_types": sorted(TYPE_ROUTING["text"]["mime_exact"]),
                "scope": "type-routed",
            },
            "yara": {
                "active": (
                    HAS_YARA
                    and _az.get("yara", {}).get("enabled", False)
                    and getattr(self, "_yara_rules", None) is not None
                ),
                "scope": "global",
            },
            "yara_x": {
                "active": (
                    HAS_YARA_X
                    and _az.get("yara_x", {}).get("enabled", False)
                    and getattr(self, "_yara_x_rules", None) is not None
                ),
                "scope": "global",
            },
        }

        # --- aggregate mime_types block ----------------------------------
        _type_routed_names = [
            n
            for n, a in analyzers.items()
            if a.get("scope") == "type-routed" and a.get("active")
        ]
        _exact: set[str] = set()
        _prefixes: set[str] = set()
        _patterns: set[str] = set()
        _extensions: set[str] = set()
        for _n in _type_routed_names:
            _r = TYPE_ROUTING.get(_n, {})
            _exact.update(_r.get("mime_exact", ()))
            _prefixes.update(_r.get("mime_prefixes", ()))
            _patterns.update(f + "*" for f in _r.get("mime_fragments", ()))
            _extensions.update(_r.get("extensions", ()))

        _global_scanners = sorted(
            n
            for n, a in analyzers.items()
            if a.get("scope") == "global" and a.get("active")
        )
        mime_types = {
            "exact": sorted(_exact),
            "extensions": sorted(_extensions),
            "global_scanners": _global_scanners,
            "patterns": sorted(_patterns),
            "prefixes": sorted(_prefixes),
        }

        return {
            "analyzers": analyzers,
            "engine": engine,
            "limits": limits,
            "mime_types": mime_types,
            "response_formats": sorted(response_formats),
        }

    async def handle_capabilities(self, request: web.Request) -> web.Response:
        """Handle ``GET /v1/capabilities`` — expose active analyzers and MIME routing.

        Returns a JSON document describing which analyzers are active, what
        MIME types they accept, and the current limits.  The response is
        stable-sorted and carries an ``ETag`` for conditional re-fetching.

        Args:
            request: Incoming aiohttp request.

        Returns:
            ``application/json`` 200 with payload and ``ETag`` / ``Cache-Control``
            headers, ``304 Not Modified`` when the ``If-None-Match`` header
            matches the current ETag, or a JSON 401 when authentication fails.
        """
        s = make_session(request)
        if not verify_api_key(s, request):
            return web.json_response({"error": "Unauthorized"}, status=401)
        payload = self.build_capabilities()
        body = json.dumps(payload, sort_keys=True)
        etag = '"' + hashlib.sha256(body.encode()).hexdigest() + '"'
        if request.headers.get("If-None-Match") == etag:
            return web.Response(status=304, headers={"ETag": etag})
        return web.Response(
            text=body,
            content_type="application/json",
            headers={
                "ETag": etag,
                "Cache-Control": "max-age=60",
            },
        )

    async def handle_metrics(self, request: web.Request) -> web.Response:
        """Handle ``GET /v1/metrics`` — expose Prometheus-format counters.

        Emits all :data:`stats` counters plus the current in-memory task
        count as a plain-text Prometheus exposition.

        Args:
            request: Incoming aiohttp request.

        Returns:
            ``text/plain`` response in the Prometheus exposition format,
            or a JSON 401 if authentication fails.
        """
        timer("start")
        s = make_session(request)
        if not verify_api_key(s, request):
            return web.json_response({"error": "Unauthorized"}, status=401)
        lines = [
            "# HELP xspct_requests_total Total scan requests received",
            "# TYPE xspct_requests_total counter",
            f"xspct_requests_total {stats['requests_total']}",
            "# HELP xspct_requests_finished Scan requests completed within timeout",
            "# TYPE xspct_requests_finished counter",
            f"xspct_requests_finished {stats['requests_finished']}",
            "# HELP xspct_requests_timeout Scan requests that timed out (202)",
            "# TYPE xspct_requests_timeout counter",
            f"xspct_requests_timeout {stats['requests_timeout']}",
            "# HELP xspct_redis_hits Redis cache hits",
            "# TYPE xspct_redis_hits counter",
            f"xspct_redis_hits {stats['redis_hits']}",
            "# HELP xspct_redis_misses Redis cache misses",
            "# TYPE xspct_redis_misses counter",
            f"xspct_redis_misses {stats['redis_misses']}",
            "# HELP xspct_redis_errors Redis errors total",
            "# TYPE xspct_redis_errors counter",
            f"xspct_redis_errors {stats['redis_errors']}",
            "# HELP xspct_tasks_in_memory Current in-memory task/report entries",
            "# TYPE xspct_tasks_in_memory gauge",
            f"xspct_tasks_in_memory {len(self.tasks)}",
            # --- Two-tier concurrency ---
            "# HELP xspct_foreground_overloaded Requests rejected: no foreground slot within deadline",
            "# TYPE xspct_foreground_overloaded counter",
            f"xspct_foreground_overloaded {stats['foreground_overloaded']}",
            "# HELP xspct_background_rejected Timed-out scans dropped: no background slot available",
            "# TYPE xspct_background_rejected counter",
            f"xspct_background_rejected {stats['background_rejected']}",
            "# HELP xspct_background_completed Background scans that finished successfully",
            "# TYPE xspct_background_completed counter",
            f"xspct_background_completed {stats['background_completed']}",
            "# HELP xspct_background_errors Background scans that raised an exception",
            "# TYPE xspct_background_errors counter",
            f"xspct_background_errors {stats['background_errors']}",
            "# HELP xspct_foreground_slots_total Configured foreground semaphore slots",
            "# TYPE xspct_foreground_slots_total gauge",
            f"xspct_foreground_slots_total {int(config.get('xspct_foreground_slots', 16))}",
            "# HELP xspct_foreground_slots_free Current free foreground semaphore slots",
            "# TYPE xspct_foreground_slots_free gauge",
            f"xspct_foreground_slots_free {self._fg_sem._value if self._fg_sem else 0}",
            "# HELP xspct_foreground_slots_used Current in-use foreground semaphore slots",
            "# TYPE xspct_foreground_slots_used gauge",
            f"xspct_foreground_slots_used {int(config.get('xspct_foreground_slots', 16)) - (self._fg_sem._value if self._fg_sem else 0)}",
            "# HELP xspct_background_slots_total Configured background semaphore slots",
            "# TYPE xspct_background_slots_total gauge",
            f"xspct_background_slots_total {int(config.get('xspct_background_slots', 4))}",
            "# HELP xspct_background_slots_free Current free background semaphore slots",
            "# TYPE xspct_background_slots_free gauge",
            f"xspct_background_slots_free {self._bg_sem._value if self._bg_sem else 0}",
            "# HELP xspct_background_slots_used Current in-use background semaphore slots",
            "# TYPE xspct_background_slots_used gauge",
            f"xspct_background_slots_used {int(config.get('xspct_background_slots', 4)) - (self._bg_sem._value if self._bg_sem else 0)}",
            # --- ClamAV engine ---
            "# HELP xspct_clamav_clean Files scanned clean by ClamAV",
            "# TYPE xspct_clamav_clean counter",
            f"xspct_clamav_clean {stats['clamav_clean']}",
            "# HELP xspct_clamav_infected Files detected as infected by ClamAV",
            "# TYPE xspct_clamav_infected counter",
            f"xspct_clamav_infected {stats['clamav_infected']}",
            "# HELP xspct_clamav_errors ClamAV scan errors",
            "# TYPE xspct_clamav_errors counter",
            f"xspct_clamav_errors {stats['clamav_errors']}",
            "# HELP xspct_clamav_timeouts ClamAV scans that exceeded the per-scan timeout",
            "# TYPE xspct_clamav_timeouts counter",
            f"xspct_clamav_timeouts {stats['clamav_timeouts']}",
        ]
        # Per-analyzer timing/hit metrics (labeled)
        if stats["analyzer_stats"]:
            lines += [
                "# HELP xspct_analyzer_calls_total Analyzer invocations",
                "# TYPE xspct_analyzer_calls_total counter",
            ]
            for name, e in sorted(stats["analyzer_stats"].items()):
                lines.append(
                    f'xspct_analyzer_calls_total{{analyzer="{name}"}} {e["calls"]}'
                )
            lines += [
                "# HELP xspct_analyzer_hits_total Analyzer invocations that produced at least one finding",
                "# TYPE xspct_analyzer_hits_total counter",
            ]
            for name, e in sorted(stats["analyzer_stats"].items()):
                lines.append(
                    f'xspct_analyzer_hits_total{{analyzer="{name}"}} {e["hits"]}'
                )
            lines += [
                "# HELP xspct_analyzer_hit_rate Fraction of calls that produced a finding (0–1)",
                "# TYPE xspct_analyzer_hit_rate gauge",
            ]
            for name, e in sorted(stats["analyzer_stats"].items()):
                rate = e["hits"] / e["calls"] if e["calls"] else 0.0
                lines.append(f'xspct_analyzer_hit_rate{{analyzer="{name}"}} {rate:.4f}')
            lines += [
                "# HELP xspct_analyzer_time_ms_total Cumulative analyzer wall-time in milliseconds",
                "# TYPE xspct_analyzer_time_ms_total counter",
            ]
            for name, e in sorted(stats["analyzer_stats"].items()):
                lines.append(
                    f'xspct_analyzer_time_ms_total{{analyzer="{name}"}} {e["ms_total"]}'
                )
            lines += [
                "# HELP xspct_analyzer_time_ms_avg Average analyzer wall-time in milliseconds",
                "# TYPE xspct_analyzer_time_ms_avg gauge",
            ]
            for name, e in sorted(stats["analyzer_stats"].items()):
                avg = e["ms_total"] / e["calls"] if e["calls"] else 0.0
                lines.append(
                    f'xspct_analyzer_time_ms_avg{{analyzer="{name}"}} {avg:.1f}'
                )
            lines += [
                "# HELP xspct_analyzer_time_ms_min Minimum analyzer wall-time in milliseconds",
                "# TYPE xspct_analyzer_time_ms_min gauge",
            ]
            for name, e in sorted(stats["analyzer_stats"].items()):
                lines.append(
                    f'xspct_analyzer_time_ms_min{{analyzer="{name}"}} {e["ms_min"] or 0}'
                )
            lines += [
                "# HELP xspct_analyzer_time_ms_max Maximum analyzer wall-time in milliseconds",
                "# TYPE xspct_analyzer_time_ms_max gauge",
            ]
            for name, e in sorted(stats["analyzer_stats"].items()):
                lines.append(
                    f'xspct_analyzer_time_ms_max{{analyzer="{name}"}} {e["ms_max"]}'
                )
        return web.Response(text="\n".join(lines) + "\n", content_type="text/plain")

    async def handle_admin_reload(self, request: web.Request) -> web.Response:
        """Handle ``POST /v1/admin/reload`` — hot-reload config, YARA rules, and passwords.

        Requires a valid ``X-Admin-Api-Key`` header (``xspct_admin_api_key``
        config key).  Performs the following atomically from the event loop's
        perspective (each step blocks the loop briefly while the file is read):

        1. Re-reads the YAML config file supplied at startup (no-op if no file
           was passed on the command line).
        2. Re-reads the password list(s).
        3. Recompiles YARA rules from the configured ``rules_path``.

        Args:
            request: Incoming aiohttp request.

        Returns:
            JSON response ``{"status": "ok", "reloaded": [...]}`` on success,
            or an appropriate error response (401, 403, 500).
        """
        s = make_session(request)
        if not verify_admin_key(s, request):
            return web.json_response({"error": "Forbidden"}, status=403)
        reloaded = []
        try:
            # Re-apply the config file if one was given at startup.
            import sys as _sys

            config_path = _sys.argv[1] if len(_sys.argv) > 1 else None
            if config_path and os.path.isfile(config_path):
                load_config(config_path)
                configure_logging()
                self._rebuild_cached_config()
                reloaded.append("config")
                logger.info(
                    "%s - admin reload: config reloaded from %s", s, config_path
                )
            # Re-read passwords.
            self._read_passwords()
            reloaded.append("passwords")
            # Recompile YARA rules.
            if HAS_YARA:
                self._compile_yara_rules()
                reloaded.append("yara")
            logger.info("%s - admin reload complete: %s", s, reloaded)
            return web.json_response({"status": "ok", "reloaded": reloaded})
        except Exception as exc:
            logger.exception("%s - admin reload error: %s", s, exc)
            return web.json_response({"error": "Reload failed"}, status=500)

    async def handle_openapi_json(self, request: web.Request) -> web.Response:
        """Handle ``GET /v1/openapi.json`` — return the OpenAPI 3.0 spec.

        The spec is generated once (lazily) from the pydantic response models
        and cached in memory.  If pydantic is not installed the response
        contains an error message with a 503 status.

        Args:
            request: Incoming aiohttp request (unused).

        Returns:
            JSON response with the OpenAPI spec (200) or an error (503).
        """
        spec = _get_openapi_spec()
        status = 503 if "error" in spec else 200
        return web.json_response(spec, status=status)

    async def handle_redoc(self, request: web.Request) -> web.Response:
        """Handle ``GET /v1/apidoc/redoc`` — serve the ReDoc UI.

        Renders a self-contained HTML page that loads ReDoc from the
        official CDN and points it at ``/v1/openapi.json``.

        Args:
            request: Incoming aiohttp request (unused).

        Returns:
            HTML response with the ReDoc UI.
        """
        html = """<!DOCTYPE html>
<html>
<head>
  <title>xspct-scan API</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>body { margin: 0; padding: 0; }</style>
</head>
<body>
  <redoc spec-url="/v1/openapi.json"></redoc>
  <script src="https://cdn.jsdelivr.net/npm/redoc@2.4.0/bundles/redoc.standalone.js"
          crossorigin="anonymous"></script>
</body>
</html>"""
        return web.Response(text=html, content_type="text/html")


# ---------------------------------------------------------------------------
# Periodic stats logger
# ---------------------------------------------------------------------------


async def _log_stats_periodically(daemon: InspectorDaemon) -> None:
    interval = int(config["xspct_stats_interval"])

    # Snapshots of cumulative counters taken at the end of the previous
    # interval.  Deltas (current − previous) are logged so that a quiet
    # period shows zeros rather than repeating the lifetime totals.
    _prev: dict = {
        "requests_total": 0,
        "requests_finished": 0,
        "requests_timeout": 0,
        "redis_hits": 0,
        "redis_misses": 0,
    }
    # Per-analyzer previous snapshot: {name: {calls, hits, ms_total}}
    _prev_az: dict = {}

    while True:
        await asyncio.sleep(interval)

        # --- global counters ---
        total = stats["requests_total"]
        finished = stats["requests_finished"]
        timeout = stats["requests_timeout"]
        r_hits = stats["redis_hits"]
        r_misses = stats["redis_misses"]

        d_total = total - _prev["requests_total"]
        d_finished = finished - _prev["requests_finished"]
        d_timeout = timeout - _prev["requests_timeout"]
        d_hits = r_hits - _prev["redis_hits"]
        d_misses = r_misses - _prev["redis_misses"]

        d_lookups = d_hits + d_misses
        hit_rate = (d_hits / d_lookups * 100) if d_lookups > 0 else 0.0

        logger.info(
            "STATS requests_total=%d(+%d) finished=%d(+%d) timeout=%d(+%d) "
            "redis_hits=%d(+%d) redis_misses=%d(+%d) hit_rate=%.1f%% tasks_in_memory=%d",
            total,
            d_total,
            finished,
            d_finished,
            timeout,
            d_timeout,
            r_hits,
            d_hits,
            r_misses,
            d_misses,
            hit_rate,
            len(daemon.tasks),
        )

        _prev["requests_total"] = total
        _prev["requests_finished"] = finished
        _prev["requests_timeout"] = timeout
        _prev["redis_hits"] = r_hits
        _prev["redis_misses"] = r_misses

        # --- slot fill rate (instantaneous snapshot) ---
        fg_total = int(config.get("xspct_foreground_slots", 16))
        bg_total = int(config.get("xspct_background_slots", 4))
        fg_free = daemon._fg_sem._value if daemon._fg_sem else fg_total
        bg_free = daemon._bg_sem._value if daemon._bg_sem else bg_total
        fg_used = fg_total - fg_free
        bg_used = bg_total - bg_free
        fg_pct = fg_used / fg_total * 100 if fg_total else 0.0
        bg_pct = bg_used / bg_total * 100 if bg_total else 0.0
        logger.info(
            "SLOTS fg=%d/%d(%.0f%%) bg=%d/%d(%.0f%%) "
            "fg_overloaded=%d(+%d) bg_rejected=%d(+%d) bg_completed=%d bg_errors=%d",
            fg_used,
            fg_total,
            fg_pct,
            bg_used,
            bg_total,
            bg_pct,
            stats["foreground_overloaded"],
            stats["foreground_overloaded"] - _prev.get("foreground_overloaded", 0),
            stats["background_rejected"],
            stats["background_rejected"] - _prev.get("background_rejected", 0),
            stats["background_completed"],
            stats["background_errors"],
        )
        _prev["foreground_overloaded"] = stats["foreground_overloaded"]
        _prev["background_rejected"] = stats["background_rejected"]

        # --- per-analyzer counters ---
        for name, e in sorted(stats["analyzer_stats"].items()):
            calls = e["calls"]
            hits = e["hits"]
            ms_total = e["ms_total"]

            prev = _prev_az.get(name, {"calls": 0, "hits": 0, "ms_total": 0})
            d_calls = calls - prev["calls"]
            d_hits = hits - prev["hits"]
            d_ms = ms_total - prev["ms_total"]

            # Average over the new calls in this window only.
            avg = d_ms / d_calls if d_calls else 0.0
            pct = d_hits / d_calls * 100 if d_calls else 0.0

            logger.info(
                "ANALYZER %-12s calls=%d(+%d) hits=%d(+%d)(%.0f%%) "
                "time avg=%.0fms min=%dms max=%dms",
                name,
                calls,
                d_calls,
                hits,
                d_hits,
                pct,
                avg,
                e["ms_min"] or 0,
                e["ms_max"],
            )

            _prev_az[name] = {"calls": calls, "hits": hits, "ms_total": ms_total}


# ---------------------------------------------------------------------------
# App factory (with lifecycle hooks)
# ---------------------------------------------------------------------------


async def make_app() -> web.Application:
    """Create and configure the aiohttp :class:`~aiohttp.web.Application`.

    Instantiates :class:`InspectorDaemon`, wires lifecycle hooks
    (:meth:`~InspectorDaemon.setup` / :meth:`~InspectorDaemon.teardown`),
    and registers all routes:

    =================  ======  ====================
    Path               Method  Handler
    =================  ======  ====================
    /v1/scan           POST    :meth:`~InspectorDaemon.handle_scan`
    /v1/query          POST    :meth:`~InspectorDaemon.handle_query`
    /v1/query          GET     :meth:`~InspectorDaemon.handle_query`
    /v1/metrics        GET     :meth:`~InspectorDaemon.handle_metrics`
    /v1/admin/reload   POST    :meth:`~InspectorDaemon.handle_admin_reload`
    /v1/openapi.json   GET     :meth:`~InspectorDaemon.handle_openapi_json`
    /v1/apidoc/redoc   GET     :meth:`~InspectorDaemon.handle_redoc`
    /health            GET     Returns ``OK`` (unversioned)
    /ping              GET     Returns ``pong`` (unversioned)
    /                  GET     Returns ``xspct-scan``
    =================  ======

    Returns:
        Configured :class:`aiohttp.web.Application` ready to be served.
    """
    daemon = InspectorDaemon()

    async def _on_startup(app: web.Application) -> None:
        await daemon.setup()
        if config["xspct_stats_enabled"]:
            asyncio.create_task(_log_stats_periodically(daemon))
        logger.info("xspct-scan ready")

    async def _on_shutdown(app: web.Application) -> None:
        await daemon.teardown()
        logger.info("xspct-scan stopped")

    app = web.Application(client_max_size=MAX_UPLOAD_BYTES)
    app["daemon"] = daemon
    app.on_startup.append(_on_startup)
    app.on_shutdown.append(_on_shutdown)
    app.router.add_post("/v1/scan", daemon.handle_scan)
    app.router.add_post("/v1/query", daemon.handle_query)
    app.router.add_get("/v1/query", daemon.handle_query)
    app.router.add_get("/v1/capabilities", daemon.handle_capabilities)
    app.router.add_get("/v1/metrics", daemon.handle_metrics)
    app.router.add_post("/v1/admin/reload", daemon.handle_admin_reload)
    app.router.add_get("/v1/openapi.json", daemon.handle_openapi_json)
    app.router.add_get("/v1/apidoc/redoc", daemon.handle_redoc)

    async def _health(r: web.Request) -> web.Response:
        return web.Response(text="OK")

    async def _ping(r: web.Request) -> web.Response:
        return web.Response(text="pong")

    async def _root(r: web.Request) -> web.Response:
        return web.Response(text="xspct-scan")

    app.router.add_get("/health", _health)
    app.router.add_get("/ping", _ping)
    app.router.add_get("/", _root)
    return app
