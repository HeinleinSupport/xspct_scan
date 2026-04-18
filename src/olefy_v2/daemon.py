# SPDX-License-Identifier: EUPL-1.2
# Copyright (C) 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""
Olefy v2 Daemon
===============
Async HTTP service for analyzing Office/PDF/HTML documents for malware indicators.

Public API
----------
    load_config(path)       -- load and merge a YAML config file into `config`
    configure_logging()     -- configure the 'olefy' logger from current `config`
    make_app()              -- coroutine returning a configured aiohttp.web.Application
    config                  -- module-level dict with current configuration
    stats                   -- module-level dict with runtime counters
    InspectorDaemon         -- the analysis engine class
"""

import asyncio
import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import sys
import time
import timeit
import contextvars
import zipfile
from collections import OrderedDict

import magic
import msoffcrypto
import yaml
from aiohttp import web
from oletools.olevba import VBA_Parser
from oletools.rtfobj import RtfObjParser, RtfParser

try:
    import redis.asyncio as redis
    HAS_REDIS = True
except ImportError:
    try:
        import aioredis as redis  # type: ignore[no-redef]
        HAS_REDIS = True
    except ImportError:
        HAS_REDIS = False

# ---------------------------------------------------------------------------
# Per-request timer (ContextVar — isolated per async task)
# ---------------------------------------------------------------------------
_time_start_var: contextvars.ContextVar[float] = contextvars.ContextVar(
    'time_start', default=0.0
)


class _LazyTimer:
    """Deferred timer whose __str__ is only evaluated when the log record fires."""
    __slots__ = ()

    def __str__(self) -> str:
        return str(round(timeit.default_timer() - _time_start_var.get(), 5))

    __repr__ = __str__


_LAZY_TIMER = _LazyTimer()


def timer(action: str = '') -> object:
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
    if action == 'start':
        _time_start_var.set(timeit.default_timer())
        return 0
    return _LAZY_TIMER


# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------
config: dict = {
    'olefy_listen_address': ['0.0.0.0'],
    'olefy_listen_port': 8080,
    'olefy_listen_backlog': 256,
    'olefy_log_level': 20,
    'olefy_log_prefix': 'olefy',
    'olefy_api_header': 'X-Api-Key',
    'olefy_api_key': [],
    'olefy_api_key_verify_fail': True,
    'olefy_rspamd_header': 'X-Rspamd-ID',
    'olefy_tls': {
        'tls_enabled': False,
        'tls_cert': '',
        'tls_key': '',
    },
    'olefy_redis_cache': {
        'enabled': False,
        'host': 'localhost',
        'port': 6379,
        'user': '',
        'password': '',
        'prefix': 'olefy:',
        'expire': 3600,
        'max_errors': 3,
    },
    'olefy_stats_enabled': True,
    'olefy_stats_interval': 60,
    'olefy_password_file': '10k-most-common.txt',
}
"""Module-level configuration dictionary.

Populated by :func:`load_config`. Keys mirror the YAML configuration file;
see the :doc:`configuration` page for the full reference.
"""

# ---------------------------------------------------------------------------
# Runtime stats
# ---------------------------------------------------------------------------
stats: dict = {
    'requests_total': 0,
    'requests_finished': 0,
    'requests_timeout': 0,
    'redis_hits': 0,
    'redis_misses': 0,
    'redis_errors': 0,
}
"""Module-level runtime counters.

All values are integers incremented by the request handlers.
Exposed as Prometheus metrics via ``GET /metrics``.
"""

# ---------------------------------------------------------------------------
# Logger — NullHandler so we don't warn when used as a library.
# Call configure_logging() to attach a real handler.
# ---------------------------------------------------------------------------
logger = logging.getLogger('olefy')
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Public init helpers
# ---------------------------------------------------------------------------

def load_config(path: 'str | None' = None) -> None:
    """Load *path* (YAML) and deep-merge it into the module-level ``config`` dict.

    Sub-dicts ``olefy_tls`` and ``olefy_redis_cache`` are merged key-by-key so
    callers only need to specify the keys they want to override.

    Raises ``SystemExit(1)`` if the file is missing or contains invalid YAML.
    """
    if path is None:
        _normalise_api_key()
        return
    if not os.path.isfile(path):
        print(f'Config file not found: {path}', file=sys.stderr)
        sys.exit(1)
    try:
        with open(path) as fh:
            extra = yaml.safe_load(fh)
        if extra:
            for sub in ('olefy_tls', 'olefy_redis_cache'):
                if sub in extra:
                    merged = config[sub].copy()
                    merged.update(extra.pop(sub))
                    extra[sub] = merged
            config.update(extra)
    except yaml.YAMLError as exc:
        print(f'YAML error in {path}: {exc}', file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f'Cannot read {path}: {exc}', file=sys.stderr)
        sys.exit(1)
    _normalise_api_key()


def _normalise_api_key() -> None:
    key = config['olefy_api_key']
    if isinstance(key, str):
        config['olefy_api_key'] = [key] if key else []


def configure_logging() -> None:
    """Attach a ``StreamHandler`` to the *olefy* logger using current ``config``.

    Safe to call multiple times; existing non-NullHandler handlers are removed
    first so reconfiguration works correctly.
    """
    logger.setLevel(int(config['olefy_log_level']))
    # Remove any real handlers added by a previous call, keep NullHandler
    for h in list(logger.handlers):
        if not isinstance(h, logging.NullHandler):
            logger.removeHandler(h)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(
        config['olefy_log_prefix'] + ' %(levelname)s %(funcName)s %(message)s'
    ))
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


def make_session(request: web.Request, session_id: 'str | None' = None) -> str:
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
    rspamd_id = request.headers.get(config['olefy_rspamd_header'], '') if request else ''
    if rspamd_id:
        return f'<{sid[:6]}-{rspamd_id[:6]}>'
    return f'<{sid[:6]}>'


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
    keys = config['olefy_api_key']
    if not keys:
        return True
    provided = str(request.headers.get(config['olefy_api_header'], '') or '')
    valid = False
    for k in keys:
        valid |= hmac.compare_digest(provided, str(k))
    if valid:
        logger.debug('%s - api key verification success', s)
        return True
    if not config['olefy_api_key_verify_fail']:
        logger.debug('%s - api key failed but not fatal', s)
        return True
    logger.warning('%s - api key verification failed', s)
    return False


# ---------------------------------------------------------------------------
# RTF text extractor
# ---------------------------------------------------------------------------

class TextExtractorRtf(RtfParser):
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
            self.all_text.append(text.decode('ascii', errors='ignore'))
        except Exception:
            pass

    def get_text(self) -> str:
        """Parse the document and return all extracted text.

        Returns:
            A single string made up of all collected text tokens.
        """
        self.parse()
        return ''.join(self.all_text)


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

    * :meth:`handle_scan`     — ``POST /scan``
    * :meth:`handle_query`    — ``GET|POST /query``
    * :meth:`handle_metrics`  — ``GET /metrics``
    """

    _URL_RE = re.compile(r'https?://[a-zA-Z0-9\-\.\/\_\?\&\=\%\#\:]+')
    _IP_RE  = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    _DOM_RE = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    )
    _TASKS_MAX_SIZE = 512

    def __init__(self) -> None:
        """Create a new daemon instance with empty state.

        Attributes are fully initialised by :meth:`setup`; do not use
        the instance before calling it.
        """
        self.passwords: list[str] = []
        self.redis_pool = None
        self._redis_error_count = 0
        self.tasks: OrderedDict = OrderedDict()

    # ------------------------------------------------------------------
    # Redis helpers
    # ------------------------------------------------------------------

    def _redis_enabled(self, s: str) -> bool:
        if not config['olefy_redis_cache']['enabled'] or not self.redis_pool:
            return False
        if self._redis_error_count > int(config['olefy_redis_cache']['max_errors']):
            logger.debug('%s - Redis circuit-breaker open (%d errors)', s, self._redis_error_count)
            return False
        return True

    def _redis_record_error(self, s: str, exc: Exception) -> None:
        self._redis_error_count += 1
        logger.error('%s - Redis error (#%d): %s', s, self._redis_error_count, exc)
        stats['redis_errors'] += 1

    def _redis_reset_errors(self, s: str) -> None:
        if self._redis_error_count > 0:
            logger.info('%s - Redis recovered, resetting circuit-breaker', s)
            self._redis_error_count = 0

    async def get_cached_report(self, s: str, file_hash: str) -> 'dict | None':
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
            stats['redis_misses'] += 1
            return None
        key = config['olefy_redis_cache']['prefix'] + file_hash
        try:
            raw = await self.redis_pool.get(key)
            self._redis_reset_errors(s)
        except Exception as exc:
            self._redis_record_error(s, exc)
            return None
        if raw:
            stats['redis_hits'] += 1
            logger.debug('%s - Redis hit: %s', s, file_hash)
            return json.loads(raw)
        stats['redis_misses'] += 1
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
        self.tasks[file_hash] = report
        self.tasks.move_to_end(file_hash)
        self._evict_tasks()
        if not self._redis_enabled(s):
            return
        key = config['olefy_redis_cache']['prefix'] + file_hash
        expire = int(config['olefy_redis_cache']['expire'])
        try:
            await self.redis_pool.setex(key, expire, json.dumps(report))
            self._redis_reset_errors(s)
            logger.info('%s - cached report for %s (TTL %ds)', s, file_hash, expire)
        except Exception as exc:
            self._redis_record_error(s, exc)

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
        if HAS_REDIS and config['olefy_redis_cache']['enabled']:
            rc = config['olefy_redis_cache']
            url = f"redis://{rc['host']}:{rc['port']}"
            try:
                if hasattr(redis, 'from_url'):
                    self.redis_pool = redis.from_url(
                        url,
                        username=rc['user'] or None,
                        password=rc['password'] or None,
                        decode_responses=True,
                    )
                else:
                    self.redis_pool = await redis.create_redis_pool(url, encoding='utf-8')
                logger.info('Connected to Redis at %s', url)
            except Exception as exc:
                logger.error('Failed to connect to Redis: %s', exc)
                self.redis_pool = None
        elif config['olefy_redis_cache']['enabled'] and not HAS_REDIS:
            logger.warning('Redis requested but library not found. Caching disabled.')

    async def teardown(self) -> None:
        """Gracefully close the Redis connection pool.

        Called once during application shutdown via the aiohttp
        ``on_cleanup`` signal.
        """
        if self.redis_pool:
            try:
                await self.redis_pool.aclose()
            except Exception:
                pass

    def _read_passwords(self) -> None:
        defaults = ['VelvetSweatshop', '123', '1234', '12345', '123456', '4321']
        pw_file = config['olefy_password_file']
        try:
            with open(pw_file) as fh:
                self.passwords = fh.read().splitlines() + defaults
        except FileNotFoundError:
            logger.warning('Password file %s not found. Using defaults.', pw_file)
            self.passwords = defaults
        logger.info('Loaded %d passwords.', len(self.passwords))

    # ------------------------------------------------------------------
    # IOC extraction
    # ------------------------------------------------------------------

    def extract_iocs(self, data: bytes) -> dict:
        """Extract indicators of compromise (IOCs) from raw document bytes.

        Decodes the data as both UTF-8 and UTF-16 LE and scans the combined
        text with regular expressions for URLs, IP addresses, and domain names.

        Args:
            data: Raw file bytes to scan.

        Returns:
            A dict with keys ``urls``, ``ips``, and ``domains``, each
            containing a sorted list of unique strings.
        """
        try:
            text_utf8  = data.decode('utf-8',   'ignore')
            text_utf16 = data.decode('utf-16le', 'ignore')
        except Exception:
            text_utf8  = data.decode('ascii', 'ignore')
            text_utf16 = ''
        combined = text_utf8 + ' ' + text_utf16
        urls = sorted(set(self._URL_RE.findall(combined)))
        raw_ips = set(self._IP_RE.findall(combined))
        ips = sorted(
            ip for ip in raw_ips
            if all(0 <= int(p) <= 255 for p in ip.split('.'))
        )
        domains = sorted(set(self._DOM_RE.findall(combined)))
        return {'urls': urls, 'ips': ips, 'domains': domains}

    # ------------------------------------------------------------------
    # PDF analysis
    # ------------------------------------------------------------------

    def analyze_pdf(self, data: bytes) -> 'dict | None':
        """Analyse a PDF document for malware indicators.

        Searches for dangerous PDF markers (JavaScript, OpenAction, Launch,
        EmbeddedFiles, XFA, Encrypt) and extracts ``/URI`` IOCs.

        Args:
            data: Raw PDF bytes. Must start with ``%PDF``.

        Returns:
            A report dict on success, or ``None`` if *data* is not a PDF.

            Report keys:
                - **has_javascript** (bool)
                - **has_openaction** (bool)
                - **has_embedded_files** (bool)
                - **has_launch** (bool)
                - **is_encrypted** (bool)
                - **analyses** (list[dict]): Detected indicators.
                - **iocs** (dict): Extracted URLs, IPs, and domains.
                - **text_preview** (str)
        """
        if not data.startswith(b'%PDF'):
            return None
        report: dict = {
            'has_javascript': False, 'has_openaction': False,
            'has_embedded_files': False, 'has_launch': False,
            'is_encrypted': False, 'analyses': [],
            'iocs': {'urls': [], 'ips': [], 'domains': []},
        }
        markers = {
            b'/JS':            ('JavaScript',   'Embedded JavaScript code found'),
            b'/JavaScript':    ('JavaScript',   'Embedded JavaScript code found'),
            b'/OpenAction':    ('AutoExecute',  'Automatic action on open found'),
            b'/AA':            ('AutoExecute',  'Additional Action (auto-execute) found'),
            b'/EmbeddedFiles': ('EmbeddedFile', 'Embedded files found in PDF'),
            b'/Launch':        ('Execution',    'Launch action found (can execute external programs)'),
            b'/Encrypt':       ('Encryption',   'PDF is encrypted'),
            b'/XFA':           ('XFA',          'XML Forms Architecture (can contain scripts) found'),
        }
        for marker, (m_type, desc) in markers.items():
            if marker in data:
                report['analyses'].append({
                    'type': m_type,
                    'keyword': marker.decode('ascii'),
                    'description': desc,
                })
                if m_type == 'JavaScript':   report['has_javascript']     = True
                if m_type == 'AutoExecute':  report['has_openaction']     = True
                if m_type == 'EmbeddedFile': report['has_embedded_files'] = True
                if m_type == 'Execution':    report['has_launch']         = True
                if m_type == 'Encryption':   report['is_encrypted']       = True
        for uri in re.findall(rb'/URI\s*\((https?://[^\)]+)\)', data):
            try:
                url = uri.decode('utf-8', 'ignore')
                if url not in report['iocs']['urls']:
                    report['iocs']['urls'].append(url)
            except Exception:
                pass
        body_iocs = self.extract_iocs(data)
        for k in ('urls', 'ips', 'domains'):
            report['iocs'][k] = sorted(set(report['iocs'][k] + body_iocs[k]))
        report['text_preview'] = self.extract_text_preview(data, 'application/pdf')
        return report

    # ------------------------------------------------------------------
    # HTML analysis
    # ------------------------------------------------------------------

    def analyze_html(self, data: bytes) -> 'dict | None':
        """Analyse an HTML document for phishing and malware indicators.

        Detects suspicious JavaScript functions, HTML forms, iframes,
        meta-refresh redirects, and large Base64-encoded blobs that may
        indicate HTML smuggling.

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
        if b'<' not in header and b'http-equiv' not in header.lower():
            return None
        report: dict = {
            'has_scripts': False, 'has_forms': False,
            'has_iframes': False, 'has_meta_refresh': False,
            'analyses': [], 'iocs': {'urls': [], 'ips': [], 'domains': []},
        }
        try:
            text = data.decode('utf-8', 'ignore')
        except Exception:
            text = data.decode('ascii', 'ignore')
        if re.search(r'<script', text, re.I):
            report['has_scripts'] = True
            for func, desc in {
                'eval(':                'Use of eval() for dynamic code execution',
                'unescape(':            'Use of unescape() (often used for obfuscation)',
                'document.write(':      'Use of document.write() for dynamic content',
                'atob(':                'Use of atob() for Base64 decoding',
                'String.fromCharCode(': 'Use of String.fromCharCode() for obfuscation',
            }.items():
                if func in text:
                    report['analyses'].append({
                        'type': 'SuspiciousJS',
                        'keyword': func,
                        'description': desc,
                    })
        if re.search(r'<form', text, re.I):
            report['has_forms'] = True
            report['analyses'].append({
                'type': 'HTMLForm', 'keyword': 'form',
                'description': 'HTML form found (potential phishing)',
            })
        if re.search(r'<iframe', text, re.I):
            report['has_iframes'] = True
            report['analyses'].append({
                'type': 'HTMLIframe', 'keyword': 'iframe',
                'description': 'HTML iframe found (potential hidden content)',
            })
        if re.search(r'http-equiv=["\']refresh["\']', text, re.I):
            report['has_meta_refresh'] = True
            report['analyses'].append({
                'type': 'HTMLRedirect', 'keyword': 'meta-refresh',
                'description': 'Automatic redirect via meta-refresh found',
            })
        blobs = re.findall(r'[a-zA-Z0-9+/]{1000,}', text)
        if blobs:
            report['analyses'].append({
                'type': 'HTMLSmuggling', 'keyword': 'base64-blob',
                'description': f'Large Base64-like blob found ({len(blobs)} blobs > 1000 chars)',
            })
        report['iocs'] = self.extract_iocs(data)
        report['text_preview'] = self.extract_text_preview(data, 'text/html')
        return report

    # ------------------------------------------------------------------
    # Text preview
    # ------------------------------------------------------------------

    def extract_text_preview(self, data: bytes, file_mime: 'str | None',
                              limit: int = 2000) -> str:
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
        mime_lower = (file_mime or '').lower()
        if 'html' in mime_lower or mime_lower == 'application/xhtml+xml':
            try:
                text = data.decode('utf-8', 'ignore')
                text = re.sub(r'<(script|style)[^>]*>.*?</\1>', ' ', text,
                              flags=re.I | re.S)
                text = re.sub(r'<[^>]+>', ' ', text)
                return re.sub(r'\s+', ' ', text)[:limit].strip()
            except Exception:
                pass
        if 'rtf' in mime_lower or data.startswith(b'{\\rt'):
            try:
                te = TextExtractorRtf(data)
                return re.sub(r'\s+', ' ', te.get_text())[:limit].strip()
            except Exception as exc:
                logger.warning('RTF text extraction failed: %s', exc)
        if 'openxmlformats' in mime_lower:
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    for xml_path in ('word/document.xml', 'xl/worksheets/sheet1.xml'):
                        if xml_path in z.namelist():
                            content = z.read(xml_path).decode('utf-8', 'ignore')
                            text = re.sub(r'<[^>]+>', ' ', content)
                            return re.sub(r'\s+', ' ', text)[:limit].strip()
            except Exception:
                pass
        printable = ''.join(
            chr(c) if 32 <= c <= 126 or c in (9, 10, 13) else ' ' for c in data
        )
        return re.sub(r'\s+', ' ', printable)[:limit].strip()

    # ------------------------------------------------------------------
    # File type detection
    # ------------------------------------------------------------------

    def get_detected_type(self, mime: 'str | None', desc: 'str | None',
                          filename: 'str | None', data: 'bytes | None') -> str:
        """Determine the analysis type to run for a given file.

        Checks MIME type, magic description string, filename extension, and
        (for RTF) the magic bytes ``{\\rt`` in that order.

        Args:
            mime: MIME type string (e.g. ``application/pdf``).
            desc: Human-readable magic description (e.g. ``PDF document``).
            filename: Original filename (used for extension matching).
            data: First few bytes of the file (used for RTF magic detection).

        Returns:
            One of ``'pdf'``, ``'html'``, or ``'office'``.
        """
        mime     = (mime     or '').lower()
        desc     = (desc     or '').lower()
        filename = (filename or '').lower()
        if 'pdf' in mime or 'pdf' in desc or filename.endswith('.pdf'):
            return 'pdf'
        if ('html' in mime or 'html' in desc or mime == 'application/xhtml+xml'
                or any(filename.endswith(e) for e in ('.html', '.htm', '.xhtml'))):
            return 'html'
        if 'rtf' in mime or 'rtf' in desc or (data and data.startswith(b'{\\rt')):
            return 'office'
        return 'office'

    # ------------------------------------------------------------------
    # Report merging
    # ------------------------------------------------------------------

    def merge_reports(self, target: dict, source: 'dict | None') -> None:
        """Merge a partial analysis report into an accumulator dict in-place.

        Rules:
            - ``analyses`` and ``rtf_objects`` lists are appended without
              duplicates.
            - ``iocs`` sub-dicts are union-merged and sorted.
            - Boolean indicator flags are OR-ed together.
            - String fields (``decryption_password``, ``text_preview``) keep
              the longest non-empty value.
            - The ``meta`` key is never overwritten.

        Args:
            target: The accumulator report dict to merge *source* into.
            source: A partial report dict returned by one of the
                ``analyze_*`` methods. Ignored if ``None``.
        """
        if not source:
            return
        for key, value in source.items():
            if key == 'analyses':
                for item in value:
                    if item not in target['analyses']:
                        target['analyses'].append(item)
            elif key == 'iocs':
                for ik in ('urls', 'ips', 'domains'):
                    target['iocs'][ik] = sorted(
                        set(target['iocs'][ik] + value.get(ik, []))
                    )
            elif key == 'rtf_objects':
                for item in value:
                    if item not in target['rtf_objects']:
                        target['rtf_objects'].append(item)
            elif key in ('has_macro', 'has_javascript', 'has_openaction',
                         'has_embedded_files', 'has_launch', 'is_encrypted',
                         'has_scripts', 'has_forms', 'has_iframes',
                         'has_meta_refresh', 'decrypted'):
                if isinstance(value, bool):
                    target[key] = target.get(key, False) or value
            elif key in ('decryption_password', 'text_preview'):
                if value and (
                    not target.get(key)
                    or len(str(value)) > len(str(target.get(key, '')))
                ):
                    target[key] = value
            elif key == 'meta':
                continue
            elif key not in target:
                target[key] = value

    # ------------------------------------------------------------------
    # Office / OLE / RTF analysis
    # ------------------------------------------------------------------

    def analyze_office(self, s: str, filename: str, data: bytes,
                       file_mime: 'str | None', rtf_eval: bool = False,
                       custom_passwords: 'list | None' = None) -> 'dict | None':
        """Analyse an Office document (OLE2, OOXML, RTF) for malware indicators.

        Uses :mod:`oletools.olevba` to detect and analyse VBA/XLM macros.
        Encrypted files are decrypted automatically via
        :mod:`msoffcrypto` and the oletools decryption helpers using the
        password list from :attr:`passwords`.

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
        """
        office_report: dict = {
            'has_macro': False, 'analyses': [], 'rtf_objects': [],
            'decrypted': False, 'decryption_password': None,
            'iocs': {'urls': [], 'ips': [], 'domains': []},
            'text_preview': '',
        }
        if rtf_eval and (
            file_mime in ('text/rtf', 'application/rtf') or data.startswith(b'{\\rt')
        ):
            try:
                rtfp = RtfObjParser(data)
                rtfp.parse()
                for rtfobj in rtfp.objects:
                    office_report['rtf_objects'].append({
                        'is_ole':      rtfobj.is_ole,
                        'class_name':  rtfobj.class_name,
                        'oledata_md5': rtfobj.oledata_md5 if rtfobj.is_ole else None,
                        'is_package':  rtfobj.is_package,
                    })
            except Exception as exc:
                logger.error('%s - RTF analysis error: %s', s, exc)

        passwords = (custom_passwords or []) + self.passwords
        working_data = data
        vba_parser = None
        try:
            vba_parser = VBA_Parser(filename, data=data)
            if vba_parser.type is None:
                vba_parser.close()
                vba_parser = None
                return office_report if office_report['rtf_objects'] else None

            vba_parser.no_xlm = False
            office_report['has_macro'] = vba_parser.detect_vba_macros()

            if vba_parser.detect_is_encrypted():
                logger.info('%s - %s is encrypted. Trying msoffcrypto...', s, filename)
                ms_file_io = io.BytesIO(data)
                try:
                    ms_file = msoffcrypto.OfficeFile(ms_file_io)
                    decrypted_data = None
                    for password in passwords:
                        try:
                            ms_file.load_key(password=password)
                            dec_io = io.BytesIO()
                            ms_file.decrypt(dec_io)
                            decrypted_data = dec_io.getvalue()
                            office_report['decryption_password'] = password
                            logger.info('%s - decrypted with msoffcrypto', s)
                            break
                        except Exception:
                            continue
                    if decrypted_data:
                        vba_parser.close()
                        working_data = decrypted_data
                        vba_parser = VBA_Parser(filename, data=working_data)
                        vba_parser.no_xlm = False
                        office_report['has_macro'] = vba_parser.detect_vba_macros()
                        office_report['decrypted'] = True
                    else:
                        logger.warning('%s - msoffcrypto failed, trying oletools...', s)
                        working_data, vba_parser, office_report = (
                            self._try_oletools_decrypt(
                                s, filename, passwords, vba_parser, office_report
                            )
                        )
                except Exception as exc:
                    logger.error(
                        '%s - msoffcrypto setup error: %s, falling back to oletools', s, exc
                    )
                    working_data, vba_parser, office_report = (
                        self._try_oletools_decrypt(
                            s, filename, passwords, vba_parser, office_report
                        )
                    )

            results = vba_parser.analyze_macros(False, True)
            if results:
                for kw_type, keyword, description in results:
                    if kw_type == 'IOC':
                        if '://' in keyword:
                            if keyword not in office_report['iocs']['urls']:
                                office_report['iocs']['urls'].append(keyword)
                        elif re.match(
                            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', keyword
                        ):
                            if keyword not in office_report['iocs']['ips']:
                                office_report['iocs']['ips'].append(keyword)
                        else:
                            if keyword not in office_report['iocs']['domains']:
                                office_report['iocs']['domains'].append(keyword)
                    else:
                        office_report['analyses'].append({
                            'type': kw_type,
                            'keyword': keyword,
                            'description': description,
                        })

            effective = working_data if working_data is not None else data
            body_iocs = self.extract_iocs(effective)
            for k in ('urls', 'ips', 'domains'):
                office_report['iocs'][k] = sorted(
                    set(office_report['iocs'][k] + body_iocs[k])
                )
            office_report['text_preview'] = self.extract_text_preview(effective, file_mime)

        except Exception as exc:
            logger.error('%s - OLE analysis error for %s: %s', s, filename, exc)
            effective = working_data if working_data is not None else data
            office_report['iocs']         = self.extract_iocs(effective)
            office_report['text_preview'] = self.extract_text_preview(effective, file_mime)
        finally:
            if vba_parser is not None:
                try:
                    vba_parser.close()
                except Exception:
                    pass
        return office_report

    def _try_oletools_decrypt(self, s: str, filename: str, passwords: list,
                              vba_parser, office_report: dict):
        decrypted_file = None
        for pw in passwords:
            try:
                res = vba_parser.decrypt_file([pw])
                if res:
                    decrypted_file = res
                    office_report['decryption_password'] = pw
                    break
            except Exception:
                continue
        if decrypted_file:
            logger.info('%s - decrypted with oletools', s)
            vba_parser.close()
            try:
                with open(decrypted_file, 'rb') as fh:
                    working_data = fh.read()
            finally:
                try:
                    os.unlink(decrypted_file)
                except OSError:
                    pass
            vba_parser = VBA_Parser(filename, data=working_data)
            vba_parser.no_xlm = False
            office_report['has_macro'] = vba_parser.detect_vba_macros()
            office_report['decrypted'] = True
            return working_data, vba_parser, office_report
        logger.warning('%s - decryption failed with all tools', s)
        return None, vba_parser, office_report

    # ------------------------------------------------------------------
    # Full analysis pipeline
    # ------------------------------------------------------------------

    def sync_analyze(self, s: str, filename: str, data: bytes,
                     file_mime: 'str | None', file_desc: 'str | None' = None,
                     rtf_eval: bool = False,
                     custom_passwords: 'list | None' = None,
                     types_to_run: 'list | None' = None) -> dict:
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
            and ``meta``.
        """
        file_hash = hashlib.sha256(data).hexdigest()
        if not types_to_run:
            types_to_run = [self.get_detected_type(file_mime, file_desc, filename, data)]
        report: dict = {
            'filename':            filename,
            'file_hash':           file_hash,
            'file_type':           file_mime,
            'file_description':    file_desc,
            'detected_type':       '',
            'has_macro':           False,
            'analyses':            [],
            'meta': {
                'script_name': 'olefy_v2',
                'version': '2.0.0',
                'type': 'MetaInformation',
            },
            'rtf_objects':         [],
            'decrypted':           False,
            'decryption_password': None,
            'iocs':                {'urls': [], 'ips': [], 'domains': []},
            'text_preview':        '',
        }
        successful_types = []
        for t in types_to_run:
            res = None
            if t == 'pdf':
                res = self.analyze_pdf(data)
            elif t == 'html':
                res = self.analyze_html(data)
            elif t == 'office':
                res = self.analyze_office(
                    s, filename, data, file_mime, rtf_eval, custom_passwords
                )
            if res:
                successful_types.append(t)
                self.merge_reports(report, res)
        report['detected_type'] = (
            ','.join(sorted(successful_types)) if successful_types else 'unknown'
        )
        if not report['text_preview']:
            report['text_preview'] = self.extract_text_preview(data, file_mime)
        return report

    async def analyze_task(self, s: str, file_hash: str, filename: str,
                           data: bytes, file_mime: 'str | None',
                           file_desc: 'str | None' = None,
                           rtf_eval: bool = False,
                           custom_passwords: 'list | None' = None,
                           types_to_run: 'list | None' = None) -> dict:
        """Run :meth:`sync_analyze` in a thread-pool and cache the result.

        Wraps :meth:`sync_analyze` with :func:`asyncio.get_running_loop`\ ``.run_in_executor`` so CPU-bound oletools work does not block the
        event loop, then persists the finished report via
        :meth:`cache_report`.

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
            The finished report dict from :meth:`sync_analyze`.
        """
        logger.info('%s - starting analysis for %s (%s)', s, filename, file_hash)
        loop = asyncio.get_running_loop()
        report = await loop.run_in_executor(
            None, self.sync_analyze, s, filename, data, file_mime,
            file_desc, rtf_eval, custom_passwords, types_to_run,
        )
        await self.cache_report(s, file_hash, report)
        return report

    # ------------------------------------------------------------------
    # HTTP request handlers
    # ------------------------------------------------------------------

    async def handle_scan(self, request: web.Request) -> web.Response:
        """Handle ``POST /scan`` — accept a multipart file and return a report.

        Reads the ``doc`` part (required), optional ``passwords``,
        ``file_mime``, and ``file_type`` parts.  Checks the Redis cache
        first; on a miss, dispatches to :meth:`analyze_task` and waits up
        to *timeout* seconds (default 10).  Returns HTTP 202 with status
        ``processing`` if the timeout is exceeded — the analysis continues
        in the background and the result can be polled via ``GET /query``.

        Args:
            request: Incoming aiohttp request.

        Returns:
            JSON :class:`aiohttp.web.Response` containing the report dict
            (HTTP 200), a ``processing`` stub (HTTP 202), or an error
            response (HTTP 400 / 401 / 500).
        """
        timer('start')
        s = make_session(request)
        stats['requests_total'] += 1
        if not verify_api_key(s, request):
            return web.json_response({'error': 'Unauthorized'}, status=401)
        start_time = time.monotonic()
        filename = None
        try:
            timeout  = float(request.query.get('timeout', 10))
            rtf_eval = request.query.get('rtf', 'false').lower() == 'true'
            reader = await request.multipart()
            filedata:           'bytes | None' = None
            custom_passwords:   list           = []
            file_mime_provided: 'str | None'   = None
            file_type_provided: 'str | None'   = None
            async for part in reader:
                if part.name == 'doc':
                    filename = part.filename
                    filedata = bytes(await part.read())
                    logger.info('%s (%s) - read %d bytes from %s',
                                s, timer(), len(filedata), filename)
                elif part.name == 'passwords':
                    raw = await part.text()
                    custom_passwords = [
                        p.strip() for p in raw.replace(',', '\n').split('\n') if p.strip()
                    ]
                    logger.info('%s (%s) - received %d custom passwords',
                                s, timer(), len(custom_passwords))
                elif part.name == 'file_mime':
                    file_mime_provided = (await part.text()).strip()
                elif part.name == 'file_type':
                    file_type_provided = (await part.text()).strip()
            if not filedata:
                logger.warning('%s - no "doc" part in multipart request', s)
                return web.json_response(
                    {'error': 'No file part named "doc"'}, status=400
                )
            file_hash = hashlib.sha256(filedata).hexdigest()
            cached = await self.get_cached_report(s, file_hash)
            if cached:
                if cached.get('decrypted') or not custom_passwords:
                    logger.info('%s (%s) - cache hit for %s', s, timer(), file_hash)
                    cached['cache_hit'] = True
                    return web.json_response(cached)
                logger.info('%s - cache hit but re-analyzing (custom passwords)', s)
            file_magic_mime = magic.Magic(mime=True)
            magic_mime = file_magic_mime.from_buffer(filedata[:2048])
            file_magic_desc = magic.Magic()
            magic_desc = file_magic_desc.from_buffer(filedata[:2048])
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
            logger.info('%s (%s) - file=%s mime=%s types=%s',
                        s, timer(), filename, file_mime, types_to_run)
            task = asyncio.create_task(
                self.analyze_task(
                    s, file_hash, filename, filedata, file_mime,
                    file_desc, rtf_eval, custom_passwords, list(types_to_run),
                )
            )
            self.tasks[file_hash] = task
            self.tasks.move_to_end(file_hash)
            self._evict_tasks()
            try:
                report = await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
                report['status']     = 'finished'
                report['time_taken'] = round(time.monotonic() - start_time, 4)
                stats['requests_finished'] += 1
                return web.json_response(report)
            except asyncio.TimeoutError:
                logger.info('%s (%s) - timeout for %s, continuing in background',
                            s, timer(), filename)
                stats['requests_timeout'] += 1
                return web.json_response({
                    'status':     'processing',
                    'file_hash':  file_hash,
                    'message':    'Analysis is continuing in background',
                    'time_taken': round(time.monotonic() - start_time, 4),
                }, status=202)
        except Exception as exc:
            logger.exception(
                '%s - error handling scan for %s: %s', s, filename or 'unknown', exc
            )
            return web.json_response({'error': 'Internal server error'}, status=500)

    async def handle_query(self, request: web.Request) -> web.Response:
        """Handle ``GET|POST /query`` — look up a report by file hash.

        Accepts the hash via query-string (``?hash=…``) or in a JSON
        request body (``{"hash": "…"}``).  Checks the in-memory task
        dict first, then falls back to Redis.

        Args:
            request: Incoming aiohttp request.

        Returns:
            JSON response with ``status`` set to ``'finished'``,
            ``'processing'``, ``'error'``, or ``'not_found'`` (HTTP 404).
        """
        timer('start')
        s = make_session(request)
        if not verify_api_key(s, request):
            return web.json_response({'error': 'Unauthorized'}, status=401)
        try:
            if request.method == 'POST':
                body = await request.json()
                file_hash = body.get('hash')
            else:
                file_hash = request.query.get('hash')
        except Exception:
            file_hash = request.query.get('hash')
        if not file_hash:
            return web.json_response({'error': 'No hash provided'}, status=400)
        if file_hash in self.tasks:
            result = self.tasks[file_hash]
            if isinstance(result, asyncio.Task):
                if result.done():
                    try:
                        report = result.result()
                        return web.json_response({'status': 'finished', 'report': report})
                    except Exception as exc:
                        logger.exception(
                            '%s - background task for %s raised: %s', s, file_hash, exc
                        )
                        return web.json_response(
                            {'status': 'error', 'error': 'Internal server error'},
                            status=500,
                        )
                return web.json_response({'status': 'processing'})
            return web.json_response({'status': 'finished', 'report': result})
        report = await self.get_cached_report(s, file_hash)
        if report:
            return web.json_response({'status': 'finished', 'report': report})
        return web.json_response({'status': 'not_found'}, status=404)

    async def handle_metrics(self, request: web.Request) -> web.Response:
        """Handle ``GET /metrics`` — expose Prometheus-format counters.

        Emits all :data:`stats` counters plus the current in-memory task
        count as a plain-text Prometheus exposition.

        Args:
            request: Incoming aiohttp request.

        Returns:
            ``text/plain`` response in the Prometheus exposition format,
            or a JSON 401 if authentication fails.
        """
        timer('start')
        s = make_session(request)
        if not verify_api_key(s, request):
            return web.json_response({'error': 'Unauthorized'}, status=401)
        lines = [
            '# HELP olefy_requests_total Total scan requests received',
            '# TYPE olefy_requests_total counter',
            f'olefy_requests_total {stats["requests_total"]}',
            '# HELP olefy_requests_finished Scan requests completed within timeout',
            '# TYPE olefy_requests_finished counter',
            f'olefy_requests_finished {stats["requests_finished"]}',
            '# HELP olefy_requests_timeout Scan requests that timed out (202)',
            '# TYPE olefy_requests_timeout counter',
            f'olefy_requests_timeout {stats["requests_timeout"]}',
            '# HELP olefy_redis_hits Redis cache hits',
            '# TYPE olefy_redis_hits counter',
            f'olefy_redis_hits {stats["redis_hits"]}',
            '# HELP olefy_redis_misses Redis cache misses',
            '# TYPE olefy_redis_misses counter',
            f'olefy_redis_misses {stats["redis_misses"]}',
            '# HELP olefy_redis_errors Redis errors total',
            '# TYPE olefy_redis_errors counter',
            f'olefy_redis_errors {stats["redis_errors"]}',
            '# HELP olefy_tasks_in_memory Current in-memory task/report entries',
            '# TYPE olefy_tasks_in_memory gauge',
            f'olefy_tasks_in_memory {len(self.tasks)}',
        ]
        return web.Response(text='\n'.join(lines) + '\n', content_type='text/plain')


# ---------------------------------------------------------------------------
# Periodic stats logger
# ---------------------------------------------------------------------------

async def _log_stats_periodically(daemon: InspectorDaemon) -> None:
    interval = int(config['olefy_stats_interval'])
    while True:
        await asyncio.sleep(interval)
        total   = stats['requests_total']
        finished = stats['requests_finished']
        timeout  = stats['requests_timeout']
        hits     = stats['redis_hits']
        misses   = stats['redis_misses']
        total_lookups = hits + misses
        hit_rate = (hits / total_lookups * 100) if total_lookups > 0 else 0.0
        logger.info(
            'STATS requests_total=%d finished=%d timeout=%d '
            'redis_hits=%d redis_misses=%d hit_rate=%.1f%% tasks_in_memory=%d',
            total, finished, timeout, hits, misses, hit_rate, len(daemon.tasks),
        )


# ---------------------------------------------------------------------------
# App factory (with lifecycle hooks)
# ---------------------------------------------------------------------------

async def make_app() -> web.Application:
    """Create and configure the aiohttp :class:`~aiohttp.web.Application`.

    Instantiates :class:`InspectorDaemon`, wires lifecycle hooks
    (:meth:`~InspectorDaemon.setup` / :meth:`~InspectorDaemon.teardown`),
    and registers all routes:

    =========  ======  ====================
    Path       Method  Handler
    =========  ======  ====================
    /scan      POST    :meth:`~InspectorDaemon.handle_scan`
    /query     POST    :meth:`~InspectorDaemon.handle_query`
    /query     GET     :meth:`~InspectorDaemon.handle_query`
    /metrics   GET     :meth:`~InspectorDaemon.handle_metrics`
    /health    GET     Returns ``OK``
    /ping      GET     Returns ``pong``
    /          GET     Returns ``Olefy v2``
    =========  ======  ====================

    Returns:
        Configured :class:`aiohttp.web.Application` ready to be served.
    """
    daemon = InspectorDaemon()

    async def _on_startup(app: web.Application) -> None:
        await daemon.setup()
        if config['olefy_stats_enabled']:
            asyncio.create_task(_log_stats_periodically(daemon))
        logger.info('Olefy v2 ready')

    async def _on_shutdown(app: web.Application) -> None:
        await daemon.teardown()
        logger.info('Olefy v2 stopped')

    app = web.Application()
    app.on_startup.append(_on_startup)
    app.on_shutdown.append(_on_shutdown)
    app.router.add_post('/scan',   daemon.handle_scan)
    app.router.add_post('/query',  daemon.handle_query)
    app.router.add_get('/query',   daemon.handle_query)
    app.router.add_get('/metrics', daemon.handle_metrics)
    app.router.add_get('/health',  lambda r: web.Response(text='OK'))
    app.router.add_get('/ping',    lambda r: web.Response(text='pong'))
    app.router.add_get('/',        lambda r: web.Response(text='Olefy v2'))
    return app
