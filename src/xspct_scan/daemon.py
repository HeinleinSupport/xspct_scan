# SPDX-License-Identifier: EUPL-1.2
# Copyright (C) 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
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

import olefile as _olefile
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
    from PIL import Image as _PILImage
    import pytesseract as _pytesseract
    HAS_OCR = True
except ImportError:
    HAS_OCR = False

try:
    from pyzbar import pyzbar as _pyzbar
    HAS_PYZBAR = True
except ImportError:
    HAS_PYZBAR = False

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
    'xspct_listen_address': ['0.0.0.0'],
    'xspct_listen_port': 8080,
    'xspct_listen_backlog': 256,
    'xspct_log_level': 20,
    'xspct_log_prefix': 'xspct-scan',
    'xspct_api_header': 'X-Api-Key',
    'xspct_api_key': [],
    'xspct_api_key_verify_fail': True,
    'xspct_rspamd_header': 'X-Rspamd-ID',
    'xspct_tls': {
        'tls_enabled': False,
        'tls_cert': '',
        'tls_key': '',
    },
    'xspct_redis_cache': {
        'enabled': False,
        'host': 'localhost',
        'port': 6379,
        'user': '',
        'password': '',
        'prefix': 'xspct:',
        'expire': 3600,
        'max_errors': 3,
    },
    'xspct_stats_enabled': True,
    'xspct_stats_interval': 60,
    'xspct_password_file': '10k-most-common.txt',
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
logger = logging.getLogger('xspct-scan')
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Public init helpers
# ---------------------------------------------------------------------------

def load_config(path: 'str | None' = None) -> None:
    """Load *path* (YAML) and deep-merge it into the module-level ``config`` dict.

    Sub-dicts ``xspct_tls`` and ``xspct_redis_cache`` are merged key-by-key so
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
            for sub in ('xspct_tls', 'xspct_redis_cache'):
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
    key = config['xspct_api_key']
    if isinstance(key, str):
        config['xspct_api_key'] = [key] if key else []


def configure_logging() -> None:
    """Attach a ``StreamHandler`` to the *xspct-scan* logger using current ``config``.

    Safe to call multiple times; existing non-NullHandler handlers are removed
    first so reconfiguration works correctly.
    """
    logger.setLevel(int(config['xspct_log_level']))
    # Remove any real handlers added by a previous call, keep NullHandler
    for h in list(logger.handlers):
        if not isinstance(h, logging.NullHandler):
            logger.removeHandler(h)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(
        config['xspct_log_prefix'] + ' %(levelname)s %(funcName)s %(message)s'
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
    rspamd_id = request.headers.get(config['xspct_rspamd_header'], '') if request else ''
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
    keys = config['xspct_api_key']
    if not keys:
        return True
    provided = str(request.headers.get(config['xspct_api_header'], '') or '')
    valid = False
    for k in keys:
        valid |= hmac.compare_digest(provided, str(k))
    if valid:
        logger.debug('%s - api key verification success', s)
        return True
    if not config['xspct_api_key_verify_fail']:
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
        if not config['xspct_redis_cache']['enabled'] or not self.redis_pool:
            return False
        if self._redis_error_count > int(config['xspct_redis_cache']['max_errors']):
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
        key = config['xspct_redis_cache']['prefix'] + file_hash
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
        key = config['xspct_redis_cache']['prefix'] + file_hash
        expire = int(config['xspct_redis_cache']['expire'])
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
        if HAS_REDIS and config['xspct_redis_cache']['enabled']:
            rc = config['xspct_redis_cache']
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
        elif config['xspct_redis_cache']['enabled'] and not HAS_REDIS:
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
        pw_file = config['xspct_password_file']
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
    # JavaScript static analysis + sandbox
    # ------------------------------------------------------------------

    # Patterns that indicate a script is worth looking at more closely
    _JS_SUSPICIOUS = [
        (r'\beval\s*\(',               'SuspiciousJS', 'eval()',               'Use of eval() for dynamic code execution'),
        (r'\bunescape\s*\(',           'SuspiciousJS', 'unescape()',           'Use of unescape() — common obfuscation'),
        (r'\batob\s*\(',               'SuspiciousJS', 'atob()',               'Use of atob() for Base64 decoding'),
        (r'String\.fromCharCode\s*\(', 'SuspiciousJS', 'String.fromCharCode','Character-code obfuscation'),
        (r'document\.write\s*\(',      'SuspiciousJS', 'document.write()',    'Dynamic content injection'),
        (r'this\.exportDataObject\b',  'SuspiciousJS', 'exportDataObject()',  'PDF exportDataObject — can write files to disk'),
        (r'app\.launchURL\b',          'SuspiciousJS', 'app.launchURL()',     'Launches external URLs from PDF'),
        (r'app\.openDoc\b',            'SuspiciousJS', 'app.openDoc()',       'Opens external documents from PDF'),
        (r'util\.printf\b',            'SuspiciousJS', 'util.printf()',       'Used in heap-spray exploits'),
        (r'ActiveXObject\b',           'SuspiciousJS', 'ActiveXObject',       'ActiveX object instantiation'),
        (r'WScript\b',                 'SuspiciousJS', 'WScript',             'Windows Script Host reference'),
        (r'ShellExecute\b',            'SuspiciousJS', 'ShellExecute',        'Shell execution attempt'),
    ]

    def analyze_javascript(self, js_src: str, source_label: str = '') -> list[dict]:
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
            source_label = re.sub(r'[\x00-\x1f\x7f]', '', source_label)[:80]

        hits: list[dict] = []

        # -- 1. Beautify -------------------------------------------------------
        _JS_BEAUTIFY_LIMIT = 512 * 1024  # 512 KB — pure-Python parser; no time guard
        if HAS_JSBEAUTIFIER and len(js_src) <= _JS_BEAUTIFY_LIMIT:
            try:
                opts = _jsbeautifier.default_options()
                opts.unescape_strings = True
                js_src = _jsbeautifier.beautify(js_src, opts)
            except Exception as exc:
                logger.debug('jsbeautifier failed (%s): %s', source_label, exc)
        elif HAS_JSBEAUTIFIER:
            logger.debug(
                'jsbeautifier skipped for %s: input too large (%d bytes > %d)',
                source_label, len(js_src), _JS_BEAUTIFY_LIMIT,
            )

        # -- 2. Static pattern scan -------------------------------------------
        for pattern, a_type, keyword, desc in self._JS_SUSPICIOUS:
            if re.search(pattern, js_src):
                entry = {
                    'type': a_type,
                    'keyword': keyword,
                    'description': f'{desc} [in {source_label}]' if source_label else desc,
                }
                if entry not in hits:
                    hits.append(entry)

        # -- 3. QuickJS sandbox emulation --------------------------------------
        _JS_EMULATE_LIMIT = 512 * 1024  # 512 KB — parse/compile overhead guard
        if HAS_QUICKJS and len(js_src) <= _JS_EMULATE_LIMIT:
            try:
                ctx = _quickjs.Context()
                output: list[str] = []

                # Stub out browser/PDF globals that the sandbox doesn't have
                ctx.eval('''
                    var document = {write: function(s){ print(s); }, cookie: '', location: {href:''}};
                    var window = {location: {href:''}, navigator: {}};
                    var app = {launchURL: print, openDoc: print};
                    var console = {log: print, warn: print, error: print};
                ''')

                # Capture print() output
                ctx.set_memory_limit(32 * 1024 * 1024)  # 32 MB heap cap
                ctx.set_max_stack_size(256 * 1024)       # 256 KB stack — limits deep recursion
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

                def _collect(s=''):
                    nonlocal _collect_bytes, _collect_truncated
                    if _collect_truncated:
                        return
                    chunk = str(s)
                    _collect_bytes += len(chunk)
                    if len(collected) >= _COLLECT_MAX_CALLS or _collect_bytes > _COLLECT_MAX_BYTES:
                        _collect_truncated = True
                        return
                    collected.append(chunk)

                ctx.add_callable('print', _collect)
                _js_runtime_error = False
                try:
                    ctx.eval(js_src)
                except _quickjs.JSException as exc:
                    _js_runtime_error = True
                    logger.debug('QuickJS JSException (%s): %s', source_label, exc)
                    # JSException is expected when stubs are incomplete; suppress the hit
                    # to avoid false positives on clean scripts that reference browser APIs.
                except Exception:
                    pass

                if collected:
                    combined_output = ' '.join(collected)
                    logger.debug('QuickJS output from %s (%s): %r',
                                 source_label,
                                 'truncated' if _collect_truncated else 'complete',
                                 combined_output[:200])
                    # Sanitise attacker-controlled output before embedding in the report:
                    # replace control characters (including newlines) with a space so that
                    # log-injection and JSON-breaking sequences cannot pass through.
                    _safe_output = re.sub(r'[\x00-\x1f\x7f]', ' ', combined_output)[:120]
                    # Scan emulated output for IOCs / suspicious strings
                    if re.search(r'https?://', combined_output):
                        hits.append({
                            'type': 'DynamicJS',
                            'keyword': 'emulated-url',
                            # confidence:low because the script itself controls what is
                            # printed — decoy URLs can be injected to pollute the report.
                            'confidence': 'low',
                            'description': (
                                f'Dynamic JS emulation produced URL(s) '
                                f'[{source_label}]: {_safe_output}'
                            ),
                        })
                    if re.search(r'eval\(|unescape\(|atob\(', combined_output):
                        hits.append({
                            'type': 'DynamicJS',
                            'keyword': 'emulated-obfuscation',
                            # confidence:low for the same reason as emulated-url.
                            'confidence': 'low',
                            'description': (
                                f'Emulated JS output contains obfuscation calls '
                                f'[{source_label}]'
                            ),
                        })
            except _quickjs.JSException as exc:
                # JSException from the setup phase (e.g. stubs referencing undefined
                # globals) — expected, same policy as the inner handler.
                logger.debug('QuickJS setup JSException (%s): %s', source_label, exc)
            except Exception as exc:
                # A host-level (non-JS) exception during emulation setup or eval is
                # genuinely unexpected and may mask errors in a malicious payload.
                logger.debug('QuickJS emulation failed (%s): %s', source_label, exc)
                hits.append({
                    'type': 'DynamicJSError',
                    'keyword': 'js-emulation-error',
                    'description': (
                        f'JS emulation raised a host-level error [{source_label}]: '
                        f'{type(exc).__name__}'
                    ),
                })
        elif HAS_QUICKJS:
            logger.debug(
                'QuickJS emulation skipped for %s: input too large (%d bytes > %d)',
                source_label, len(js_src), _JS_EMULATE_LIMIT,
            )

        return hits

    # ------------------------------------------------------------------
    # Image analysis — OCR + QR/barcode
    # ------------------------------------------------------------------

    def analyze_image(self, image_data: bytes, label: str = '') -> dict:
        """Run OCR and QR/barcode decoding on raw image bytes.

        Uses ``pytesseract`` for OCR (English + German) and ``pyzbar`` for
        QR codes and barcodes.  Falls back gracefully when either library is
        unavailable.

        Args:
            image_data: Raw image bytes (PNG, JPEG, BMP, TIFF, …).
            label: Human-readable source label for log messages.

        Returns:
            A dict with keys:

            - **ocr_text** (str): Extracted text (empty when OCR unavailable).
            - **qr_codes** (list[str]): Decoded QR/barcode values.
            - **analyses** (list[dict]): Suspicious findings from OCR text.
            - **iocs** (dict): URLs/IPs/domains extracted from OCR text.
        """
        result: dict = {
            'ocr_text': '',
            'qr_codes': [],
            'analyses': [],
            'iocs': {'urls': [], 'ips': [], 'domains': []},
        }
        if not image_data:
            return result

        img = None
        if HAS_OCR or HAS_PYZBAR:
            try:
                img = _PILImage.open(io.BytesIO(image_data))
            except Exception as exc:
                logger.debug('PIL cannot open image (%s): %s', label, exc)
                return result

        # -- QR / barcode decoding -------------------------------------------
        if HAS_PYZBAR and img is not None:
            try:
                decoded = _pyzbar.decode(img)
                for sym in decoded:
                    try:
                        value = sym.data.decode('utf-8', 'ignore').strip()
                    except Exception:
                        value = repr(sym.data)
                    if value:
                        result['qr_codes'].append(value)
                        result['analyses'].append({
                            'type': 'QRCode',
                            'keyword': sym.type,
                            'description': f'{sym.type} decoded: {value[:120]}',
                        })
                        # Extract IOCs from QR content
                        qr_iocs = self.extract_iocs(sym.data)
                        for k in ('urls', 'ips', 'domains'):
                            result['iocs'][k] = sorted(
                                set(result['iocs'][k] + qr_iocs[k])
                            )
            except Exception as exc:
                logger.debug('pyzbar decoding failed (%s): %s', label, exc)

        # -- OCR -------------------------------------------------------------
        if HAS_OCR and img is not None:
            try:
                ocr_text = _pytesseract.image_to_string(
                    img, lang='eng+deu',
                    config='--psm 3',
                )
                result['ocr_text'] = ocr_text.strip()
                if ocr_text.strip():
                    ocr_iocs = self.extract_iocs(ocr_text.encode('utf-8', 'ignore'))
                    for k in ('urls', 'ips', 'domains'):
                        result['iocs'][k] = sorted(
                            set(result['iocs'][k] + ocr_iocs[k])
                        )
                    # Detect URL-only images (common in phishing PDFs)
                    if ocr_iocs['urls']:
                        result['analyses'].append({
                            'type': 'OCRUrl',
                            'keyword': 'ocr-url',
                            'description': (
                                f'URL found in image via OCR ({label}): '
                                + ', '.join(ocr_iocs['urls'][:3])
                            ),
                        })
            except Exception as exc:
                logger.debug('pytesseract OCR failed (%s): %s', label, exc)

        return result

    # ------------------------------------------------------------------
    # PDF analysis
    # ------------------------------------------------------------------

    def analyze_pdf(self, data: bytes,
                    custom_passwords: 'list | None' = None) -> 'dict | None':
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
        if not data.startswith(b'%PDF'):
            return None
        passwords = list(custom_passwords or []) + self.passwords
        report: dict = {
            'has_javascript': False, 'has_openaction': False,
            'has_embedded_files': False, 'has_launch': False,
            'has_forms': False, 'is_encrypted': False,
            'decrypted': False, 'decryption_password': None,
            'analyses': [], 'iocs': {'urls': [], 'ips': [], 'domains': []},
        }

        if HAS_PYMUPDF:
            self._analyze_pdf_pymupdf(data, report, passwords)
        else:
            logger.debug('PyMuPDF not available — falling back to byte-scan PDF analysis')
            self._analyze_pdf_bytescan(data, report)

        body_iocs = self.extract_iocs(data)
        for k in ('urls', 'ips', 'domains'):
            report['iocs'][k] = sorted(set(report['iocs'][k] + body_iocs[k]))
        report['text_preview'] = self.extract_text_preview(data, 'application/pdf')
        return report

    def _analyze_pdf_pymupdf(self, data: bytes, report: dict,
                              passwords: list) -> None:
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
            entry = {'type': a_type, 'keyword': keyword, 'description': desc}
            if entry not in report['analyses']:
                report['analyses'].append(entry)

        def _add_url(url: str) -> None:
            url = url.strip()
            if url and url not in report['iocs']['urls']:
                report['iocs']['urls'].append(url)

        try:
            doc = fitz.open(stream=data, filetype='pdf')
        except Exception as exc:
            logger.warning('PyMuPDF could not open PDF: %s', exc)
            self._analyze_pdf_bytescan(data, report)
            return

        try:
            # -- Encryption / password decryption --------------------------
            if doc.needs_pass:
                report['is_encrypted'] = True
                for pwd in passwords:
                    if doc.authenticate(pwd):
                        report['decrypted'] = True
                        report['decryption_password'] = pwd
                        logger.info('PDF decrypted with password: %s', pwd)
                        break
                else:
                    _add('Encryption', '/Encrypt',
                         'PDF is encrypted — no matching password found')
                    return
            elif doc.is_encrypted:
                # Opened with the empty/owner password (no password needed)
                report['is_encrypted'] = True
                _add('Encryption', '/Encrypt', 'PDF is encrypted')

            # -- Document-level metadata / trailer -------------------------
            trailer = doc.pdf_trailer()
            if isinstance(trailer, dict):
                if 'Encrypt' in trailer:
                    report['is_encrypted'] = True
                    _add('Encryption', '/Encrypt', 'PDF is encrypted')

            # -- Document-level JavaScript (doc.get_js_code) ---------------
            js_blocks = []
            try:
                js_blocks = doc.get_js_code()  # list of JS strings
            except AttributeError:
                pass
            if js_blocks:
                report['has_javascript'] = True
                _add('JavaScript', '/JavaScript',
                     f'Document-level JavaScript found ({len(js_blocks)} block(s))')
                for i, js_src in enumerate(js_blocks):
                    for hit in self.analyze_javascript(js_src, f'PDF /JavaScript block {i+1}'):
                        if hit not in report['analyses']:
                            report['analyses'].append(hit)

            # -- OpenAction / AA (auto-execute) ----------------------------
            try:
                root = doc.pdf_catalog()
                if isinstance(root, dict):
                    if 'OpenAction' in root:
                        report['has_openaction'] = True
                        action = root['OpenAction']
                        action_type = action.get('S', '') if isinstance(action, dict) else ''
                        _add('AutoExecute', '/OpenAction',
                             f'OpenAction found (type: {action_type or "unknown"})')
                        if action_type == 'JavaScript':
                            report['has_javascript'] = True
                            js_src_oa = action.get('JS', '')
                            if js_src_oa:
                                _add('JavaScript', '/OpenAction/JS',
                                     'JavaScript in OpenAction')
                                for hit in self.analyze_javascript(js_src_oa, 'PDF /OpenAction'):
                                    if hit not in report['analyses']:
                                        report['analyses'].append(hit)
                    if 'AA' in root:
                        _add('AutoExecute', '/AA',
                             'Additional Actions (AA) on document level found')
                    # AcroForm / XFA
                    if 'AcroForm' in root:
                        acro = root['AcroForm']
                        if isinstance(acro, dict) and 'XFA' in acro:
                            report['has_forms'] = True
                            _add('XFA', '/XFA',
                                 'XML Forms Architecture (XFA) found — can contain scripts')
                        else:
                            report['has_forms'] = True
                            _add('AcroForm', '/AcroForm', 'PDF AcroForm found')
            except Exception as exc:
                logger.debug('PDF catalog inspection failed: %s', exc)

            # -- Embedded files --------------------------------------------
            try:
                ef_count = doc.embfile_count()
                if ef_count > 0:
                    report['has_embedded_files'] = True
                    names = []
                    for i in range(ef_count):
                        info = doc.embfile_info(i)
                        names.append(info.get('filename', f'file{i}'))
                    _add('EmbeddedFile', '/EmbeddedFiles',
                         f'{ef_count} embedded file(s): {', '.join(names[:5])}')
            except Exception as exc:
                logger.debug('PDF embedded file check failed: %s', exc)

            # -- Page-level: links, annotations, actions -------------------
            for page in doc:
                try:
                    for link in page.get_links():
                        uri  = link.get('uri', '')
                        kind = link.get('kind', 0)
                        # kind 2 = external URI
                        if uri:
                            _add_url(uri)
                        # kind 4 = launch action
                        if kind == fitz.LINK_LAUNCH:
                            report['has_launch'] = True
                            _add('Execution', '/Launch',
                                 f'Launch action found: {uri or "(no URI)"}')
                        # kind 5 = named action  (e.g. GoToR)
                        if kind == fitz.LINK_NAMED:
                            _add('AutoExecute', '/Named',
                                 f'Named action on page {page.number}: {uri}')

                    for annot in page.annots():
                        adict = annot.info
                        # URI annotations
                        uri = adict.get('uri') or ''
                        if uri:
                            _add_url(uri)
                        # Subtype-level checks
                        subtype = annot.type[1] if annot.type else ''
                        if subtype == 'FileAttachment':
                            report['has_embedded_files'] = True
                            fname = adict.get('file', 'unknown')
                            _add('EmbeddedFile', '/FileAttachment',
                                 f'File attachment annotation: {fname}')
                        if subtype == 'Screen':
                            _add('Execution', '/Screen',
                                 'Screen annotation found (can trigger media/scripts)')

                    # Widget annotations (form fields with JS)
                    for widget in page.widgets() or []:
                        widget_js_found = False
                        for attr in ('script', 'script_stroke', 'script_format',
                                     'script_change', 'script_calc'):
                            js = getattr(widget, attr, None)
                            if js:
                                report['has_javascript'] = True
                                if not widget_js_found:
                                    _add('JavaScript', '/Widget/JS',
                                         f'JavaScript in form widget ({attr})')
                                    widget_js_found = True
                                for hit in self.analyze_javascript(
                                    js, f'PDF widget/{attr} page {page.number}'
                                ):
                                    if hit not in report['analyses']:
                                        report['analyses'].append(hit)

                except Exception as exc:
                    logger.debug('PDF page %d inspection failed: %s', page.number, exc)

            # -- Image extraction + OCR / QR scan -------------------------
            if HAS_OCR or HAS_PYZBAR:
                try:
                    for page in doc:
                        for img_info in page.get_images():
                            xref = img_info[0]
                            base_image = doc.extract_image(xref)
                            img_bytes = base_image.get('image', b'')
                            if img_bytes:
                                img_result = self.analyze_image(
                                    img_bytes,
                                    label=f'PDF page {page.number} xref {xref}',
                                )
                                for hit in img_result.get('analyses', []):
                                    if hit not in report['analyses']:
                                        report['analyses'].append(hit)
                                for k in ('urls', 'ips', 'domains'):
                                    report['iocs'][k] = sorted(
                                        set(report['iocs'][k] + img_result['iocs'][k])
                                    )
                except Exception as exc:
                    logger.debug('PDF image extraction failed: %s', exc)

            # -- Document metadata ------------------------------------------
            try:
                raw_meta = doc.metadata or {}
                def _clean(v: str) -> str:
                    return re.sub(r'[\x00-\x1f\x7f]', '', str(v or ''))[:256]
                report['meta_document'] = {
                    'title':         _clean(raw_meta.get('title')),
                    'author':        _clean(raw_meta.get('author')),
                    'subject':       _clean(raw_meta.get('subject')),
                    'keywords':      _clean(raw_meta.get('keywords')),
                    'creator':       _clean(raw_meta.get('creator')),
                    'producer':      _clean(raw_meta.get('producer')),
                    'creation_date': _clean(raw_meta.get('creationDate')),
                    'mod_date':      _clean(raw_meta.get('modDate')),
                    'encryption':    _clean(raw_meta.get('encryption')),
                }
            except Exception as exc:
                logger.debug('PDF metadata extraction failed: %s', exc)

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
                entry = {'type': m_type, 'keyword': marker.decode('ascii'), 'description': desc}
                if entry not in report['analyses']:
                    report['analyses'].append(entry)
                if m_type == 'JavaScript':   report['has_javascript']     = True
                if m_type == 'AutoExecute':  report['has_openaction']     = True
                if m_type == 'EmbeddedFile': report['has_embedded_files'] = True
                if m_type == 'Execution':    report['has_launch']         = True
                if m_type == 'Encryption':   report['is_encrypted']       = True
        for uri in re.findall(rb'/URI\s*\((https?://[^\)]+)\)', data):
            try:
                url = uri.decode('utf-8', 'ignore').strip()
                if url and url not in report['iocs']['urls']:
                    report['iocs']['urls'].append(url)
            except Exception:
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
        style_blocks = re.findall(r'<style[^>]*>(.*?)</style>', text, re.I | re.S)
        inline_styles = re.findall(r'style=["\']([^"\']{1,2000})["\']', text, re.I)
        all_css = '\n'.join(style_blocks + inline_styles)

        # --- Invisible/collapsed element patterns ---
        _HIDING: list[tuple[str, str, str]] = [
            (
                r'display\s*:\s*none',
                'display:none',
                'CSS display:none hides element from view',
            ),
            (
                r'visibility\s*:\s*hidden',
                'visibility:hidden',
                'CSS visibility:hidden hides element without collapsing it',
            ),
            (
                r'opacity\s*:\s*0(?:[^.]|$)',
                'opacity:0',
                'CSS opacity:0 makes element fully transparent',
            ),
            (
                r'font-size\s*:\s*0',
                'font-size:0',
                'CSS font-size:0 collapses text to zero height',
            ),
            (
                r'(?:width|height)\s*:\s*0\s*(?:px\b|;|$)',
                'width/height:0',
                'CSS zero-dimension collapses element to invisible sliver',
            ),
            (
                r'(?:max-width|max-height)\s*:\s*0\s*(?:px\b|;|$)',
                'max-width/height:0',
                'CSS max-dimension:0 collapses element',
            ),
            (
                r'overflow\s*:\s*hidden',
                'overflow:hidden',
                'CSS overflow:hidden (possible clipping of phishing content)',
            ),
            (
                # position:absolute|fixed with a large negative top or left offset
                r'position\s*:\s*(?:absolute|fixed)',
                'position:absolute/fixed',
                'CSS absolute/fixed positioning (check for off-screen placement)',
            ),
            (
                r'(?:top|left)\s*:\s*-\d{3,}',
                'top/left negative offset',
                'CSS off-screen negative offset (content moved far outside viewport)',
            ),
            (
                r'color\s*:\s*(?:#(?:fff(?:fff)?|ffffff)|white\b|rgba?\(\s*255\s*,\s*255\s*,\s*255)',
                'color:white',
                'CSS white text colour (possible white-on-white steganographic hiding)',
            ),
            (
                r'background(?:-color)?\s*:\s*(?:#(?:000(?:000)?|ffffff|fff\b)|black\b|white\b)',
                'background:black/white',
                'CSS solid black or white background (combined with matching text = invisible)',
            ),
            (
                r'clip(?:-path)?\s*:\s*rect\(\s*0',
                'clip:rect(0)',
                'CSS clip:rect(0,0,0,0) collapses visible area to nothing',
            ),
        ]
        for pattern, keyword, desc in _HIDING:
            if re.search(pattern, all_css, re.I):
                hits.append({
                    'type': 'CSSHiding',
                    'keyword': keyword,
                    'description': desc,
                })

        # --- Remote CSS loading (hides effective styles from static analysis) ---
        # <link rel="stylesheet" href="https://...">  (attribute order may vary)
        external_links = re.findall(
            r'<link\b[^>]*\brel=["\']stylesheet["\'][^>]*\bhref=["\'](\s*https?://[^"\']+)["\']'
            r'|<link\b[^>]*\bhref=["\'](\s*https?://[^"\']+)["\'][^>]*\brel=["\']stylesheet["\']',
            text, re.I,
        )
        n_links = sum(1 for pair in external_links if any(pair))
        if n_links:
            hits.append({
                'type': 'ExternalCSS',
                'keyword': '<link rel=stylesheet>',
                'description': (
                    f'Remote CSS stylesheet loaded via <link> ({n_links} URL(s)) — '
                    'rendered appearance cannot be determined without fetching the URL'
                ),
            })

        # @import url("https://...") or @import "https://..." inside <style> blocks
        css_imports = re.findall(
            r'@import\s+(?:url\s*\(\s*)?["\']?(https?://[^"\')\s]+)',
            all_css, re.I,
        )
        if css_imports:
            hits.append({
                'type': 'ExternalCSS',
                'keyword': '@import',
                'description': (
                    f'CSS @import of remote stylesheet ({len(css_imports)} URL(s)) — '
                    'allows server-side injection of hiding rules at render time'
                ),
            })

        return hits

    def analyze_html(self, data: bytes) -> 'dict | None':
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
        # Spam/malware: <script src="https://evil.com/?u=<base62token>">
        # A short alphanumeric tracker token after ?u= is the canonical pattern
        # used to inject remote affiliate/redirect loaders into HTML mail.
        tracker_scripts = re.findall(
            r'<script[^>]+src=["\']([^"\']*\?u=[a-zA-Z0-9]{8,}[^"\']*)["\']',
            text, re.I,
        )
        if tracker_scripts:
            report['analyses'].append({
                'type': 'SpamRedirect',
                'keyword': 'script-tracker-url',
                'description': (
                    f'Injected tracker/affiliate redirect script found '
                    f'({len(tracker_scripts)} URL(s) with ?u= parameter)'
                ),
            })
        # Detect CSS-based content-hiding techniques
        for hit in self._analyze_css_hiding(text):
            if hit not in report['analyses']:
                report['analyses'].append(hit)
        report['iocs'] = self.extract_iocs(data)
        # Analyse inline JavaScript blocks
        for script_body in re.findall(r'<script[^>]*>(.*?)</script>', text, re.I | re.S):
            if script_body.strip():
                for hit in self.analyze_javascript(script_body, 'HTML <script>'):
                    if hit not in report['analyses']:
                        report['analyses'].append(hit)
        # Analyse inline base64-encoded images (data URIs)
        if HAS_OCR or HAS_PYZBAR:
            for i, (mime_hint, b64data) in enumerate(re.findall(
                r'<img[^>]+src=["\']data:(image/[^;]+);base64,([A-Za-z0-9+/=\s]{100,})["\']',
                text, re.I,
            )):
                try:
                    img_bytes = __import__('base64').b64decode(
                        b64data.replace(' ', '').replace('\n', '').replace('\r', '')
                    )
                    img_result = self.analyze_image(
                        img_bytes, label=f'HTML data-URI image {i+1} ({mime_hint})'
                    )
                    for hit in img_result.get('analyses', []):
                        if hit not in report['analyses']:
                            report['analyses'].append(hit)
                    for k in ('urls', 'ips', 'domains'):
                        report['iocs'][k] = sorted(
                            set(report['iocs'].get(k, []) + img_result['iocs'][k])
                        )
                except Exception as exc:
                    logger.debug('HTML inline image %d decode failed: %s', i + 1, exc)
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
        if 'pdf' in mime_lower or data.startswith(b'%PDF'):
            if HAS_PYMUPDF:
                try:
                    doc = fitz.open(stream=data, filetype='pdf')
                    parts = []
                    for page in doc:
                        parts.append(page.get_text())
                        if sum(len(p) for p in parts) >= limit * 2:
                            break
                    doc.close()
                    return re.sub(r'\s+', ' ', ' '.join(parts))[:limit].strip()
                except Exception as exc:
                    logger.debug('PyMuPDF text extraction failed: %s', exc)
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
            elif key == 'meta_document':
                # Keep the first non-None metadata block; PDF and OLE each
                # produce at most one, and they are never both present.
                if value and not target.get('meta_document'):
                    target['meta_document'] = value
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

            # -- OLE2 document properties (SummaryInformation stream) -------
            if _olefile.isOleFile(io.BytesIO(effective)):
                try:
                    ole = _olefile.OleFileIO(io.BytesIO(effective))
                    m = ole.get_metadata()
                    def _oclean(v) -> str:
                        if v is None:
                            return ''
                        s_val = v.decode('utf-8', 'ignore') if isinstance(v, bytes) else str(v)
                        return re.sub(r'[\x00-\x1f\x7f]', '', s_val)[:256]
                    office_report['meta_document'] = {
                        'title':          _oclean(m.title),
                        'author':         _oclean(m.author),
                        'subject':        _oclean(m.subject),
                        'keywords':       _oclean(m.keywords),
                        'last_saved_by':  _oclean(m.last_saved_by),
                        'company':        _oclean(m.company),
                        'app_name':       _oclean(m.app_name),
                        'revision_num':   str(m.revision_num or ''),
                        'creation_date':  str(m.create_time or ''),
                        'mod_date':       str(m.last_saved or ''),
                    }
                    ole.close()
                except Exception as exc:
                    logger.debug('%s - OLE metadata extraction failed: %s', s, exc)

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
            ``meta``, and ``meta_document``.
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
                'script_name': 'xspct-scan',
                'version': '2.0.0',
                'type': 'MetaInformation',
            },
            'rtf_objects':         [],
            'decrypted':           False,
            'decryption_password': None,
            'iocs':                {'urls': [], 'ips': [], 'domains': []},
            'text_preview':        '',
            'meta_document':       None,
        }
        successful_types = []
        for t in types_to_run:
            res = None
            if t == 'pdf':
                res = self.analyze_pdf(data, custom_passwords=custom_passwords)
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
        # Image OCR / QR analysis for OOXML (contains media/ entries in ZIP)
        if (HAS_OCR or HAS_PYZBAR) and file_mime and 'openxmlformats' in file_mime.lower():
            try:
                import zipfile
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    for name in z.namelist():
                        if re.match(r'(?:word|xl|ppt)/media/', name, re.I):
                            img_bytes = z.read(name)
                            img_result = self.analyze_image(img_bytes, label=f'OOXML {name}')
                            for hit in img_result.get('analyses', []):
                                if hit not in report['analyses']:
                                    report['analyses'].append(hit)
                            for k in ('urls', 'ips', 'domains'):
                                report['iocs'][k] = sorted(
                                    set(report['iocs'].get(k, []) + img_result['iocs'][k])
                                )
            except Exception as exc:
                logger.debug('OOXML image extraction failed: %s', exc)
        return report

    async def analyze_task(self, s: str, file_hash: str, filename: str,
                           data: bytes, file_mime: 'str | None',
                           file_desc: 'str | None' = None,
                           rtf_eval: bool = False,
                           custom_passwords: 'list | None' = None,
                           types_to_run: 'list | None' = None) -> dict:
        """Run :meth:`sync_analyze` in a thread-pool and cache the result.

        Wraps :meth:`sync_analyze` with :func:`asyncio.get_running_loop` (``.run_in_executor``) so CPU-bound oletools work does not block the
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
            # Sanitise libmagic output before storing in the report: strip control
            # characters and cap length so a crafted file cannot inject misleading
            # content into file_type / file_description response fields.
            magic_mime = re.sub(r'[\x00-\x1f\x7f]', '', magic_mime or '')[:256]
            magic_desc = re.sub(r'[\x00-\x1f\x7f]', '', magic_desc or '')[:256]
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
            '# HELP xspct_requests_total Total scan requests received',
            '# TYPE xspct_requests_total counter',
            f'xspct_requests_total {stats["requests_total"]}',
            '# HELP xspct_requests_finished Scan requests completed within timeout',
            '# TYPE xspct_requests_finished counter',
            f'xspct_requests_finished {stats["requests_finished"]}',
            '# HELP xspct_requests_timeout Scan requests that timed out (202)',
            '# TYPE xspct_requests_timeout counter',
            f'xspct_requests_timeout {stats["requests_timeout"]}',
            '# HELP xspct_redis_hits Redis cache hits',
            '# TYPE xspct_redis_hits counter',
            f'xspct_redis_hits {stats["redis_hits"]}',
            '# HELP xspct_redis_misses Redis cache misses',
            '# TYPE xspct_redis_misses counter',
            f'xspct_redis_misses {stats["redis_misses"]}',
            '# HELP xspct_redis_errors Redis errors total',
            '# TYPE xspct_redis_errors counter',
            f'xspct_redis_errors {stats["redis_errors"]}',
            '# HELP xspct_tasks_in_memory Current in-memory task/report entries',
            '# TYPE xspct_tasks_in_memory gauge',
            f'xspct_tasks_in_memory {len(self.tasks)}',
        ]
        return web.Response(text='\n'.join(lines) + '\n', content_type='text/plain')


# ---------------------------------------------------------------------------
# Periodic stats logger
# ---------------------------------------------------------------------------

async def _log_stats_periodically(daemon: InspectorDaemon) -> None:
    interval = int(config['xspct_stats_interval'])
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
    /          GET     Returns ``xspct-scan``
    =========  ======  ====================

    Returns:
        Configured :class:`aiohttp.web.Application` ready to be served.
    """
    daemon = InspectorDaemon()

    async def _on_startup(app: web.Application) -> None:
        await daemon.setup()
        if config['xspct_stats_enabled']:
            asyncio.create_task(_log_stats_periodically(daemon))
        logger.info('xspct-scan ready')

    async def _on_shutdown(app: web.Application) -> None:
        await daemon.teardown()
        logger.info('xspct-scan stopped')

    app = web.Application()
    app.on_startup.append(_on_startup)
    app.on_shutdown.append(_on_shutdown)
    app.router.add_post('/scan',   daemon.handle_scan)
    app.router.add_post('/query',  daemon.handle_query)
    app.router.add_get('/query',   daemon.handle_query)
    app.router.add_get('/metrics', daemon.handle_metrics)
    app.router.add_get('/health',  lambda r: web.Response(text='OK'))
    app.router.add_get('/ping',    lambda r: web.Response(text='pong'))
    app.router.add_get('/',        lambda r: web.Response(text='xspct-scan'))
    return app
