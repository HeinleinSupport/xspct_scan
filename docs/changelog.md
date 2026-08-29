# Changelog

> **Commit convention cutover:** starting with the release after `0.5.2`,
> commits follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
> (see `CONTRIBUTING.md`). Earlier history uses the previous informal
> `[Tag] Description` convention and was not rewritten.

## Unreleased

### Added
- **`xspct_analyzers.image.max_images_per_document` config option** (default
  `20`) — caps the number of embedded images (PDF pages, OOXML/ODF media
  parts, HTML data-URIs) sent through OCR/QR analysis per document. Prevents
  pathologically long scans of image-heavy documents such as a multi-hundred
  page PDF with dozens of pictures per page. Set to `0` for unlimited. When
  the cap is hit, a `ScanLimit`/`max-images-per-document:<source>` finding
  is added to `analyses`, tagged with the analyzer that hit the cap
  (`pdf-image`, `html-image`, `ooxml-image`, or `odf-image`).
- **VHD/VHDX archive support** — `.vhd` / `.vhdx` (Virtual Hard Disk), a
  known Mark-of-the-Web-bypass container for malware delivery (the same
  rationale as the existing ISO support), are now routed to the `archive`
  analyzer and extracted via SFlock2's `zip7`-backed unpacker. No stdlib
  fallback exists for this format (`py7zr` does not support VHD/VHDX).
- **EMF recognition** — `.emf` (Enhanced Metafile) is now routed to the
  existing `image` analyzer. Pillow cannot decode the GDI record format, so
  there's no OCR/QR output, but the file is now declared in
  `/v1/capabilities` and still covered by the global YARA/ClamAV/
  `iocsearcher` scanners instead of going unrecognized.

### Fixed
- **ZIP fallback password handling** — the optional stdlib ZIP fallback now
  continues trying configured passwords when a ZipCrypto candidate passes its
  one-byte header check but fails the member CRC. Corrupt unencrypted members
  still stop after one attempt, avoiding repeated decompression for every
  configured password.
- Suppressed a noisy `UserWarning` from torch's deprecated
  `quantize_per_tensor`/`quantize_per_channel` API, triggered by EasyOCR's
  quantized recognition network at reader init (once per process, not
  per-scan; not actionable on our side).

## 0.7.1 — 2026-08-28

### Changed
- CI now also tests against Python 3.13 and 3.14, in addition to 3.10–3.12.

## 0.7.0 — 2026-08-28

### Changed
- **BREAKING: project naming unified to `xspct_scan` (underscore)
  everywhere.** The distribution name, console scripts, logger name, and
  default `xspct_log_prefix` previously used a hyphen (`xspct-scan`,
  `xspct-scan-client`) while the Python package, GitHub repository, and
  documentation titles used an underscore. All of it now uses the
  underscore form consistently:
  - PyPI/distribution name: `xspct-scan` → `xspct_scan`.
  - Console scripts: `xspct-scan` → `xspct_scan`, `xspct-scan-client` →
    `xspct_scan_client`. Update systemd units, shell scripts, and Rspamd
    integration configs that invoke the old hyphenated command names.
  - Logger name and `xspct_log_prefix` default: `"xspct-scan"` →
    `"xspct_scan"`. Anything grepping log output for the old prefix needs
    updating.
  - No config keys, HTTP response fields, or Prometheus metric names are
    affected — those were already underscored.

### Fixed
- **MIME recognition gaps vs. Rspamd's `lua_magic`** — several content-types
  Rspamd's built-in magic detector reports (`types.lua`) weren't recognized
  by `xspct_scan`, so a Rspamd integration that builds its MIME filter from
  `GET /v1/capabilities` would never forward these attachments for scanning:
  - `application/x-bzip` (bzip2) and `application/x-iso` (ISO 9660 image)
    are now recognized alongside the existing `x-bzip2`/`x-iso9660-image`
    variants, routed to the `archive` analyzer.
  - `.Z` / `application/x-compress` (Unix `compress`) is now recognized and
    routed to `archive`.
  - `.lnk` / `application/x-ms-application` is now recognized — Rspamd
    reports this same content-type for both `.lnk` shortcuts and PE
    executables, so it is not trusted alone; the `.lnk` extension or the
    `ShellLinkHeader` GUID magic bytes must corroborate it before routing to
    the `lnk` analyzer.
  - `.p7s` / `application/pkcs7-signature` (detached S/MIME signature) is
    now declared in `/v1/capabilities` so it gets forwarded and covered by
    the global YARA/ClamAV/`iocsearcher` scanners; it has no dedicated
    content analyzer, so `detected_type` remains `unknown`.

## 0.6.0 — 2026-08-25

### Added
- **Digital signature detection** — a new `signature` analyzer, backed by
  the optional [pyhanko](https://github.com/MatthiasValvekens/pyhanko)
  dependency (`[advanced]` extra), covering three signature kinds:
  - **VBA project signatures**: the `\x05DigitalSignature*` OLE2 stream (or
    the equivalent `vbaProjectSignature*.bin` OOXML part) is parsed as a
    [MS-OSHARED] DigSigBlob and its embedded PKCS#7/CMS signature is
    validated against the embedded certificate.
  - **OOXML whole-document signatures**: each `_xmlsignatures/*.xml`
    XML-DSig signature is validated by re-hashing every manifest-listed
    package part directly from the live ZIP and comparing it to the signed
    digest, then verifying the outer `SignedInfo` signature against the
    embedded certificate. `covers_whole_document` separately reports whether
    every non-signature package member is included in the signed manifest.
  - **PDF (PAdES) signatures**: detected and validated via `pyhanko`,
    including whether the signature covers the entire file.
  - Pure detection — never influences `verdict.score`/`severity`.
    `trusted` is always `false`; certificate trust-store validation is a
    separate, later stage.
  - Results are reported under a new, additive `engines.signature` field
    (single object, or an array when multiple signatures are found), with
    `present`, `type`, `valid`, `signer`, `issuer_fingerprint`, `trusted`,
    `key_usage_valid`, `cert_time_valid`, `covers_whole_document`, and an
    optional `timestamp`.
  - `key_usage_valid`/`cert_time_valid` are informational by default; set
    the new `xspct_analyzers.signature.strict` config key (default
    `false`) to also require both for `valid`.
  - New config key `xspct_analyzers.signature.enabled` (default `true`).
  - When `pyhanko` isn't installed, the analyzer cleanly skips.
- **`invalidate_cache` scan option** — new query parameter and structured
  `metadata` field (bool, default `false`) for `POST /v1/scan`, alongside
  `force_analyzers`. When set, the daemon deletes the Redis and in-memory
  cached report and performs a full rescan. Older in-flight scans cannot
  repopulate the deleted entry; only the fresh report is cached. Intended
  for callers (e.g. Rspamd) that invalidate their own cache for a known
  file hash and re-submit it with a new/updated password list — without
  this, a cache hit on an already-decrypted file would short-circuit
  re-analysis and never try the new passwords. Exposed in
  `xspct-scan-client` as `--invalidate-cache`.
- **Structured `metadata` + `file` multipart shape for `POST /v1/scan`** — a
  third accepted request shape alongside the legacy `doc` multipart and raw
  octet-stream uploads. The `metadata` part is JSON or msgpack and carries
  `filename`, `declared_content_type`, `detected_type`, `rspamd_uid`,
  `queue_id`, `message_id`, `passwords`, `force_analyzers`, and `timeout_s`.
  Metadata fields take precedence over query parameters; mixing structured
  and legacy multipart parts is rejected with HTTP 400. `timeout_s` may only
  tighten the effective timeout, never loosen it.
  `rspamd_uid`/`queue_id`/`message_id` are folded into the session log tag
  as soon as the metadata part is parsed; the file-read log is emitted after
  multipart parsing so it carries the correlation tag regardless of part order,
  and is echoed back in a new, additive `request` response block — never
  persisted into the cached report, since correlation IDs belong to the
  request, not the file content. All string metadata fields are stripped of
  control characters and length-capped before use, to prevent log injection.
  Passwords supplied via `metadata.passwords` are stripped of surrounding
  whitespace, matching the legacy `passwords` field. Multipart metadata and
  file parts honor base64 or quoted-printable `Content-Transfer-Encoding`.
- **`xspct-scan-client` uses the structured `metadata` + `file` shape by
  default** — `--passwords`/`--force-analyzers` are now sent inside the
  `metadata` part rather than a legacy field/query parameter. New
  `--rspamd-uid`, `--queue-id`, `--message-id` flags populate the
  corresponding metadata fields. `--legacy-multipart` restores the old
  `doc`-field behavior for talking to older daemons.
- **Standalone script analysis** — a new `script` detected type and
  `analyze_script()` analyzer for previously-unhandled script attachments:
  `.vbs`, `.vbe`, `.js`, `.jse`, `.wsf`, `.wsh`, `.ps1`, `.bat`, `.cmd`.
  - VBScript (`.vbs`, decoded `.vbe`, VBScript `<script>` blocks in
    WSF/WSH) is scanned via oletools' `VBA_Scanner` — reused directly since
    it works on any VBA/VBScript source, not just OLE containers — with a
    built-in keyword fallback when oletools isn't installed.
  - JScript (`.js`, decoded `.jse`, JScript `<script>` blocks in WSF/WSH)
    is routed through the existing JavaScript analyzer, previously only
    reachable for script embedded in HTML.
  - `.vbe`/`.jse` (Microsoft Script Encoder) are decoded before analysis
    using SFlock2's bundled decoder when installed (`[advanced]` extra);
    flagged as undecoded otherwise.
  - `.wsf`/`.wsh` containers are unwrapped into their `<script
    language="...">` blocks, each routed by language.
  - `.ps1`/`.bat`/`.cmd` get regex heuristics for download cradles,
    `-EncodedCommand` (Base64/UTF-16LE-decoded and recursively analysed),
    AMSI bypass, Defender tampering, persistence (Run keys, scheduled
    tasks), living-off-the-land binaries (certutil/bitsadmin/mshta/
    regsvr32), shadow-copy deletion, self-deletion, and obfuscation
    density — this cross-cutting scan also runs against every other script
    language, not just PS1/BAT.
  - `.hta` is **not** part of the script analyzer — it's an HTML container
    and is detected as `html`, matching the existing SVG treatment.
    `analyze_html()` gained HTA-specific findings for the
    `<HTA:APPLICATION>` tag and stealth attributes (`WINDOWSTATE=minimize`,
    `SHOWINTASKBAR=no`), and an HTA's embedded `<script>` blocks also get
    the same cross-cutting heuristics and, for VBScript (including
    Script-Encoder-encoded VBScript, decoded before scanning), the
    `VBA_Scanner` pass that standalone `.vbs`/`.wsf` files get.
  - New `text_preview`/`text_full` sources: `script`, `script-decoded`.
  - New config key `xspct_analyzers.script.enabled` (default `true`).
  - `.js`/`.bat`/`.ps1`/`.vbs` are no longer routed to the generic `text`
    analyzer (they were previously indistinguishable from plain text); the
    filename-independent magic-only detection pass in `handle_scan()` no
    longer runs `text` redundantly alongside `script` for the same upload
    — but only while the script analyzer is enabled; when it's disabled,
    archive members and top-level uploads alike still fall back to `text`
    instead of going unanalyzed.
- **Windows shortcut (`.lnk`) analysis** — a new `lnk` detected type and
  `analyze_lnk()` analyzer, backed by the optional
  [LnkParse3](https://github.com/Matmaus/LnkParse) dependency
  (`[advanced]` extra):
  - Extracts the shortcut's target path, command-line arguments, working
    directory, and icon location, then flags: a script interpreter or
    LOLBin target/argument (`cmd`, `powershell`, `pwsh`, `wscript`,
    `cscript`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`,
    `msiexec`, `installutil`, `regasm`, `regsvcs`); arguments matching the
    same regex heuristics as the `script` analyzer (download cradles,
    `-EncodedCommand`, AMSI bypass, persistence, etc.); a network share
    (UNC) target; command-line arguments exceeding the 260-character
    Explorer Properties UI limit; long whitespace runs used to pad a
    command past that limit; and an executable target using a document-like
    icon path (e.g. `.pdf`, `.docx`, or `.jpg`). Normal DLL icon resources
    and `.ico` files are not flagged.
  - Target + arguments are fed into the standard IOC/iocsearcher pipeline.
  - New `text_preview`/`text_full` source: `lnk`.
  - New config key `xspct_analyzers.lnk.enabled` (default `true`).
  - Unlike `script`, disabling `xspct_analyzers.lnk.enabled` suppresses both
    structural LNK analysis and raw text fallback for the binary content.
    Global scanners such as YARA and ClamAV remain unaffected.
  - When the analyzer is enabled but `LnkParse3` is unavailable, raw text
    fallback still feeds IOC extraction without raising a hard error.

### Changed
- **RTF object extraction always runs** — `analyze_office()` now always
  runs `oletools.rtfobj` extraction for RTF input; the opt-in `rtf` query
  parameter (`POST /v1/scan?rtf=true`) has been removed, along with the
  `xspct-scan-client --rtf` flag. Previously RTF-embedded object detection
  was skipped unless explicitly requested.
- **`invalidate_cache` is now safe across horizontally-scaled daemon
  processes sharing one Redis instance.** The cache-generation guard that
  protects a fresh report from being repopulated by a stale in-flight scan
  is now backed by a Redis counter (per file hash) instead of a purely
  in-process one, so invalidation on one daemon process is correctly
  observed by every other process sharing the same cache. The counter is
  bumped and the cached report deleted atomically via a Redis Lua script,
  and a second Lua script performs an atomic compare-and-set on write to
  reject a write whose captured generation has since been superseded.
  Both scripts are loaded once at daemon startup (`SCRIPT LOAD`) and
  invoked by their SHA (`EVALSHA`), transparently falling back to sending
  the script body (`EVAL`) and re-caching the SHA if the server reports
  the script is unrecognized (e.g. after a Redis restart). `GET /v1/query`
  now re-checks Redis before returning a completed report for any file
  hash this daemon process has already written to or rejected via Redis,
  so an invalidation issued on a peer process is observed instead of
  serving a stale report straight out of local memory.

## 0.5.2 — 2026-07-09

### Added
- **GitHub Actions CI** (`.github/workflows/`):
  - `ci.yml` — three-job pipeline: lint (ruff + REUSE), test matrix
    (Python 3.10/3.11/3.12, coverage upload to Codecov), dependency audit
    (`pip-audit`).
  - `codeql.yml` — weekly + on-push CodeQL analysis with `security-extended`
    query suite covering OWASP Top 10 patterns.
  - `dependency-review.yml` — PR-level dependency review; blocks CVEs ≥
    moderate and licenses incompatible with EUPL-1.2.

### Changed
- `REUSE.toml` and `LICENSES/` updated to reflect new workflow files and
  third-party license inventory.
- `__version__` / `_ENGINE_VERSION` derive from `importlib.metadata` at
  runtime; `pyproject.toml` is the single source of truth for the version
  string (bumped to `0.5.2`).

## 0.5.1 — 2026-07-09

### Added
- **`GET /v1/capabilities` endpoint** — exposes active analyzers, accepted MIME
  types, file extensions, limits, and supported response formats as JSON.
  Clients (e.g. Rspamd) can query this endpoint to build their MIME include
  filter dynamically instead of maintaining a static list.
  - Per-analyzer `active` flag (enabled in config **and** runtime prerequisites
    met), `scope` (`type-routed` / `global` / `post-processing`), `mime_types`,
    `mime_patterns`, and `extensions`.
  - Top-level `mime_types` aggregate: `exact`, `prefixes`, `patterns`,
    `extensions`, and `global_scanners` (active YARA / ClamAV).
  - `ETag` (SHA-256 of the response body) with `If-None-Match` / `304 Not
    Modified` support and `Cache-Control: max-age=60`.
  - API-key authentication consistent with all other `/v1/` endpoints.
  - OpenAPI 3.0 path entry at `/v1/capabilities`.
- **`xspct-scan-client --capabilities`** — new CLI flag to query and display the
  capabilities endpoint. `--json` outputs raw JSON; rich-formatted table view
  when Rich is installed. Mutually exclusive with FILE arguments; `files`
  positional changed from `nargs="+"` to `nargs="*"`.
- **`TYPE_ROUTING` module-level constant** — unified MIME/extension routing table
  consumed by both `get_detected_type()` and `build_capabilities()`; eliminates
  the inline tuple literals that previously lived only inside the router method.
- **`MAX_UPLOAD_BYTES`** (`50 MiB`) and **`DEFAULT_SCAN_TIMEOUT`** (`10 s`) —
  module-level constants reused by `make_app()`, `handle_scan()`, and
  `build_capabilities()`.
- **`_engine_matrix()`** method on `InspectorDaemon` — extracted from `setup()`;
  shared between startup logging and `build_capabilities()`.
- **`CHANGELOG.md` symlink** at repository root pointing to `docs/changelog.md`
  for GitHub/tooling discoverability.

### Changed
- `get_detected_type()` refactored to consume `TYPE_ROUTING`; routing behavior
  is bit-for-bit identical (all 29 `TestGetDetectedType` cases pass unchanged).
- `make_app()` uses `MAX_UPLOAD_BYTES` instead of an inline `50 * 1024 * 1024`.
- `handle_scan()` uses `DEFAULT_SCAN_TIMEOUT` for the `timeout` query parameter
  default.
- Version string consolidated: `pyproject.toml` is now the **single source of
  truth**. `__init__.__version__` is derived via `importlib.metadata`; daemon's
  `_ENGINE_VERSION` is imported from `__version__`. The OpenAPI spec and legacy
  `meta.version` field now reference `_ENGINE_VERSION` instead of hardcoded
  strings.
- `docs/api-http.md` (duplicate of `docs/guide/api-http.md`) removed; README
  links updated to `docs/guide/api-http.md`.
- README deduplicated — second full copy (stale, ~430 lines) removed.
- Test `test_meta_always_present` assertion uses `xspct._ENGINE_VERSION` instead
  of a hardcoded string.
- Client subprocess tests use `sys.executable` instead of `.venv/bin/python`.

## 0.5.0 — 2026-07-07

### Added
- **v2 report schema** (`schema_version: "2.0"`) — structured, grouped, omit-empty:
  - `engine` — scanner identity (`{name, version}`).
  - `file` — file identity: `{name, sha256, size, mime, magic, type}`.
    SHA-256 hash and MIME are now nested here; dates are **ISO-8601**.
  - `scan` — lifecycle bookkeeping: `{status, duration_s, cache_hit, analyzers}`.
    Analyzer timings, completed/pending lists, and errors are grouped here.
  - `verdict` — placeholder for aggregated risk: `{score, severity, labels,
    summary, contributors}`. Scoring logic planned for a later release.
  - `flags` — content indicators map; **only `true` keys are emitted**
    (no `has_macro: false` noise). Possible keys: `encrypted`, `decrypted`,
    `decryption_password`, `macros`, `javascript`, `open_action`, `launch`,
    `embedded_files`, `forms`, `scripts`, `iframes`, `meta_refresh`.
  - `iocs` — unified, typed, **rich IOC objects** `{value, source, confidence}`
    replacing the old flat `urls`/`ips`/`domains` lists plus `iocs_extended`.
    Basic scanner domains start with `medium` confidence; iocsearcher hits
    upgrade them to `high`. New types: `emails`, `hashes`, `cves`, `wallets`,
    `onions`, `phones`.
  - `findings` — was `analyses`; enriched with `severity` and `source` fields.
  - `content` — `{preview, full}` — lists of `{source, text}` segments;
    only emitted when non-empty and enabled by config.
  - `document` — was `meta_document`; empty-string fields omitted; dates
    normalized to ISO-8601 (`D:YYYYMMDDHHmmSSZ` → `YYYY-MM-DDTHH:MM:SSZ`).
  - `engines` — per-engine raw output grouped under named sub-keys
    (`clamav`, `yara`, `pdfid`, `archive`, `image`, `rtf`); a sub-key is
    **omitted** when the engine produced no output.
- `_normalize_pdf_date()` — module-level helper for PDF date normalization.
- `_to_v2_report()` — single transformation boundary in `analyze_task`;
  internal v1 accumulation is preserved; only the HTTP output is v2.
- New pydantic v2 models: `_V2Engine`, `_V2File`, `_V2Scan`, `_V2Verdict`,
  `_V2IocEntry`, `_V2Iocs`, `_V2Finding`, `_V2ScanReport`; legacy models kept.
- `urllib.parse` import for URL-decoding filenames in output.
- Dependency SBOM (`bom.json`, CycloneDX JSON, 168 components).
- REUSE annotation for `bom.json`.

### Changed
- `file.sha256` (was top-level `file_hash`), `file.type` (was `detected_type`),
  `file.mime` (was `file_type`), `file.magic` (was `file_description`).
- `scan.duration_s` (was `time_taken`; `time_taken` kept at top-level too for
  compatibility with HTTP handlers).
- `findings` (was `analyses`); `content.preview` / `content.full` (were
  `text_preview` / `text_full` at top level).
- `engines.clamav` (was top-level `clamav`), `engines.yara.matches` (was
  `yara_matches`), `engines.pdfid` (was `pdfid_keywords` / `pdfid_meta`),
  `engines.archive.files` (was `archive_files`), `engines.image.exif` (was `exif`).
- `openapi.json` 200-response schema updated to reference `V2ScanReport`.
- `xspct-scan-client` display functions updated to read v2 field paths with
  v1 fallbacks for backward-compatible polling of cached v1 reports.
- `__version__` bumped to `0.5.0` in `__init__.py` and `pyproject.toml`.

## 0.4.0 — 2026-07-07

### Added
- **ODF analyzer** (`analyze_odf`): full analysis of OpenDocument Format files
  (`.odt`, `.ods`, `.odp`, `.odg`, `.odf`).  Uses `odfdo` when available
  (requires `[advanced]` extra) with a raw ZIP/XML fallback.
  - Body text and metadata extracted via `odfdo`; XML tag-stripping fallback.
  - Hyperlink extraction from every `xlink:href` attribute (covers `draw:a`,
    event-listeners, and form controls, not just `text:a`).
  - StarBasic macro detection via ZIP entry scan; macro source fed to
    `VBA_Scanner` keyword analysis (oletools) and IOC extraction.
  - Embedded OLE object detection.
  - Embedded images extracted from `Pictures/` and analysed with OCR/QR.
  - `_is_odf()` helper detects ODF by MIME prefix, file extension, or ZIP
    `mimetype` entry.
  - Added `.odg` and `.odf` to the office extension list.
  - Added `odfdo>=3.20` to the `[advanced]` optional dependency group.
- **Scanned-PDF OCR fallback**: when PyMuPDF finds an empty text layer, OCR
  text collected from embedded images is used for `text_preview` and feeds
  iocsearcher.
- **Multi-source text extraction**: `text_preview` and `text_full` are now
  lists of `{source, text}` segments.  Every extractor contributes an
  independently labelled segment (sources: `pdf`, `pdf-image`, `office`,
  `office-macro`, `odf`, `odf-macro`, `odf-image`, `html`, `html-image`,
  `ooxml-image`, `text`, `image-ocr`, `image-qr`).
- **All extracted text reaches iocsearcher**: OCR/QR results from images and
  macro source code now pass through the extended IOC catcher (email, CVE,
  hash, wallet, onion addresses) in addition to the regex extractor.  Image
  extraction runs before iocsearcher in `analyze_pipeline`.
- **Renamed CLI tool**: `xspct-client` is now `xspct-scan-client`.
- **REUSE 3.3 compliance**: SPDX metadata added for all source files;
  `LicenseRef-Public-Domain` licence file added for vendored Didier Stevens
  tools; `.github/prompts/` workflow prompt files added.
- **Agent workflow prompts** in `.github/prompts/`: `check-code`, `format-code`,
  `run-tests`, `prepare-commit`, `generate-sbom`.

### Changed
- `text_preview` and `text_full` response fields are now **lists** of
  `{source, text}` objects instead of plain strings.
- `xspct_text_preview_length` and `xspct_text_max_length` now apply per
  segment rather than to a single combined string.
- `xspct_include_text_preview`/`xspct_include_text_full` now zero the
  respective list to `[]` when disabled (was `""` / `null`).

### Fixed
- ODF files previously fell through to oletools which cannot parse them;
  dispatch now routes ODF through the dedicated path before VBA_Parser.
- PDF byte-scan marker flags (`has_javascript`, `has_openaction`, etc.) were
  on single-line `if m_type == ...: flag = True` statements; expanded to
  full `if/else` form (Python 3.10+ f-string nested-quote fix).
- `xml.etree.ElementTree` removed from ODF meta.xml fallback; regex extraction
  used instead to prevent entity-expansion DoS on hostile input.
- `_OdfLink` dead import removed.
- Internal text accumulation keys (`_pdf_ocr_text`, `_text_full_extracted`)
  were not cleaned up in `sync_analyze`; they are now popped before return.

## Unreleased

## 0.3.0 — 2026-05-06

### Added
- **sflock2 archive backend**: when `SFlock2` is installed (`pip install "xspct_scan[advanced]"`)
  archive extraction runs inside the zipjail usermode sandbox, covering RAR,
  TAR/TGZ/TBZ2, CAB, ACE, ISO, EML, MSG, MSO, lzip, and ZPAQ in addition to
  the existing ZIP and 7z support.  The stdlib `zipfile`/`py7zr` fallback is
  retained for environments without sflock2.
- **EML and MSG routed through archive pipeline**: `get_detected_type` now returns
  `'archive'` for `message/rfc822`, `application/vnd.ms-outlook`, `.eml`, `.msg`,
  and `.mso` files so attachments are extracted in-sandbox.
- **`HAS_SFLOCK` feature flag** visible in the Python API (same pattern as
  `HAS_YARA`, `HAS_IOCSEARCHER`, etc.).

## 0.2.0 — 2026-04-24

Initial public release of xspct_scan (renamed from olefy_v2).

### Features

- Async HTTP daemon built on [aiohttp](https://docs.aiohttp.org/)
- Scan Office (OLE2, OOXML), PDF, and HTML documents for malware indicators
- VBA macro detection and analysis via [oletools](https://github.com/decalage2/oletools)
- Automatic decryption of password-protected Office files via
  [msoffcrypto-tool](https://github.com/nolze/msoffcrypto-tool) and oletools
- RTF object extraction via `rtfobj`
- IOC extraction (URLs, IP addresses, domains) from document content
- Optional Redis result cache with circuit-breaker
- API key authentication with key-rotation support
- Prometheus metrics endpoint (`/metrics`)
- Optional TLS termination
- Optional [uvloop](https://github.com/MagicStack/uvloop) event loop
- REUSE / SPDX licence compliance (EUPL-1.2)
- **Parallel pipeline** — analyzers run concurrently; partial results returned
  on timeout via `202 Accepted` with `analyzers_completed` / `analyzers_pending`
- **`application/octet-stream` upload** — raw bytes can be POSTed directly
  to `/scan` without multipart encoding
- **OpenAPI 3.0** specification at `/openapi.json`; ReDoc UI at `/apidoc/redoc`
  (requires `[openapi]` extra)
- **YARA scanning** — optional static signature matching on raw file bytes;
  supports Hyperscan acceleration (requires `[advanced]` extra)
- **iocsearcher** — extended IOC types (email, hash, CVE, …) extracted from
  document text (requires `[advanced]` extra)
- **PDF enrichment** — vendored pdfid v0.2.10 adds keyword counts and metadata
  to PDF scan reports
- **Image analysis** — OCR via pytesseract, QR/barcode decode via pyzbar,
  EXIF metadata extraction (GPS hits flagged), embedded OOXML images scanned
- **Archive analysis** — ZIP and 7z extraction with configurable depth/size
  limits and password loop; nested documents recursively analysed
- **`text_full` field** — full-text extraction included in reports when
  `xspct_include_text_full: true`
- **Admin reload** — `POST /admin/reload` reloads config/passwords/YARA
  without restart (requires `xspct_admin_api_key`)
- **`text` analyzer** — plain-text and script files (`text/plain`, ASCII,
  UTF-8, Unicode) are now a first-class type: `analyze_text()` decodes the
  content, populates `text_preview`, and extracts baseline IOCs; YARA and
  iocsearcher run over the same bytes in parallel
- **YARA on all types** — YARA now runs on every file regardless of type
  (PDFs, images, archives, text, unknown).  In the synchronous pipeline
  (`sync_analyze`) YARA is called after the primary analyzer and merged into
  the report.  Inside archive extraction every member — including images and
  unknown blobs — is individually YARA-scanned.
- **Archive member coverage** — `_analyse_member` now handles `text` and
  `unknown` members (previously ignored), and image members are passed
  through both `analyze_image` and YARA.  `merge_reports` is used throughout
  so `yara_matches`, `iocs_extended`, `pdfid_*`, and `rtf_objects` from
  sub-files are correctly propagated to the top-level archive report.
