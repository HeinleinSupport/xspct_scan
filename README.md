# xspct_scan

**xspct_scan** is an async HTTP daemon that analyses Office, PDF, HTML, ODF,
image, archive, and standalone-script files for malware indicators. It
combines static structural analysis (VBA/OLE parsing, PDF object trees,
archive extraction), signature-based scanning (YARA, ClamAV), and IOC/text
extraction (URLs, IPs, domains, hashes, and more, including from OCR and
decoded macros) into a single concurrent analysis pipeline, returning a
unified JSON (or msgpack/CBOR) report per file.

It is designed to sit alongside a mail-filtering stack —
built primarily to integrate with [Rspamd](https://rspamd.com/) as an
attachment-scanning backend, but usable standalone via its HTTP API or the
bundled `xspct-scan-client` CLI for on-demand or scripted scanning. Analysis
is parallelised across per-file-type analyzers with a two-tier
foreground/background concurrency model, so slow scans degrade gracefully
(`202 Accepted` + polling) instead of blocking the caller, and results can be
cached in Redis (or served from an in-memory LRU) to avoid re-analysing the
same file hash.

## Table of Contents

- [xspct\_scan](#xspct_scan)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
    - [Document analysis](#document-analysis)
    - [Enrichment](#enrichment)
    - [Multi-source text extraction](#multi-source-text-extraction)
    - [Infrastructure](#infrastructure)
  - [Quick start](#quick-start)
  - [Requirements](#requirements)
  - [Installation](#installation)
    - [From GitHub](#from-github)
    - [Optional extras](#optional-extras)
    - [From source](#from-source)
  - [Configuration](#configuration)
  - [HTTP API](#http-api)
    - [`POST /v1/scan`](#post-v1scan)
    - [Endpoints](#endpoints)
    - [`GET /v1/capabilities`](#get-v1capabilities)
  - [Decrypting password-protected files](#decrypting-password-protected-files)
    - [Global password list](#global-password-list)
    - [Per-request passwords](#per-request-passwords)
  - [YARA scanning](#yara-scanning)
  - [Sandboxed archive extraction](#sandboxed-archive-extraction)
  - [Image OCR and QR/barcode scanning](#image-ocr-and-qrbarcode-scanning)
    - [OCR exclusion gates](#ocr-exclusion-gates)
    - [System dependencies](#system-dependencies)
  - [ODF analysis](#odf-analysis)
  - [SVG analysis](#svg-analysis)
  - [Standalone script analysis](#standalone-script-analysis)
  - [Windows shortcut (.lnk) analysis](#windows-shortcut-lnk-analysis)
  - [Digital signature detection](#digital-signature-detection)
  - [ClamAV integration](#clamav-integration)
    - [Requirements](#requirements-1)
    - [Configuration](#configuration-1)
    - [Response fields](#response-fields)
  - [Systemd unit](#systemd-unit)
  - [Documentation](#documentation)
  - [Licence](#licence)

---

## Features

### Document analysis

- **Office / OLE2 + OOXML** — VBA macro extraction and keyword analysis via
  [oletools](https://github.com/decalage2/oletools); automatic decryption of
  password-protected files with
  [msoffcrypto-tool](https://github.com/nolze/msoffcrypto-tool)
- **ODF** (`.odt`, `.ods`, `.odp`, `.odg`, `.odf`) — body text, hyperlinks
  (`xlink:href` on all elements, not just `text:a`), metadata, StarBasic macro
  detection, embedded object detection, and OCR on embedded images; uses
  [odfdo](https://github.com/jdum/odfdo) when available with a ZIP/XML fallback
- **PDF** — deep content analysis via [PyMuPDF](https://pymupdf.readthedocs.io/)
  (JavaScript, URIs, document metadata, encryption) plus structural keyword
  counts via vendored [pdfid](https://github.com/DidierStevens/DidierStevensSuite);
  OCR fallback for scanned/image-only PDFs
- **HTML / SVG** — script extraction, CSS-hiding detection, external resource
  tracking; SVG files are treated as HTML
- **Standalone scripts** — VBScript, encoded VBScript/JScript (Microsoft
  Script Encoder), JScript, Windows Script Files, PowerShell, and batch
  files (`.vbs`, `.vbe`, `.js`, `.jse`, `.wsf`, `.wsh`, `.ps1`, `.bat`,
  `.cmd`); `.hta` (HTML Application) is treated as HTML. See
  [Standalone script analysis](#standalone-script-analysis)
- **Windows shortcuts** (`.lnk`) — target/argument extraction, LOLBin and
  script-interpreter detection, UNC/network target flagging, hidden-command
  and whitespace-padding obfuscation, and icon/target extension-mismatch
  detection; uses [LnkParse3](https://github.com/Matmaus/LnkParse) when
  available. See
  [Windows shortcut (.lnk) analysis](#windows-shortcut-lnk-analysis)
- **Digital signatures** — detects and cryptographically validates VBA
  project signatures, OOXML whole-document XML-DSig signatures, and PDF
  (PAdES) signatures via [pyhanko](https://github.com/MatthiasValvekens/pyhanko);
  pure detection, never affects score/severity. See
  [Digital signature detection](#digital-signature-detection)
- **RTF** — embedded object extraction via `rtfobj` (opt-in per request)
- **Dynamic JS emulation** — sandboxed execution with
  [quickjs](https://github.com/PetterS/quickjs) and deobfuscation with
  [jsbeautifier](https://github.com/beautify-web/js-beautify) (optional;
  QuickJS emulation is **disabled by default** — enable with
  `xspct_analyzers.javascript.quickjs: true`)

### Enrichment

- **IOC extraction** — URLs, IPs, and domains from all document types and all
  text sources (body, macros, OCR/QR, archive members)
- **Extended IOCs** — email addresses, file hashes, CVE IDs, crypto wallets,
  onion addresses, and more via
  [iocsearcher](https://github.com/malicialab/iocsearcher) — runs over **all**
  extracted text segments, including OCR output and macro source code (optional)
- **YARA scanning** — static signature matching via
  [yara-python](https://github.com/VirusTotal/yara-python) (classic engine,
  optional Hyperscan acceleration) and/or
  [yara-x](https://github.com/VirusTotal/yara-x) (Rust rewrite); both engines
  can run simultaneously for comparison
- **Image analysis** — OCR text extraction via
  [pytesseract](https://github.com/madmaze/pytesseract) and
  [EasyOCR](https://github.com/JaidedAI/EasyOCR) (both run in parallel),
  QR-code and barcode decoding via
  [pyzbar](https://github.com/NaturalHistoryMuseum/pyzbar),
  and EXIF metadata extraction with GPS coordinate flagging (optional; all
  require `[enrichment]`)
- **Archive extraction** — sandboxed extraction via
  [SFlock2](https://github.com/doomedraven/sflock2) (zipjail usermode sandbox)
  covering ZIP, 7z, RAR, TAR/TGZ/TBZ2, CAB, ACE, ISO, EML, MSG, MSO, lzip,
  and ZPAQ; configurable depth/size limits, password loop, recursive sub-file
  analysis. Falls back to stdlib `zipfile`/`py7zr` without SFlock2.
- **ClamAV integration** — every file and individual archive members forwarded
  to a running `clamd` daemon for antivirus signature matching (optional;
  requires `[enrichment]`)

### Multi-source text extraction

All extracted text — document body, macro source, image OCR/QR results,
archive-member text — is collected as **labelled segments** and exposed in the
`text_preview` and `text_full` response fields:

```json
"text_preview": [
  {"source": "office",       "text": "Dear customer …"},
  {"source": "office-macro", "text": "Shell \"cmd.exe …\""},
  {"source": "ooxml-image",  "text": "https://evil.example/…"}
]
```

Every segment independently feeds both the basic IOC regex extractor and the
extended iocsearcher, so no URLs, email addresses, or file hashes embedded in
images or macros are silently missed.

Available sources: `pdf`, `pdf-image`, `office`, `office-macro`, `odf`,
`odf-macro`, `odf-image`, `html`, `html-image`, `ooxml-image`, `text`,
`script`, `script-decoded`, `lnk`, `lnk-working-directory`, `image-ocr`,
`image-qr`.

### Infrastructure

- **Parallel pipeline** — analyzers run as concurrent asyncio tasks; partial
  results returned on timeout (`202 Accepted`) with `analyzers_completed` /
  `analyzers_pending` fields
- **Redis result cache** — optional; survives restarts, shared across instances
- **Prometheus metrics** — exposed at `/v1/metrics`
- **OpenAPI 3.0** — spec at `/v1/openapi.json`; ReDoc UI at `/v1/apidoc/redoc`
- **Admin API** — live reload of config / passwords / YARA rules via
  `POST /v1/admin/reload`
- **API key auth** — per-header key with rotation support; separate admin key

---

## Quick start

```bash
pip install "git+https://github.com/HeinleinSupport/xspct_scan.git"
xspct-scan /etc/xspct_scan/config.yml
```

Scan a document:

```bash
curl -s -F "doc=@invoice.docx" http://localhost:8080/v1/scan | python3 -m json.tool
```

Or upload raw bytes:

```bash
curl -s -X POST http://localhost:8080/v1/scan \
  --data-binary @invoice.docx \
  -H "Content-Type: application/octet-stream" \
  | python3 -m json.tool
```

---

## Requirements

- Python 3.10+
- `libmagic` system library

  ```bash
  # Debian / Ubuntu
  sudo apt-get install libmagic1

  # RHEL / Fedora
  sudo dnf install file-libs
  ```

---

## Installation

### From GitHub

```bash
pip install "git+https://github.com/HeinleinSupport/xspct_scan.git"
```

### Optional extras

| Extra | Installs | Use when |
|-------|----------|----------|
| `uvloop` | `uvloop` | Higher-throughput async event loop |
| `redis` | `redis[asyncio]` | Persistent result cache across restarts |
| `enrichment` | `Pillow`, `pytesseract`, `pyzbar`, `easyocr`, `clamd`, `jsbeautifier`, `quickjs`, `tree-sitter` | Image OCR/barcode/EXIF (Tesseract + EasyOCR), ClamAV integration, JS deobfuscation |
| `openapi` | `pydantic>=2.0` | OpenAPI 3.0 spec + ReDoc UI |
| `advanced` | `yara-python`, `yara-x`, `iocsearcher`, `odfdo`, `py7zr`, `SFlock2`, `tldextract`, `LnkParse3`, `pyhanko` | YARA scanning, extended IOCs, ODF analysis, sandboxed archive extraction, .lnk shortcut analysis, digital signature detection |
| `serialization` | `msgpack`, `cbor2` | msgpack and CBOR response serialization |
| `compression` | `zstandard` | zstd response compression and transparent upload decompression |

```bash
pip install "xspct_scan[uvloop,redis,enrichment,openapi,advanced] @ git+https://github.com/HeinleinSupport/xspct_scan.git"
```

### From source

```bash
git clone https://github.com/HeinleinSupport/xspct_scan.git
cd xspct_scan
pip install -e ".[uvloop,redis,enrichment,openapi,advanced]"
```

---

## Configuration

Copy the example config and edit to suit:

```bash
cp config/xspct_scan.example.yml /etc/xspct_scan/config.yml
xspct-scan /etc/xspct_scan/config.yml
```

Key settings:

| Key | Default | Description |
|-----|---------|-------------|
| `xspct_listen_address` | `0.0.0.0` | Bind address(es) |
| `xspct_listen_port` | `8080` | Listen port |
| `xspct_api_key` | _(empty)_ | Shared secret for `X-Api-Key` auth |
| `xspct_admin_api_key` | _(empty)_ | Key for `POST /v1/admin/reload` |
| `xspct_redis_cache.enabled` | `false` | Enable Redis result cache |
| `xspct_password_file` | | Path to wordlist for decrypting encrypted files |
| `xspct_analyzers` | _(all enabled)_ | Per-analyzer enable/disable + options |
| `xspct_analyzers.javascript.quickjs` | `false` | Enable QuickJS sandbox emulation for JS |
| `xspct_analyzers.image.ocr_max_bytes` | `2097152` | Skip OCR for images larger than this (bytes). `0` = disabled. |
| `xspct_analyzers.image.ocr_max_pixels` | `4000000` | Skip OCR when `W×H` exceeds this (pixels). `0` = disabled. |
| `xspct_analyzers.image.ocr_skip_camera` | `true` | Skip OCR when EXIF Make/Model tag present (camera shot) |
| `xspct_include_text_preview` | `true` | Include `text_preview` segments (`[{source, text}]`) in reports |
| `xspct_include_text_full` | `false` | Include `text_full` segments (`[{source, text}]`) at full length |
| `xspct_text_preview_length` | `2000` | Max characters per `text_preview` segment |
| `xspct_text_max_length` | `50000` | Max characters per `text_full` segment |
| `xspct_response_format` | `auto` | Response serialization: `auto`, `json`, `msgpack`, or `cbor` |
| `xspct_archive_max_depth` | `2` | Recursion limit for archive extraction |
| `xspct_foreground_slots` | `16` | Max concurrent scans holding a client connection open |
| `xspct_background_slots` | `4` | Max concurrent scans continuing after `202` timeout |

See [docs/guide/configuration.md](docs/guide/configuration.md) for the full reference.

---

## HTTP API

### `POST /v1/scan`

Submit a document for analysis.

**multipart/form-data** (field `doc`):

```bash
curl -s -F "doc=@malware.xlsm" http://localhost:8080/v1/scan
```

**multipart/form-data** (structured `metadata` + `file` parts) — for callers
like Rspamd that want to pass correlation IDs and per-request overrides as a
single structured object instead of query parameters:

```bash
curl -s http://localhost:8080/v1/scan \
  -F 'metadata={"rspamd_uid":"7f3a9c1e-b2d4","passwords":["Secret123"]};type=application/json' \
  -F "file=@malware.xlsm"
```

**application/octet-stream** (raw bytes, metadata as query params):

```bash
curl -s -X POST "http://localhost:8080/v1/scan?filename=malware.xlsm" \
  --data-binary @malware.xlsm \
  -H "Content-Type: application/octet-stream"
```

**msgpack / CBOR responses** — set the `Accept` header to
`application/x-msgpack` or `application/cbor`. Requires `[serialization]`.

**zstd-compressed responses** — add `Accept-Encoding: zstd`. Requires
`[compression]`.

**zstd-compressed uploads** — the daemon transparently decompresses a
zstd-compressed body (detected via Zstandard frame magic bytes); the `.zst`
filename suffix is stripped before type detection.

Example response (schema v2.0 — omit-empty, grouped):

```json
{
  "schema_version": "2.0",
  "engine":  { "name": "xspct-scan", "version": "0.5.0" },
  "file":    { "name": "malware.xlsm", "sha256": "sha256...", "sha1": "sha1...",
               "rspamd_digest": "blake2b...", "size": 48291,
               "mime": "application/vnd.openxmlformats-officedocument...",
               "magic": "Microsoft Word 2007+", "type": "office" },
  "scan":    { "status": "finished", "duration_s": 0.18, "cache_hit": false,
               "analyzers": { "completed": ["office","yara","iocs"], "pending": [],
                              "timings_s": {"office": 0.09, "yara": 0.03, "iocs": 0.01} } },
  "verdict": { "score": null, "severity": "unknown", "labels": [], "summary": null, "contributors": {} },
  "flags":   { "macros": true },
  "iocs":    { "urls":    [{"value": "https://evil.example/payload", "source": "scanner",     "confidence": "high"}],
               "domains": [{"value": "evil.example",                 "source": "iocsearcher", "confidence": "high"}] },
  "findings": [{"type": "AutoExec", "keyword": "AutoOpen", "description": "...", "severity": "medium", "source": "scanner"}],
  "content": { "preview": [{"source": "office", "text": "..."}] },
  "engines": { "clamav": {"status": "clean", "scan_time_s": 0.01},
               "yara":   {"matches": [{"engine": "classic", "rule": "Eicar_Test", "tags": [], "meta": {}}]} },
  "status": "finished",
  "time_taken": 0.18
}
```

Returns `202 Accepted` when analysis exceeds the configured timeout.
Poll `/v1/query?hash=<sha256>` for the result:

```bash
curl "http://localhost:8080/v1/query?hash=sha256..."
```

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/scan` | POST | Submit file for analysis |
| `/v1/query` | GET / POST | Retrieve result by SHA-256 hash |
| `/v1/capabilities` | GET | Active analyzers, MIME routing tables, and limits |
| `/health` | GET | Health check (unversioned) |
| `/ping` | GET | Returns `pong` (unversioned) |
| `/v1/metrics` | GET | Prometheus metrics |
| `/v1/openapi.json` | GET | OpenAPI 3.0 spec (requires `[openapi]`) |
| `/v1/apidoc/redoc` | GET | ReDoc UI (requires `[openapi]`) |
| `/v1/admin/reload` | POST | Live-reload config / passwords / YARA rules |

See [docs/guide/api-http.md](docs/guide/api-http.md) for full request/response details.

### `GET /v1/capabilities`

Returns the list of active analyzers, their accepted MIME types, and current
limits — useful for building a dynamic MIME include filter in Rspamd:

```bash
curl -s http://localhost:8080/v1/capabilities | python3 -m json.tool

# CLI client
xspct-scan-client --capabilities
xspct-scan-client --capabilities --json
```

Responses carry an `ETag`; use `If-None-Match` to avoid redundant transfers:

```bash
ETAG=$(curl -si http://localhost:8080/v1/capabilities \
  | grep -i '^ETag:' | awk '{print $2}' | tr -d '\r')
curl -si -H "If-None-Match: $ETAG" http://localhost:8080/v1/capabilities
# HTTP/1.1 304 Not Modified
```

---

## Decrypting password-protected files

xspct_scan automatically tries to decrypt encrypted Office and PDF documents
using a password list loaded at startup.

### Global password list

```yaml
xspct_password_file: /etc/xspct_scan/passwords.txt
```

The file is reloaded on `POST /v1/admin/reload`.

### Per-request passwords

Extra passwords supplied with the request are tried **before** the global list:

```bash
curl -s \
  -F "doc=@protected.xlsx" \
  -F "passwords=Secret123,CompanyPass" \
  http://localhost:8080/v1/scan
```

When decryption succeeds the response includes `"decrypted": true` and
`"decryption_password": "Secret123"`.

---

## YARA scanning

YARA runs on **every** file — PDFs, HTML, Office documents, ODF, images, plain
text, archive members, and unknown blobs. Two engines can run in parallel:

```yaml
xspct_analyzers:
  yara:
    enabled: true
    rules_path: /etc/xspct_scan/rules/       # classic yara-python
  yara_x:
    enabled: true
    rules_path: /etc/xspct_scan/rules/       # yara-x (Rust)
```

Each match in `yara_matches` carries an `"engine"` field (`"classic"` or
`"yara-x"`). Reload rules without restart with `POST /v1/admin/reload`.

---

## Sandboxed archive extraction

Install `SFlock2` (included in `[advanced]`) to enable sandboxed extraction
via **zipjail**:

```bash
pip install "xspct_scan[advanced] @ git+https://github.com/HeinleinSupport/xspct_scan.git"

# System packages for full native-format support (Debian / Ubuntu)
sudo apt-get install p7zip-full rar unace-nonfree cabextract lzip zpaq
```

With SFlock2 installed the following formats are extracted in-sandbox:
ZIP, 7z, RAR, TAR, TAR.GZ, TBZ2, CAB, ACE, ISO, EML, MSG, MSO, lzip, ZPAQ.
**EML and MSG** files are routed through the archive pipeline automatically
so that email attachments are extracted and analysed.

---

## Image OCR and QR/barcode scanning

When `[enrichment]` is installed, raster images (JPEG, PNG, GIF, BMP, TIFF,
WebP, ICO) and images embedded in PDFs, OOXML, and ODF documents are analysed:

1. **OCR** — Tesseract and EasyOCR both run in parallel; extracted text is
   collected as `image-ocr` segments and fed to both the regex IOC extractor
   and iocsearcher.
2. **QR / barcode decode** — pyzbar decodes QR codes and 1-D barcodes;
   decoded payloads are surfaced in `qr_codes` and as `image-qr` text
   segments, also feeding IOC extraction.

### OCR exclusion gates

Large natural-photo images (camera JPEGs, scanned outdoor photos) can take
minutes in OCR and yield no useful output. Three configurable gates skip OCR
automatically:

| Config key | Default | Trigger condition |
|---|---|---|
| `ocr_max_bytes` | 2 MiB | Raw file size exceeds threshold |
| `ocr_max_pixels` | 4 MP (2000×2000) | `width × height` exceeds threshold |
| `ocr_skip_camera` | `true` | EXIF `Make` or `Model` tag present |

When a gate fires the reason appears in `scan.exclusions.image.ocr`. Set any
threshold to `0` to disable that gate. Override gates for a single scan:

```bash
# API — query parameter
curl -F "doc=@photo.jpg" 'http://localhost:8080/v1/scan?force_analyzers=image.ocr'

# CLI
xspct-scan-client --force-ocr photo.jpg
xspct-scan-client --force-analyzers image.ocr photo.jpg
```

### System dependencies

```bash
# Debian / Ubuntu
sudo apt-get install tesseract-ocr libzbar0

# RHEL / Fedora
sudo dnf install tesseract zbar
```

---

## ODF analysis

OpenDocument Format files (`.odt`, `.ods`, `.odp`, `.odg`, `.odf`) are handled
by a dedicated analyzer (requires `odfdo` from the `[advanced]` extra):

```bash
pip install "xspct_scan[advanced] @ git+https://github.com/HeinleinSupport/xspct_scan.git"
```

What is extracted:

| Source | Details |
|--------|---------|
| Body text | Plain text via odfdo or XML tag-stripping fallback |
| Hyperlinks | All `xlink:href` attributes — covers `draw:a`, event-listeners, and form controls, not just `text:a` |
| Metadata | Title, author, subject, keywords, app name, revision count, dates |
| Macros | `Basic/` ZIP entries scanned; macro source analysed by VBA_Scanner and IOC extraction |
| Embedded objects | `Object NN/` ZIP entries flagged as `EmbeddedObject` |
| Embedded images | `Pictures/` entries passed to the image analyzer (OCR/QR) |

All extracted text feeds iocsearcher.

---

## SVG analysis

SVG files are XML-based and can carry `<script>` tags, inline event handlers,
and external references. xspct_scan routes SVG through the **HTML analyzer**:
all HTML checks apply, no extra configuration required.

---

## Standalone script analysis

Standalone script attachments — a common first-stage delivery vector — are
routed to a dedicated analyzer instead of falling through to YARA/ClamAV as
an unknown blob:

| Extension | Handling |
|-----------|----------|
| `.vbs` | Keyword/heuristic scan via oletools' `VBA_Scanner` (same engine used for Office macros) — reused as-is since it works on any VBA/VBScript source, not just OLE containers. Falls back to a small built-in keyword scan when oletools isn't installed. |
| `.vbe` | Microsoft Script Encoder decoding, then scanned as `.vbs`. Requires `[advanced]` (SFlock2) for the decoder — the encoding scheme has no cryptographic secret, but the substitution table is reused from SFlock2's bundled decoder rather than re-derived, to avoid transcription errors. Without it, the file is flagged as undecoded and keyword heuristics don't run. |
| `.js` | Routed directly through the existing JavaScript analyzer (`eval`/`unescape`/`ActiveXObject`/tree-sitter AST scan/optional QuickJS emulation) — previously only reachable for JS *embedded* in HTML. |
| `.jse` | Microsoft Script Encoder decoding, then scanned as `.js`. |
| `.wsf` / `.wsh` | XML container — `<script language="...">` blocks are extracted and each routed to the VBScript or JScript path by its `language` attribute. |
| `.ps1` | Regex heuristics for download cradles, `-EncodedCommand` (decoded and recursively analysed), AMSI bypass patterns, Defender tampering, persistence (Run keys, scheduled tasks), and obfuscation density. |
| `.bat` / `.cmd` | Same heuristic set as PowerShell, plus living-off-the-land patterns (`certutil`, `bitsadmin`, `mshta`, `regsvr32`), shadow-copy deletion, and self-deletion. |
| `.hta` | Treated as **HTML**, not script — an HTA is an HTML container that executes with full local scripting privileges. `analyze_html()` additionally flags the `<HTA:APPLICATION>` tag and stealth attributes (`WINDOWSTATE=minimize`, `SHOWINTASKBAR=no`). |

Every script (and each WSF/WSH `<script>` block) also gets a cross-cutting
regex pass for indicators that aren't language-specific: download cradles,
persistence, AMSI bypass, and obfuscation density. All extracted/decoded
text feeds the same IOC and iocsearcher pipeline as every other analyzer.

```bash
xspct-scan-client suspicious.ps1
```

---

## Windows shortcut (.lnk) analysis

Windows shortcut files are a common LOLBin-launching delivery vector
(e.g. a `.lnk` disguised as an invoice that runs `powershell.exe` with a
hidden download cradle). When [LnkParse3](https://github.com/Matmaus/LnkParse)
is installed (`[advanced]` extra), `.lnk` files are parsed and checked for:

| Finding | Description |
|---------|-------------|
| `lnk-lolbin-target` | Target or arguments reference a script interpreter or LOLBin (`cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `certutil.exe`, `bitsadmin.exe`, ...). |
| *(reused script heuristics)* | Arguments are scanned with the same regex heuristics as the `script` analyzer — download cradles, `-EncodedCommand`, AMSI bypass, persistence, etc. |
| `long-command-line` | Arguments exceed the 260-character Explorer Properties UI limit — content beyond this point is invisible when a user inspects the shortcut. |
| `whitespace-padding` | A long run of whitespace in the arguments, typically used to push a malicious command past the visible UI limit. |
| `unc-path` | The shortcut target is a network share (UNC path) rather than a local file. |
| `icon-target-mismatch` | An executable target uses a document-like icon path (`.pdf`, `.docx`, `.jpg`, etc.). DLL icon resources and ordinary `.ico` files are not flagged. |

The target path and arguments are also fed into the standard IOC/iocsearcher
pipeline. If the analyzer is enabled but `LnkParse3` is unavailable, the raw
text fallback still feeds IOC extraction without raising a hard error. Setting
`xspct_analyzers.lnk.enabled: false` disables both structural LNK analysis and
that raw fallback; global scanners such as YARA and ClamAV remain unaffected.

```bash
xspct-scan-client suspicious.lnk
```

---

## Digital signature detection

When [pyhanko](https://github.com/MatthiasValvekens/pyhanko) is installed
(`[advanced]` extra), Office and PDF documents are checked for digital
signatures. This is **pure detection** — results never influence
`verdict.score`/`severity` — and reported under `engines.signature` (single
object, or an array when multiple signatures are present):

| Type | Source | `valid` means |
|------|--------|----------------|
| `vba_project` | `\x05DigitalSignature*` OLE2 stream, or the equivalent `vbaProjectSignature*.bin` OOXML part | The embedded PKCS#7/CMS signature is internally self-consistent (verifies against its own embedded certificate) |
| `ooxml_document` | `_xmlsignatures/*.xml` (XML-DSig) | Every manifest-listed package part still matches its signed digest **and** the outer signature verifies; `covers_whole_document` says whether the signed manifest includes every non-signature package member |
| `pdf` | Embedded PAdES signature | The CMS signature is intact and valid; `covers_whole_document` reflects whether it covers the entire file |

Every entry also carries `signer` (certificate subject), `issuer_fingerprint`
(`sha256:<hex>` of the cryptographically verified direct issuer certificate,
or the signing certificate when no such issuer is embedded), `key_usage_valid` (the
signing certificate's KeyUsage extension, if present, permits digital
signatures), `cert_time_valid` (the certificate's `not_valid_before`/
`not_valid_after` window covers the current time), and an optional
`timestamp` (ISO-8601 UTC signing time). **`trusted` is always `false`** —
certificate trust-store validation (verifying the signer's certificate
chains to a trusted root) is out of scope for this stage.

By default, `key_usage_valid`/`cert_time_valid` are reported for information
only and never affect `valid` — a certificate with no signing-appropriate
KeyUsage bits, or one that's expired/not-yet-valid, can still produce
`valid: true` if the cryptographic checks pass. Set
`xspct_analyzers.signature.strict: true` to additionally require both to be
true for `valid`.

OOXML signatures using XML-DSig transforms that xspct_scan does not implement
are skipped rather than reported as validated.

`xspct_analyzers.signature.enabled: false` disables the analyzer; if
`pyhanko` isn't installed, it cleanly skips.

---

## ClamAV integration

xspct_scan can forward every scanned file (and individual archive members) to a
running `clamd` daemon for antivirus signature matching.

### Requirements

```bash
pip install "xspct_scan[enrichment] @ git+https://github.com/HeinleinSupport/xspct_scan.git"

# ClamAV daemon (Debian / Ubuntu)
sudo apt-get install clamav-daemon
sudo systemctl enable --now clamav-daemon
```

### Configuration

```yaml
xspct_clamav:
  enabled: true
  socket: /var/run/clamav/clamd.ctl   # Unix socket (preferred); set to '' for TCP
  host: 127.0.0.1
  port: 3310
  timeout: 60
  max_size: 26214400                   # skip files larger than this (bytes)
  scan_members: true                   # also scan individual archive members
```

### Response fields

ClamAV results appear under `clamav` in the scan response:

```json
{
  "clamav": {
    "status": "infected",
    "viruses": ["Win.Trojan.Agent-12345"],
    "engine_version": "1.4.1",
    "db_version": "27482",
    "scan_time_s": 0.12
  }
}
```

Possible `status` values: `clean`, `infected`, `error`, `skipped` (file
exceeds `max_size`), `unavailable`.

Prometheus counters `xspct_clamav_clean`, `xspct_clamav_infected`,
`xspct_clamav_errors`, and `xspct_clamav_timeouts` track scan outcomes at
`/v1/metrics`.

---

## Systemd unit

```ini
[Unit]
Description=xspct_scan malware scanner
After=network.target

[Service]
Type=simple
User=xspct-scan
ExecStart=/usr/local/bin/xspct-scan /etc/xspct_scan/config.yml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

---

## Documentation

Full docs are in the [docs/](docs/) directory and can be built with Sphinx:

```bash
pip install "xspct_scan[docs] @ git+https://github.com/HeinleinSupport/xspct_scan.git"
sphinx-build docs docs/_build/html
```

---

## Licence

[EUPL-1.2](LICENSE) — © 2026 Carsten Rosenberg, Heinlein Support GmbH
