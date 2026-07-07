# xspct_scan

[[_TOC_]]

**xspct_scan** is an async HTTP daemon that analyses Office, PDF, HTML, image,
and archive files for malware indicators. It is designed to integrate with
[Rspamd](https://rspamd.com/) and other mail-security pipelines, and exposes
a simple HTTP API for on-demand scanning.

## Features

### Document analysis
- **Office / OLE2 + OOXML** — VBA macro extraction and keyword analysis via
  [oletools](https://github.com/decalage2/oletools); automatic decryption of
  password-protected files with
  [msoffcrypto-tool](https://github.com/nolze/msoffcrypto-tool)
- **PDF** — deep content analysis via [PyMuPDF](https://pymupdf.readthedocs.io/)
  (JavaScript, URIs, document metadata, encryption) plus structural keyword
  counts via vendored [pdfid](https://github.com/DidierStevens/DidierStevensSuite)
- **HTML / SVG** — script extraction, CSS-hiding detection, external resource
  tracking; SVG files (`image/svg+xml`) are treated as HTML because they are
  XML-based and can carry `<script>` elements, inline event handlers, and
  external `href`/`src` references
- **RTF** — embedded object extraction via `rtfobj` (opt-in per request)
- **Dynamic JS emulation** — sandboxed execution with
  [quickjs](https://github.com/PetterS/quickjs) and deobfuscation with
  [jsbeautifier](https://github.com/beautify-web/js-beautify) (optional;
  QuickJS emulation is **disabled by default** — enable with
  `xspct_analyzers.javascript.quickjs: true`)

### Enrichment
- **IOC extraction** — URLs, IPs, and domains from all document types
- **Extended IOCs** — email addresses, file hashes, CVE IDs, and more via
  [iocsearcher](https://github.com/malicialab/iocsearcher) (optional)
- **YARA scanning** — static signature matching via
  [yara-python](https://github.com/VirusTotal/yara-python) (classic engine,
  optional Hyperscan acceleration) and/or
  [yara-x](https://github.com/VirusTotal/yara-x) (Rust rewrite); both engines
  can run simultaneously for comparison
- **Image analysis** — OCR text extraction via
  [pytesseract](https://github.com/madmaze/pytesseract) (wraps Tesseract) and
  [EasyOCR](https://github.com/JaidedAI/EasyOCR) (both run in parallel; results
  are merged and deduplicated), QR-code and barcode decoding via
  [pyzbar](https://github.com/NaturalHistoryMuseum/pyzbar) (requires the
  `libzbar0` system library), and EXIF metadata extraction with GPS coordinate
  flagging (optional; all require `[enrichment]`)
- **Archive extraction** — sandboxed extraction via
  [SFlock2](https://github.com/doomedraven/sflock2) (zipjail usermode sandbox)
  covering ZIP, 7z, RAR, TAR/TGZ/TBZ2, CAB, ACE, ISO, EML, MSG, MSO, lzip,
  and ZPAQ; configurable depth/size limits, password loop for encrypted
  archives, recursive sub-file analysis.  Falls back to stdlib
  `zipfile`/`py7zr` without SFlock2.
- **ClamAV integration** — every file (and individual archive members) forwarded
  to a running `clamd` daemon for antivirus signature matching; results surfaced
  in the `clamav` response field and appended to `analyses` (optional; requires
  `[enrichment]`)

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

## Quick start

```bash
pip install "git+https://github.com/HeinleinSupport/xspct_scan.git"
xspct_scan /etc/xspct_scan/config.yml
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

## Requirements

- Python 3.10+
- `libmagic` system library

  ```bash
  # Debian / Ubuntu
  sudo apt-get install libmagic1

  # RHEL / Fedora
  sudo dnf install file-libs
  ```

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
| `enrichment` | `Pillow`, `pytesseract`, `pyzbar`, `easyocr`, `clamd`, `jsbeautifier`, `quickjs`, `tree-sitter` | Image OCR/barcode/EXIF (Tesseract + EasyOCR), ClamAV integration, JS deobfuscation (QuickJS sandbox opt-in via config) |
| `openapi` | `pydantic>=2.0` | OpenAPI 3.0 spec + ReDoc UI |
| `advanced` | `yara-python`, `yara-x`, `iocsearcher`, `py7zr`, `SFlock2` | YARA scanning, extended IOCs, sandboxed archive extraction (ZIP/RAR/7z/EML/MSG/…) |
| `serialization` | `msgpack`, `cbor2` | msgpack and CBOR response serialization (negotiated via `Accept` header or `xspct_response_format` config) |
| `compression` | `zstandard` | zstd response compression (`Accept-Encoding: zstd`) and transparent zstd decompression of uploaded files |

```bash
pip install "xspct_scan[uvloop,redis,enrichment,openapi,advanced] @ git+https://github.com/HeinleinSupport/xspct_scan.git"
```

### From source

```bash
git clone https://github.com/HeinleinSupport/xspct_scan.git
cd xspct_scan
pip install -e ".[uvloop,redis,enrichment,openapi,advanced]"
```

## Configuration

Copy the example config and edit to suit:

```bash
cp config/xspct_scan.example.yml /etc/xspct_scan/config.yml
xspct_scan /etc/xspct_scan/config.yml
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
| `xspct_include_text_preview` | `true` | Include the truncated `text_preview` segments (`[{source, text}]`) in reports |
| `xspct_include_text_full` | `false` | Include full extracted text as `text_full` segments (`[{source, text}]`) in reports |
| `xspct_response_format` | `auto` | Response serialization: `auto` (negotiate via `Accept` header), `json`, `msgpack`, or `cbor` |
| `xspct_archive_max_depth` | `2` | Recursion limit for archive extraction |
| `xspct_foreground_slots` | `16` | Max concurrent scans holding a client connection open |
| `xspct_background_slots` | `4` | Max concurrent scans continuing after `202` timeout |

See [docs/configuration.md](docs/configuration.md) for the full reference.

## HTTP API

### `POST /v1/scan`

Submit a document for analysis.

**multipart/form-data** (field `doc`):

```bash
curl -s -F "doc=@malware.xlsm" http://localhost:8080/v1/scan
```

**application/octet-stream** (raw bytes, metadata as query params):

```bash
curl -s -X POST "http://localhost:8080/v1/scan?filename=malware.xlsm" \
  --data-binary @malware.xlsm \
  -H "Content-Type: application/octet-stream"
```

**msgpack / CBOR responses** — set the `Accept` header to request a non-JSON
wire format (`application/x-msgpack` or `application/cbor`). Requires
`pip install "xspct_scan[serialization] @ git+https://github.com/HeinleinSupport/xspct_scan.git"`. The server-wide default is
controlled by `xspct_response_format`.

**zstd-compressed responses** — add `Accept-Encoding: zstd` to receive a
zstd-compressed response body (`Content-Encoding: zstd`). Requires
`pip install "xspct_scan[compression] @ git+https://github.com/HeinleinSupport/xspct_scan.git"`.

**zstd-compressed uploads** — the daemon transparently decompresses a
zstd-compressed `doc` part or octet-stream body (detected via the Zstandard
frame magic bytes). The `.zst` filename suffix is stripped before type
detection.

Example response:

```json
{
  "filename": "malware.xlsm",
  "file_hash": "sha256...",
  "detected_type": "office",
  "has_macro": true,
  "analyses": [{"type": "AutoExec", "keyword": "AutoOpen", "description": "..."}],
  "iocs": {"urls": ["https://evil.example/payload"], "ips": [], "domains": []},
  "iocs_extended": {"url": ["https://evil.example/payload"], "email": []},
  "yara_matches": [{"engine": "classic", "rule": "Eicar_Test", "tags": [], ...}],
  "pdfid_keywords": null,
  "archive_files": [],
  "exif": {},
  "text_preview": [{"source": "office", "text": "..."}],
  "analyzers_completed": ["office", "yara", "iocs"],
  "analyzers_pending": [],
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
| `/health` | GET | `{"status":"ok"}` — load-balancer check (unversioned) |
| `/ping` | GET | Returns `pong` (unversioned) |
| `/v1/metrics` | GET | Prometheus metrics |
| `/v1/openapi.json` | GET | OpenAPI 3.0 spec (requires `[openapi]`) |
| `/v1/apidoc/redoc` | GET | ReDoc UI (requires `[openapi]`) |
| `/v1/admin/reload` | POST | Live-reload config/passwords/YARA rules |

See [docs/api-http.md](docs/api-http.md) for full request/response details.

## Decrypting password-protected files

xspct_scan automatically tries to decrypt encrypted **Office and PDF** documents
using a password list loaded at startup.

### Global password list

Point `xspct_password_file` at a newline-delimited file of candidate passwords
(lines starting with `#` are ignored):

```yaml
xspct_password_file: /etc/xspct_scan/passwords.txt
```

The file is reloaded on `POST /v1/admin/reload`. If not found, a small set of
built-in defaults (`infected`, `virus`, `malware`, …) is used.

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

## YARA scanning

When YARA rules are loaded, YARA runs on **every** file — PDFs, HTML,
Office documents, images, plain text, archive members, and unknown blobs.
Two engines can run in parallel for comparison or redundancy:

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

## Sandboxed archive extraction

Install `SFlock2` (included in `[advanced]`) to enable sandboxed extraction
via **zipjail**:

```bash
# Python package
pip install "xspct_scan[advanced] @ git+https://github.com/HeinleinSupport/xspct_scan.git"

# System packages for full native-format support (Debian / Ubuntu)
sudo apt-get install p7zip-full rar unace-nonfree cabextract lzip zpaq
```

With SFlock2 installed, the following formats are extracted in-sandbox:
ZIP, 7z, RAR, TAR, TAR.GZ, TBZ2, CAB, ACE, ISO, EML, MSG, MSO, lzip, ZPAQ.
**EML and MSG** files are routed through the archive pipeline automatically
so that email attachments are extracted and analysed.

## Image OCR and QR/barcode scanning

When `[enrichment]` is installed, raster images (JPEG, PNG, GIF, BMP, TIFF,
WebP, ICO) are passed through two additional analysis steps:

1. **OCR** — Tesseract and EasyOCR both run in parallel and extract embedded
   text, which is then included in the IOC extraction pipeline (URLs, IPs,
   domains, etc.). EasyOCR tries a normal and an inverted variant and stops
   as soon as text is found.
2. **QR / barcode decode** — pyzbar decodes any QR codes or 1-D barcodes found
   in the image; decoded payloads are surfaced in `qr_codes` and added to the
   IOC results.

### System dependencies

```bash
# Debian / Ubuntu
sudo apt-get install tesseract-ocr libzbar0

# RHEL / Fedora
sudo dnf install tesseract zbar
```

### Enabling / disabling

```yaml
xspct_analyzers:
  image:
    enabled: true   # set to false to skip OCR and QR decode entirely
```

## SVG analysis

SVG files are XML-based vector graphics that can embed `<script>` tags, inline
event handlers (`onload`, `onclick`, …), and external references — making them
a phishing and malware delivery vector.

xspct_scan detects SVG by MIME type (`image/svg+xml`) and `.svg` extension and
routes the file through the **HTML analyzer** rather than the image pipeline.
All HTML checks apply: script extraction, CSS-hiding detection, external
resource tracking, and IOC extraction.

No additional configuration or packages are required; SVG analysis is active
whenever the HTML analyzer is enabled.

## ClamAV integration

xspct_scan can forward every scanned file (and individual archive members) to a
running `clamd` daemon for antivirus signature matching.

### Requirements

```bash
# Python library
pip install "xspct_scan[enrichment] @ git+https://github.com/HeinleinSupport/xspct_scan.git"

# ClamAV daemon (Debian / Ubuntu)
sudo apt-get install clamav-daemon
sudo systemctl enable --now clamav-daemon
```

### Configuration

```yaml
xspct_clamav:
  enabled: true
  socket: /var/run/clamav/clamd.ctl   # Unix socket (preferred); set to '' to use TCP
  host: 127.0.0.1                      # TCP host (used when socket is empty)
  port: 3310                           # TCP port
  timeout: 60                          # per-scan timeout in seconds
  max_size: 26214400                   # skip files larger than this (bytes; default 25 MB)
  scan_members: true                   # also scan individual archive members
```

When `socket` is non-empty, a Unix domain socket is used; otherwise a TCP
connection is made to `host`:`port`.

### Response fields

ClamAV results appear in the scan response under `clamav`:

```json
{
  "clamav": {
    "status": "infected",
    "signature": "Win.Trojan.Agent-12345"
  }
}
```

Possible `status` values: `clean`, `infected`, `error`, `skipped` (file
exceeds `max_size`), `disabled`.

Prometheus counters `xspct_clamav_clean`, `xspct_clamav_infected`,
`xspct_clamav_errors`, and `xspct_clamav_timeouts` track ClamAV scan outcomes
at `/v1/metrics`.

## Systemd unit

```ini
[Unit]
Description=xspct_scan malware scanner
After=network.target

[Service]
Type=simple
User=xspct-scan
ExecStart=/usr/local/bin/xspct_scan /etc/xspct_scan/config.yml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## Documentation

Full docs are in the [docs/](docs/) directory and can be built with Sphinx:

```bash
pip install "xspct_scan[docs] @ git+https://github.com/HeinleinSupport/xspct_scan.git"
sphinx-build docs docs/_build/html
```

## Licence

[EUPL-1.2](LICENSE) — © 2026 Carsten Rosenberg, Heinlein Support GmbH
