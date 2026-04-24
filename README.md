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
- **HTML** — script extraction, CSS-hiding detection, external resource tracking
- **RTF** — embedded object extraction via `rtfobj` (opt-in per request)
- **Dynamic JS emulation** — sandboxed execution with
  [quickjs](https://github.com/PetterS/quickjs) and deobfuscation with
  [jsbeautifier](https://github.com/beautify-web/js-beautify) (optional)

### Enrichment
- **IOC extraction** — URLs, IPs, and domains from all document types
- **Extended IOCs** — email addresses, file hashes, CVE IDs, and more via
  [iocsearcher](https://github.com/malicialab/iocsearcher) (optional)
- **YARA scanning** — static signature matching via
  [yara-python](https://github.com/VirusTotal/yara-python) (classic engine,
  optional Hyperscan acceleration) and/or
  [yara-x](https://github.com/VirusTotal/yara-x) (Rust rewrite); both engines
  can run simultaneously for comparison
- **Image analysis** — OCR via [pytesseract](https://github.com/madmaze/pytesseract),
  QR/barcode decode via [pyzbar](https://github.com/NaturalHistoryMuseum/pyzbar),
  EXIF metadata extraction with GPS flagging (optional)
- **Archive extraction** — ZIP and 7z with configurable depth/size limits,
  password loop for encrypted archives, recursive sub-file analysis

### Infrastructure
- **Parallel pipeline** — analyzers run as concurrent asyncio tasks; partial
  results returned on timeout (`202 Accepted`) with `analyzers_completed` /
  `analyzers_pending` fields
- **Redis result cache** — optional; survives restarts, shared across instances
- **Prometheus metrics** — exposed at `/metrics`
- **OpenAPI 3.0** — spec at `/openapi.json`; ReDoc UI at `/apidoc/redoc`
- **Admin API** — live reload of config / passwords / YARA rules via
  `POST /admin/reload`
- **API key auth** — per-header key with rotation support; separate admin key

## Quick start

```bash
pip install xspct_scan
xspct_scan /etc/xspct_scan/config.yml
```

Scan a document:

```bash
curl -s -F "doc=@invoice.docx" http://localhost:8080/scan | python3 -m json.tool
```

Or upload raw bytes:

```bash
curl -s -X POST http://localhost:8080/scan \
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

### From PyPI

```bash
pip install xspct_scan
```

### Optional extras

| Extra | Installs | Use when |
|-------|----------|----------|
| `uvloop` | `uvloop` | Higher-throughput async event loop |
| `redis` | `redis[asyncio]` | Persistent result cache across restarts |
| `enrichment` | `Pillow`, `pytesseract`, `pyzbar`, `jsbeautifier`, `quickjs` | Image OCR/barcode/EXIF, dynamic JS analysis |
| `openapi` | `pydantic>=2.0` | OpenAPI 3.0 spec + ReDoc UI |
| `advanced` | `yara-python`, `yara-x`, `iocsearcher`, `py7zr` | YARA scanning, extended IOCs, 7z archives |

```bash
pip install "xspct_scan[uvloop,redis,enrichment,openapi,advanced]"
```

### From source

```bash
git clone https://github.com/heinlein-support/xspct_scan.git
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
| `xspct_admin_api_key` | _(empty)_ | Key for `POST /admin/reload` |
| `xspct_redis_cache.enabled` | `false` | Enable Redis result cache |
| `xspct_password_file` | | Path to wordlist for decrypting encrypted files |
| `xspct_analyzers` | _(all enabled)_ | Per-analyzer enable/disable + options |
| `xspct_include_text` | `false` | Include full extracted text in reports |
| `xspct_archive_max_depth` | `2` | Recursion limit for archive extraction |

See [docs/configuration.md](docs/configuration.md) for the full reference.

## HTTP API

### `POST /scan`

Submit a document for analysis.

**multipart/form-data** (field `doc`):

```bash
curl -s -F "doc=@malware.xlsm" http://localhost:8080/scan
```

**application/octet-stream** (raw bytes, metadata as query params):

```bash
curl -s -X POST "http://localhost:8080/scan?filename=malware.xlsm" \
  --data-binary @malware.xlsm \
  -H "Content-Type: application/octet-stream"
```

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
  "text_preview": "...",
  "analyzers_completed": ["office", "yara", "iocs"],
  "analyzers_pending": [],
  "status": "finished",
  "time_taken": 0.18
}
```

Returns `202 Accepted` when analysis exceeds the configured timeout.
Poll `/query?hash=<sha256>` for the result:

```bash
curl "http://localhost:8080/query?hash=sha256..."
```

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/scan` | POST | Submit file for analysis |
| `/query` | GET / POST | Retrieve result by SHA-256 hash |
| `/health` | GET | `{"status":"ok"}` — load-balancer check |
| `/ping` | GET | Returns `pong` |
| `/metrics` | GET | Prometheus metrics |
| `/openapi.json` | GET | OpenAPI 3.0 spec (requires `[openapi]`) |
| `/apidoc/redoc` | GET | ReDoc UI (requires `[openapi]`) |
| `/admin/reload` | POST | Live-reload config/passwords/YARA rules |

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

The file is reloaded on `POST /admin/reload`. If not found, a small set of
built-in defaults (`infected`, `virus`, `malware`, …) is used.

### Per-request passwords

Extra passwords supplied with the request are tried **before** the global list:

```bash
curl -s \
  -F "doc=@protected.xlsx" \
  -F "passwords=Secret123,CompanyPass" \
  http://localhost:8080/scan
```

When decryption succeeds the response includes `"decrypted": true` and
`"decryption_password": "Secret123"`.

## YARA scanning

Two YARA engines can run in parallel for comparison or redundancy:

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
`"yara-x"`). Reload rules without restart with `POST /admin/reload`.

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
pip install "xspct_scan[docs]"
sphinx-build docs docs/_build/html
```

## Licence

[EUPL-1.2](LICENSE) — © 2026 Carsten Rosenberg, Heinlein Support GmbH
