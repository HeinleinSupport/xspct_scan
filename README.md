# olefy_v2

[[_TOC_]]

**olefy_v2** is an async HTTP daemon that scans Office, PDF, and HTML documents
for malware indicators. It is designed to integrate with
[Rspamd](https://rspamd.com/) and other mail-security pipelines.

## Features

- **Office / OLE2** — VBA macro extraction and keyword analysis via
  [oletools](https://github.com/decalage2/oletools); decrypts password-protected
  files with [msoffcrypto-tool](https://github.com/nolze/msoffcrypto-tool)
- **PDF** — deep content analysis via [PyMuPDF](https://pymupdf.readthedocs.io/);
  extracts embedded JavaScript, URIs, and document metadata; decrypts
  password-protected PDFs using the same password list as Office files
- **HTML** — script extraction, CSS hiding detection, external resource analysis
- **RTF** — embedded object extraction via `rtfobj` (opt-in per request)
- **Dynamic JS emulation** — optional sandboxed execution with
  [quickjs](https://github.com/PetterS/quickjs) and deobfuscation with
  [jsbeautifier](https://github.com/beautify-web/js-beautify)
- **IOC extraction** — URLs, IPs, and domains harvested from all document types
- **Redis result cache** — optional; survives restarts, shared across instances
- **Prometheus metrics** — exposed at `/metrics`

## Quick start

```bash
pip install olefy_v2
olefy_v2 /etc/olefy_v2/config.yml
```

Scan a document:

```bash
curl -s -F "doc=@invoice.docx" http://localhost:8080/scan | python3 -m json.tool
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
pip install olefy_v2
```

### Optional extras

| Extra | Installs | Use when |
|-------|----------|----------|
| `uvloop` | `uvloop` | Higher-throughput async event loop |
| `redis` | `redis[asyncio]` | Persistent result cache |
| `enrichment` | `jsbeautifier`, `quickjs`, `Pillow`, `pytesseract`, `pyzbar` | Dynamic JS analysis, image OCR/barcode |

```bash
pip install "olefy_v2[uvloop,redis,enrichment]"
```

### From source

```bash
git clone https://github.com/heinlein-support/olefy_v2.git
cd olefy_v2
pip install -e ".[uvloop,redis,enrichment]"
```

## Configuration

Copy the example config and edit to suit:

```bash
cp config/olefy_v2.example.yml /etc/olefy_v2/config.yml
olefy_v2 /etc/olefy_v2/config.yml
```

Key settings:

| Key | Default | Description |
|-----|---------|-------------|
| `olefy_listen_address` | `0.0.0.0` | Bind address(es) |
| `olefy_listen_port` | `8080` | Listen port |
| `olefy_api_key` | _(empty)_ | Shared secret for `X-Api-Key` auth |
| `olefy_redis_cache.enabled` | `false` | Enable Redis result cache |
| `olefy_password_file` | | Path to wordlist for decrypting Office files |

See [docs/configuration.md](docs/configuration.md) for the full reference.

## HTTP API

### `POST /scan`

Submit a document for analysis (`multipart/form-data`, field `doc`).

```bash
curl -s -F "doc=@malware.xlsm" http://localhost:8080/scan
```

Returns a JSON report:

```json
{
  "filename": "malware.xlsm",
  "file_hash": "sha256...",
  "detected_type": "office",
  "has_macro": true,
  "analyses": [
    {"type": "AutoExec", "keyword": "AutoOpen", "description": "..."}
  ],
  "iocs": {"urls": ["https://evil.example/payload"], "ips": [], "domains": []},
  "meta_document": {"author": "John Doe", "creation_date": "2026-01-15"},
  "status": "finished",
  "time_taken": 0.18
}
```

Returns `202 Accepted` when analysis exceeds the timeout; poll with:

```bash
curl "http://localhost:8080/query?hash=sha256..."
```

### Other endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | `{"status":"ok"}` — for load-balancer checks |
| `/ping` | GET | Returns `pong` |
| `/query` | GET / POST | Retrieve result by SHA-256 hash |
| `/metrics` | GET | Prometheus metrics |

See [docs/api-http.md](docs/api-http.md) for full request/response details.

## Decrypting password-protected files

olefy_v2 automatically tries to decrypt encrypted **Office and PDF** documents
using a password list loaded at startup.

### Global password list (config)

Point `olefy_password_file` at a newline-delimited file of candidate passwords
(lines starting with `#` are ignored):

```yaml
olefy_password_file: /etc/olefy_v2/passwords.txt
```

The file is loaded once on startup. If the file is not found, a small set of
built-in defaults (`infected`, `virus`, `malware`, …) is used instead.

For PDFs, PyMuPDF's `authenticate()` API is used; for Office files,
`msoffcrypto-tool` handles decryption. Both use the same password list.

### Per-request passwords

Extra passwords can be supplied with each `/scan` request via the `passwords`
field. They are tried **before** the global list and work for both Office and PDF files:

```bash
# comma-separated
curl -s \
  -F "doc=@protected.xlsx" \
  -F "passwords=Secret123,CompanyPass" \
  http://localhost:8080/scan

# PDF example
curl -s \
  -F "doc=@invoice.pdf" \
  -F "passwords=Secret123,CompanyPass" \
  http://localhost:8080/scan

# newline-separated (useful for many passwords)
curl -s \
  -F "doc=@protected.xlsx" \
  -F $'passwords=Secret123\nCompanyPass\nQ1-2026' \
  http://localhost:8080/scan
```

When decryption succeeds, the response includes:

```json
{
  "decrypted": true,
  "decryption_password": "Secret123",
  ...
}
```

## Systemd unit

```ini
[Unit]
Description=olefy_v2 malware scanner
After=network.target

[Service]
Type=simple
User=olefy
ExecStart=/usr/local/bin/olefy_v2 /etc/olefy_v2/config.yml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## Documentation

Full docs are in the [docs/](docs/) directory and can be built with Sphinx:

```bash
pip install "olefy_v2[docs]"
sphinx-build docs docs/_build/html
```

## Licence

[EUPL-1.2](LICENSE) — © 2026 Carsten Rosenberg, Heinlein Support GmbH
