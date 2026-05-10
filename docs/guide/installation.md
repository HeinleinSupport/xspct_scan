# Installation

## Requirements

- Python 3.10 or newer
- `libmagic` (system library used by python-magic)

  ```bash
  # Debian / Ubuntu
  sudo apt-get install libmagic1

  # RHEL / Fedora
  sudo dnf install file-libs
  ```

## Install from GitHub

```bash
pip install "git+https://github.com/HeinleinSupport/xspct_scan.git"
```

### Optional extras

| Extra | Installs | Use when |
|-------|----------|----------|
| `uvloop` | `uvloop` | Higher-throughput async event loop |
| `redis` | `redis[asyncio]` | Persistent result cache across restarts |
| `enrichment` | `Pillow`, `pytesseract`, `pyzbar`, `jsbeautifier`, `quickjs` | Image OCR / barcode / EXIF, dynamic JS analysis |
| `openapi` | `pydantic>=2.0` | OpenAPI 3.0 spec at `/openapi.json` + ReDoc UI |
| `advanced` | `yara-python`, `yara-x`, `iocsearcher`, `py7zr` | YARA scanning (classic + Rust engines), extended IOC extraction, 7z archive support |

```bash
pip install "xspct_scan[uvloop,redis,enrichment,openapi,advanced] @ git+https://github.com/HeinleinSupport/xspct_scan.git"
```

## Install from source

```bash
git clone https://github.com/HeinleinSupport/xspct_scan.git
cd xspct_scan
pip install -e ".[uvloop,redis,enrichment,openapi,advanced]"
```

## Running

```bash
# With a config file
xspct_scan /etc/xspct_scan/config.yml

# With defaults (listens on 0.0.0.0:8080)
xspct_scan
```

Alternatively, run as a module:

```bash
python -m xspct_scan /etc/xspct_scan/config.yml
```

## Systemd unit (example)

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
