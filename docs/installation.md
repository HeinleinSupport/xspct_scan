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

## Install from PyPI

```bash
pip install xspct_scan
```

### Optional extras

| Extra | Installs | Use when |
|-------|----------|----------|
| `uvloop` | `uvloop` | Higher-throughput async event loop |
| `redis` | `redis[asyncio]` | Persistent result cache across restarts |

```bash
pip install "xspct_scan[uvloop,redis]"
```

## Install from source

```bash
git clone https://github.com/heinlein-support/xspct_scan.git
cd xspct_scan
pip install -e ".[uvloop,redis]"
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
