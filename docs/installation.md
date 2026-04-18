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
pip install olefy_v2
```

### Optional extras

| Extra | Installs | Use when |
|-------|----------|----------|
| `uvloop` | `uvloop` | Higher-throughput async event loop |
| `redis` | `redis[asyncio]` | Persistent result cache across restarts |

```bash
pip install "olefy_v2[uvloop,redis]"
```

## Install from source

```bash
git clone https://github.com/heinlein-support/olefy_v2.git
cd olefy_v2
pip install -e ".[uvloop,redis]"
```

## Running

```bash
# With a config file
olefy_v2 /etc/olefy_v2/config.yml

# With defaults (listens on 0.0.0.0:8080)
olefy_v2
```

Alternatively, run as a module:

```bash
python -m olefy_v2 /etc/olefy_v2/config.yml
```

## Systemd unit (example)

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
