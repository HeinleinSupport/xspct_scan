# Configuration

xspct_scan is configured via a YAML file passed as the first argument.
All keys are optional — built-in defaults are used for any key that is absent.

## Minimal example

```yaml
xspct_listen_port: 8080
xspct_log_level: 20
```

## Full reference

### Network

| Key | Default | Description |
|-----|---------|-------------|
| `xspct_listen_address` | `0.0.0.0` | IP address(es) to listen on. Accept a string or a YAML list. |
| `xspct_listen_port` | `8080` | TCP port. |
| `xspct_listen_backlog` | `256` | Socket listen backlog. |

### Logging

| Key | Default | Description |
|-----|---------|-------------|
| `xspct_log_level` | `20` | Python log level integer (`10`=DEBUG, `20`=INFO, `30`=WARNING, `40`=ERROR). |
| `xspct_log_prefix` | `xspct-scan` | Logger name used in log output. |

### Authentication

(authentication)=

API key authentication is disabled by default. When `xspct_api_key` is set, all
requests to `/scan`, `/query`, and `/metrics` must include the key in the header
named by `xspct_api_header`.

| Key | Default | Description |
|-----|---------|-------------|
| `xspct_api_header` | `X-Api-Key` | HTTP request header that carries the API key. |
| `xspct_api_key` | `` | API key string, or a YAML list of keys (for rotation). Empty = auth disabled. |
| `xspct_api_key_verify_fail` | `true` | When `true`, requests with a wrong key return `401`. When `false`, they are allowed through. |

Example with key rotation:

```yaml
xspct_api_key:
  - 'current-secret-key'
  - 'old-secret-key-during-rotation'
```

### Rspamd integration

| Key | Default | Description |
|-----|---------|-------------|
| `xspct_rspamd_header` | `X-Rspamd-ID` | Request header used to correlate scan requests with Rspamd task IDs. |

### TLS

| Key | Default | Description |
|-----|---------|-------------|
| `xspct_tls.tls_enabled` | `false` | Enable TLS termination. |
| `xspct_tls.tls_cert` | `` | Path to PEM certificate file. |
| `xspct_tls.tls_key` | `` | Path to PEM private key file. |

### Redis result cache

Requires the `redis` extra (`pip install "xspct_scan[redis]"`).

| Key | Default | Description |
|-----|---------|-------------|
| `xspct_redis_cache.enabled` | `false` | Enable the Redis cache. |
| `xspct_redis_cache.host` | `localhost` | Redis host. |
| `xspct_redis_cache.port` | `6379` | Redis port. |
| `xspct_redis_cache.user` | `` | Redis ACL username (Redis 6+). |
| `xspct_redis_cache.password` | `` | Redis password. |
| `xspct_redis_cache.prefix` | `xspct:` | Key prefix for all cached entries. |
| `xspct_redis_cache.expire` | `3600` | TTL in seconds for cached results. |
| `xspct_redis_cache.max_errors` | `3` | Circuit-breaker: disable cache after this many consecutive errors. |

### Statistics

| Key | Default | Description |
|-----|---------|-------------|
| `xspct_stats_enabled` | `true` | Log runtime counters periodically. |
| `xspct_stats_interval` | `60` | Interval in seconds between stats log lines. |

### Password list

| Key | Default | Description |
|-----|---------|-------------|
| `xspct_password_file` | `10k-most-common.txt` | Path to a newline-delimited password list used when attempting to decrypt encrypted Office documents. Lines starting with `#` are ignored. |
