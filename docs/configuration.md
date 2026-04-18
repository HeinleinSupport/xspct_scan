# Configuration

olefy_v2 is configured via a YAML file passed as the first argument.
All keys are optional — built-in defaults are used for any key that is absent.

## Minimal example

```yaml
olefy_listen_port: 8080
olefy_log_level: 20
```

## Full reference

### Network

| Key | Default | Description |
|-----|---------|-------------|
| `olefy_listen_address` | `0.0.0.0` | IP address(es) to listen on. Accept a string or a YAML list. |
| `olefy_listen_port` | `8080` | TCP port. |
| `olefy_listen_backlog` | `256` | Socket listen backlog. |

### Logging

| Key | Default | Description |
|-----|---------|-------------|
| `olefy_log_level` | `20` | Python log level integer (`10`=DEBUG, `20`=INFO, `30`=WARNING, `40`=ERROR). |
| `olefy_log_prefix` | `olefy` | Logger name used in log output. |

### Authentication

(authentication)=

API key authentication is disabled by default. When `olefy_api_key` is set, all
requests to `/scan`, `/query`, and `/metrics` must include the key in the header
named by `olefy_api_header`.

| Key | Default | Description |
|-----|---------|-------------|
| `olefy_api_header` | `X-Api-Key` | HTTP request header that carries the API key. |
| `olefy_api_key` | `` | API key string, or a YAML list of keys (for rotation). Empty = auth disabled. |
| `olefy_api_key_verify_fail` | `true` | When `true`, requests with a wrong key return `401`. When `false`, they are allowed through. |

Example with key rotation:

```yaml
olefy_api_key:
  - 'current-secret-key'
  - 'old-secret-key-during-rotation'
```

### Rspamd integration

| Key | Default | Description |
|-----|---------|-------------|
| `olefy_rspamd_header` | `X-Rspamd-ID` | Request header used to correlate scan requests with Rspamd task IDs. |

### TLS

| Key | Default | Description |
|-----|---------|-------------|
| `olefy_tls.tls_enabled` | `false` | Enable TLS termination. |
| `olefy_tls.tls_cert` | `` | Path to PEM certificate file. |
| `olefy_tls.tls_key` | `` | Path to PEM private key file. |

### Redis result cache

Requires the `redis` extra (`pip install "olefy_v2[redis]"`).

| Key | Default | Description |
|-----|---------|-------------|
| `olefy_redis_cache.enabled` | `false` | Enable the Redis cache. |
| `olefy_redis_cache.host` | `localhost` | Redis host. |
| `olefy_redis_cache.port` | `6379` | Redis port. |
| `olefy_redis_cache.user` | `` | Redis ACL username (Redis 6+). |
| `olefy_redis_cache.password` | `` | Redis password. |
| `olefy_redis_cache.prefix` | `olefy:` | Key prefix for all cached entries. |
| `olefy_redis_cache.expire` | `3600` | TTL in seconds for cached results. |
| `olefy_redis_cache.max_errors` | `3` | Circuit-breaker: disable cache after this many consecutive errors. |

### Statistics

| Key | Default | Description |
|-----|---------|-------------|
| `olefy_stats_enabled` | `true` | Log runtime counters periodically. |
| `olefy_stats_interval` | `60` | Interval in seconds between stats log lines. |

### Password list

| Key | Default | Description |
|-----|---------|-------------|
| `olefy_password_file` | `10k-most-common.txt` | Path to a newline-delimited password list used when attempting to decrypt encrypted Office documents. Lines starting with `#` are ignored. |
