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

Each stats interval emits three types of log lines:

- **`STATS`** — global counters in `total(+delta)` format so that a quiet
  period shows `(+0)` rather than repeating the same lifetime totals.
- **`SLOTS`** — instantaneous foreground/background slot fill-rate
  (`fg=used/total(%)`) plus per-interval deltas for rejection counters.
- **`ANALYZER`** — per-analyzer call counts, hit rates, and timing
  averaged over the current interval window only.

### Password list

| Key | Default | Description |
|-----|---------|-------------|
| `xspct_password_file` | `10k-most-common.txt` | Path to a newline-delimited password list used when attempting to decrypt encrypted Office documents. Lines starting with `#` are ignored. |

### Analyzer toggles

Each analyzer can be individually enabled or disabled. YARA requires the
`advanced` extra and a `rules_path`.

```yaml
xspct_analyzers:
  pdf:        { enabled: true }
  html:       { enabled: true }
  office:     { enabled: true }
  image:
    enabled: true
    ocr_max_bytes:   2097152   # skip OCR for files > 2 MB (camera JPEGs)
    ocr_max_pixels:  4000000   # skip OCR for images > 4 megapixels
    ocr_skip_camera: true      # skip OCR when EXIF Make/Model present
  archive:    { enabled: true }
  text:       { enabled: true }
  script:     { enabled: true }   # standalone .vbs/.vbe/.js/.jse/.wsf/.wsh/.ps1/.bat/.cmd
  iocs:       { enabled: true }
  javascript: { enabled: true, quickjs: false }
  yara:       { enabled: false, rules_path: '' }
  yara_x:     { enabled: false, rules_path: '' }
```

| Key | Default | Description |
|-----|---------|-------------|
| `xspct_analyzers.<name>.enabled` | `true` | Enable/disable the named analyzer. |
| `xspct_analyzers.javascript.quickjs` | `false` | Enable sandboxed JS emulation via QuickJS. Disabled by default because it adds significant per-request CPU time. Set to `true` to activate (requires the `enrichment` extra). |
| `xspct_analyzers.yara.rules_path` | `` | Path to a YARA rules file or directory. Required when `yara.enabled` is `true`. |
| `xspct_analyzers.yara_x.rules_path` | `` | Same as above for the yara-x engine. |

#### Image OCR exclusion gates

Large natural-photo images (camera JPEGs, scanned pages) can take minutes in
OCR.  These gates skip OCR automatically when the image is unlikely to contain
document text.  Set any gate to `0` to disable it.

| Key | Default | Description |
|-----|---------|-------------|
| `xspct_analyzers.image.ocr_max_bytes` | `2097152` | Skip OCR when the raw file exceeds this many bytes (2 MiB). Camera JPEGs are typically 3–15 MB; phishing screenshots and QR images are usually <500 KB. |
| `xspct_analyzers.image.ocr_max_pixels` | `4000000` | Skip OCR when `width × height` exceeds this value (4 MP = 2000×2000). |
| `xspct_analyzers.image.ocr_skip_camera` | `true` | Skip OCR when EXIF tags `Make` or `Model` are present, indicating a camera photo rather than a document scan or screenshot. |

When a gate triggers the reason is reported in `scan.exclusions`:

```json
"scan": {
  "exclusions": {
    "image.ocr": "camera photo detected via EXIF (OnePlus/OnePlus 12)"
  }
}
```

To override a gate for a single request use `?force_analyzers=image.ocr`
(API) or `--force-ocr` / `--force-analyzers image.ocr` (CLI).

The **`text`** analyzer handles files detected as `text/plain`, ASCII, UTF-8, or any
script not matched by the other analyzers.  It decodes the content, populates
`text_preview`, and extracts baseline IOCs.  YARA and iocsearcher then run on
the same bytes/text in parallel.

When YARA rules are loaded, YARA runs on **every** file regardless of type —
PDFs, images, Office documents, plain text, and unknown blobs.  In the
synchronous sub-pipeline (used for files inside archives), YARA is invoked
after the primary type-specific analyzer and its hits are merged into the
report.  Each archive member is individually YARA-scanned, including images
and unknown blobs.

### Text extraction

| Key | Default | Description |
|-----|---------|-------------|
| `xspct_include_text_preview` | `true` | When `true`, the `text_preview` field (a list of `{source, text}` segments) is included in scan reports. |
| `xspct_include_text_full` | `false` | When `true`, the `text_full` field (a list of `{source, text}` segments) is included in scan reports. |
| `xspct_text_preview_length` | `2000` | Maximum characters per `text_preview` segment — the short excerpt included in every response. |
| `xspct_text_max_length` | `50000` | Maximum characters per extracted-text segment. Used by iocsearcher and (when `xspct_include_text_full` is `true`) for `text_full`. Higher values improve IOC recall on long documents at the cost of more memory and CPU per scan. |

### Response serialization

| Key | Default | Description |
|-----|---------|-------------|
| `xspct_response_format` | `auto` | Wire format for scan and query responses. `auto` negotiates via the `Accept` request header (first of `application/json`, `application/x-msgpack`, `application/cbor` wins, default `json`). Set to `json`, `msgpack`, or `cbor` to force a fixed format regardless of client headers. Msgpack and CBOR require `pip install "xspct_scan[serialization]"`. |

### Archive analysis

| Key | Default | Description |
|-----|---------|-------------|
| `xspct_archive_max_depth` | `2` | Maximum recursion depth when extracting nested archives. Set to `0` to disable. |
| `xspct_archive_max_size` | `52428800` | Maximum total bytes to extract from a single archive (default 50 MiB). |

**Extraction backend** — when `SFlock2` is installed (included in the
`advanced` extra), all archive extraction runs inside the **zipjail** usermode
sandbox.  Supported formats include ZIP, 7z, RAR, TAR/TAR.GZ/TBZ2, CAB, ACE,
ISO, EML, MSG, MSO, lzip, and ZPAQ.  Without SFlock2 the fallback uses
stdlib `zipfile` (ZIP) and optional `py7zr` (7z).

Installing sflock2 and enabling full format support:

```bash
# Python package (included in the advanced extra)
pip install "xspct_scan[advanced]"

# System packages for native-format support on Debian / Ubuntu
apt-get install p7zip-full rar unace-nonfree cabextract lzip zpaq
```

**EML and MSG files** are routed through the archive pipeline (not the
office pipeline) so that sflock2 can extract their attachments in-sandbox.
Each extracted attachment is analysed individually with the normal type
detection logic.

Each extracted member is routed through the same type-detection logic as a
top-level file.  All member types — PDF, HTML, Office, text, image, and
unknown — are individually analysed.  When YARA rules are loaded every
member is YARA-scanned regardless of type.  Results are merged into the
top-level archive report via `yara_matches`, `iocs`, `iocs_extended`, and
`analyses`.

### Partial / in-progress reports

| Key | Default | Description |
|-----|---------|-------------|
| `xspct_cache_partial` | `false` | When `true`, partial (in-progress) reports are written to the Redis cache so that polling clients see incremental results. |

### Two-tier concurrency

xspct_scan separates concurrent capacity into two pools to prevent a
feedback loop where slow background scans starve new foreground requests.

| Key | Default | Description |
|-----|---------|-------------|
| `xspct_foreground_slots` | `16` | Maximum scans that may run while a client connection is open. When all slots are taken a new request waits up to its `timeout` seconds; if still no slot it receives `503 Service Unavailable`. |
| `xspct_background_slots` | `4` | Maximum scans that continue after returning `202`. When a scan times out and no background slot is immediately available the scan is cancelled and the response carries `"status": "dropped"`. |

**Sizing rule:** `foreground_slots + background_slots` should not exceed the
thread capacity of downstream workers (e.g. `clamd MaxThreads`).  Start with
an 80/20 split and tune using these metrics:

| Metric | Type | High value means |
|--------|------|------------------|
| `xspct_foreground_overloaded` | counter | Increase `foreground_slots` or reduce per-scan latency |
| `xspct_background_rejected` | counter | Increase `background_slots` or investigate which file types are slow |
| `xspct_background_completed` | counter | Background scans finishing — useful baseline for business case |
| `xspct_background_errors` | counter | Background scan exceptions — check logs |
| `xspct_foreground_slots_total` | gauge | Configured foreground capacity |
| `xspct_foreground_slots_free` | gauge | Should be close to `foreground_slots` under normal load |
| `xspct_foreground_slots_used` | gauge | Instantaneous in-use foreground slots (`total − free`) |
| `xspct_background_slots_total` | gauge | Configured background capacity |
| `xspct_background_slots_free` | gauge | Available background slots |
| `xspct_background_slots_used` | gauge | Instantaneous in-use background slots |

### IOC URL / domain exclusion list

| Key | Default | Description |
|-----|---------|-------------|
| `xspct_ioc_url_exclude_domains` | *(see below)* | List of domain suffixes to exclude from IOC extraction. Applies to both `iocs` (regex-based) and `iocs_extended` (iocsearcher). |

URLs and domains whose hostname **equals** an excluded entry or is a
**subdomain** of it are silently dropped from the `urls`, `domains`,
`fqdn`, and `url` fields in every report.  This prevents schema-namespace
references (e.g. `http://www.w3.org/1999/xhtml`) and other boilerplate
from polluting the IOC output.

**Built-in defaults:**

```yaml
xspct_ioc_url_exclude_domains:
  - w3.org
  - schema.org
  - schemas.microsoft.com
  - schemas.openxmlformats.org
  - purl.org
  - dublincore.org
  - xmlsoap.org
  - ns.adobe.com
  - creativecommons.org
  - opengis.net
```

To extend the list, override the key in your config file — the entire list is
replaced, so include the defaults you want to keep:

```yaml
xspct_ioc_url_exclude_domains:
  - w3.org
  - schema.org
  - schemas.microsoft.com
  - schemas.openxmlformats.org
  - purl.org
  - dublincore.org
  - xmlsoap.org
  - ns.adobe.com
  - creativecommons.org
  - opengis.net
  # site-specific additions:
  - cdn.example.com
  - tracking-allowed-domain.internal
```

To disable filtering entirely, set the list to an empty sequence:

```yaml
xspct_ioc_url_exclude_domains: []
```

### Admin API

| Key | Default | Description |
|-----|---------|-------------|
| `xspct_admin_api_key` | `[]` | API key(s) required for `POST /admin/reload`. Empty = admin API disabled. Accept a string or a YAML list. |
