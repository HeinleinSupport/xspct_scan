# HTTP API

All endpoints return JSON unless stated otherwise.
Authentication (when enabled) is via the `X-Api-Key` header — see
[Authentication](authentication).

All API endpoints are versioned under the `/v1/` prefix.
Health-check endpoints (`/health`, `/ping`) are unversioned.

## Endpoints

### `GET /health`

Returns `200 OK` with `{"status": "ok"}`. No authentication required.
Used for load-balancer health checks. This endpoint is **unversioned**.

```bash
curl http://localhost:8080/health
```

```json
{"status": "ok"}
```

---

### `GET /ping`

Returns `200 OK` with the plain text body `pong`. No authentication required.
This endpoint is **unversioned**.

---

### `POST /v1/scan`

Submit a document for malware analysis.

**Request** — `multipart/form-data` **or** `application/octet-stream`

*multipart/form-data fields*

| Field | Required | Description |
|-------|----------|-------------|
| `doc` | ✓ | The file to scan (any filename). |
| `file_mime` | | Override the detected MIME type. |
| `file_type` | | Override the detected file description string. |
| `passwords` | | Comma- or newline-separated passwords to try when decrypting encrypted Office **or PDF** files. Custom passwords are tried before the daemon-wide list. |

*application/octet-stream*: send raw file bytes as the request body.
Pass optional metadata as query parameters (`filename`, `file_mime`, `file_type`,
`passwords`).

**Query parameters**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `timeout` | `10` | Max seconds to wait for analysis before returning `202`. |
| `rtf` | `false` | Set to `true` to enable RTF object extraction via `rtfobj`. |
| `force_analyzers` | | Comma-separated analyzer paths to bypass exclusion gates (e.g. `image.ocr`). |

`detected_type` (inside `file.type`) will be one of: `pdf`, `html`, `office`,
`odf`, `image`, `archive`, `text`, or `unknown`.

**Response `200 OK`** — analysis finished within timeout.

All responses since v2.0 follow a structured, grouped schema (`schema_version: "2.0"`).
Sections are **omitted when empty** (no null/empty noise).

```json
{
  "schema_version": "2.0",
  "engine": { "name": "xspct-scan", "version": "0.5.0" },

  "file": {
    "name": "invoice.docx",
    "sha256": "sha256hex...",
    "size": 48291,
    "mime": "application/vnd.openxmlformats-officedocument...",
    "magic": "Microsoft Word 2007+",
    "type": "office"
  },

  "scan": {
    "status": "finished",
    "duration_s": 0.123,
    "cache_hit": false,
    "analyzers": {
      "completed": ["office", "yara", "iocs"],
      "pending": [],
      "timings_s": { "office": 0.08, "yara": 0.03, "iocs": 0.01 }
    }
  },

  "verdict": {
    "score": null,
    "severity": "unknown",
    "labels": [],
    "summary": null,
    "contributors": {}
  },

  "flags": {
    "macros": true
  },

  "iocs": {
    "urls": [
      { "value": "https://malware.example.com/payload", "source": "scanner", "confidence": "high" }
    ],
    "domains": [
      { "value": "malware.example.com", "source": "iocsearcher", "confidence": "high" }
    ]
  },

  "findings": [
    { "type": "AutoExec", "keyword": "AutoOpen", "description": "...", "severity": "medium", "source": "scanner" }
  ],

  "content": {
    "preview": [ { "source": "office", "text": "Dear customer..." } ]
  },

  "document": {
    "author": "John Doe",
    "title": "Q1 Invoice",
    "created": "2026-01-15T12:00:00Z"
  },

  "engines": {
    "clamav": { "status": "clean", "scan_time_s": 0.012 },
    "yara":   { "matches": [] }
  },

  "status": "finished",
  "time_taken": 0.123
}
```

### Response schema reference

#### Always-present top-level keys

| Key | Type | Description |
|-----|------|-------------|
| `schema_version` | string | `"2.0"` |
| `engine` | object | `{name, version}` — scan engine identity |
| `file` | object | File identity — see below |
| `scan` | object | Lifecycle and analyzer bookkeeping — see below |
| `verdict` | object | Aggregated risk assessment — see below |
| `flags` | object | Content indicators that are `true` (empty when nothing flagged) |
| `iocs` | object | Rich IOC entries grouped by type (omitted when empty) |
| `status` | string | `finished` / `processing` / `dropped` / `error` |
| `time_taken` | float | Wall-clock seconds from request receipt to response |

#### `file`

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | URL-decoded filename |
| `sha256` | string | SHA-256 hex digest |
| `sha1` | string | SHA-1 hex digest |
| `rspamd_digest` | string | Rspamd-compatible keyed BLAKE2b-512 digest (matches `part->digest` in Rspamd's MIME parser) |
| `size` | int | File size in bytes |
| `mime` | string/null | libmagic MIME type |
| `magic` | string/null | libmagic description |
| `type` | string | `pdf`\|`html`\|`office`\|`odf`\|`image`\|`archive`\|`text`\|`unknown` |
| `resolution` | string | `WxH` pixel dimensions for image files; absent for other types |

#### `scan`

| Key | Type | Description |
|-----|------|-------------|
| `status` | string | Same as top-level `status` |
| `duration_s` | float | Analysis pipeline duration |
| `cache_hit` | bool | `true` when report served from Redis |
| `analyzers.completed` | list | Analyzer names that finished |
| `analyzers.pending` | list | Analyzer names still running (non-empty in `202` only) |
| `analyzers.timings_s` | object | `{analyzer: seconds}` |
| `analyzers.errors` | object | Present only when ≥1 analyzer errored |

`scan.exclusions` is present when at least one analyzer gate was triggered:

| Key | Description |
|-----|-------------|
| `image.ocr` | OCR was skipped; value is a human-readable reason. Override with `?force_analyzers=image.ocr`. |

#### `verdict`

| Key | Type | Description |
|-----|------|-------------|
| `score` | int/null | 0–100 risk score; `null` until scoring is configured |
| `severity` | string | `unknown`\|`clean`\|`low`\|`medium`\|`high`\|`critical` |
| `labels` | list | Taxonomy labels (e.g. `phishing`, `macro`, `redirect`) |
| `summary` | string/null | Human-readable one-liner |
| `contributors` | object | Signal-to-weight breakdown of the score |

#### `flags`

Only keys whose value is `true` are emitted:
`encrypted`, `decrypted`, `decryption_password` (string), `macros`, `javascript`,
`open_action`, `launch`, `embedded_files`, `forms`, `scripts`, `iframes`, `meta_refresh`.

#### `iocs`

Only non-empty type arrays are present.
Possible type keys: `urls`, `domains`, `ips`, `emails`, `hashes`, `cves`, `wallets`, `onions`, `phones`.

Each entry:

| Key | Type | Description |
|-----|------|-------------|
| `value` | string | The IOC value |
| `source` | string | Producing extractor: `scanner` (regex), `iocsearcher`, or a segment source |
| `confidence` | string | `high`\|`medium`\|`low` (scanner domains start `medium`; iocsearcher upgrades to `high`) |
| `defanged` | string | Optional defanged form (`hxxp://…`) |
| `context` | string | Optional surrounding text snippet |

#### `findings` (present when non-empty)

| Key | Type | Description |
|-----|------|-------------|
| `type` | string | e.g. `AutoExec`, `SuspiciousJS`, `ClamAV`, `OCRUrl` |
| `keyword` | string | Short keyword |
| `description` | string | Human-readable detail |
| `severity` | string | `info`\|`low`\|`medium`\|`high`\|`critical` |
| `source` | string | Producing analyzer |
| `confidence` | string | Optional |

#### `content` (present when non-empty and enabled by config)

| Key | Type | Description |
|-----|------|-------------|
| `preview` | list | `[{source, text}]` truncated to `xspct_text_preview_length` per segment |
| `full` | list | `[{source, text}]` up to `xspct_text_max_length`; requires `xspct_include_text_full: true` |

Segment `source` values: `pdf`, `pdf-image`, `office`, `office-macro`, `odf`, `odf-macro`, `odf-image`, `html`, `html-image`, `ooxml-image`, `text`, `image-ocr`, `image-qr`.

#### `document` (present when ≥1 field is non-empty)

Document metadata.  Dates are **ISO-8601** (e.g. `"2026-04-30T04:14:51Z"`).
Possible keys: `title`, `author`, `subject`, `keywords`, `creator`, `producer`,
`last_saved_by`, `company`, `app_name`, `revision`, `created`, `modified`, `encryption`.

#### `engines` (present when ≥1 engine produced output)

| Sub-key | Shape | Notes |
|---------|----------|-------|
| `clamav` | `{status, viruses[], engine_version?, db_version?, db_date?, scan_time_s}` | Always present when enabled |
| `yara` | `{matches: [{engine, rule, namespace, tags[], meta{}, strings[]}]}` | Only when matches ≥1 |
| `pdfid` | `{keywords{}, meta{}?}` | Non-zero keyword counts only |
| `archive` | `{files: [{name, size, detected_type, analyzers_run[], findings}]}` | Archives only |
| `image` | `{exif{}?}` | Images/embedded images |
| `rtf` | `{objects: [{is_ole, class_name, oledata_md5, is_package}]}` | RTF only |

**Response `202 Accepted`** — analysis still running (timeout exceeded).
The partial report snapshot (v1 internal structure) is returned alongside
bookkeeping fields.  Poll `/v1/query?hash=<sha256>` for the finished v2 report.

```json
{
  "status": "processing",
  "file_hash": "sha256hex...",
  "message": "Analysis is continuing in background",
  "time_taken": 10.0,
  "analyzers_completed": ["office"],
  "analyzers_pending": ["iocs", "yara"]
}
```

**Response `400 Bad Request`** — no `doc` field in the request.

**Response `415 Unsupported Media Type`** — Content-Type is neither
`multipart/form-data` nor `application/octet-stream`.

---

### `GET /v1/query?hash=<sha256>`

### `POST /v1/query`

Retrieve a previously submitted scan result by its SHA-256 hash.

**GET** — pass hash as a query parameter:

```bash
curl "http://localhost:8080/v1/query?hash=sha256hex..."
```

**POST** — pass hash as a JSON body:

```bash
curl -s -X POST http://localhost:8080/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"hash": "sha256hex..."}'
```

**Response `200 OK`** — the scan report wrapped in `{status, report}`:

```json
{
  "status": "finished",
  "report": { ... }  // v2 report (same schema as /v1/scan response)
}
```

When the scan is still running: `{"status": "processing"}` (partial fields included).

**Response `404 Not Found`** — hash not in cache or in-memory results.

**Response `400 Bad Request`** — no hash provided.

---

### `GET /v1/metrics`

Prometheus-compatible counter/gauge text exposition.

```
# HELP xspct_requests_total Total scan requests received
# TYPE xspct_requests_total counter
xspct_requests_total 42
# HELP xspct_requests_finished Scan requests completed within timeout
# TYPE xspct_requests_finished counter
xspct_requests_finished 40
...
```

| Metric | Type | Description |
|--------|------|-------------|
| `xspct_requests_total` | counter | Total `/v1/scan` requests received |
| `xspct_requests_finished` | counter | Scans completed within timeout |
| `xspct_requests_timeout` | counter | Scans that returned `202` |
| `xspct_redis_hits` | counter | Redis cache hits |
| `xspct_redis_misses` | counter | Redis cache misses |
| `xspct_redis_errors` | counter | Redis errors |
| `xspct_tasks_in_memory` | gauge | Current in-memory task/report entries |

---

### `POST /v1/admin/reload`

Reload the configuration file, password list, and YARA rules without
restarting the daemon.

**Authentication** — requires the `X-Admin-Api-Key` header to match one of
the keys configured in `xspct_admin_api_key`. Returns `403` if the admin API
is disabled (no keys configured).

```bash
curl -s -X POST http://localhost:8080/v1/admin/reload \
  -H 'X-Admin-Api-Key: my-admin-secret'
```

```json
{"status": "ok", "reloaded": ["config", "passwords", "yara_rules"]}
```

---

### `GET /v1/openapi.json`

Returns the OpenAPI 3.0 specification for this API in JSON format.
Requires `pydantic` (`pip install "xspct_scan[openapi]"`).

### `GET /v1/apidoc/redoc`

Interactive API documentation rendered with [ReDoc](https://redocly.com/redoc/).
Requires `pydantic`.
