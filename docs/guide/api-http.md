# HTTP API

All endpoints return JSON by default.  Responses can alternatively be
returned as **msgpack** (`application/x-msgpack`) or **CBOR**
(`application/cbor`) by sending an appropriate `Accept` header — see
[Content negotiation](#content-negotiation) below.

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

**Request** — `multipart/form-data` (two shapes) **or** `application/octet-stream`

*multipart/form-data, legacy shape*

| Field | Required | Description |
|-------|----------|-------------|
| `doc` | ✓ | The file to scan (any filename). The daemon transparently decompresses a zstd-compressed part if the Zstandard frame magic bytes are detected. A `.zst` suffix is stripped from the filename before type detection. |
| `file_mime` | | Override the detected MIME type. |
| `file_type` | | Override the detected file description string. |
| `passwords` | | Comma- or newline-separated passwords to try when decrypting encrypted Office **or PDF** files. Custom passwords are tried before the daemon-wide list. |

*multipart/form-data, structured metadata shape*

| Part | Required | Description |
|------|----------|-------------|
| `file` | ✓ | The file to scan. Same zstd auto-decompression and `.zst` suffix stripping as `doc`. |
| `metadata` | ✓ | A JSON or msgpack object (see below). An explicit part `Content-Type` (`application/json` or `application/x-msgpack`) selects the format; otherwise msgpack is tried first, then JSON. |

`metadata` fields (all optional except where noted):

| Field | Description |
|-------|-------------|
| `filename` | Overrides the `file` part's own filename. |
| `declared_content_type` | The Content-Type declared by the originating mail part (informational, logged). |
| `detected_type` | The type detected by the caller, e.g. Rspamd's `lua_magic` (informational, logged). |
| `rspamd_uid` | Rspamd task UID. Folded into the session log tag and echoed back in the response's `request` block for cross-system correlation. |
| `queue_id` | Mail queue ID. Folded into the session log tag and echoed back in `request`. |
| `message_id` | Message-ID header value. Echoed back in `request`. |
| `passwords` | List of decryption passwords. Overrides the `passwords` query parameter. |
| `force_analyzers` | List of analyzer paths to force-run. Overrides the `force_analyzers` query parameter. |
| `invalidate_cache` | Boolean. Overrides the `invalidate_cache` query parameter. |
| `timeout_s` | Caller's timeout hint in seconds. May only **tighten** the effective timeout (`min` of this and the `timeout` query parameter/default), never loosen it. |

Fields present in `metadata` take precedence over the equivalent query
parameter. The legacy `doc` shape and the structured `metadata`+`file` shape
are mutually exclusive; mixing parts from both shapes returns HTTP 400.

```bash
curl -s http://localhost:8080/v1/scan \
  -F 'metadata={"rspamd_uid":"7f3a9c1e-b2d4","passwords":["Secret123"]};type=application/json' \
  -F 'file=@invoice.xlsm'
```

*application/octet-stream*: send raw file bytes as the request body.
Pass optional metadata as query parameters (`filename`, `file_mime`, `file_type`,
`passwords`). Zstd-compressed bodies are automatically decompressed via magic bytes.

**Query parameters**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `timeout` | `10` | Max seconds to wait for analysis before returning `202`. |
| `force_analyzers` | | Comma-separated analyzer paths to bypass exclusion gates for this request (e.g. `image.ocr`). |
| `invalidate_cache` | `false` | Set to `true` to delete the Redis and in-memory cached report and force a full rescan. Older in-flight scans cannot repopulate the deleted cache entry; only the fresh report is cached. Use this when re-submitting a known file with a new/updated `passwords` list that must be tried from scratch. |

`detected_type` (inside `file.type`) will be one of: `pdf`, `html`, `office`,
`odf`, `image`, `archive`, `script`, `lnk`, `text`, or `unknown`. `.hta` files are
detected as `html` (they're HTML containers), not `script`.

**Response `200 OK`** — analysis finished within timeout.

All responses since v2.0 follow a structured, grouped schema (`schema_version: "2.0"`).
Sections are **omitted when empty** (no null/empty noise).

```json
{
  "schema_version": "2.0",
  "engine": { "name": "xspct_scan", "version": "0.5.0" },

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
| `rspamd_digest` | string | Rspamd-compatible keyed BLAKE2b-512 digest (128 hex chars) — matches `part->digest` in Rspamd's MIME parser |
| `size` | int | File size in bytes |
| `mime` | string/null | libmagic MIME type |
| `magic` | string/null | libmagic description |
| `type` | string | `pdf`\|`html`\|`office`\|`odf`\|`image`\|`archive`\|`script`\|`lnk`\|`text`\|`unknown` |
| `resolution` | string | `WxH` pixel dimensions for image files (e.g. `2096x4608`); absent for non-image files |

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

`scan.exclusions` is added when at least one analyzer gate was triggered:

| Key | Description |
|-----|-------------|
| `image.ocr` | OCR was skipped; value is a human-readable reason (e.g. `camera photo detected via EXIF (OnePlus/OnePlus 12)` or `file exceeds ocr_max_bytes (5,617,053 > 2,097,152)`) |

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

Segment `source` values: `pdf`, `pdf-image`, `office`, `office-macro`, `odf`, `odf-macro`, `odf-image`, `html`, `html-image`, `ooxml-image`, `text`, `script`, `script-decoded`, `lnk`, `lnk-working-directory`, `image-ocr`, `image-qr`.

#### `request` (present when the structured metadata part supplied ≥1 correlation ID)

Echoes back the correlation IDs supplied in the `metadata` part, so the
caller of *this specific* `POST /v1/scan` request can tie its immediate
response (`200` or `202`) back to the `rspamd_uid`/`queue_id`/`message_id`
it sent, without having to also thread the file hash through its own
bookkeeping.

**Scope: this response only — never persisted, never present on
`/v1/query`.** `request` reflects the request that produced *this specific*
HTTP response, not a property of the file content, so:
- A later cache-hit `/v1/scan` response for the same file content
  (submitted with different or no correlation IDs) never carries a previous
  requester's values.
- If a scan is promoted to the background (`202` → poll `/v1/query`), the
  `202` response you receive immediately *does* carry your correlation IDs,
  but the finished report you later retrieve via `/v1/query?hash=...` does
  **not** — that endpoint is a stateless, hash-keyed lookup shared by any
  caller who knows the hash, so it intentionally never carries any single
  requester's correlation IDs. Correlate background results by `file_hash`
  (present in both the `202` response and your own request bookkeeping)
  instead.

| Key | Type | Description |
|-----|------|-------------|
| `rspamd_uid` | string | Present when supplied in `metadata.rspamd_uid` |
| `queue_id` | string | Present when supplied in `metadata.queue_id` |
| `message_id` | string | Present when supplied in `metadata.message_id` |

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
| `signature` | `{...}` or `[{...}, ...]` | Single object if exactly one signature was found, array if multiple — see below |

`signature` — digital signature detection (VBA project, OOXML whole-document,
PDF/PAdES). Pure detection: never affects `verdict.score`/`severity`.

| Key | Type | Description |
|-----|------|-------------|
| `present` | bool | Always `true` (only emitted when a signature exists) |
| `type` | string | `vba_project`\|`ooxml_document`\|`pdf` |
| `valid` | bool | Signature is cryptographically self-consistent (and, for `ooxml_document`, that every manifest-listed package part still matches its signed digest) |
| `signer` | string | Signing certificate subject |
| `issuer_fingerprint` | string | `sha256:<hex>` of the cryptographically verified direct issuer certificate, or the signer's own certificate when no verified issuer is embedded |
| `trusted` | bool | Always `false` — certificate trust-store validation is a separate, later stage |
| `key_usage_valid` | bool | Signing certificate's KeyUsage extension, if present, permits digital signatures (informational only unless `xspct_analyzers.signature.strict: true`) |
| `cert_time_valid` | bool | Certificate's `not_valid_before`/`not_valid_after` window covers the current time (informational only unless `xspct_analyzers.signature.strict: true`) |
| `covers_whole_document` | bool | `true` when the signature covers the entire file/package, not just a subset |
| `timestamp` | string | ISO-8601 UTC signing time, when available (otherwise omitted) |

**Response `202 Accepted`** — analysis still running (timeout exceeded).
The partial report snapshot is returned alongside bookkeeping fields.
Poll `/v1/query?hash=<sha256>` for the finished v2 report.

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

**CLI** — look up a hash directly without re-uploading the file:

```bash
xspct_scan_client --query sha256hex...
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

---

### `GET /v1/capabilities`

Returns a JSON document describing which analyzers are currently active, what
MIME types and file extensions they accept, and the effective limits.  This
endpoint is primarily intended for Rspamd and other clients that need to
build a dynamic MIME include filter without maintaining a static list.

**Response schema**

```json
{
  "engine": { "name": "xspct_scan", "version": "0.5.0", "schema_version": "2.0" },
  "limits": {
    "max_file_size": 52428800,
    "default_timeout": 10,
    "archive_max_depth": 2,
    "archive_max_size": 52428800
  },
  "response_formats": ["json"],
  "analyzers": {
    "pdf":  { "active": true,  "scope": "type-routed", "detected_type": "pdf",
              "mime_types": ["application/pdf"], "mime_patterns": [], "extensions": [".pdf"] },
    "html": { "active": true,  "scope": "type-routed", "detected_type": "html", "...": "..." },
    "yara": { "active": false, "scope": "global" },
    "iocs": { "active": true,  "scope": "post-processing" }
  },
  "mime_types": {
    "exact":           ["application/pdf", "application/zip", "message/rfc822"],
    "prefixes":        ["image/", "text/"],
    "patterns":        ["application/msword*", "application/vnd.ms-*"],
    "extensions":      [".docx", ".pdf", ".zip"],
    "global_scanners": ["yara"]
  }
}
```

**Semantics**

- `analyzers.*.active` — the analyzer is both enabled in config **and** its runtime
  prerequisites (optional Python libraries) are satisfied.
- `analyzers.*.scope`:
  - `type-routed` — dispatched based on the detected file type; carries
    `mime_types`, `mime_patterns`, and `extensions`.
  - `global` — runs on every file regardless of type (YARA, ClamAV).
  - `post-processing` — runs on content extracted by primary analyzers (iocsearcher, JavaScript).
- `mime_types.*` (top level) is the **union over all active type-routed analyzers** —
  this is the list Rspamd should use as its dynamic include filter.
- `mime_types.global_scanners` lists active `global`-scope analyzers.  A non-empty
  list means files outside the MIME list still receive meaningful scanning.
- The response is computed per request from the live config so it reflects
  changes applied via `POST /v1/admin/reload`.

**Caching (ETag / 304)**

The response body is deterministically sorted (`sort_keys=True`) and its SHA-256
digest is returned as an `ETag` header.  Clients can reuse the cached response
until it changes:

```bash
# First request — save the ETag
ETAG=$(curl -si http://localhost:8080/v1/capabilities \
  | grep -i '^ETag:' | awk '{print $2}' | tr -d '\r')

# Subsequent requests — 304 when nothing changed
curl -si -H "If-None-Match: $ETAG" http://localhost:8080/v1/capabilities
# HTTP/1.1 304 Not Modified
```

A `Cache-Control: max-age=60` header is also set so HTTP caches and proxies
can hold the response for up to 60 seconds.

**CLI client**

```bash
xspct_scan_client --capabilities
xspct_scan_client --capabilities --json          # raw JSON
xspct_scan_client --capabilities --url http://scan.internal:8080
xspct_scan_client --capabilities --output caps.json
```

**Rspamd integration note**

Fetch the capabilities at startup (and revalidate periodically via `If-None-Match`):

1. Extract `mime_types.exact` and `mime_types.prefixes` to build the
   `mime_types` include filter for the `antivirus` module.
2. If `mime_types.global_scanners` is non-empty, files outside the MIME list
   are also scanned — you may choose to forward all attachments.
3. Keep a static fallback list for when the endpoint is unreachable.

Note that server-side type detection also uses libmagic descriptions and
filename extensions, so the MIME list is authoritative for client-side
filtering but not the only routing signal inside the daemon.

---

## Content negotiation

All endpoints that return a scan report support three wire formats.
The format is selected in the following priority order:

1. **`xspct_response_format` config key** — if set to `json`, `msgpack`, or
   `cbor`, that format is always used regardless of request headers.
2. **`Accept` request header** — the first recognised MIME type wins:
   `application/json`, `application/x-msgpack`, `application/cbor`.
3. **Fallback** — `application/json`.

Msgpack and CBOR require the `serialization` extra:

```bash
pip install "xspct_scan[serialization]"
```

Example — request msgpack:

```bash
curl -s -F "doc=@invoice.pdf" \
  -H "Accept: application/x-msgpack" \
  http://localhost:8080/v1/scan | python3 -c "import sys,msgpack; print(msgpack.unpackb(sys.stdin.buffer.read()))"
```

The `/v1/query` `POST` endpoint also accepts a msgpack or CBOR request body
(detected via `Content-Type: application/x-msgpack` or
`Content-Type: application/cbor`).

---

## Response compression (zstd)

Add `Accept-Encoding: zstd` to any scan or query request to receive a
zstd-compressed response body. The response will carry
`Content-Encoding: zstd`; the payload format (`Content-Type`) is unchanged.

Requires the `compression` extra:

```bash
pip install "xspct_scan[compression]"
```

Example:

```bash
curl -s -F "doc=@invoice.pdf" \
  -H "Accept-Encoding: zstd" \
  http://localhost:8080/v1/scan | zstd -d
```

---

## Compressed uploads (zstd)

The daemon transparently decompresses zstd-compressed uploads. Detection is
based on the Zstandard frame magic bytes (`\x28\xb5\x2f\xfd`) at the start of
the data — no special header is required.

- **Multipart** — compress the `doc` field payload before attaching it to the
  form.
- **Octet-stream** — send the compressed bytes as the request body.

A `.zst` filename suffix is stripped before type detection, so
`invoice.pdf.zst` is analysed as a PDF.

Example:

```bash
zstd -c invoice.pdf | curl -s \
  -X POST "http://localhost:8080/v1/scan?filename=invoice.pdf.zst" \
  --data-binary @- \
  -H "Content-Type: application/octet-stream"
```
