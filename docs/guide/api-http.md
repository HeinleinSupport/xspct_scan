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

**Request** — `multipart/form-data` **or** `application/octet-stream`

*multipart/form-data fields*

| Field | Required | Description |
|-------|----------|-------------|
| `doc` | ✓ | The file to scan (any filename). The daemon transparently decompresses a zstd-compressed part if the Zstandard frame magic bytes are detected. A `.zst` suffix is stripped from the filename before type detection. |
| `file_mime` | | Override the detected MIME type. |
| `file_type` | | Override the detected file description string. |
| `passwords` | | Comma- or newline-separated passwords to try when decrypting encrypted Office **or PDF** files. Custom passwords are tried before the daemon-wide list. |

*application/octet-stream*: send raw file bytes as the request body.
Pass optional metadata as query parameters (`filename`, `file_mime`, `file_type`,
`passwords`). Zstd-compressed bodies are automatically decompressed via magic bytes.

**Query parameters**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `timeout` | `10` | Max seconds to wait for analysis before returning `202`. |
| `rtf` | `false` | Set to `true` to enable RTF object extraction via `rtfobj`. |

`detected_type` in the response will be one of: `pdf`, `html`, `office`,
`image`, `archive`, `text`, or `unknown`.  For the `text` type the daemon
decodes the content, runs YARA on the raw bytes, and passes the full text to
iocsearcher.

**Response `200 OK`** — analysis finished within timeout.

```json
{
  "filename": "invoice.docx",
  "file_hash": "sha256hex...",
  "file_type": "application/vnd.openxmlformats-officedocument...",
  "file_description": "Microsoft Word 2007+",
  "detected_type": "office",
  "has_macro": true,
  "is_encrypted": false,
  "analyses": [
    {"type": "AutoExec", "keyword": "AutoOpen", "description": "..."}
  ],
  "iocs": {
    "urls": ["https://malware.example.com/payload"],
    "ips": [],
    "domains": []
  },
  "iocs_extended": {
    "url": ["https://malware.example.com/payload"],
    "email": []
  },
  "yara_matches": [],
  "pdfid_keywords": null,
  "pdfid_meta": null,
  "archive_files": [],
  "exif": {},
  "rtf_objects": [],
  "decrypted": false,
  "decryption_password": null,
  "text_preview": "...",
  "text_full": null,
  "meta_document": {
    "author": "John Doe",
    "title": "Q1 Invoice",
    "creation_date": "D:20260115120000Z"
  },
  "meta": {"script_name": "xspct_scan", "version": "0.3.0", "type": "MetaInformation"},
  "analyzers_completed": ["office", "iocs"],
  "analyzers_pending": [],
  "status": "finished",
  "time_taken": 0.123
}
```

New report fields (v0.2.0+):

| Field | Type | Description |
|-------|------|-------------|
| `yara_matches` | list | YARA rule matches (name, tags, meta, strings). Requires `[advanced]` + `xspct_analyzers.yara.enabled: true`. Populated for **all** file types including images and archive members. |
| `iocs_extended` | dict | Extended IOC types from [iocsearcher](https://github.com/malicialab/iocsearcher) keyed by IOC type (`url`, `email`, `md5`, …). Requires `[advanced]`. |
| `pdfid_keywords` | dict/null | Raw pdfid keyword counts for PDF files. |
| `pdfid_meta` | dict/null | pdfid metadata record for PDF files. |
| `archive_files` | list | Files extracted from archives (`{name, size}`). When `SFlock2` is installed extraction runs in-sandbox and covers ZIP, 7z, RAR, TAR, CAB, ACE, ISO, EML, MSG, and more. Without sflock2 only ZIP and 7z are supported. EML and MSG attachments are included when sflock2 is available. All member types — PDF, HTML, Office, text, image, unknown — are individually analysed and their results merged into the top-level report. |
| `exif` | dict | EXIF metadata extracted from image files. |
| `text_preview` | list | Extracted text segments, each `{source, text}`, with `text` truncated to `xspct_text_preview_length`. One entry per extractor (document body, image OCR/QR, macros, archive members, …). Included when `xspct_include_text_preview: true` (default). |
| `text_full` | list | Extracted text segments, each `{source, text}`, with `text` up to `xspct_text_max_length`. Only populated when `xspct_include_text_full: true`. |
| `analyzers_completed` | list | Analyzer names that finished. |
| `analyzers_pending` | list | Analyzer names still running (non-empty only in `202` responses). |

**Response `202 Accepted`** — analysis still running (timeout exceeded).
Poll `/v1/query?hash=<file_hash>` for the result.

```json
{
  "status": "processing",
  "file_hash": "sha256hex...",
  "message": "Analysis in progress",
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

**Response `200 OK`** — the full scan report (same schema as `/v1/scan`).

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
