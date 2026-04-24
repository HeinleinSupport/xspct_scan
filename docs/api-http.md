# HTTP API

All endpoints return JSON unless stated otherwise.
Authentication (when enabled) is via the `X-Api-Key` header — see
[Authentication](authentication).

## Endpoints

### `GET /health`

Returns `200 OK` with `{"status": "ok"}`. No authentication required.
Used for load-balancer health checks.

```bash
curl http://localhost:8080/health
```

```json
{"status": "ok"}
```

---

### `GET /ping`

Returns `200 OK` with the plain text body `pong`. No authentication required.

---

### `POST /scan`

Submit a document for malware analysis.

**Request** — `multipart/form-data`

| Field | Required | Description |
|-------|----------|-------------|
| `doc` | ✓ | The file to scan (any filename). |
| `file_mime` | | Override the detected MIME type. |
| `file_type` | | Override the detected file description string. |
| `passwords` | | Comma- or newline-separated passwords to try when decrypting encrypted Office **or PDF** files. Custom passwords are tried before the daemon-wide list. |

**Query parameters**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `timeout` | `10` | Max seconds to wait for analysis before returning `202`. |
| `rtf` | `false` | Set to `true` to enable RTF object extraction via `rtfobj`. |

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
  "rtf_objects": [],
  "decrypted": false,
  "decryption_password": null,
  "text_preview": "...",
  "meta_document": {
    "author": "John Doe",
    "title": "Q1 Invoice",
    "creation_date": "D:20260115120000Z"
  },
  "meta": {"script_name": "olefy_v2", "version": "2.0.0", "type": "MetaInformation"},
  "status": "finished",
  "time_taken": 0.123
}
```

**Response `202 Accepted`** — analysis still running (timeout exceeded).
Poll `/query?hash=<file_hash>` for the result.

```json
{"status": "pending", "file_hash": "sha256hex..."}
```

**Response `400 Bad Request`** — no `doc` field in the request.

---

### `GET /query?hash=<sha256>`

### `POST /query`

Retrieve a previously submitted scan result by its SHA-256 hash.

**GET** — pass hash as a query parameter:

```bash
curl "http://localhost:8080/query?hash=sha256hex..."
```

**POST** — pass hash as a JSON body:

```bash
curl -s -X POST http://localhost:8080/query \
  -H 'Content-Type: application/json' \
  -d '{"hash": "sha256hex..."}'
```

**Response `200 OK`** — the full scan report (same schema as `/scan`).

**Response `404 Not Found`** — hash not in cache or in-memory results.

**Response `400 Bad Request`** — no hash provided.

---

### `GET /metrics`

Prometheus-compatible counter/gauge text exposition.

```
# HELP olefy_requests_total Total scan requests received
# TYPE olefy_requests_total counter
olefy_requests_total 42
# HELP olefy_requests_finished Scan requests completed within timeout
# TYPE olefy_requests_finished counter
olefy_requests_finished 40
...
```

| Metric | Type | Description |
|--------|------|-------------|
| `olefy_requests_total` | counter | Total `/scan` requests received |
| `olefy_requests_finished` | counter | Scans completed within timeout |
| `olefy_requests_timeout` | counter | Scans that returned `202` |
| `olefy_redis_hits` | counter | Redis cache hits |
| `olefy_redis_misses` | counter | Redis cache misses |
| `olefy_redis_errors` | counter | Redis errors |
| `olefy_tasks_in_memory` | gauge | Current in-memory task/report entries |
