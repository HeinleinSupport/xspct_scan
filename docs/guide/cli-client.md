# CLI client

`xspct_scan_client` is a standalone command-line client, installed
alongside the daemon (`pyproject.toml` console script), for scanning files
or querying results without writing an HTTP client of your own. It talks to
the same [HTTP API](api-http.md) documented elsewhere in this guide.

## Basic usage

```bash
# Scan one or more files (scanned concurrently)
xspct_scan_client invoice.pdf malware.docx

# Talk to a remote/authenticated daemon
xspct_scan_client --url https://scan.internal:8443 --api-key s3cr3t invoice.pdf

# Wait for a slow scan instead of getting a 202 back
xspct_scan_client --poll --timeout 60 large_archive.zip

# Write the full JSON report to a file instead of printing a summary
xspct_scan_client --json --output result.json sample.doc
```

## Looking up results by hash

`--query` fetches a previously-submitted report by its SHA-256 hash via
`GET /v1/query`, without re-uploading the file — useful when a scan is still
processing in the background:

```bash
xspct_scan_client --query <sha256>
```

## Rspamd correlation metadata

`--rspamd-uid`, `--queue-id`, and `--message-id` are placed in the
structured `metadata` part of the request (see
[`POST /v1/scan`](api-http.md#post-v1scan)) so a scan can be correlated with
the originating Rspamd task:

```bash
xspct_scan_client --rspamd-uid 7f3a9c1e-b2d4 --queue-id 1a2b3c invoice.docx
```

These flags require the default structured metadata shape and cannot be
combined with `--legacy-multipart`.

## Inspecting daemon capabilities

`--capabilities` fetches `GET /v1/capabilities` and prints the active
analyzers, MIME routing, and current limits:

```bash
xspct_scan_client --capabilities
xspct_scan_client --capabilities --json
```

## Overriding OCR exclusion gates

`--force-ocr` (shortcut for `--force-analyzers image.ocr`) forces OCR for a
single request even when the size/camera-photo exclusion gates would
otherwise skip it — see
[OCR exclusion gates](../../README.md#ocr-exclusion-gates):

```bash
xspct_scan_client --force-ocr photo.jpg
xspct_scan_client --force-analyzers image.ocr photo.jpg
```

## Full flag reference

| Flag | Description |
|------|-------------|
| `--url URL` | Daemon base URL (default: `http://localhost:8080`) |
| `--api-key KEY` | `X-Api-Key` header value |
| `--timeout SECS` | Analysis timeout in seconds sent to the daemon (default: `30`) |
| `--passwords LIST` | Comma-separated passwords to try for encrypted files |
| `--force-analyzers LIST` | Comma-separated analyzer paths to bypass exclusion gates for this request (e.g. `image.ocr`) |
| `--force-ocr` | Shortcut for `--force-analyzers image.ocr` |
| `--invalidate-cache` | Delete the daemon's cached report and force a full rescan |
| `--legacy-multipart` | Use the legacy `doc` multipart field instead of the structured `metadata` + `file` shape (default) |
| `--rspamd-uid ID` | `rspamd_uid` correlation value placed in the metadata part |
| `--queue-id ID` | `queue_id` placed in the metadata part |
| `--message-id ID` | `message_id` placed in the metadata part |
| `--poll` | Poll `/v1/query` until the result is ready when a `202` is returned |
| `--poll-interval SECS` | Seconds between poll attempts (default: `2`) |
| `--query HASH` | Look up a report by SHA-256 hash via `GET /v1/query` instead of submitting a file |
| `--capabilities` | Fetch `GET /v1/capabilities` and display the active analyzer/MIME overview |
| `--json` | Output raw JSON instead of a formatted summary |
| `--output FILE` | Write JSON result(s) to `FILE` |
| `--no-color` | Disable coloured `rich` output |
| `--insecure` | Skip TLS certificate verification |

`--capabilities`, `--query`, and `FILE` arguments are mutually exclusive —
provide exactly one mode per invocation.
