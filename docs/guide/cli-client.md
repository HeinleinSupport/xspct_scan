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

## Config file

Instead of repeating `--url`/`--api-key` on every invocation, the client
reads a YAML config file for defaults. CLI flags always take precedence over
the config file, which takes precedence over the built-in defaults.

The first existing path wins, in this order:

1. `--config PATH`
2. `$XSPCT_SCAN_CLIENT_CONFIG`
3. `~/.config/xspct_scan/client.yml`
4. `/etc/xspct_scan/client.yml`

```yaml
# ~/.config/xspct_scan/client.yml
url: https://scan.internal:8443
api_key: s3cr3t
timeout: 60
```

Config files support connection, request, and output defaults in the flag
reference below; their keys match the CLI flag names with dashes replaced by
underscores. Mode selectors (`--capabilities`, `--query`, and `FILE`
arguments) must be supplied on the command line.

Values are type-checked when the file is read, so a mistake fails immediately
with a clear message instead of surfacing later as a traceback:

- `timeout` and `poll_interval` accept a number or a numeric string.
- `passwords` and `force_analyzers` accept either the comma-separated string
  the flag takes or a YAML list.
- Boolean keys must be real YAML booleans — a quoted `"false"` is rejected
  rather than treated as the truthy string it is.
- Unknown keys are ignored with a warning naming the closest valid key, so a
  mistyped `api_key` cannot silently drop authentication.

A path named through `--config` or `$XSPCT_SCAN_CLIENT_CONFIG` must exist;
naming a missing file is an error rather than a silent fallback to the
built-in defaults. The two unnamed default locations are skipped when absent.

Boolean defaults can be explicitly overridden for one invocation with
`--use-cache`, `--structured-multipart`, `--no-poll`, `--no-json`, `--color`,
or `--secure`.

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

| Flag | Short | Description |
|------|-------|-------------|
| `--config PATH` | `-c` | Path to a YAML config file providing defaults for the other options (default: `$XSPCT_SCAN_CLIENT_CONFIG`, `~/.config/xspct_scan/client.yml`, or `/etc/xspct_scan/client.yml`, first match wins) |
| `--url URL` | `-u` | Daemon base URL (default: `http://localhost:8080`, or the config file) |
| `--api-key KEY` | `-a` | `X-Api-Key` header value |
| `--timeout SECS` | `-t` | Analysis timeout in seconds sent to the daemon (default: `30`, or the config file) |
| `--passwords LIST` | `-p` | Comma-separated passwords to try for encrypted files |
| `--force-analyzers LIST` | `-f` | Comma-separated analyzer paths to bypass exclusion gates for this request (e.g. `image.ocr`) |
| `--force-ocr` | `-F` | Shortcut for `--force-analyzers image.ocr` |
| `--invalidate-cache` | `-R` | Delete the daemon's cached report and force a full rescan (`--use-cache` overrides a config default) |
| `--legacy-multipart` | `-L` | Use the legacy `doc` multipart field instead of the structured `metadata` + `file` shape (default; `--structured-multipart` overrides a config default) |
| `--rspamd-uid ID` | `-r` | `rspamd_uid` correlation value placed in the metadata part |
| `--queue-id ID` | `-Q` | `queue_id` placed in the metadata part |
| `--message-id ID` | `-m` | `message_id` placed in the metadata part |
| `--poll` | `-P` | Poll `/v1/query` until the result is ready when a `202` is returned (`--no-poll` overrides a config default) |
| `--poll-interval SECS` | `-I` | Seconds between poll attempts (default: `2`, or the config file) |
| `--query HASH` | `-q` | Look up a report by SHA-256 hash via `GET /v1/query` instead of submitting a file |
| `--capabilities` | `-C` | Fetch `GET /v1/capabilities` and display the active analyzer/MIME overview |
| `--json` | `-j` | Output raw JSON instead of a formatted summary (`--no-json` overrides a config default) |
| `--output FILE` | `-o` | Write JSON result(s) to `FILE` |
| `--no-color` | `-n` | Disable coloured `rich` output (`--color` overrides a config default) |
| `--insecure` | `-i` | Skip TLS certificate verification (`--secure` overrides a config default) |

`--capabilities`, `--query`, and `FILE` arguments are mutually exclusive —
provide exactly one mode per invocation.
