# Changelog

## 2.0.0 — 2026-04-24

Initial public release of xspct_scan (renamed from olefy_v2).

### Features

- Async HTTP daemon built on [aiohttp](https://docs.aiohttp.org/)
- Scan Office (OLE2, OOXML), PDF, and HTML documents for malware indicators
- VBA macro detection and analysis via [oletools](https://github.com/decalage2/oletools)
- Automatic decryption of password-protected Office files via
  [msoffcrypto-tool](https://github.com/nolze/msoffcrypto-tool) and oletools
- RTF object extraction via `rtfobj`
- IOC extraction (URLs, IP addresses, domains) from document content
- Optional Redis result cache with circuit-breaker
- API key authentication with key-rotation support
- Prometheus metrics endpoint (`/metrics`)
- Optional TLS termination
- Optional [uvloop](https://github.com/MagicStack/uvloop) event loop
- REUSE / SPDX licence compliance (EUPL-1.2)
- **Parallel pipeline** — analyzers run concurrently; partial results returned
  on timeout via `202 Accepted` with `analyzers_completed` / `analyzers_pending`
- **`application/octet-stream` upload** — raw bytes can be POSTed directly
  to `/scan` without multipart encoding
- **OpenAPI 3.0** specification at `/openapi.json`; ReDoc UI at `/apidoc/redoc`
  (requires `[openapi]` extra)
- **YARA scanning** — optional static signature matching on raw file bytes;
  supports Hyperscan acceleration (requires `[advanced]` extra)
- **iocsearcher** — extended IOC types (email, hash, CVE, …) extracted from
  document text (requires `[advanced]` extra)
- **PDF enrichment** — vendored pdfid v0.2.10 adds keyword counts and metadata
  to PDF scan reports
- **Image analysis** — OCR via pytesseract, QR/barcode decode via pyzbar,
  EXIF metadata extraction (GPS hits flagged), embedded OOXML images scanned
- **Archive analysis** — ZIP and 7z extraction with configurable depth/size
  limits and password loop; nested documents recursively analysed
- **`text_full` field** — full-text extraction included in reports when
  `xspct_include_text: true`
- **Admin reload** — `POST /admin/reload` reloads config/passwords/YARA
  without restart (requires `xspct_admin_api_key`)
- **`text` analyzer** — plain-text and script files (`text/plain`, ASCII,
  UTF-8, Unicode) are now a first-class type: `analyze_text()` decodes the
  content, populates `text_preview`, and extracts baseline IOCs; YARA and
  iocsearcher run over the same bytes in parallel
- **YARA on all types** — YARA now runs on every file regardless of type
  (PDFs, images, archives, text, unknown).  In the synchronous pipeline
  (`sync_analyze`) YARA is called after the primary analyzer and merged into
  the report.  Inside archive extraction every member — including images and
  unknown blobs — is individually YARA-scanned.
- **Archive member coverage** — `_analyse_member` now handles `text` and
  `unknown` members (previously ignored), and image members are passed
  through both `analyze_image` and YARA.  `merge_reports` is used throughout
  so `yara_matches`, `iocs_extended`, `pdfid_*`, and `rtf_objects` from
  sub-files are correctly propagated to the top-level archive report.
