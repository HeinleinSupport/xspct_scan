# Changelog

## 0.4.0 — 2026-07-07

### Added
- **ODF analyzer** (`analyze_odf`): full analysis of OpenDocument Format files
  (`.odt`, `.ods`, `.odp`, `.odg`, `.odf`).  Uses `odfdo` when available
  (requires `[advanced]` extra) with a raw ZIP/XML fallback.
  - Body text and metadata extracted via `odfdo`; XML tag-stripping fallback.
  - Hyperlink extraction from every `xlink:href` attribute (covers `draw:a`,
    event-listeners, and form controls, not just `text:a`).
  - StarBasic macro detection via ZIP entry scan; macro source fed to
    `VBA_Scanner` keyword analysis (oletools) and IOC extraction.
  - Embedded OLE object detection.
  - Embedded images extracted from `Pictures/` and analysed with OCR/QR.
  - `_is_odf()` helper detects ODF by MIME prefix, file extension, or ZIP
    `mimetype` entry.
  - Added `.odg` and `.odf` to the office extension list.
  - Added `odfdo>=3.20` to the `[advanced]` optional dependency group.
- **Scanned-PDF OCR fallback**: when PyMuPDF finds an empty text layer, OCR
  text collected from embedded images is used for `text_preview` and feeds
  iocsearcher.
- **Multi-source text extraction**: `text_preview` and `text_full` are now
  lists of `{source, text}` segments.  Every extractor contributes an
  independently labelled segment (sources: `pdf`, `pdf-image`, `office`,
  `office-macro`, `odf`, `odf-macro`, `odf-image`, `html`, `html-image`,
  `ooxml-image`, `text`, `image-ocr`, `image-qr`).
- **All extracted text reaches iocsearcher**: OCR/QR results from images and
  macro source code now pass through the extended IOC catcher (email, CVE,
  hash, wallet, onion addresses) in addition to the regex extractor.  Image
  extraction runs before iocsearcher in `analyze_pipeline`.
- **Renamed CLI tool**: `xspct-client` is now `xspct-scan-client`.
- **REUSE 3.3 compliance**: SPDX metadata added for all source files;
  `LicenseRef-Public-Domain` licence file added for vendored Didier Stevens
  tools; `.github/prompts/` workflow prompt files added.
- **Agent workflow prompts** in `.github/prompts/`: `check-code`, `format-code`,
  `run-tests`, `prepare-commit`, `generate-sbom`.

### Changed
- `text_preview` and `text_full` response fields are now **lists** of
  `{source, text}` objects instead of plain strings.
- `xspct_text_preview_length` and `xspct_text_max_length` now apply per
  segment rather than to a single combined string.
- `xspct_include_text_preview`/`xspct_include_text_full` now zero the
  respective list to `[]` when disabled (was `""` / `null`).

### Fixed
- ODF files previously fell through to oletools which cannot parse them;
  dispatch now routes ODF through the dedicated path before VBA_Parser.
- PDF byte-scan marker flags (`has_javascript`, `has_openaction`, etc.) were
  on single-line `if m_type == ...: flag = True` statements; expanded to
  full `if/else` form (Python 3.10+ f-string nested-quote fix).
- `xml.etree.ElementTree` removed from ODF meta.xml fallback; regex extraction
  used instead to prevent entity-expansion DoS on hostile input.
- `_OdfLink` dead import removed.
- Internal text accumulation keys (`_pdf_ocr_text`, `_text_full_extracted`)
  were not cleaned up in `sync_analyze`; they are now popped before return.

## Unreleased

## 0.3.0 — 2026-05-06

### Added
- **sflock2 archive backend**: when `SFlock2` is installed (`pip install "xspct_scan[advanced]"`)
  archive extraction runs inside the zipjail usermode sandbox, covering RAR,
  TAR/TGZ/TBZ2, CAB, ACE, ISO, EML, MSG, MSO, lzip, and ZPAQ in addition to
  the existing ZIP and 7z support.  The stdlib `zipfile`/`py7zr` fallback is
  retained for environments without sflock2.
- **EML and MSG routed through archive pipeline**: `get_detected_type` now returns
  `'archive'` for `message/rfc822`, `application/vnd.ms-outlook`, `.eml`, `.msg`,
  and `.mso` files so attachments are extracted in-sandbox.
- **`HAS_SFLOCK` feature flag** visible in the Python API (same pattern as
  `HAS_YARA`, `HAS_IOCSEARCHER`, etc.).

## 0.2.0 — 2026-04-24

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
  `xspct_include_text_full: true`
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
