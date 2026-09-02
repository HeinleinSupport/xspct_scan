# Development & Testing

## Prerequisites

- Python 3.10 or newer
- `libmagic` system library (see [installation](installation.md))
- A virtual environment is strongly recommended

```bash
python3 -m venv ~/venv
source ~/venv/bin/activate
```

## Install with dev dependencies

The `[dev]` extra installs pytest and the aiohttp/asyncio test plugins.
Install all optional extras as well so the full test suite can run:

```bash
pip install -e ".[dev,enrichment,openapi,advanced]"
```

Minimal install (unit tests only, no image/YARA/iocsearcher tests):

```bash
pip install -e ".[dev]"
```

## Running the tests

From the repository root:

```bash
pytest
```

Or via the venv explicitly:

```bash
~/venv/bin/pytest
```

Useful flags:

| Flag | Effect |
|------|--------|
| `-v` | Verbose — show each test name |
| `-q` | Quiet — one dot per test |
| `-x` | Stop after the first failure |
| `-k EXPR` | Run only tests whose name matches *EXPR* |
| `--tb=short` | Shorter tracebacks |
| `-p no:warnings` | Suppress deprecation warnings from third-party libs |

Examples:

```bash
# Run one area (tests are split one module per analyzer / concern)
pytest -v tests/test_http_endpoints.py

# Run every analyzer module
pytest -v tests/test_analyzer_*.py

# Run a single class
pytest -v tests/test_analyzer_archive.py::TestAnalyzeArchive

# Run a single test
pytest "tests/test_analyzer_archive.py::TestAnalyzeArchive::test_zip_with_pdf_extracted" -v

# Run with oletools test data for real-file fixture tests
pytest --oletools-testdata /path/to/oletools/tests/test-data
```

## Test configuration

All pytest settings live in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"   # all async test functions run automatically
testpaths    = ["tests"]
```

`asyncio_mode = "auto"` means you do **not** need to decorate async test
functions with `@pytest.mark.asyncio`.

## Fixture files

Integration tests that exercise real Office and RTF documents use files in
`tests/fixtures/`:

| File | Used by |
|------|---------|
| `autostart-encrypt-standardpassword.xls` | `TestSyncAnalyze`, `TestScanEndpoint` — encrypted OLE macro document |
| `RTF-Spec-1.7.rtf` | `TestSyncAnalyze`, `TestScanEndpoint` — RTF document |
| `passwords.txt` | All tests — password wordlist loaded by the daemon fixture |
| `pdf_javascript.pdf` | `TestPdfJavascriptFixture` — PDF with `/OpenAction` JS, `eval`, `launchURL` |
| `pdf_embedded.pdf` | `TestPdfEmbeddedFileFixture` — PDF with embedded file attachment |
| `pdf_uri.pdf` | `TestPdfUriFixture` — PDF with external URI hyperlink |
| `html_phishing.html` | `TestHtmlPhishingFixture` — form, iframe, meta-refresh, eval, CSS hiding |
| `archive_mixed.zip` | `TestArchiveMixedFixture` — ZIP with text, JS, and nested PDF members |
| `email_with_attachment.eml` | `TestEmlFixture` — RFC 2822 e-mail with a PDF attachment |
| `qr_code.png` | `TestQrCodeFixture` — PNG QR code (→ run `create_fixtures.py` with `qrcode` or `segno`) |

### Generating fixture files

The script `tests/create_fixtures.py` creates all the generated fixtures:

```bash
python tests/create_fixtures.py
```

Fixtures are deterministic and safe to commit.  Re-running the script
overwrites them with identical content.  The PDF fixtures require
PyMuPDF (a mandatory project dependency).  The QR code PNG additionally
requires either `qrcode` or `segno`:

```bash
pip install qrcode   # or: pip install segno
python tests/create_fixtures.py
```

If these files are absent the dependent tests are **automatically skipped**
(guarded by `@pytest.mark.skipif(not os.path.exists(...))`).

You can substitute the oletools test-data tree (which contains the same
files) using the `--oletools-testdata` CLI option:

```bash
pytest --oletools-testdata ~/git/oletools/tests/test-data
```

## Conditional / optional tests

Several tests are skipped when optional libraries are not installed:

| Skip condition | Affected classes |
|----------------|-----------------|
| `PyMuPDF` not installed | `TestAnalyzePdfEncrypted` (encrypted PDF creation + scan) |
| `Pillow` not installed | `TestAnalyzeImage::test_blank_png_does_not_raise` |
| `iocsearcher` not installed | `TestAnalyzeIocsearcher::test_returns_dict_when_installed` |
| `pydantic` not installed | `TestOpenApiEndpoints::test_openapi_json_*`, `test_redoc_*` |
| `yara-python` / `yara-x` not installed | `TestAnalyzeYaraNoEngine` is always active; `TestSyncAnalyzeYara::test_yara_called_when_rules_loaded` uses `monkeypatch` and runs unconditionally || `SFlock2` not installed | `TestAnalyzeArchiveSflock` uses `monkeypatch` to stub `_sflock` and runs unconditionally — no skip needed |
Install all extras to minimise skips:

```bash
pip install -e ".[dev,enrichment,openapi,advanced]"
```

## Test structure

```
tests/
├── conftest.py                      # pytest configuration, shared constants,
│                                    # autouse fixtures, byte-level document
│                                    # fixtures and helpers
├── __init__.py
├── create_fixtures.py               # regenerates the generated fixtures below
├── test_analyzer_archive.py         # one module per analyzer …
├── test_analyzer_html.py
├── test_analyzer_image.py
├── test_analyzer_javascript.py
├── test_analyzer_lnk.py
├── test_analyzer_odf.py
├── test_analyzer_pdf.py
├── test_analyzer_script.py
├── test_analyzer_signature.py
├── test_analyzer_text.py
├── test_analyzer_yara.py
├── test_auth.py                     # … plus one per cross-cutting area
├── test_cache.py
├── test_capabilities_openapi.py
├── test_config_logging.py
├── test_http_endpoints.py
├── test_ioc.py
├── test_pipeline_concurrency.py
├── test_report_merging.py
├── test_response_formats.py
├── test_scan_multipart_metadata.py
└── fixtures/
    ├── autostart-encrypt-standardpassword.xls
    ├── RTF-Spec-1.7.rtf
    └── passwords.txt
```

Tests are split one module per analyzer plus one per cross-cutting area. Add
new tests to the module matching what you touched — a new analyzer gets its own
`test_analyzer_<type>.py`.

| Module | What it covers |
|--------|----------------|
| `test_analyzer_archive.py` | ZIP extraction, depth/size guards, YARA on members, sflock2 path, RAR/EML/MSG/CAB/ACE/ISO/TGZ format detection, `archive_mixed.zip` and `email_with_attachment.eml` fixtures |
| `test_analyzer_html.py` | HTML analyzer, RemoteScriptInjection, inline JS, data URIs, HTA-in-HTML, `html_phishing.html` fixture |
| `test_analyzer_image.py` | Image analyzer, OCR gating, per-document image cap, `qr_code.png` QR decode |
| `test_analyzer_javascript.py` | JS keyword detection and emulation |
| `test_analyzer_lnk.py` | `.lnk` parsing and its pipeline routing |
| `test_analyzer_odf.py` | OpenDocument analyzer |
| `test_analyzer_pdf.py` | PDF analyzer (clean, markers, IOCs), encrypted PDFs, `pdf_javascript.pdf` / `pdf_embedded.pdf` / `pdf_uri.pdf` fixtures |
| `test_analyzer_script.py` | VBS/VBE/JSE/WSF/PowerShell analyzer and its pipeline routing |
| `test_analyzer_signature.py` | VBA, OOXML and PDF signature validation (requires pyhanko) |
| `test_analyzer_text.py` | `analyze_text()`, text preview strategies, `text_full`, RTF extractor |
| `test_analyzer_yara.py` | YARA no-engine path and `sync_analyze` integration |
| `test_auth.py` | `xspct_api_key` / `xspct_admin_api_key` logic, endpoint enforcement, `POST /admin/reload` |
| `test_cache.py` | Rspamd digest, Redis cache, cache invalidation (requires fakeredis) |
| `test_capabilities_openapi.py` | `GET /v1/capabilities`, `/openapi.json`, `/apidoc/redoc` |
| `test_config_logging.py` | Session IDs, YAML config loading, logger setup |
| `test_http_endpoints.py` | `/health`, `/ping`, `/`, `/metrics`, `POST /scan`, octet-stream rejection, client polling and multipart shape |
| `test_ioc.py` | URL / IP / domain extraction, exclusion rules, iocsearcher integration |
| `test_pipeline_concurrency.py` | Task eviction, full sync pipeline, `PartialReport`, two-tier fg/bg concurrency |
| `test_report_merging.py` | MIME / extension / magic-byte detection, report skeleton, merge semantics |
| `test_response_formats.py` | msgpack and CBOR serialization, zstd compression |
| `test_scan_multipart_metadata.py` | Multipart `metadata` part parsing and correlation IDs |

Some fixtures under `fixtures/` are generated and git-ignored — regenerate them
with `python tests/create_fixtures.py`. Tests depending on a missing generated
fixture skip themselves.

## Writing new tests

- **Async integration tests** — use `async def test_…(self, client)`. The
  `client` fixture provides a fully initialised daemon via `aiohttp_client`.
  No extra decorator needed (`asyncio_mode = "auto"`).
- **Unit tests** — use `def test_…(self, daemon)`. The `daemon` fixture
  returns a bare `InspectorDaemon` with a short password list.
- **Global config mutations** — the `reset_global_state` autouse fixture
  saves and restores `xspct.config` and `xspct.stats` around every test.
  Mutate config freely inside a test; it will be reverted automatically.
- **Optional-library guards** — use
  `@pytest.mark.skipif(not xspct.HAS_PYDANTIC, reason='pydantic not installed')`
  for tests that require an optional dependency. When the optional import lives
  in `conftest.py`, bind the alias to `None` in the `except ImportError` branch
  as well — modules do `from tests.conftest import _pymupdf`, and an unbound
  name breaks *collection* before any `skipif` can apply.
- **Checking the degraded path** — the CI matrix installs every extra, so run
  this locally after touching an optional import:

  ```bash
  python -m pytest -p tests.optional_dep_blocker -q      # full suite, deps hidden
  python -m pytest -p tests.optional_dep_blocker -q --collect-only   # collection only
  ```

  Use `python -m pytest`, not the bare `pytest` console script: the `-p`
  flag imports the plugin during argument preparsing, before pytest has
  added the repo root to `sys.path`, and only `python -m` puts it there in
  time for `tests.optional_dep_blocker` to resolve.

  The plugin hides every optional dependency behind a meta-path hook, which
  reproduces a bare install without needing one. The full run must be green —
  every test needing an absent engine skips itself rather than failing. CI runs
  the same command in its `minimal` job.
