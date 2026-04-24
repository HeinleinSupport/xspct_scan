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
# Run only the HTTP endpoint tests
pytest -v -k "TestScan or TestQuery or TestAdmin"

# Run only unit tests (no HTTP)
pytest -v -k "not TestScan and not TestQuery and not TestAuth and not TestMetrics and not TestHealth and not TestOpenApi"

# Run a single test
pytest "tests/test_olefy.py::TestAnalyzeArchive::test_zip_with_pdf_extracted" -v

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
| `yara-python` / `yara-x` not installed | `TestAnalyzeYaraNoEngine` is always active; `TestSyncAnalyzeYara::test_yara_called_when_rules_loaded` uses `monkeypatch` and runs unconditionally |

Install all extras to minimise skips:

```bash
pip install -e ".[dev,enrichment,openapi,advanced]"
```

## Test structure

```
tests/
├── conftest.py          # pytest configuration, shared constants, autouse fixtures
├── __init__.py
├── test_olefy.py        # all tests (unit + integration)
└── fixtures/
    ├── autostart-encrypt-standardpassword.xls
    ├── RTF-Spec-1.7.rtf
    └── passwords.txt
```

`test_olefy.py` is organised into test classes:

| Class | Type | What it tests |
|-------|------|---------------|
| `TestSessionHelpers` | unit | Session ID generation |
| `TestApiKeyVerification` | unit | `xspct_api_key` auth logic |
| `TestVerifyAdminKey` | unit | `xspct_admin_api_key` admin auth |
| `TestExtractIocs` | unit | URL / IP / domain extraction |
| `TestAnalyzePdf` | unit | PDF analyzer (clean, markers, IOCs) |
| `TestAnalyzePdfEncrypted` | unit | Encrypted PDF (requires PyMuPDF) |
| `TestAnalyzeHtml` | unit | HTML analyzer |
| `TestAnalyzeHtmlExtras` | unit | SpamRedirect, inline JS, data URIs |
| `TestAnalyzeJavascript` | unit | JS keyword detection |
| `TestAnalyzeImage` | unit | Image analyzer (empty, invalid, PNG) |
| `TestAnalyzeYaraNoEngine` | unit | YARA — no-engine path |
| `TestSyncAnalyzeYara` | unit | YARA called from `sync_analyze` when rules are loaded |
| `TestAnalyzeIocsearcher` | unit | iocsearcher integration |
| `TestAnalyzeArchive` | unit | ZIP extraction, depth/size guards, YARA on members |
| `TestAnalyzeText` | unit | `analyze_text()` — decode, preview, IOCs, limits |
| `TestExtractTextPreview` | unit | Text extraction strategies |
| `TestGetDetectedType` | unit | MIME / extension / magic-byte detection |
| `TestGetDetectedTypeExtended` | unit | Image / archive / text types |
| `TestMakeBaseReport` | unit | Report skeleton fields |
| `TestMergeReports` | unit | Classic merge fields |
| `TestMergeReportsNewFields` | unit | `yara_matches`, `iocs_extended`, `archive_files`, `exif`, `text_full` |
| `TestPartialReport` | unit | `PartialReport` snapshot + merge |
| `TestTextFull` | unit | `text_full` presence / absence |
| `TestTextTypePipeline` | integration | `text` detected type flows through `/scan` |
| `TestEvictTasks` | unit | In-memory task eviction |
| `TestSyncAnalyze` | unit | Full sync pipeline |
| `TestTextExtractorRtf` | unit | RTF text extractor |
| `TestLoadConfig` | unit | YAML config loading |
| `TestConfigureLogging` | unit | Logger setup |
| `TestHealthPingRoot` | integration | `GET /health`, `/ping`, `/` |
| `TestMetricsEndpoint` | integration | `GET /metrics` |
| `TestScanEndpoint` | integration | `POST /scan` (multipart) |
| `TestScanOctetStream` | integration | `POST /scan` (octet-stream, 415) |
| `TestQueryEndpoint` | integration | `GET|POST /query` |
| `TestAuthentication` | integration | API key enforcement |
| `TestAdminReload` | integration | `POST /admin/reload` |
| `TestOpenApiEndpoints` | integration | `GET /openapi.json`, `/apidoc/redoc` |

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
  for tests that require an optional dependency.
