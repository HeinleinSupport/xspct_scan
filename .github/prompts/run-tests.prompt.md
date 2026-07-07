---
description: "Run the pytest test suite for xspct_scan. Supports optional -k filter and --cov for coverage. Shows full tracebacks on failure."
agent: agent
argument-hint: "Optional: -k <filter> or --cov"
tools: [execute, read]
---

Run the xspct_scan test suite with pytest.

## Steps

1. Build the pytest command based on any arguments provided:
   - No argument → run all tests
   - `-k <filter>` → run matching tests only: `pytest -k "<filter>"`
   - `--cov` or `coverage` → add `--cov=xspct_scan --cov-report=term-missing`
   - A file path → run that file only

2. **Run pytest** from the project root:
   ```bash
   .venv/bin/python -m pytest -v --tb=short
   ```
   Append any flags derived from the argument above.

3. **Report results**:
   - Total passed / failed / errors / skipped
   - For each failure: test name, file, line, full error message and traceback
   - For each error: same detail
   - If coverage was requested: coverage percentage per module and overall total

## Notes

- Tests use `pytest-asyncio` with `asyncio_mode = "auto"` — all async tests run without extra decorators.
- Test email addresses always use `@mailexample.de`. Flag any test that uses a different domain as a bug.
- The `delay` backend (`db_type: delay`) is used to test timeout/queue behaviour; its tests may take slightly longer.
