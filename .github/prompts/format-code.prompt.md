---
description: "Auto-format Python source code with ruff. Reports which files were changed."
agent: agent
tools: [execute, read]
---

Format all Python source files in xspct_scan with ruff.

## Steps

1. **Format** source and test files:
   ```bash
   .venv/bin/ruff format src/ tests/
   ```
   If `.venv/bin/ruff` is not available try `ruff format src/ tests/`.

2. **Check import order** (ruff's isort-compatible `I` rules):
   ```bash
   .venv/bin/ruff check --select I --fix src/ tests/
   ```

3. **Report** which files were reformatted (ruff prints "X files reformatted, Y files left unchanged").
   If no files changed, confirm "already formatted".

## Notes

- ruff format follows the project's `line-length = 100` configured in `pyproject.toml`.
- Do NOT auto-fix lint errors beyond import ordering — use `/check-code` to review other issues first.
- After formatting, remind the user to stage the changed files before committing.
