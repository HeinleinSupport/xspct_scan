---
description: "Run all code quality checks: ruff lint and REUSE/SPDX compliance. Reports issues on modified or all source files."
agent: agent
tools: [execute, search, read]
---

Run all code quality checks for xspct_scan.

## Steps

1. **Determine scope**: If the user specified files or a scope (e.g. "modified files"), use that.
   Otherwise check all source files:
   ```
   src/xspct_scan/
   tests/
   ```

2. **Ruff lint** — report every issue with file, line, and rule code:
   ```bash
   .venv/bin/ruff check src/ tests/
   ```
   If `.venv/bin/ruff` is not available try `ruff check src/ tests/`.

3. **REUSE / SPDX compliance** — every source file must have lines 1–2:
   ```
   # SPDX-License-Identifier: EUPL-1.2
   # SPDX-FileCopyrightText: <year> Carsten Rosenberg <c.rosenberg@heinlein-support.de>
   ```
   Run:
   ```bash
   .venv/bin/reuse lint
   ```
   If reuse is not installed, manually scan for files that are missing the SPDX header.

## Output

Summarise:
- Count of ruff issues (or "no issues")
- List of REUSE violations (or "compliant")
- For each issue: file path, line number, rule / description
- Suggested fix for each issue where applicable
