---
description: "Generate and commit the dependency SBOM for xspct_scan (CycloneDX JSON via cyclonedx-bom)."
agent: agent
tools: [execute, read]
---

Generate the dependency SBOM for xspct_scan and commit the result.

## Prerequisites

The active virtualenv must have all optional extras installed for full dependency coverage:

```bash
pip install -e ".[uvloop,redis,enrichment,openapi,advanced,dev]"
```

## Steps (run in order — stop and report on failure)

### 1. Generate dependency SBOM (CycloneDX JSON)

Covers the installed dependency tree:

```bash
.venv/bin/cyclonedx-py environment --of JSON -o bom.json
```

Report the number of components listed.

### 2. Verify REUSE compliance still passes

```bash
.venv/bin/reuse lint
```

Stop on any violations.

### 3. Stage the file

```bash
git add bom.json
git diff --cached --stat
```

### 4. Commit

```bash
git commit -S -m "[Docs] Update dependency SBOM"
```

Remind the user to verify their GPG key is available (`gpg --list-secret-keys`) before committing.
