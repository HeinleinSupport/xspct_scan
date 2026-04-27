# xspct_scan

**xspct_scan** is an async HTTP daemon that analyses Office, PDF, HTML, image,
and archive files for malware indicators using
[oletools](https://github.com/decalage2/oletools),
[msoffcrypto-tool](https://github.com/nolze/msoffcrypto-tool),
[PyMuPDF](https://pymupdf.readthedocs.io/), and optional enrichment libraries
(YARA, iocsearcher, pytesseract, pyzbar, py7zr).

It exposes a simple HTTP API designed to integrate with
[Rspamd](https://rspamd.com/) and other mail-security pipelines.

```{toctree}
:maxdepth: 2
:caption: User Guide

guide/installation
guide/configuration
guide/api-http
guide/api-python
guide/development
```

```{toctree}
:maxdepth: 2
:caption: API Reference

reference/index
```

```{toctree}
:maxdepth: 1
:caption: Project

changelog
license
```

## Quick start

```bash
pip install xspct_scan
xspct_scan /etc/xspct_scan/config.yml
```

Then scan a document:

```bash
curl -s -F "doc=@invoice.docx" http://localhost:8080/v1/scan | python3 -m json.tool
```

## Licence

EUPL-1.2 — see [LICENSES/EUPL-1.2.txt](https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12)
for the full text.
