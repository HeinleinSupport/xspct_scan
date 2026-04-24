# xspct_scan

**xspct_scan** is an async HTTP daemon that scans Office, PDF, and HTML documents
for malware indicators using [oletools](https://github.com/decalage2/oletools),
[msoffcrypto-tool](https://github.com/nolze/msoffcrypto-tool), and
[python-magic](https://github.com/ahupp/python-magic).

It exposes a simple HTTP API designed to integrate with
[Rspamd](https://rspamd.com/) and other mail-security pipelines.

```{toctree}
:maxdepth: 2
:caption: Contents

installation
configuration
api-http
api-python
changelog
```

## Quick start

```bash
pip install xspct_scan
xspct_scan /etc/xspct_scan/config.yml
```

Then scan a document:

```bash
curl -s -F "doc=@invoice.docx" http://localhost:8080/scan | python3 -m json.tool
```

## Licence

EUPL-1.2 — see [LICENSES/EUPL-1.2.txt](https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12)
for the full text.
