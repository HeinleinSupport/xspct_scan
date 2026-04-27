# Python API

The public Python API lives in `xspct_scan.daemon`.

## Feature flags

The following module-level booleans are set at import time based on which
optional dependencies are installed:

| Flag | `True` when |
|------|-------------|
| `HAS_PYMUPDF` | `PyMuPDF` (`fitz`) is installed |
| `HAS_JSBEAUTIFIER` | `jsbeautifier` is installed |
| `HAS_QUICKJS` | `quickjs` is installed |
| `HAS_OCR` | `Pillow` + `pytesseract` are installed |
| `HAS_PYZBAR` | `pyzbar` is installed |
| `HAS_PYDANTIC` | `pydantic>=2` is installed |
| `HAS_YARA` | `yara-python` is installed |
| `HAS_YARA_HYPERSCAN` | yara-python was compiled with Hyperscan |
| `HAS_YARA_X` | `yara-x` is installed |
| `HAS_IOCSEARCHER` | `iocsearcher` is installed |
| `HAS_PDFID` | Vendored `pdfid.py` loaded successfully |
| `HAS_SFLOCK` | `SFlock2` is installed (sandboxed archive extraction) |

## Module-level objects

```{eval-rst}
.. autodata:: xspct_scan.daemon.config
.. autodata:: xspct_scan.daemon.stats
```

## Functions

```{eval-rst}
.. autofunction:: xspct_scan.daemon.load_config
.. autofunction:: xspct_scan.daemon.configure_logging
.. autofunction:: xspct_scan.daemon.make_app
```

## PartialReport

```{eval-rst}
.. autoclass:: xspct_scan.daemon.PartialReport
   :members:
   :undoc-members:
```

## InspectorDaemon

```{eval-rst}
.. autoclass:: xspct_scan.daemon.InspectorDaemon
   :members:
   :undoc-members:
   :show-inheritance:
```
