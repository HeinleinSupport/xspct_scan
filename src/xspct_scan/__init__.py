# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""xspct_scan – Async HTTP daemon for scanning Office/PDF/HTML documents for malware indicators."""

try:
    from importlib.metadata import version as _pkg_version

    __version__: str = _pkg_version("xspct_scan")
except Exception:  # package not installed (editable install not yet synced)
    __version__ = "unknown"
__author__ = "Carsten Rosenberg"
__email__ = "c.rosenberg@heinlein-support.de"
__license__ = "EUPL-1.2"
