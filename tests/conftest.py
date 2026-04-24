# SPDX-License-Identifier: EUPL-1.2
# Copyright (C) 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""
Pytest configuration for the xspct_scan test suite.

Provides:
  - session-scoped logging setup
  - FIXTURES_DIR / OLE_FILE / RTF_FILE / PASSWD_FILE constants
  - reset_global_state autouse fixture

CLI options:
  --oletools-testdata PATH
      Path to the oletools tests/test-data directory.
      When given, OLE_FILE and RTF_FILE are resolved from that tree instead
      of the local tests/fixtures/ copies.
      Example:
          pytest --oletools-testdata /home/cr/git/oletools/tests/test-data
"""

import os
from pathlib import Path

import xspct_scan.daemon as xspct

# ---------------------------------------------------------------------------
# Logging — configure once for the whole test session
# ---------------------------------------------------------------------------
xspct.configure_logging()

# ---------------------------------------------------------------------------
# Fixture file locations (populated by pytest_configure below)
# ---------------------------------------------------------------------------
FIXTURES_DIR = Path(__file__).parent / 'fixtures'
OLE_FILE:    str = ''
RTF_FILE:    str = ''
PASSWD_FILE: str = ''

# Generated fixtures (created by tests/create_fixtures.py)
PDF_JS_FILE:       str = str(FIXTURES_DIR / 'pdf_javascript.pdf')
PDF_EMBEDDED_FILE: str = str(FIXTURES_DIR / 'pdf_embedded.pdf')
PDF_URI_FILE:      str = str(FIXTURES_DIR / 'pdf_uri.pdf')
HTML_PHISHING_FILE:str = str(FIXTURES_DIR / 'html_phishing.html')
ARCHIVE_MIXED_FILE:str = str(FIXTURES_DIR / 'archive_mixed.zip')
EML_FILE:          str = str(FIXTURES_DIR / 'email_with_attachment.eml')
QR_FILE:           str = str(FIXTURES_DIR / 'qr_code.png')


def pytest_addoption(parser):
    parser.addoption(
        '--oletools-testdata',
        metavar='PATH',
        default=None,
        help='Path to oletools tests/test-data directory (overrides local fixture copies)',
    )


def pytest_configure(config):
    global OLE_FILE, RTF_FILE, PASSWD_FILE
    td = config.getoption('--oletools-testdata', default=None)
    if td:
        base = Path(td)
        OLE_FILE = str(base / 'encrypted' / 'autostart-encrypt-standardpassword.xls')
        RTF_FILE = str(base / 'msodde' / 'RTF-Spec-1.7.rtf')
    else:
        OLE_FILE = str(FIXTURES_DIR / 'autostart-encrypt-standardpassword.xls')
        RTF_FILE = str(FIXTURES_DIR / 'RTF-Spec-1.7.rtf')
    PASSWD_FILE = str(FIXTURES_DIR / 'passwords.txt')
