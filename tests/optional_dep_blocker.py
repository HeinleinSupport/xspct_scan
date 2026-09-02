# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Pytest plugin that hides every optional dependency from the test suite.

Not loaded automatically — activate it explicitly for the dependency-free suite:

    python -m pytest -p tests.optional_dep_blocker -q

Use ``--collect-only`` when only collection safety needs checking. Run via
``python -m pytest``, not the bare ``pytest`` script: ``-p`` imports the
plugin before pytest puts the repo root on ``sys.path``, and only
``python -m`` does that in time.

xspct_scan must degrade cleanly when an optional library is absent: analyzers
skip instead of raising, and the tests covering them skip instead of failing.
That contract is easy to break in a way the normal CI matrix cannot see,
because CI installs every extra.  The failure mode is specifically nasty for
``conftest.py``: an optional import whose ``except ImportError`` branch forgets
to bind the alias leaves the name undefined, so every module doing
``from tests.conftest import _pymupdf`` dies during *collection* — before any
``skipif`` marker can apply, taking the whole suite with it.

Loading this plugin installs a meta-path hook that raises ImportError for all
optional modules, which reproduces a bare install without needing one.  Because
``-p`` plugins load before ``conftest.py`` is imported, the hook is already in
place when the suite starts importing things.
"""

import sys

# Optional imports guarded by HAS_* / _HAS_* flags in src/xspct_scan/daemon.py
# and the test suite. pymupdf is a hard dependency in pyproject.toml but is
# still feature-gated behind HAS_PYMUPDF, so it belongs here too.
BLOCKED_ROOTS = frozenset(
    {
        "clamd",
        "cbor2",
        "easyocr",
        "fakeredis",
        "fitz",
        "iocsearcher",
        "jsbeautifier",
        "LnkParse3",
        "lupa",
        "msgpack",
        "odfdo",
        "PIL",
        "py7zr",
        "pydantic",
        "pyhanko",
        "pymupdf",
        "pytesseract",
        "pyzbar",
        "quickjs",
        "redis",
        "sflock",
        "tldextract",
        "tree_sitter",
        "tree_sitter_javascript",
        "yara",
        "yara_x",
        "zstandard",
    }
)


class _OptionalDepBlocker:
    """Meta-path finder that refuses to import any optional dependency."""

    def find_spec(self, fullname, path=None, target=None):
        if fullname.partition(".")[0] in BLOCKED_ROOTS:
            raise ImportError(
                f"{fullname} is hidden by tests.optional_dep_blocker "
                "(simulating an install without optional extras)"
            )
        return None


def _install() -> None:
    # Drop anything already imported so the hook also applies to modules a
    # earlier import pulled in (pytest imports some of these itself).
    for name in list(sys.modules):
        if name.partition(".")[0] in BLOCKED_ROOTS:
            del sys.modules[name]
    if not any(isinstance(f, _OptionalDepBlocker) for f in sys.meta_path):
        sys.meta_path.insert(0, _OptionalDepBlocker())


_install()
