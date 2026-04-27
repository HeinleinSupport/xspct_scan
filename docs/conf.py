# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""Sphinx configuration for xspct_scan documentation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / 'src'))

from xspct_scan import __version__  # noqa: E402

# -- Project information -------------------------------------------------------
project   = 'xspct_scan'
author    = 'Carsten Rosenberg'
copyright = '2026, Carsten Rosenberg'
release   = __version__
version   = '.'.join(__version__.split('.')[:2])

# -- General configuration -----------------------------------------------------
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    'sphinx.ext.viewcode',
    'sphinx.ext.napoleon',
    'sphinx.ext.intersphinx',
    'sphinx_autodoc_typehints',
    'myst_parser',
]

templates_path   = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# (MyST source_suffix and extensions are configured below, near HTML output)

# -- autodoc -------------------------------------------------------------------
autodoc_default_options = {
    'members': True,
    'undoc-members': True,
    'show-inheritance': True,
    'special-members': '__init__',
}
autodoc_member_order                   = 'bysource'
autodoc_typehints                      = 'description'
autodoc_typehints_format               = 'short'
autodoc_typehints_description_target   = 'documented'
autosummary_generate                   = True

# -- Napoleon ------------------------------------------------------------------
napoleon_google_docstring      = True
napoleon_numpy_docstring       = False
napoleon_include_init_with_doc = True

# -- Intersphinx ---------------------------------------------------------------
intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
    'aiohttp': ('https://docs.aiohttp.org/en/stable/', None),
}

# -- MyST / source suffix -----------------------------------------------------
myst_enable_extensions = ['colon_fence', 'deflist']
source_suffix = {
    '.md': 'markdown',
}

# -- HTML output ---------------------------------------------------------------
html_theme         = 'furo'
html_static_path   = ['_static']
html_title         = f'xspct_scan {release}'
html_short_title   = 'xspct_scan'
html_theme_options = {
    'sidebar_hide_name': False,
}
