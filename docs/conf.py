# SPDX-License-Identifier: EUPL-1.2
# Copyright (C) 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
# Sphinx configuration for olefy_v2

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / 'src'))

# -- Project information -------------------------------------------------------
project   = 'olefy_v2'
author    = 'Carsten Rosenberg'
copyright = '2026, Carsten Rosenberg'
release   = '2.0.0'

# -- General configuration -----------------------------------------------------
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
    'sphinx.ext.napoleon',
    'sphinx_autodoc_typehints',
    'myst_parser',
]

templates_path   = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# MyST extensions (enables admonitions, colon fences, etc.)
myst_enable_extensions = ['colon_fence', 'deflist']

# -- autodoc -------------------------------------------------------------------
autodoc_member_order       = 'bysource'
autodoc_typehints          = 'description'
autodoc_typehints_format   = 'short'

# -- HTML output ---------------------------------------------------------------
html_theme         = 'furo'
html_static_path   = ['_static']
html_title         = 'olefy_v2'
html_short_title   = 'olefy_v2'
