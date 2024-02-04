# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))


# -- Project information -----------------------------------------------------

project = 'PowerHub'
copyright = '2018-2023, Adrian Vollmer'
author = 'Adrian Vollmer'

# The full version, including alpha/beta/rc tags
release = "2.0.7"


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = ["myst_parser"]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# Add read the docs lower left menu
try:
    html_context
except NameError:
    html_context = dict()
html_context['display_lower_left'] = True

REPO_NAME = project
from git import Repo  # noqa
repo = Repo(search_parent_directories=True)
html_context['current_version'] = release
html_context['version'] = release
html_context['versions'] = list()
versions = set(['master', release])
versions.update([tag.name for tag in repo.tags
                 if tag.name.startswith('2.')])

# get tags from env variable (in case we are in a github action env)
import os
if 'git_tags' in os.environ:
    import json
    print('Tags:', os.environ['git_tags'])
    tags = json.loads(os.environ['git_tags'])
    tags = [t['ref'].split('/')[2] for t in tags]
    tags = [t for t in tags if t.startswith('2.')]
    print('Tags:', tags)
    versions.update(tags)
for version in versions:
    html_context['versions'].append((version, '/' + REPO_NAME + '/' + version + '/'))
html_context['versions'].append(('latest', '/' + REPO_NAME + '/latest/'))
html_context['versions'].sort(key=lambda k: k[0])

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store', 'docs']


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#

html_theme = 'sphinx_rtd_theme'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']
