"""Packaging invariants cheap enough to run with every test run (the full wheel/sdist check
is scripts/check_package.py, run by CI on built files)."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import mcpsonar

ROOT = Path(__file__).resolve().parent.parent


def test_one_version_everywhere():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["version"] == mcpsonar.__version__


def test_readme_has_no_relative_links():
    # PyPI renders the README without the repository around it: relative links break there.
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    relative = re.findall(r"\]\((?!https?://|#|mailto:)[^)\s]+\)|(?:src|href)=\"(?!https?://|#|mailto:)[^\"]+\"",
                          readme)
    assert relative == []
