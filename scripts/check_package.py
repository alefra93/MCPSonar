"""Check built distributions before anyone installs them: ``python scripts/check_package.py dist``.

Run after ``python -m build`` (CI does, on every push). It fails (exit 1) on:

* a version that differs between ``pyproject.toml``, ``mcpsonar.__version__`` and the files;
* metadata PyPI and installers rely on: name, ``Requires-Python``, license, project URLs,
  the ``mcpsonar`` console script, a Markdown long description;
* README links or images that are relative (they break on PyPI): use absolute URLs;
* wheel content outside the package, or caches, databases and local configs in either file.

Standard library only, so it runs before anything is installed.
"""

from __future__ import annotations

import re
import sys
import tarfile
import tomllib
import zipfile
from email.parser import Parser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN = re.compile(r"(^|/)(__pycache__|\.venv|\.claude|\.pytest_cache|\.ruff_cache)(/|$)"
                       r"|\.pyc$|\.db$|(^|/)config\.yaml$")
RELATIVE_LINK = re.compile(r"\]\((?!https?://|#|mailto:)[^)\s]+\)|(?:src|href)=\"(?!https?://|#|mailto:)[^\"]+\"")
REQUIRED_URLS = {"Homepage", "Repository", "Changelog", "Issues"}


def _expected_version() -> str:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    init = (ROOT / "src" / "mcpsonar" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "([^"]+)"', init, re.MULTILINE)
    package = match.group(1) if match else None
    if package != project["version"]:
        sys.exit(f"pyproject.toml says {project['version']}, mcpsonar.__version__ says {package}")
    return project["version"]


def check_wheel(path: Path, version: str) -> list[str]:
    problems = []
    with zipfile.ZipFile(path) as wheel:
        names = wheel.namelist()
        dist_info = f"mcpsonar-{version}.dist-info/"
        meta = Parser().parsestr(wheel.read(dist_info + "METADATA").decode("utf-8"))
        entry_points = wheel.read(dist_info + "entry_points.txt").decode("utf-8")
    for name in names:
        if not name.startswith(("mcpsonar/", dist_info)):
            problems.append(f"wheel: unexpected file outside the package: {name}")
        if FORBIDDEN.search(name):
            problems.append(f"wheel: should not ship {name}")
    for needed in ("mcpsonar/__init__.py", "mcpsonar/cli.py", "mcpsonar/storage.py"):
        if needed not in names:
            problems.append(f"wheel: missing {needed}")

    if meta["Name"] != "mcpsonar" or meta["Version"] != version:
        problems.append(f"metadata: {meta['Name']} {meta['Version']}, expected mcpsonar {version}")
    if meta["Requires-Python"] != ">=3.11":
        problems.append(f"metadata: Requires-Python is {meta['Requires-Python']!r}")
    if not (meta["License"] or meta["License-Expression"] or meta.get_all("License-File")):
        problems.append("metadata: no license")
    urls = {u.split(",", 1)[0].strip() for u in meta.get_all("Project-URL") or []}
    if missing := REQUIRED_URLS - urls:
        problems.append(f"metadata: missing project URLs {sorted(missing)}")
    if meta["Description-Content-Type"] != "text/markdown":
        problems.append(f"metadata: long description is {meta['Description-Content-Type']!r}")
    for link in RELATIVE_LINK.findall(meta.get_payload() or ""):
        problems.append(f"README: relative link breaks on PyPI: {link}")
    if "mcpsonar = mcpsonar.cli:main" not in entry_points:
        problems.append("entry points: no `mcpsonar` console script")
    print(f"wheel  {path.name}: {len(names)} files")
    return problems


def check_sdist(path: Path, version: str) -> list[str]:
    problems = []
    prefix = f"mcpsonar-{version}/"
    with tarfile.open(path) as sdist:
        names = [m.name for m in sdist.getmembers() if m.isfile()]
    for name in names:
        if not name.startswith(prefix):
            problems.append(f"sdist: unexpected top-level path {name}")
        elif FORBIDDEN.search(name[len(prefix):]):
            problems.append(f"sdist: should not ship {name}")
    for needed in ("pyproject.toml", "README.md", "LICENSE", "src/mcpsonar/__init__.py"):
        if prefix + needed not in names:
            problems.append(f"sdist: missing {needed}")
    size = path.stat().st_size // 1024
    print(f"sdist  {path.name}: {len(names)} files, {size} KiB")
    return problems


def main(dist: str) -> int:
    version = _expected_version()
    folder = Path(dist)
    wheels = sorted(folder.glob(f"mcpsonar-{version}-*.whl"))
    sdists = sorted(folder.glob(f"mcpsonar-{version}.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        print(f"expected one wheel and one sdist for {version} in {folder}, found "
              f"{[p.name for p in folder.iterdir()]}")
        return 1
    problems = check_wheel(wheels[0], version) + check_sdist(sdists[0], version)
    for problem in problems:
        print(f"  FAIL {problem}")
    print("package OK" if not problems else f"{len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "dist"))
