"""``mcpsonar version`` (also ``mcpsonar --version``)."""

from __future__ import annotations

import platform
import sys
from importlib import metadata
from typing import Any

from .. import __version__
from ..output import EXIT_OK, add_format_args, output_for


def dependency_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def version_line() -> str:
    return (f"mcpsonar {__version__} (mcp {dependency_version('mcp') or '?'}, "
            f"Python {platform.python_version()}, {platform.system()})")


def register(sub: Any) -> None:
    p = sub.add_parser("version", help="Show the versions of mcpsonar, the MCP SDK and Python.")
    add_format_args(p)
    p.set_defaults(handler=run)


def run(args: Any) -> int:
    out = output_for(args)
    if out.json_mode:
        out.emit_json("version", {
            "mcpsonar": __version__,
            "mcp": dependency_version("mcp"),
            "python": platform.python_version(),
            "platform": sys.platform,
        })
    else:
        out.print(version_line())
    return EXIT_OK
