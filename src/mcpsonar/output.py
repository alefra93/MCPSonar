"""Terminal output shared by every CLI command: colors, tables, JSON, diagnostics, exit codes.

Conventions every command follows:

* **stdout** carries the result (a table, or JSON with ``--format json``); **stderr** carries
  diagnostics. JSON mode prints exactly one JSON document and nothing else.
* Colors only when stdout is a terminal, ``NO_COLOR`` is unset and ``--no-color`` was not
  given. Meaning never depends on color: statuses are words, severities are words.
* JSON documents carry ``"kind"`` and ``"schema_version"`` so scripts can rely on them;
  fields are only ever added within a schema version.
* Exit codes (stable, shared with ``mcpsonar scan``'s CI contract):

  ===  ============================================================================
  0    success, nothing at or above the failure threshold
  1    the command worked and found a problem: findings at/above ``--fail-on``,
       lockfile drift, a server not healthy, a failed doctor check
  2    the command could not do its job: usage error, unreachable server, invalid
       configuration or input
  130  interrupted (Ctrl-C)
  ===  ============================================================================
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Sequence
from typing import Any, TextIO

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_ERROR = 2
EXIT_INTERRUPTED = 130

SCHEMA_VERSION = 1
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def color_enabled(stream: TextIO, no_color_flag: bool = False) -> bool:
    if no_color_flag or "NO_COLOR" in os.environ:
        return False
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


class Style:
    """ANSI styling that degrades to plain text."""

    def __init__(self, enabled: bool) -> None:
        self.on = enabled

    def __call__(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.on else text

    def bold(self, t: str) -> str:
        return self(t, "1")

    def dim(self, t: str) -> str:
        return self(t, "2")

    def red(self, t: str) -> str:
        return self(t, "31")

    def green(self, t: str) -> str:
        return self(t, "32")

    def yellow(self, t: str) -> str:
        return self(t, "33")

    def cyan(self, t: str) -> str:
        return self(t, "36")

    def severity(self, sev: str, width: int = 0) -> str:
        """A severity as an upper-case word (padded before coloring, so columns align)."""
        word = sev.upper().ljust(width)
        return {"high": self.red, "medium": self.yellow}.get(sev, self.dim)(word)


def visible_len(text: str) -> int:
    return len(_ANSI.sub("", text))


def table(headers: Sequence[str], rows: Sequence[Sequence[str]], style: Style) -> str:
    """A plain aligned table (no box drawing: it copies cleanly into issues and chats)."""
    widths = [visible_len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], visible_len(cell))

    def line(cells: Sequence[str]) -> str:
        padded = [c + " " * (w - visible_len(c)) for c, w in zip(cells, widths, strict=True)]
        return "  ".join(padded).rstrip()

    return "\n".join([style.bold(line(headers)), *(line(r) for r in rows)])


class Output:
    """Where a command writes. Built once per invocation from the global options."""

    def __init__(
        self,
        fmt: str = "text",
        no_color: bool = False,
        stdout: TextIO | None = None,
        stderr: TextIO | None = None,
    ) -> None:
        self.fmt = fmt
        self.stdout = stdout or sys.stdout
        self.stderr = stderr or sys.stderr
        self.style = Style(fmt == "text" and color_enabled(self.stdout, no_color))
        self.err_style = Style(color_enabled(self.stderr, no_color))

    @property
    def json_mode(self) -> bool:
        return self.fmt == "json"

    def print(self, text: str = "") -> None:
        print(text, file=self.stdout)

    def emit_json(self, kind: str, payload: dict[str, Any]) -> None:
        doc = {"kind": kind, "schema_version": SCHEMA_VERSION, **payload}
        print(json.dumps(doc, indent=2, ensure_ascii=False, default=str), file=self.stdout)

    def warn(self, message: str) -> None:
        print(f"{self.err_style.yellow('warning:')} {message}", file=self.stderr)

    def error(self, message: str) -> None:
        print(f"{self.err_style.red('error:')} {message}", file=self.stderr)


def add_format_args(parser: Any, formats: Sequence[str] = ("text", "json")) -> None:
    """``--format`` (and ``--json`` as a shorthand) plus ``--no-color``, for every command."""
    parser.add_argument("--format", choices=list(formats), default="text",
                        help="Output format (default: text).")
    parser.add_argument("--json", dest="format", action="store_const", const="json",
                        help="Shorthand for --format json.")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colors (also: NO_COLOR environment variable).")


def output_for(args: Any) -> Output:
    return Output(fmt=getattr(args, "format", "text"), no_color=getattr(args, "no_color", False))
