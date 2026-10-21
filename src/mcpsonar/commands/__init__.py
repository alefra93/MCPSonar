"""CLI commands beyond ``run`` / ``scan`` / ``demo``.

Each module exposes ``register(subparsers)``: it adds its sub-command(s) and sets
``handler`` (an ``async`` or plain callable taking the parsed args, returning an exit code)
as a parser default. ``mcpsonar.cli.main`` dispatches to it. Commands only parse, call
:mod:`mcpsonar.services` (or other shared modules) and render through :mod:`mcpsonar.output`
— no command talks MCP itself.
"""

from __future__ import annotations

from typing import Any

from . import config_cmd, doctor, inspect_cmd, monitor_cmd, servers_cmd, version


def register_all(subparsers: Any) -> None:
    for module in (monitor_cmd, servers_cmd, inspect_cmd, config_cmd, doctor, version):
        module.register(subparsers)
