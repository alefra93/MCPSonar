"""Which MCP server a command talks to, in local (direct) mode.

A target is one of:

* a URL — ``mcpsonar tools https://example.com/mcp`` (``-H`` for headers);
* ``--stdio "command args"`` — a local server launched for this command;
* a server *name* from a YAML config — ``mcpsonar tools my-server --config servers.yaml``.

Names of servers stored in a *running* instance are a remote-mode feature (planned for
v0.7, through the instance's authenticated API — never by opening its database).
"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from ..loader import ConfigError, load_config
from ..models import ServerConfig
from ..scan import build_config


class TargetError(Exception):
    """The target could not be resolved; the message says what to do instead."""


def add_target_args(parser: Any) -> None:
    parser.add_argument("target", nargs="?",
                        help="Server URL, or a server name from --config.")
    parser.add_argument("--stdio", metavar="CMD",
                        help='Launch a stdio server instead, e.g. --stdio "npx -y @scope/server".')
    parser.add_argument("--config", metavar="FILE",
                        help="YAML config file: TARGET is the name of a server in it.")
    parser.add_argument("--transport", choices=["http", "sse"],
                        help="Force the transport for a URL (default: sse if it ends in /sse).")
    parser.add_argument("-H", "--header", action="append", default=[], metavar="'K: V'",
                        help="HTTP header, repeatable (e.g. -H 'Authorization: Bearer ...').")
    parser.add_argument("-e", "--env", action="append", default=[], metavar="K=V",
                        help="Environment variable for --stdio, repeatable.")
    parser.add_argument("--timeout", type=float, default=20.0,
                        help="Seconds per request (default 20).")


def resolve_target(args: Any) -> tuple[ServerConfig, str]:
    """``(config, display label)`` for the command's target. The label never contains
    credentials (URLs are redacted)."""
    if args.config:
        try:
            config = load_config(args.config)
        except (ConfigError, ValidationError, OSError) as exc:
            raise TargetError(f"cannot use {args.config}: {exc}") from exc
        names = list(config.servers)
        name = args.target
        if name is None and len(names) == 1:
            name = names[0]
        if name not in config.servers:
            hint = ", ".join(names) or "(none)"
            raise TargetError(f"no server named {name!r} in {args.config}; servers: {hint}")
        return config.servers[name], name
    if not args.stdio and not args.target:
        raise TargetError('give a server URL, --stdio "command args", or NAME --config FILE')
    if args.target and not args.stdio and "://" not in args.target:
        raise TargetError(
            f"{args.target!r} is not a URL. To use a server by name, pass --config FILE."
        )
    if any("=" not in e for e in args.env):
        raise TargetError("--env takes K=V")
    try:
        return build_config(args.target, args.stdio, args.transport, args.header, args.env)
    except (ValidationError, ValueError) as exc:
        raise TargetError(f"invalid target: {exc}") from exc
