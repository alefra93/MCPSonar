"""``mcpsonar servers``: the servers a running instance monitors (remote mode).

Credentials are masked by the instance itself (the API never returns them), so nothing
printed here can leak a token. Changes go through the same endpoints as the dashboard:
validation, secret handling (masked values sent back mean "unchanged"), the stdio policy
and the live scheduler update all happen on the instance, once.

Commands that change something need a *write* token. ``remove`` asks for confirmation on
a terminal and refuses to run unattended without ``--yes``.
"""

from __future__ import annotations

import os
import sys
from typing import Any

import yaml

from ..output import EXIT_ERROR, EXIT_OK, Output, add_format_args, output_for, table
from ..scan import split_command
from ._remote import Remote, RemoteError, add_remote_args, server_path

# Fields of a server the API accepts on create/update (ServerInput = ServerConfig + name,
# enabled); everything else in a GET response (the id) is dropped before a PUT.
_INPUT_FIELDS = (
    "name", "enabled", "transport", "url", "headers", "command", "args", "env",
    "check_interval_seconds", "tools_to_test", "thresholds", "webhooks", "on_tool_change",
    "anomaly",
)


def register(sub: Any) -> None:
    servers = sub.add_parser("servers", help="List, inspect and manage monitored servers "
                                             "(remote).")
    actions = servers.add_subparsers(dest="servers_action", required=True, metavar="ACTION")

    lst = actions.add_parser("list", help="Every monitored server.")
    add_remote_args(lst)
    add_format_args(lst)
    lst.set_defaults(handler=run_list)

    show = actions.add_parser("show", help="One server's configuration (credentials masked).")
    show.add_argument("server", help="Server name or id.")
    add_remote_args(show)
    add_format_args(show, formats=("yaml", "json"))
    show.set_defaults(handler=run_show, format="yaml")

    add = actions.add_parser(
        "add", help="Start monitoring a server (write token).",
        description="Add a server; the instance starts checking it immediately. Prefer "
        "--header-from-env for credentials: values given with -H end up in shell history.")
    add.add_argument("name", help="Display name.")
    target = add.add_mutually_exclusive_group(required=True)
    target.add_argument("--endpoint", dest="server_url", metavar="URL",
                        help="The MCP server's Streamable HTTP or SSE URL (--url is the "
                        "MCPSonar instance).")
    target.add_argument("--stdio", metavar="CMD",
                        help='A local server the instance launches, e.g. "npx -y pkg@1.2.3".')
    add.add_argument("--transport", choices=["http", "sse"],
                     help="For --endpoint (default: sse if the URL ends in /sse).")
    _add_config_args(add)
    add.add_argument("--paused", action="store_true", help="Add it paused (not checked).")
    add_remote_args(add)
    add_format_args(add)
    add.set_defaults(handler=run_add)

    edit = actions.add_parser(
        "edit", help="Change a server's settings (write token).",
        description="Only the options given are changed; everything else, credentials "
        "included, is kept.")
    edit.add_argument("server", help="Server name or id.")
    edit.add_argument("--name", dest="new_name", help="New display name.")
    edit.add_argument("--endpoint", dest="server_url", metavar="URL",
                      help="New MCP server URL.")
    _add_config_args(edit)
    edit.add_argument("--remove-header", action="append", default=[], metavar="NAME",
                      help="Drop a header, repeatable.")
    edit.add_argument("--clear-probes", action="store_true",
                      help="Remove every tool probe.")
    add_remote_args(edit)
    add_format_args(edit)
    edit.set_defaults(handler=run_edit)

    for verb, help_text in (("pause", "Stop checking a server (history is kept)."),
                            ("resume", "Resume checking a paused server.")):
        p = actions.add_parser(verb, help=f"{help_text} (write token)")
        p.add_argument("server", help="Server name or id.")
        add_remote_args(p)
        add_format_args(p)
        p.set_defaults(handler=run_pause if verb == "pause" else run_resume)

    rm = actions.add_parser(
        "remove", help="Stop monitoring a server and delete its history (write token).",
        description="Deletes the server, its check history and its tool baseline. Asks for "
        "confirmation on a terminal; anywhere else it requires --yes.")
    rm.add_argument("server", help="Server name or id.")
    rm.add_argument("-y", "--yes", action="store_true", help="Do not ask for confirmation.")
    add_remote_args(rm)
    add_format_args(rm)
    rm.set_defaults(handler=run_remove)


def _add_config_args(p: Any) -> None:
    p.add_argument("-H", "--header", action="append", default=[], metavar="'K: V'",
                   help="HTTP header, repeatable.")
    p.add_argument("--header-from-env", action="append", default=[], metavar="K=VAR",
                   help="HTTP header K whose value is read from environment variable VAR "
                   "(keeps the secret out of shell history), repeatable.")
    p.add_argument("-e", "--env", action="append", default=[], metavar="K=V",
                   help="Environment variable for a stdio server, repeatable.")
    p.add_argument("--interval", type=int, metavar="SECONDS", help="Check interval.")
    p.add_argument("--probe", action="append", default=[], metavar="TOOL",
                   help="Tool to call on every check (no arguments), repeatable. Only probe "
                   "tools that are safe to call repeatedly.")
    p.add_argument("--degraded-ms", type=float, help="Latency threshold for degraded.")
    p.add_argument("--down-ms", type=float, help="Latency threshold for down.")
    p.add_argument("--on-tool-change", choices=["degrade", "alert", "ignore"],
                   help="What a tool-definition change does to the status.")


class _InputError(Exception):
    pass


def _headers(args: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for h in args.header:
        key, sep, value = h.partition(":")
        if not sep or not key.strip():
            raise _InputError(f"-H takes 'Name: value', got {h!r}")
        out[key.strip()] = value.strip()
    for spec in args.header_from_env:
        key, sep, var = spec.partition("=")
        if not sep or not key.strip() or not var.strip():
            raise _InputError(f"--header-from-env takes NAME=ENV_VAR, got {spec!r}")
        value = os.environ.get(var.strip())
        if value is None:
            raise _InputError(f"environment variable {var.strip()} is not set")
        out[key.strip()] = value
    return out


def _env(args: Any) -> dict[str, str]:
    out = {}
    for item in args.env:
        key, sep, value = item.partition("=")
        if not sep or not key:
            raise _InputError(f"-e takes K=V, got {item!r}")
        out[key] = value
    return out


def _apply_common(body: dict[str, Any], args: Any) -> None:
    if args.interval is not None:
        body["check_interval_seconds"] = args.interval
    if args.degraded_ms is not None or args.down_ms is not None:
        thresholds = dict(body.get("thresholds") or {})
        if args.degraded_ms is not None:
            thresholds["latency_degraded_ms"] = args.degraded_ms
        if args.down_ms is not None:
            thresholds["latency_down_ms"] = args.down_ms
        body["thresholds"] = thresholds
    if args.on_tool_change:
        body["on_tool_change"] = args.on_tool_change


def _summary(server: dict[str, Any]) -> str:
    target = server.get("url") or " ".join([server.get("command") or "", *server.get("args", [])])
    state = "active" if server["enabled"] else "paused"
    return f"{server['name']} ({server['id']}) · {server['transport']} · {target} · {state}"


def _done(out: Output, kind: str, verb: str, server: dict[str, Any] | None) -> int:
    if out.json_mode:
        out.emit_json(kind, {"server": server})
    elif server is not None:
        out.print(f"{verb}: {_summary(server)}")
    return EXIT_OK


# ---- read --------------------------------------------------------------------- #
async def run_list(args: Any) -> int:
    out = output_for(args)
    try:
        async with Remote(args.url, out) as remote:
            servers = await remote.get("/api/servers")
    except RemoteError as exc:
        out.error(str(exc))
        return EXIT_ERROR
    if out.json_mode:
        out.emit_json("servers", {"servers": servers})
        return EXIT_OK
    if not servers:
        out.print("No servers monitored yet.")
        return EXIT_OK
    st = out.style
    rows = [[s["name"], s["id"], s["transport"], s["url"] or s["command"] or "",
             "yes" if s["enabled"] else st.dim("paused"), f"{s['check_interval_seconds']}s",
             str(len(s["tools_to_test"]))]
            for s in sorted(servers, key=lambda s: s["name"].lower())]
    out.print(table(["NAME", "ID", "TRANSPORT", "TARGET", "ENABLED", "INTERVAL", "PROBES"],
                    rows, st))
    return EXIT_OK


async def run_show(args: Any) -> int:
    out = output_for(args)
    try:
        async with Remote(args.url, out) as remote:
            server = await remote.resolve_server(args.server)
    except RemoteError as exc:
        out.error(str(exc))
        return EXIT_ERROR
    if args.format == "json":
        out.emit_json("server", {"server": server})
    else:
        out.print(yaml.safe_dump(server, sort_keys=False, allow_unicode=True).rstrip())
    return EXIT_OK


# ---- change ------------------------------------------------------------------- #
async def run_add(args: Any) -> int:
    out = output_for(args)
    try:
        body: dict[str, Any] = {"name": args.name, "enabled": not args.paused}
        if args.stdio:
            argv = split_command(args.stdio)
            if not argv:
                raise _InputError("--stdio needs a command")
            body.update(transport="stdio", command=argv[0], args=argv[1:], env=_env(args))
        else:
            url = args.server_url
            body.update(url=url, headers=_headers(args), transport=args.transport or (
                "sse" if url.rstrip("/").endswith("/sse") else "http"))
        if args.probe:
            body["tools_to_test"] = args.probe
        _apply_common(body, args)
    except _InputError as exc:
        out.error(str(exc))
        return EXIT_ERROR
    try:
        async with Remote(args.url, out) as remote:
            server = await remote.request("POST", "/api/servers", json=body)
    except RemoteError as exc:
        out.error(str(exc))
        return EXIT_ERROR
    return _done(out, "server", "added", server)


async def run_edit(args: Any) -> int:
    out = output_for(args)
    try:
        async with Remote(args.url, out) as remote:
            current = await remote.resolve_server(args.server)
            body = {k: current[k] for k in _INPUT_FIELDS if k in current}
            if args.new_name:
                body["name"] = args.new_name
            if args.server_url:
                if current["transport"] == "stdio":
                    raise _InputError("--endpoint does not apply to a stdio server")
                body["url"] = args.server_url
            headers = dict(body.get("headers") or {})  # masked values: kept by the instance
            for name in args.remove_header:
                headers = {k: v for k, v in headers.items() if k.lower() != name.lower()}
            headers.update(_headers(args))
            body["headers"] = headers
            if args.env:
                body["env"] = {**(body.get("env") or {}), **_env(args)}
            if args.clear_probes:
                body["tools_to_test"] = []
            if args.probe:
                existing = {p["name"]: p for p in body.get("tools_to_test") or []}
                body["tools_to_test"] = [existing.get(n, n) for n in args.probe]
            _apply_common(body, args)
            server = await remote.request("PUT", server_path(current), json=body)
    except _InputError as exc:
        out.error(str(exc))
        return EXIT_ERROR
    except RemoteError as exc:
        out.error(str(exc))
        return EXIT_ERROR
    return _done(out, "server", "updated", server)


async def _set_enabled(args: Any, enabled: bool) -> int:
    out = output_for(args)
    try:
        async with Remote(args.url, out) as remote:
            current = await remote.resolve_server(args.server)
            body = {k: current[k] for k in _INPUT_FIELDS if k in current}
            body["enabled"] = enabled
            server = await remote.request("PUT", server_path(current), json=body)
    except RemoteError as exc:
        out.error(str(exc))
        return EXIT_ERROR
    return _done(out, "server", "resumed" if enabled else "paused", server)


async def run_pause(args: Any) -> int:
    return await _set_enabled(args, False)


async def run_resume(args: Any) -> int:
    return await _set_enabled(args, True)


def _confirm(prompt: str, out: Output) -> bool | None:
    """Ask on stderr (stdout stays clean for --json). None when stdin gave no answer: on
    Windows ``isatty()`` is also true for NUL, so "a terminal" is not proof of a human."""
    out.stderr.write(prompt)
    out.stderr.flush()
    line = sys.stdin.readline()
    if not line:
        return None
    return line.strip().lower() in ("y", "yes")


async def run_remove(args: Any) -> int:
    out = output_for(args)
    try:
        async with Remote(args.url, out) as remote:
            current = await remote.resolve_server(args.server)
            if not args.yes:
                if not sys.stdin.isatty():
                    out.error(f"refusing to delete {current['name']!r} without confirmation: "
                              "pass --yes when running non-interactively")
                    return EXIT_ERROR
                answer = _confirm(f"Delete {current['name']} ({current['id']}) and its whole "
                                  "history? [y/N] ", out)
                if answer is None:
                    out.error("no answer (stdin closed): pass --yes when running "
                              "non-interactively")
                    return EXIT_ERROR
                if not answer:
                    out.error("not deleted")
                    return EXIT_ERROR
            await remote.request("DELETE", server_path(current))
    except RemoteError as exc:
        out.error(str(exc))
        return EXIT_ERROR
    if out.json_mode:
        out.emit_json("server.removed", {"id": current["id"], "name": current["name"]})
    else:
        out.print(f"removed: {current['name']} ({current['id']}) and its history")
    return EXIT_OK
