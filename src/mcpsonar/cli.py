"""Command-line entry point.

* ``mcpsonar run``  — the monitor: opens the SQLite store, optionally seeds it from a YAML
  config on first run (when the DB has no servers yet), starts the dynamic scheduler, and
  serves the dashboard + CRUD API under uvicorn.
* ``mcpsonar scan`` — one-shot security scan of a server (tool-poisoning lint + lockfile).
* ``mcpsonar demo`` — the monitor against four scripted demo servers, no setup.
"""

from __future__ import annotations

import argparse
import asyncio
import inspect
import ipaddress
import logging
import os
import secrets
import sys
import tempfile
import webbrowser

import uvicorn

from .commands import register_all
from .commands.version import version_line
from .dashboard import create_app
from .loader import ConfigError, load_config
from .output import EXIT_INTERRUPTED
from .scheduler import Scheduler
from .state import StateStore
from .storage import Storage
from .websec import LOOPBACK_HOSTS

_TRUE = {"1", "true", "yes", "on"}

logger = logging.getLogger("mcpsonar")


async def _seed_from_yaml_if_empty(storage: Storage, config_path: str) -> None:
    if await storage.list_servers():
        return  # DB already has servers; never overwrite from YAML
    config = load_config(config_path)
    for name, cfg in config.servers.items():
        await storage.create_server(name=name, config=cfg)
    logger.info("seeded %d server(s) from %s", len(config.servers), config_path)


async def _seed_demo(storage: Storage, servers, interval: int) -> None:
    from .models import ServerConfig

    for d in servers:
        await storage.create_server(
            name=d.name,
            config=ServerConfig(
                url=d.url,
                check_interval_seconds=interval,
                tools_to_test=[d.probe],
                thresholds={"latency_degraded_ms": 1500, "latency_down_ms": 5000},
            ),
        )


def _env_list(name: str) -> list[str]:
    return [v.strip() for v in os.environ.get(name, "").split(",") if v.strip()]


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def default_allowed_hosts(
    require_auth: bool, bind_host: str, extra: list[str]
) -> list[str] | None:
    """Which ``Host`` headers to accept. Without a login, only the loopback names (plus any
    the operator lists): that is what defeats DNS rebinding against an open instance. With a
    login, any host unless the operator restricts it (the session cookie protects it)."""
    if extra:
        return [*LOOPBACK_HOSTS, *extra]
    if require_auth:
        return None
    hosts = list(LOOPBACK_HOSTS)
    if bind_host not in ("0.0.0.0", "::", "") and not _is_loopback(bind_host):
        hosts.append(bind_host)
    return hosts


async def _serve(
    config_path: str | None,
    host: str,
    port: int,
    db_path: str,
    retention_days: float,
    require_auth: bool,
    demo_interval: int | None = None,
    open_browser: bool = False,
    allowed_hosts: list[str] | None = None,
    trusted_origins: list[str] | None = None,
    cookie_secure: str = "auto",
    allow_stdio_api: bool = False,
) -> None:
    storage = await Storage.open(db_path)
    if config_path:
        await _seed_from_yaml_if_empty(storage, config_path)

    demo_proc = None
    if demo_interval is not None:
        from .demo import demo_servers, spawn

        base = port + 26
        demo_proc = await asyncio.to_thread(spawn, base, demo_interval)
        await _seed_demo(storage, demo_servers(base, demo_interval), demo_interval)

    store = StateStore()
    scheduler = Scheduler(storage, store, retention_days=retention_days)
    await scheduler.start()

    setup_token = None
    if require_auth and not await storage.has_admin():
        preset = os.environ.get("MCPSONAR_SETUP_TOKEN")
        setup_token = preset or secrets.token_urlsafe(18)
        shown = "<MCPSONAR_SETUP_TOKEN>" if preset else setup_token
        browse = "127.0.0.1" if host in ("0.0.0.0", "::") else host
        logger.warning(
            "no admin yet — create one at http://%s:%d/login?setup_token=%s "
            "(the setup token is required, so nobody else can claim this instance first)",
            browse, port, shown,
        )
    if not require_auth and not _is_loopback(host):
        logger.warning(
            "--no-auth while listening on %s: anyone who can reach this port can read and "
            "change the monitored servers. Keep it behind a firewall or an authenticating "
            "proxy.", host,
        )

    app = create_app(
        storage, store, scheduler, require_auth=require_auth,
        setup_token=setup_token,
        cookie_secure=cookie_secure,  # type: ignore[arg-type]
        allowed_hosts=default_allowed_hosts(require_auth, host, allowed_hosts or []),
        trusted_origins=trusted_origins or [],
        allow_stdio_api=True if require_auth else allow_stdio_api,
        metrics_token=os.environ.get("MCPSONAR_METRICS_TOKEN") or None,
    )

    uv_config = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(uv_config)
    logger.info("dashboard at http://%s:%d  (db: %s)", host, port, db_path)
    if demo_proc is not None:
        url = f"http://{host}:{port}"
        logger.info("demo running at %s — watch the story unfold over ~5 minutes:", url)
        logger.info("  • calculator performs a rug pull (poisoned tool) after ~%ds",
                    25 * demo_interval)
        logger.info("  • docs-search gets permanently slower after ~%ds", 45 * demo_interval)
        logger.info("  • payments-gateway flaps; weather-api spikes now and then")
        if open_browser:
            asyncio.get_running_loop().call_later(1.5, webbrowser.open, url)
    try:
        await server.serve()
    finally:
        if demo_proc is not None:
            demo_proc.terminate()
        await scheduler.stop()
        await storage.close()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpsonar",
        description="MCP observability and security: monitor MCP servers, inspect their "
        "tools, detect tool changes and poisoning, gate CI on them.",
        epilog="Exit codes: 0 ok · 1 problem found (findings, drift, failed check) · "
        "2 could not run (usage, connection, config). Docs: docs/cli.md",
    )
    parser.add_argument("--version", action="version", version=version_line())
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    run = sub.add_parser("run", help="Serve the dashboard/API and run checks.")
    run.add_argument(
        "--config",
        default=None,
        help="Optional YAML to seed the DB on first run (when it has no servers yet).",
    )
    run.add_argument(
        "--db",
        default=os.environ.get("MCPSONAR_DB", "mcpsonar.db"),
        help="SQLite database path (env MCPSONAR_DB; default ./mcpsonar.db).",
    )
    run.add_argument(
        "--retention-days",
        type=float,
        default=float(os.environ.get("MCPSONAR_RETENTION_DAYS", "7")),
        help="Delete check history older than this many days (0 disables pruning).",
    )
    run.add_argument(
        "--no-auth",
        action="store_true",
        help="Disable the dashboard login (only behind a trusted proxy / on localhost).",
    )
    run.add_argument("--host", default="127.0.0.1")
    run.add_argument("--port", type=int, default=8675)
    run.add_argument(
        "--allowed-host", action="append", default=_env_list("MCPSONAR_ALLOWED_HOSTS"),
        metavar="HOST",
        help="Host name this instance is reached as, repeatable; '*.example.com' allowed "
        "(env MCPSONAR_ALLOWED_HOSTS, comma-separated). Other Host headers get 400. Default: "
        "any host with login on; only localhost/127.0.0.1/::1 with --no-auth.",
    )
    run.add_argument(
        "--trusted-origin", action="append", default=_env_list("MCPSONAR_TRUSTED_ORIGINS"),
        metavar="ORIGIN",
        help="Extra browser origin allowed to make changes, e.g. https://mcp.example.com when "
        "a reverse proxy rewrites Host (env MCPSONAR_TRUSTED_ORIGINS).",
    )
    run.add_argument(
        "--cookie-secure", choices=["auto", "always", "never"],
        default=os.environ.get("MCPSONAR_COOKIE_SECURE", "auto"),
        help="Secure flag on the session cookie: auto = when the request came over HTTPS "
        "(env MCPSONAR_COOKIE_SECURE).",
    )
    run.add_argument(
        "--allow-stdio-api", action="store_true",
        default=os.environ.get("MCPSONAR_ALLOW_STDIO_API", "").lower() in _TRUE,
        help="With --no-auth, still allow adding stdio servers (= launching commands) from "
        "the UI/API. Only if nobody else can reach the port (env MCPSONAR_ALLOW_STDIO_API).",
    )

    scan = sub.add_parser(
        "scan",
        help="One-shot security scan of an MCP server (tool poisoning + lockfile drift).",
        description="Connect once, lint every tool definition for tool-poisoning patterns "
        "and optionally compare them with a lockfile. Exit code 1 on findings/drift.",
    )
    scan.add_argument("target", nargs="?", help="Server URL (http/sse).")
    scan.add_argument("--stdio", metavar="CMD",
                      help='Launch a stdio server instead, e.g. --stdio "npx -y @scope/server"')
    scan.add_argument("--transport", choices=["http", "sse"],
                      help="Force the transport for a URL (default: sse if it ends in /sse).")
    scan.add_argument("-H", "--header", action="append", default=[], metavar="'K: V'",
                      help="HTTP header, repeatable (e.g. -H 'Authorization: Bearer ...').")
    scan.add_argument("-e", "--env", action="append", default=[], metavar="K=V",
                      help="Environment variable for --stdio, repeatable.")
    scan.add_argument("--lock", metavar="FILE",
                      help="Lockfile: written if missing, otherwise compared (drift = exit 1).")
    scan.add_argument("--update-lock", action="store_true",
                      help="Rewrite the lockfile with the current definitions.")
    scan.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="high",
                      help="Lowest finding severity that fails the scan (default: high).")
    scan.add_argument("--json", action="store_true", help="Machine-readable output.")
    scan.add_argument("--format", choices=["text", "json"], default="text",
                      help="Output format (--json is the same as --format json).")
    scan.add_argument("--timeout", type=float, default=20.0, help="Seconds (default 20).")

    demo = sub.add_parser(
        "demo",
        help="Run the dashboard against four scripted demo MCP servers (no setup).",
    )
    demo.add_argument("--port", type=int, default=8675)
    demo.add_argument("--interval", type=int, default=3,
                      help="Check interval in seconds (default 3: the story takes ~5 min).")
    demo.add_argument("--db", default=None, help="Keep the demo DB here (default: temp file).")
    demo.add_argument("--no-browser", action="store_true", help="Don't open the dashboard.")

    register_all(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):  # Windows consoles default to a legacy codepage
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = _build_parser().parse_args(argv)
    long_running = args.command in ("run", "demo")
    # The server commands log their activity; one-shot commands keep stderr for
    # diagnostics only, so their output stays clean in scripts and CI.
    logging.basicConfig(
        level=logging.INFO if long_running else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger("httpx2").setLevel(logging.WARNING)
    logging.getLogger("httpcore2").setLevel(logging.WARNING)
    # The SDK logs per-session chatter (and, for one-shot commands, server stderr noise).
    logging.getLogger("mcp").setLevel(logging.WARNING if long_running else logging.CRITICAL)

    if args.command == "scan":
        from .scan import run_scan

        return asyncio.run(run_scan(args))

    handler = getattr(args, "handler", None)
    if handler is not None:
        try:
            result = handler(args)
            return asyncio.run(result) if inspect.iscoroutine(result) else result
        except KeyboardInterrupt:
            return EXIT_INTERRUPTED

    if args.command == "demo":
        db = args.db or os.path.join(tempfile.mkdtemp(prefix="mcpsonar-demo-"), "demo.db")
        try:
            asyncio.run(
                _serve(None, "127.0.0.1", args.port, db, 1.0, require_auth=False,
                       demo_interval=args.interval, open_browser=not args.no_browser)
            )
        except KeyboardInterrupt:
            pass
        return 0

    if args.command == "run":
        try:
            asyncio.run(
                _serve(
                    args.config, args.host, args.port, args.db,
                    args.retention_days, require_auth=not args.no_auth,
                    allowed_hosts=args.allowed_host,
                    trusted_origins=args.trusted_origin,
                    cookie_secure=args.cookie_secure,
                    allow_stdio_api=args.allow_stdio_api,
                )
            )
        except KeyboardInterrupt:
            return 0
        except ConfigError as exc:
            logger.error("%s", exc)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
