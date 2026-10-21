"""``mcpsonar doctor``: is this installation able to do its job, and is it deployed safely?

Read-only by design: it never writes to the database (it opens it ``mode=ro``), never
launches MCP servers, only talks to the local MCPSonar instance's public status endpoint,
and never prints a credential (only whether one is set). Exit 1 if any check fails.
"""

from __future__ import annotations

import contextlib
import ipaddress
import os
import platform
import shutil
import sqlite3
import ssl
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx2

from .. import __version__
from ..netpolicy import OutboundPolicy
from ..output import EXIT_FAILED, EXIT_OK, add_format_args, output_for
from .version import dependency_version

DEFAULT_URL = "http://127.0.0.1:8675"
_TRUE = {"1", "true", "yes", "on"}


@dataclass
class Check:
    name: str
    status: str  # ok | warn | fail | skip
    detail: str
    fix: str | None = None


def register(sub: Any) -> None:
    p = sub.add_parser(
        "doctor",
        help="Diagnose the installation, configuration and deployment (read-only).",
        description="Check Python, the MCP SDK, the config file, the database, npx, the local "
        "instance, TLS and security-relevant settings. Never prints credentials. "
        "Exit 1 if a check fails.",
    )
    p.add_argument("--config", metavar="FILE",
                   help="Config file to validate (default: ./config.yaml if present).")
    p.add_argument("--db", default=os.environ.get("MCPSONAR_DB", "mcpsonar.db"),
                   help="Database to inspect, read-only (env MCPSONAR_DB; default ./mcpsonar.db).")
    p.add_argument("--url", default=os.environ.get("MCPSONAR_URL", DEFAULT_URL),
                   help=f"MCPSonar instance to probe (env MCPSONAR_URL; default {DEFAULT_URL}).")
    add_format_args(p)
    p.set_defaults(handler=run)


# ---- individual checks ------------------------------------------------------ #
def check_python() -> Check:
    # Below 3.11 mcpsonar cannot even be imported (pip refuses to install it there), so
    # reaching this line already proves the version is supported.
    return Check("Python", "ok", f"{platform.python_version()} ({sys.executable})")


def check_sdk() -> Check:
    ver = dependency_version("mcp")
    if ver is None:
        return Check("MCP SDK", "fail", "package 'mcp' not installed", "pip install 'mcp>=2.3,<3'")
    major_minor = tuple(int(p) for p in ver.split(".")[:2] if p.isdigit())
    if major_minor >= (3, 0):
        return Check("MCP SDK", "fail", f"mcp {ver}: 3.x is not supported yet",
                     "pip install 'mcp>=2.3,<3'")
    if major_minor < (2, 3):
        return Check("MCP SDK", "fail", f"mcp {ver} is too old (no 2026-07-28 support)",
                     "pip install -U 'mcp>=2.3,<3'")
    return Check("MCP SDK", "ok", f"mcp {ver} (protocol 2024-11-05 … 2026-07-28)")


def check_config(path: str | None) -> Check:
    from ..loader import ConfigError, load_config

    if path is None:
        if not Path("config.yaml").exists():
            return Check("Config file", "skip", "none given, no ./config.yaml (optional)")
        path = "config.yaml"
    try:
        config = load_config(path)
    except ConfigError as exc:
        return Check("Config file", "fail", str(exc))
    except Exception as exc:  # YAML or validation error
        first = str(exc).splitlines()[0]
        return Check("Config file", "fail", f"{path}: {first}",
                     f"Run `mcpsonar config validate {path}` for every problem.")
    return Check("Config file", "ok", f"{path}: {len(config.servers)} server(s) valid")


def check_database(path: str) -> list[Check]:
    db = Path(path)
    if not db.exists():
        parent = db.resolve().parent
        if parent.exists() and not os.access(parent, os.W_OK):
            return [Check("Database", "fail", f"{db} does not exist and {parent} is not writable",
                          "Choose a writable --db path or fix the directory permissions.")]
        return [Check("Database", "skip", f"{db} not created yet (`mcpsonar run` creates it)")]
    checks = []
    try:
        uri = db.resolve().as_uri() + "?mode=ro"
        with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=2)) as conn:
            servers = conn.execute("SELECT COUNT(*) FROM servers").fetchone()[0]
            users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        detail = f"{db}: {servers} server(s), {'admin created' if users else 'no admin yet'}"
        checks.append(Check("Database", "ok", detail))
    except sqlite3.Error as exc:
        return [Check("Database", "fail", f"{db}: {exc}",
                      "Is it an MCPSonar database? Restore from a backup if it is damaged.")]
    if not os.access(db, os.W_OK) or not os.access(db.resolve().parent, os.W_OK):
        checks.append(Check("Database permissions", "fail", f"{db} or its folder is read-only",
                            "The monitor needs to write the database and its journal."))
    elif os.name == "posix" and db.stat().st_mode & 0o077:
        checks.append(Check("Database permissions", "warn",
                            f"{db} is readable by other users; it contains credentials",
                            f"chmod 600 {db}"))
    return checks


def check_npx() -> Check:
    found = shutil.which("npx")
    if found:
        return Check("npx", "ok", found)
    return Check("npx", "skip", "not found (only needed for stdio servers launched with npx)")


def check_tls() -> Check:
    for var in ("SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE"):
        value = os.environ.get(var)
        if value and not Path(value).exists():
            return Check("TLS", "fail", f"{var} points to a missing path",
                         f"Fix or unset {var}; HTTPS checks will fail otherwise.")
    try:
        ctx = httpx2.create_ssl_context()
    except (ssl.SSLError, OSError) as exc:
        return Check("TLS", "fail", f"cannot build a TLS context: {exc}",
                     "Reinstall certifi (pip install -U certifi) or fix SSL_CERT_FILE.")
    if type(ctx).__module__.startswith("truststore"):  # httpx2 on Windows/macOS
        detail = "certificates verified with the operating-system trust store"
    else:
        detail = f"CA bundle loaded ({len(ctx.get_ca_certs())} certificates)"
    return Check("TLS", "ok", detail)


def check_instance(url: str) -> list[Check]:
    try:
        r = httpx2.get(url.rstrip("/") + "/api/auth/status", timeout=3.0)
        r.raise_for_status()
        status = r.json()
        if not isinstance(status, dict):
            raise TypeError("unexpected response body")
    except httpx2.ConnectError:
        return [Check("Local instance", "skip", f"nothing listening at {url} "
                                                "(fine if you only use scan/tools/risks)")]
    except (httpx2.HTTPError, ValueError, TypeError) as exc:
        return [Check("Local instance", "fail", f"{url} did not answer like MCPSonar: {exc}",
                      "Check --url / MCPSONAR_URL, or the instance's log.")]
    checks = [Check("Local instance", "ok",
                    f"{url} · login {'on' if status.get('auth_enabled') else 'OFF'}")]
    if status.get("setup_required"):
        checks.append(Check("Admin account", "warn", "not created yet",
                            "Open the setup link printed in the instance's log."))
    host = urlsplit(url).hostname or ""
    if not status.get("auth_enabled") and not _is_loopback(host):
        checks.append(Check("Exposure", "warn", f"login is off and the instance answers on {host}",
                            "Bind it to 127.0.0.1 or turn the login on."))
    return checks


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def check_settings(env: dict[str, str]) -> list[Check]:
    checks: list[Check] = []
    try:
        OutboundPolicy.from_env(env)
    except ValueError as exc:
        checks.append(Check("Outbound policy", "fail", f"invalid CIDR in "
                            f"MCPSONAR_OUTBOUND_ALLOW/DENY: {exc}", "Use CIDRs like 10.0.0.0/8."))
    for name in ("MCPSONAR_SETUP_TOKEN", "MCPSONAR_METRICS_TOKEN"):
        value = env.get(name)
        if value is not None and len(value) < 16:
            checks.append(Check(name, "warn", "set, but shorter than 16 characters",
                                "Use a long random value: python -c \"import secrets;"
                                "print(secrets.token_urlsafe(24))\""))
    if env.get("MCPSONAR_COOKIE_SECURE", "").lower() == "never":
        checks.append(Check("Cookies", "warn", "MCPSONAR_COOKIE_SECURE=never",
                            "Keep 'auto' unless the dashboard is only ever reached over plain "
                            "HTTP on localhost."))
    if env.get("MCPSONAR_ALLOW_STDIO_API", "").lower() in _TRUE:
        checks.append(Check("stdio over API", "warn", "MCPSONAR_ALLOW_STDIO_API is on",
                            "Only safe if nobody else can reach the port of a --no-auth instance."))
    if env.get("MCPSONAR_ALLOW_LINK_LOCAL", "").lower() in _TRUE:
        checks.append(Check("Link-local", "warn", "link-local destinations allowed",
                            "Cloud metadata stays blocked, but prefer leaving this off."))
    proxies = [v for v in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy")
               if env.get(v)]
    if proxies:
        checks.append(Check("Proxy", "warn", f"{proxies[0]} is set: connections go through it",
                            "The outbound policy cannot see past a proxy; enforce destinations "
                            "there."))
    if not checks:
        checks.append(Check("Security settings", "ok", "no risky overrides"))
    return checks


def collect(args: Any) -> list[Check]:
    checks = [
        check_python(),
        Check("mcpsonar", "ok", __version__),
        check_sdk(),
        check_config(args.config),
        *check_database(args.db),
        check_npx(),
        check_tls(),
        *check_instance(args.url),
        *check_settings(dict(os.environ)),
    ]
    return checks


def run(args: Any) -> int:
    out = output_for(args)
    checks = collect(args)
    failed = any(c.status == "fail" for c in checks)
    if out.json_mode:
        out.emit_json("doctor", {"ok": not failed, "checks": [asdict(c) for c in checks]})
        return EXIT_FAILED if failed else EXIT_OK

    s = out.style
    label = {"ok": s.green("OK  "), "warn": s.yellow("WARN"), "fail": s.red("FAIL"),
             "skip": s.dim("SKIP")}
    width = max(len(c.name) for c in checks)
    out.print(s.bold("mcpsonar doctor"))
    for c in checks:
        out.print(f"  {label[c.status]}  {c.name.ljust(width)}  {c.detail}")
        if c.fix and c.status in ("warn", "fail"):
            out.print(f"        {' ' * width}  {s.dim('fix:')} {c.fix}")
    counts = {k: sum(1 for c in checks if c.status == k) for k in ("ok", "warn", "fail")}
    out.print()
    out.print(f"  {counts['ok']} ok · {counts['warn']} warning(s) · {counts['fail']} failure(s)")
    return EXIT_FAILED if failed else EXIT_OK
