"""CLI: command structure, output contract (stdout/stderr, JSON, colors, exit codes) and the
local-mode commands tools / risks / config / doctor / version.

Everything runs in-process through ``mcpsonar.cli.main`` against local fixtures only (the
scripted stdio server, temp files, a local HTTP stub) — no network, no third-party servers.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from httpx2 import ASGITransport, AsyncClient

from mcpsonar.cli import main
from mcpsonar.dashboard import create_app
from mcpsonar.lint import RULES
from mcpsonar.models import ServerConfig
from mcpsonar.scheduler import Scheduler
from mcpsonar.state import StateStore
from mcpsonar.storage import Storage

FIXTURE = Path(__file__).parent / "fixtures" / "scripted_server.py"
SECRET = "sk-live-0123456789abcdef"


def stdio(mode: str) -> list[str]:
    return ["--stdio", f'"{sys.executable}" "{FIXTURE}" {mode}']


def run(capsys, *argv: str) -> tuple[int, str, str]:
    try:
        code = main(list(argv))
    except SystemExit as exc:  # argparse --help / usage errors
        code = exc.code if isinstance(exc.code, int) else 2
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# ---- structure ---------------------------------------------------------------- #
def test_help_lists_every_command(capsys):
    code, out, _ = run(capsys, "--help")
    assert code == 0
    for cmd in ("run", "scan", "demo", "tools", "risks", "config", "doctor", "version"):
        assert f"    {cmd}" in out
    assert "Exit codes" in out


@pytest.mark.parametrize("cmd", ["run", "scan", "demo", "tools", "risks", "doctor", "version",
                                 "config"])
def test_every_command_has_help(capsys, cmd):
    code, out, _ = run(capsys, cmd, "--help")
    assert code == 0 and "usage: mcpsonar" in out


def test_version(capsys):
    code, out, _ = run(capsys, "--version")
    assert code == 0 and out.startswith("mcpsonar ")
    code, out, _ = run(capsys, "version", "--json")
    doc = json.loads(out)
    assert doc["kind"] == "version" and doc["schema_version"] == 1 and doc["mcp"]


def test_usage_error_is_exit_2(capsys):
    code, _, err = run(capsys, "tools", "--format", "xml")
    assert code == 2 and "invalid choice" in err


# ---- tools ----------------------------------------------------------------- #
def test_tools_lists_every_page(capsys):
    code, out, err = run(capsys, "tools", *stdio("pages"), "--json")
    assert code == 0, err
    doc = json.loads(out)  # stdout is exactly one JSON document
    assert doc["kind"] == "tools" and len(doc["tools"]) == 12
    assert all(len(t["fingerprint"]) == 64 for t in doc["tools"])


def test_tools_text_and_no_color_when_not_a_tty(capsys):
    code, out, _ = run(capsys, "tools", *stdio("poisoned"))
    assert code == 0
    assert "\x1b[" not in out  # captured stdout is not a terminal
    assert "HIGH (5)" in out  # worst severity, then the number of findings
    assert "ping" in out and "·" in out  # UTF-8 survives (no mojibake)
    assert "mcpsonar risks" in out  # points to the explanation command


def test_tools_detail_shows_schemas(capsys):
    code, out, _ = run(capsys, "tools", *stdio("poisoned"), "--detail")
    assert code == 0 and "inputSchema" in out and "sidenote" in out


@pytest.mark.parametrize(
    "argv, message",
    [
        (["tools"], "give a server URL"),
        (["tools", "github-mcp"], "is not a URL"),
        (["tools", "--stdio", "x", "-e", "NOEQUALS"], "K=V"),
        (["tools", "ftp://h/x"], "invalid target"),
    ],
)
def test_target_errors_exit_2_on_stderr(capsys, argv, message):
    code, out, err = run(capsys, *argv)
    assert code == 2 and out == "" and message in err


def test_unreachable_server_exit_2_and_clean_json_stdout(capsys):
    code, out, err = run(capsys, "tools", "http://127.0.0.1:1/mcp", "--json")
    assert code == 2 and out == "" and "could not read" in err


def test_tools_by_name_from_config(capsys, tmp_path):
    cfg = tmp_path / "servers.yaml"
    cfg.write_text(
        "servers:\n  scripted:\n    transport: stdio\n"
        f"    command: {json.dumps(sys.executable)}\n"
        f"    args: [{json.dumps(str(FIXTURE))}, pages]\n",
        encoding="utf-8",
    )
    code, out, err = run(capsys, "tools", "scripted", "--config", str(cfg), "--json")
    assert code == 0, err
    assert json.loads(out)["target"] == "scripted"
    code, _, err = run(capsys, "tools", "missing", "--config", str(cfg))
    assert code == 2 and "servers: scripted" in err


# ---- risks ----------------------------------------------------------------- #
def test_risks_explains_findings(capsys):
    code, out, _ = run(capsys, "risks", *stdio("poisoned"))
    assert code == 0  # reporting only by default
    assert "review:" in out and "evidence:" in out
    assert "not proof of malicious behavior" in out


def test_risks_json_contract(capsys):
    _code, out, _ = run(capsys, "risks", *stdio("poisoned"), "--json")
    doc = json.loads(out)
    assert doc["kind"] == "risks" and "not proof" in doc["disclaimer"]
    rules = {f["rule"] for f in doc["findings"]}
    assert {"fake-system-tag", "hidden-from-user", "sensitive-path",
            "suspicious-parameter"} <= rules
    for f in doc["findings"]:
        assert f["evidence"] and f["remediation"] and f["tool"] == "add"


def test_risks_severity_filter_and_fail_on(capsys):
    code, out, _ = run(capsys, "risks", *stdio("poisoned"), "--severity", "high", "--json")
    assert {f["severity"] for f in json.loads(out)["findings"]} == {"high"}
    assert code == 0
    code, *_ = run(capsys, "risks", *stdio("poisoned"), "--fail-on", "high")
    assert code == 1
    code, *_ = run(capsys, "risks", *stdio("pages"), "--fail-on", "low")
    assert code == 0  # clean server


def test_every_rule_is_documented():
    from mcpsonar import lint

    emitted = {r for r, *_ in lint._PATTERN_RULES} | {
        "hidden-unicode", "encoded-blob", "long-description", "suspicious-parameter"}
    assert emitted == set(RULES)
    for info in RULES.values():
        assert info.title and info.explanation and info.remediation


# ---- one engine: CLI and dashboard agree ------------------------------------ #
async def test_dashboard_tools_view_matches_cli_risks(capsys):
    storage = await Storage.open(":memory:")
    store = StateStore()
    scheduler = Scheduler(storage, store)
    try:
        server = await storage.create_server("p", ServerConfig(
            transport="stdio", command=sys.executable, args=[str(FIXTURE), "poisoned"]),
            enabled=False)
        app = create_app(storage, store, scheduler, require_auth=False)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            api_tools = (await c.get(f"/api/servers/{server.id}/tools")).json()
        api_findings = sorted((t["name"], f["rule"]) for t in api_tools for f in t["findings"])
    finally:
        await scheduler.stop()
        await storage.close()
    _code, out, _ = await asyncio.to_thread(run, capsys, "risks", *stdio("poisoned"), "--json")
    cli_findings = sorted((f["tool"], f["rule"]) for f in json.loads(out)["findings"])
    assert api_findings == cli_findings and cli_findings


# ---- config ------------------------------------------------------------------ #
@pytest.fixture
def cfg_file(tmp_path):
    p = tmp_path / "cfg.yaml"
    p.write_text(
        "servers:\n  remote:\n"
        f"    url: https://mcp.example.com/mcp?api_key={SECRET}\n"
        f"    headers: {{Authorization: 'Bearer {SECRET}'}}\n"
        "  local:\n    transport: stdio\n    command: npx\n"
        f"    env: {{TOKEN: {SECRET}}}\n",
        encoding="utf-8",
    )
    return p


def test_config_validate(capsys, cfg_file, tmp_path):
    code, out, _ = run(capsys, "config", "validate", str(cfg_file))
    assert code == 0 and "2 server(s)" in out and "stdio servers run a command" in out
    bad = tmp_path / "bad.yaml"
    bad.write_text("servers:\n  b:\n    url: file:///etc/passwd\n", encoding="utf-8")
    code, out, err = run(capsys, "config", "validate", str(bad), "--json")
    assert code == 2 and json.loads(out)["valid"] is False and "servers.b.url" in err
    code, _, err = run(capsys, "config", "validate", str(tmp_path / "missing.yaml"))
    assert code == 2 and "not found" in err


@pytest.mark.parametrize("fmt", ["yaml", "json"])
def test_config_show_never_prints_secrets(capsys, cfg_file, fmt):
    code, out, _ = run(capsys, "config", "show", str(cfg_file), "--format", fmt)
    assert code == 0 and SECRET not in out and "********" in out


def test_config_export_secrets_only_to_a_new_file(capsys, cfg_file, tmp_path):
    code, out, _ = run(capsys, "config", "export", str(cfg_file))
    assert code == 0 and SECRET not in out
    code, out, err = run(capsys, "config", "export", str(cfg_file), "--include-secrets")
    assert code == 2 and out == "" and "-o" in err
    target = tmp_path / "full.yaml"
    code, out, err = run(capsys, "config", "export", str(cfg_file), "--include-secrets",
                         "-o", str(target))
    assert code == 0 and out == "" and SECRET in target.read_text(encoding="utf-8")
    assert "real credentials" in err
    if os.name == "posix":
        assert target.stat().st_mode & 0o777 == 0o600
    code, _, err = run(capsys, "config", "export", str(cfg_file), "--include-secrets",
                       "-o", str(target))
    assert code == 2 and "already exists" in err


# ---- doctor ------------------------------------------------------------------- #
class _Status(BaseHTTPRequestHandler):
    body = b"{}"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args):
        pass


@pytest.fixture
def status_server():
    servers = []

    def start(payload: dict) -> str:
        handler = type("H", (_Status,), {"body": json.dumps(payload).encode()})
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        server = HTTPServer(("127.0.0.1", port), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{port}"

    yield start
    for s in servers:
        s.shutdown()


def _doctor(capsys, *extra):
    code, out, _ = run(capsys, "doctor", "--json", *extra)
    doc = json.loads(out)
    return code, {c["name"]: c for c in doc["checks"]}, out


def test_doctor_healthy(capsys, tmp_path, cfg_file, status_server, monkeypatch):
    for var in ("MCPSONAR_OUTBOUND_ALLOW", "MCPSONAR_METRICS_TOKEN", "HTTPS_PROXY",
                "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY"):
        monkeypatch.delenv(var, raising=False)
    db = tmp_path / "m.db"

    async def make_db():
        s = await Storage.open(db)
        await s.create_admin("admin", "supersecret")
        await s.close()

    asyncio.run(make_db())
    url = status_server({"auth_enabled": True, "setup_required": False})
    code, checks, out = _doctor(capsys, "--db", str(db), "--config", str(cfg_file), "--url", url)
    assert code == 0, out
    assert checks["Database"]["status"] == "ok" and "admin created" in checks["Database"]["detail"]
    assert checks["Config file"]["status"] == "ok"
    assert checks["Local instance"]["status"] == "ok"
    assert SECRET not in out


def test_doctor_reports_problems_without_leaking(capsys, tmp_path, status_server, monkeypatch):
    monkeypatch.setenv("MCPSONAR_OUTBOUND_ALLOW", "not-a-cidr")
    monkeypatch.setenv("MCPSONAR_METRICS_TOKEN", "tok-Q7x9")
    bad = tmp_path / "bad.yaml"
    bad.write_text("servers: [nope]\n", encoding="utf-8")
    url = status_server({"auth_enabled": True, "setup_required": True})
    code, checks, out = _doctor(capsys, "--db", str(tmp_path / "none.db"), "--config", str(bad),
                                "--url", url)
    assert code == 1
    assert checks["Config file"]["status"] == "fail"
    assert checks["Outbound policy"]["status"] == "fail"
    assert checks["MCPSONAR_METRICS_TOKEN"]["status"] == "warn"
    assert checks["Admin account"]["status"] == "warn"
    assert checks["Database"]["status"] == "skip"
    assert "tok-Q7x9" not in out  # the token value itself is never printed


def test_doctor_non_mcpsonar_answer_fails(capsys, tmp_path, status_server):
    url = status_server(["not", "an", "mcpsonar", "status"])
    code, checks, _ = _doctor(capsys, "--db", str(tmp_path / "x.db"), "--url", url)
    assert checks["Local instance"]["status"] == "fail" and code == 1


def test_doctor_text_has_no_color_without_tty(capsys, tmp_path):
    _code, out, _ = run(capsys, "doctor", "--db", str(tmp_path / "x.db"),
                       "--url", "http://127.0.0.1:1")
    assert "mcpsonar doctor" in out and "\x1b[" not in out


# ---- command splitting (shared with `scan --stdio`) ---------------------------- #
@pytest.mark.skipif(os.name != "nt", reason="Windows quoting rules")
def test_split_command_windows_quotes_and_backslashes():
    from mcpsonar.scan import split_command

    assert split_command(r'"C:\Program Files\nodejs\npx.cmd" -y "@scope/pkg@1.0" C:\x') == [
        r"C:\Program Files\nodejs\npx.cmd", "-y", "@scope/pkg@1.0", r"C:\x"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX quoting rules")
def test_split_command_posix():
    from mcpsonar.scan import split_command

    assert split_command("'/opt/my tools/srv' --flag \"a b\"") == [
        "/opt/my tools/srv", "--flag", "a b"]
