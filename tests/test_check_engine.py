"""End-to-end tests for the check engine against the bundled mock MCP server, plus a
pure-unit test of the version-aware validator registry.

The mock is launched as a subprocess (real sockets, real MCP handshake) so these exercise
the actual SDK transport, not a stub.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from pydantic import ValidationError

from mcpsonar.check_engine import check_server
from mcpsonar.models import ServerConfig, Thresholds, ToolProbe, TransportType
from mcpsonar.validators import get_validator, run_minimal_common_validation

REPO_ROOT = Path(__file__).resolve().parents[1]
MOCK = REPO_ROOT / "scripts" / "mock_mcp_server.py"
HOST = "127.0.0.1"
PORT = 8765
URL = f"http://{HOST}:{PORT}/mcp"


def _wait_for_port(host: str, port: int, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            if sock.connect_ex((host, port)) == 0:
                return
        time.sleep(0.2)
    raise RuntimeError(f"mock server did not open {host}:{port} within {timeout}s")


@pytest.fixture(scope="module")
def mock_server():
    proc = subprocess.Popen(
        [sys.executable, str(MOCK), "--host", HOST, "--port", str(PORT)],
        # Never PIPE without reading it: once the server's log output (tracebacks from the
        # failing `boom` tool) fills the OS pipe buffer, the server blocks on write and
        # every later request times out.
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_port(HOST, PORT)
        yield URL
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def _cfg(tools: list[str] | None = None, **kw) -> ServerConfig:
    return ServerConfig(
        url=URL,
        transport=TransportType.HTTP,
        tools_to_test=tools or [],
        thresholds=Thresholds(**kw) if kw else Thresholds(),
    )


async def test_up_no_tools(mock_server):
    evt = await check_server("mock", _cfg())
    assert evt.status.value == "up"
    assert evt.spec_version == "2026-07-28"  # mcp 2.x servers speak the modern era
    assert evt.spec_version_supported is True
    assert evt.tools_checked == 0
    assert evt.tools_available == 3  # mock exposes ping, echo, boom
    assert evt.latency_ms > 0
    assert evt.detail is None


async def test_up_ping(mock_server):
    evt = await check_server("mock", _cfg(["ping"]))
    assert evt.status.value == "up"
    assert evt.tools_checked == 1
    assert evt.tools_failed == 0


async def test_echo_fails_without_args_but_passes_with_args(mock_server):
    # echo requires a `text` arg: no-arg probe fails...
    evt_bad = await check_server("mock", _cfg(["echo"]))
    assert evt_bad.status.value == "down"
    assert evt_bad.tools_failed == 1

    # ...but a probe that supplies the arg succeeds.
    cfg = _cfg()
    cfg.tools_to_test = [ToolProbe(name="echo", arguments={"text": "hi"})]
    evt_ok = await check_server("mock", cfg)
    assert evt_ok.status.value == "up"
    assert evt_ok.tools_checked == 1
    assert evt_ok.tools_failed == 0


def test_tools_to_test_coerces_bare_strings():
    cfg = ServerConfig(url=URL, tools_to_test=["ping", {"name": "echo", "arguments": {"text": "x"}}])
    assert cfg.tools_to_test[0] == ToolProbe(name="ping", arguments=None)
    assert cfg.tools_to_test[1] == ToolProbe(name="echo", arguments={"text": "x"})


async def test_degraded_partial_tool_failure(mock_server):
    # ping succeeds, boom fails -> some (not all) tools failed -> degraded
    evt = await check_server("mock", _cfg(["ping", "boom"]))
    assert evt.status.value == "degraded"
    assert evt.tools_checked == 2
    assert evt.tools_failed == 1
    assert "boom" in (evt.detail or "")


async def test_down_all_tools_failed(mock_server):
    evt = await check_server("mock", _cfg(["boom"]))
    assert evt.status.value == "down"
    assert evt.tools_checked == 1
    assert evt.tools_failed == 1


async def test_stdio_transport_against_mock():
    # mcpsonar launches the mock as a stdio subprocess and speaks MCP over its stdio.
    cfg = ServerConfig(
        transport=TransportType.STDIO,
        command=sys.executable,
        args=[str(MOCK), "--transport", "stdio"],
        tools_to_test=[ToolProbe(name="ping")],
    )
    evt = await check_server("mock-stdio", cfg)
    assert evt.status.value == "up"
    assert evt.spec_version == "2026-07-28"  # mcp 2.x servers speak the modern era
    assert evt.tools_checked == 1 and evt.tools_failed == 0


async def test_stdio_down_when_command_missing():
    cfg = ServerConfig(transport=TransportType.STDIO, command="this-command-does-not-exist-xyz")
    evt = await check_server("bad-stdio", cfg)
    assert evt.status.value == "down"
    assert evt.spec_version is None


def test_transport_field_validation():
    # http/sse need url; stdio needs command
    with pytest.raises(ValidationError):
        ServerConfig(transport=TransportType.HTTP)  # no url
    with pytest.raises(ValidationError):
        ServerConfig(transport=TransportType.STDIO)  # no command
    # valid ones
    assert ServerConfig(url="http://x/mcp").transport == TransportType.HTTP
    assert ServerConfig(transport=TransportType.STDIO, command="npx").command == "npx"


async def test_down_when_unreachable():
    # No server on this port -> connection failure -> down, no spec version.
    cfg = ServerConfig(url="http://127.0.0.1:1/mcp", transport=TransportType.HTTP)
    evt = await check_server("dead", cfg)
    assert evt.status.value == "down"
    assert evt.latency_ms == 0
    assert evt.spec_version is None
    assert evt.spec_version_supported is False
    assert "failed" in (evt.detail or "")


# ---- pure-unit: version-aware registry, no server needed --------------------- #
def test_registry_known_and_unknown_versions():
    assert get_validator("2025-11-25") is not None
    assert get_validator("1999-01-01") is None
    assert get_validator(None) is None


def test_minimal_common_validation_flags_bad_handshake():
    class _Info:
        name = ""

    class _Init:  # anything shaped like check_engine.Handshake
        protocol_version = ""
        server_info = _Info()
        capabilities = None

    issues = run_minimal_common_validation(_Init(), [])
    assert any("protocolVersion" in i for i in issues)
    assert any("serverInfo" in i for i in issues)
