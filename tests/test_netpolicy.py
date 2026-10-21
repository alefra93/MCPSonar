"""Outbound policy: address classes, DNS rebinding, redirect bypass, credential forwarding.

No test here ever opens a connection to a blocked address: the policy refuses before the
connect, and the only real sockets are local test servers on 127.0.0.1.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

import httpx2
import pytest

from mcpsonar import netpolicy
from mcpsonar.check_engine import _http_client, run_check
from mcpsonar.models import CheckStatus, ServerConfig
from mcpsonar.netpolicy import OutboundPolicy, policy_transport


# ---- address classes ------------------------------------------------------- #
@pytest.mark.parametrize(
    "ip, allowed",
    [
        ("93.184.216.34", True),  # public
        ("10.1.2.3", True),  # private: monitoring internal MCP servers is legitimate
        ("192.168.1.10", True),
        ("100.64.1.1", True),  # CGNAT / tailnets
        ("127.0.0.1", True),
        ("::1", True),
        ("fd12:3456::1", True),  # ULA
        ("169.254.169.254", False),  # AWS/GCP/Azure metadata
        ("fd00:ec2::254", False),  # AWS IPv6 metadata
        ("100.100.100.200", False),  # Alibaba metadata
        ("::ffff:169.254.169.254", False),  # IPv4-mapped bypass attempt
        ("169.254.10.10", False),  # link-local
        ("fe80::1", False),
        ("0.0.0.0", False),
        ("::", False),
        ("224.0.0.1", False),  # multicast
        ("240.0.0.1", False),  # reserved
    ],
)
def test_default_policy(ip, allowed):
    assert (OutboundPolicy().check_ip(ip) is None) is allowed


def test_block_private_networks():
    p = OutboundPolicy.from_env({"MCPSONAR_BLOCK_PRIVATE_NETWORKS": "1"})
    for ip in ("10.1.2.3", "127.0.0.1", "::1", "fd12::1", "100.64.0.1"):
        assert p.check_ip(ip) is not None, ip
    assert p.check_ip("93.184.216.34") is None


def test_allow_and_deny_lists():
    p = OutboundPolicy.from_env({
        "MCPSONAR_OUTBOUND_ALLOW": "169.254.169.254/32",
        "MCPSONAR_OUTBOUND_DENY": "10.0.0.0/8",
    })
    assert p.check_ip("169.254.169.254") is None  # only an explicit allow reaches metadata
    assert p.check_ip("10.9.9.9") is not None
    link_local = OutboundPolicy.from_env({"MCPSONAR_ALLOW_LINK_LOCAL": "1"})
    assert link_local.check_ip("169.254.10.10") is None
    assert link_local.check_ip("169.254.169.254") is not None  # metadata still blocked


def test_transport_hook_is_installed():
    """Guards the one private-attribute access against an httpcore2 upgrade."""
    t = policy_transport()
    assert isinstance(t._pool._network_backend, netpolicy.PolicyNetworkBackend)


# ---- local servers ---------------------------------------------------------- #
class _Recorder(BaseHTTPRequestHandler):
    seen: ClassVar[list[dict]] = []
    redirect_to: ClassVar[str | None] = None

    def do_GET(self):
        type(self).seen.append(dict(self.headers.items()))
        if self.redirect_to:
            self.send_response(302)
            self.send_header("Location", self.redirect_to)
        else:
            self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def serve():
    servers = []

    def start(redirect_to=None):
        handler = type("H", (_Recorder,), {"seen": [], "redirect_to": redirect_to})
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        server = HTTPServer(("127.0.0.1", port), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return handler, port

    yield start
    for s in servers:
        s.shutdown()


# ---- DNS rebinding ---------------------------------------------------------- #
async def test_hostname_resolving_to_metadata_is_blocked(monkeypatch):
    async def fake_resolve(host, port):
        return [ipaddress.ip_address("169.254.169.254")]

    monkeypatch.setattr(netpolicy, "resolve", fake_resolve)
    async with _http_client() as client:
        with pytest.raises(httpx2.ConnectError, match="metadata"):
            await client.get("http://rebind.attacker.test/mcp")


async def test_rebinding_pins_the_checked_address(monkeypatch, serve):
    """A name answering [metadata, 127.0.0.1] is connected to 127.0.0.1 — the address that
    was checked — never to the blocked one, and there is no second lookup to race."""
    handler, port = serve()
    calls = []

    async def fake_resolve(host, p):
        calls.append(host)
        return [ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("127.0.0.1")]

    monkeypatch.setattr(netpolicy, "resolve", fake_resolve)
    async with _http_client() as client:
        r = await client.get(f"http://rebind.attacker.test:{port}/mcp")
    assert r.status_code == 200 and len(handler.seen) == 1
    assert handler.seen[0]["Host"] == f"rebind.attacker.test:{port}"  # Host header kept
    assert calls == ["rebind.attacker.test"]


# ---- redirects ---------------------------------------------------------------- #
async def test_redirect_to_metadata_is_blocked(serve):
    handler, port = serve(redirect_to="http://169.254.169.254/latest/meta-data/")
    async with _http_client() as client:
        with pytest.raises(httpx2.ConnectError, match="metadata"):
            await client.get(f"http://127.0.0.1:{port}/mcp")
    assert len(handler.seen) == 1


async def test_credentials_not_forwarded_across_origins(serve):
    target, target_port = serve()
    _, first_port = serve(redirect_to=f"http://127.0.0.1:{target_port}/landing")
    headers = {"Authorization": "Bearer secret-token", "X-Api-Key": "k-123456",
               "X-Trace": "keep-me-too"}
    async with _http_client(headers=headers) as client:
        r = await client.get(f"http://127.0.0.1:{first_port}/mcp")
    assert r.status_code == 200
    got = {k.lower() for k in target.seen[0]}
    assert "authorization" not in got and "x-api-key" not in got
    # every configured header is treated as potentially secret
    assert "x-trace" not in got


async def test_credentials_still_sent_to_the_configured_origin(serve):
    handler, port = serve()
    async with _http_client(headers={"X-Api-Key": "k-123456"}) as client:
        await client.get(f"http://127.0.0.1:{port}/mcp")
    assert handler.seen[0].get("X-Api-Key") == "k-123456"


async def test_redirect_loop_is_bounded(serve):
    handler, port = serve()
    handler.redirect_to = f"http://127.0.0.1:{port}/again"
    async with _http_client() as client:
        with pytest.raises(httpx2.TooManyRedirects):
            await client.get(f"http://127.0.0.1:{port}/mcp")
    assert len(handler.seen) <= 6


# ---- end to end -------------------------------------------------------------- #
async def test_check_against_metadata_url_is_down_without_connecting():
    ev = (await run_check("s", ServerConfig(url="http://169.254.169.254/mcp"))).event
    assert ev.status == CheckStatus.DOWN
    assert "outbound policy blocked" in ev.detail


@pytest.mark.parametrize("bad", ["file:///etc/passwd", "ftp://h/x", "localhost:8000/mcp", "/mcp"])
def test_non_http_urls_rejected(bad):
    with pytest.raises(ValueError):
        ServerConfig(url=bad)
    with pytest.raises(ValueError):
        ServerConfig(url="http://h/mcp", webhooks=[{"type": "generic", "url": bad}])
