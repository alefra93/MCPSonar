"""Browser-facing hardening: cross-site writes, DNS rebinding (Host allowlist), body limits,
security headers, and the stdio-over-unauthenticated-API gate.

The regression at the heart of this file: in v0.5 a page on *any* website could POST a YAML
body (``text/plain``, no CORS preflight) to ``/api/import`` on an ``--no-auth`` instance and
make mcpsonar launch an arbitrary stdio command.
"""

from __future__ import annotations

import pytest
from httpx2 import ASGITransport, AsyncClient

from mcpsonar.cli import default_allowed_hosts
from mcpsonar.dashboard import create_app
from mcpsonar.scheduler import Scheduler
from mcpsonar.state import StateStore
from mcpsonar.storage import Storage
from mcpsonar.websec import cross_site_reason, host_allowed, split_host

STDIO_YAML = (
    "servers:\n  pwn:\n    transport: stdio\n    command: echo\n    args: [owned]\n"
    "    check_interval_seconds: 3600\n"
)
HTTP_YAML = "servers:\n  ok:\n    url: http://127.0.0.1:1/mcp\n    check_interval_seconds: 3600\n"


@pytest.fixture
async def make_client():
    opened = []

    async def factory(base_url="http://127.0.0.1:8675", **kw):
        storage = await Storage.open(":memory:")
        store = StateStore()
        scheduler = Scheduler(storage, store)
        kw.setdefault("require_auth", False)
        app = create_app(storage, store, scheduler, **kw)
        client = AsyncClient(transport=ASGITransport(app=app), base_url=base_url)
        opened.append((client, scheduler, storage))
        return client, storage

    yield factory
    for client, scheduler, storage in opened:
        await client.aclose()
        await scheduler.stop()
        await storage.close()


# ---- pure helpers ------------------------------------------------------------ #
def test_split_host():
    assert split_host("Example.com:8675") == "example.com"
    assert split_host("[::1]:8675") == "::1"
    assert split_host("127.0.0.1") == "127.0.0.1"


def test_host_allowed_patterns():
    assert host_allowed("mcp.example.com", ["*.example.com"])
    assert not host_allowed("example.com.evil.net", ["*.example.com"])
    assert host_allowed("anything", ["*"])
    assert host_allowed("::1", ["[::1]"])


@pytest.mark.parametrize(
    "headers, blocked",
    [
        ({}, False),  # curl / scripts
        ({"origin": "http://h:1", "host": "h:1"}, False),  # same origin
        ({"origin": "https://evil.example", "host": "h:1"}, True),
        ({"origin": "http://localhost:3000", "host": "localhost:8675"}, True),  # same *site*
        ({"origin": "null", "host": "h:1"}, True),  # sandboxed iframe / file://
        ({"sec-fetch-site": "cross-site", "host": "h:1"}, True),
        ({"sec-fetch-site": "same-site", "host": "h:1"}, True),
        ({"sec-fetch-site": "same-origin", "origin": "http://h:1", "host": "h:1"}, False),
    ],
)
def test_cross_site_reason(headers, blocked):
    assert (cross_site_reason("POST", headers) is not None) is blocked
    assert cross_site_reason("GET", headers) is None  # reads are never blocked


def test_trusted_origin_overrides():
    h = {"origin": "https://mcp.example.com", "host": "127.0.0.1:8675"}
    assert cross_site_reason("POST", h) is not None
    assert cross_site_reason("POST", h, ["https://MCP.example.com/"]) is None


def test_default_allowed_hosts():
    assert default_allowed_hosts(True, "0.0.0.0", []) is None
    assert default_allowed_hosts(False, "0.0.0.0", []) == ["localhost", "127.0.0.1", "::1"]
    assert "10.0.0.5" in default_allowed_hosts(False, "10.0.0.5", [])
    assert "mon.lan" in default_allowed_hosts(True, "0.0.0.0", ["mon.lan"])


# ---- the v0.5 drive-by RCE ----------------------------------------------------- #
async def test_cross_site_import_is_blocked(make_client):
    client, storage = await make_client()
    r = await client.post(
        "/api/import", content=STDIO_YAML,
        headers={"Content-Type": "text/plain", "Origin": "https://evil.example",
                 "Sec-Fetch-Site": "cross-site"},
    )
    assert r.status_code == 403
    assert await storage.list_servers() == []


async def test_stdio_refused_over_unauthenticated_api(make_client):
    client, storage = await make_client()
    # even same-origin / non-browser: without a login, the API must not launch commands
    r = await client.post("/api/import", content=STDIO_YAML)
    assert r.status_code == 403 and "stdio" in r.json()["detail"]
    r = await client.post("/api/servers", json={"name": "x", "transport": "stdio",
                                                "command": "echo"})
    assert r.status_code == 403
    assert await storage.list_servers() == []
    # http servers are unaffected
    assert (await client.post("/api/import", content=HTTP_YAML)).status_code == 200


async def test_stdio_allowed_when_explicitly_enabled_or_with_login(make_client):
    client, _ = await make_client(allow_stdio_api=True)
    r = await client.post("/api/servers", json={"name": "x", "transport": "stdio",
                                                "command": "echo", "enabled": False})
    assert r.status_code == 201


async def test_seeded_stdio_server_can_still_be_paused(make_client):
    from mcpsonar.models import ServerConfig

    client, storage = await make_client()
    seeded = await storage.create_server(
        "local", ServerConfig(transport="stdio", command="echo", args=["hi"]), enabled=False
    )
    body = {"name": "renamed", "transport": "stdio", "command": "echo", "args": ["hi"],
            "enabled": False}
    assert (await client.put(f"/api/servers/{seeded.id}", json=body)).status_code == 200
    body["command"] = "calc"  # but not repointed at another command
    assert (await client.put(f"/api/servers/{seeded.id}", json=body)).status_code == 403


# ---- DNS rebinding ----------------------------------------------------------- #
async def test_dns_rebinding_host_is_rejected(make_client):
    client, _ = await make_client(allowed_hosts=["localhost", "127.0.0.1", "::1"])
    ok = await client.get("/api/servers")
    assert ok.status_code == 200
    # the attacker's page talks to 127.0.0.1 but the browser sends its own Host
    r = await client.get("/api/servers", headers={"Host": "evil.example:8675"})
    assert r.status_code == 400


# ---- limits + headers ------------------------------------------------------- #
async def test_oversized_body_rejected(make_client):
    client, _ = await make_client(max_body_bytes=1000)
    r = await client.post("/api/import", content="x" * 2000)
    assert r.status_code == 413


async def test_oversized_chunked_body_rejected(make_client):
    client, _ = await make_client(max_body_bytes=1000)

    async def chunks():
        for _ in range(5):
            yield b"#" * 400

    r = await client.post("/api/import", content=chunks())
    assert r.status_code == 413


async def test_security_headers(make_client):
    client, _ = await make_client()
    r = await client.get("/")
    assert r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert (await client.get("/api/servers")).headers["cache-control"] == "no-store"


async def test_history_limit_bounded(make_client):
    client, storage = await make_client()
    r = await client.post("/api/import", content=HTTP_YAML)
    sid = (await storage.list_servers())[0].id
    assert (await client.get(f"/api/servers/{sid}/history?limit=999999")).status_code == 422
    assert (await client.get(f"/api/servers/{sid}/history?limit=10")).status_code == 200
    assert r.status_code == 200
