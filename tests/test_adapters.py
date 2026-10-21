"""Adapter tests using httpx2.MockTransport (no real network) + the /metrics route."""

from __future__ import annotations

import httpx2
import pytest
from httpx2 import ASGITransport, AsyncClient

from mcpsonar.adapters import render_metrics
from mcpsonar.adapters.generic_webhook import GenericWebhookAdapter
from mcpsonar.adapters.uptime_kuma import UptimeKumaAdapter
from mcpsonar.dashboard import create_app
from mcpsonar.models import CheckEvent, CheckStatus, MonitoredServer, ServerConfig
from mcpsonar.scheduler import Scheduler
from mcpsonar.state import StateStore
from mcpsonar.storage import Storage


def _event(status: CheckStatus, **kw) -> CheckEvent:
    defaults = {
        "server_id": "s1",
        "status": status,
        "latency_ms": 1234.5,
        "spec_version": "2025-11-25",
        "spec_version_supported": True,
    }
    defaults.update(kw)
    return CheckEvent(**defaults)


# ---- Uptime Kuma mapping ----------------------------------------------------- #
async def test_kuma_degraded_maps_to_up_with_msg():
    seen: dict = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen["params"] = dict(request.url.params)
        return httpx2.Response(200, text="OK")

    client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))
    adapter = UptimeKumaAdapter("http://kuma/api/push/tok", client)
    await adapter.send(_event(CheckStatus.DEGRADED, detail="slow"))
    await client.aclose()

    assert seen["params"]["status"] == "up"  # degraded -> up
    assert "degraded" in seen["params"]["msg"]
    assert seen["params"]["ping"] == "1234"


async def test_kuma_down_maps_to_down():
    seen: dict = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen["params"] = dict(request.url.params)
        return httpx2.Response(200)

    client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))
    await UptimeKumaAdapter("http://kuma/push", client).send(_event(CheckStatus.DOWN))
    await client.aclose()
    assert seen["params"]["status"] == "down"


# ---- Generic webhook: on-filter + retry/backoff ------------------------------ #
async def test_generic_skips_status_not_in_on():
    calls = 0

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1
        return httpx2.Response(200)

    client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))
    adapter = GenericWebhookAdapter("http://hook", [CheckStatus.DOWN], client)
    await adapter.send(_event(CheckStatus.UP))  # UP not in on -> no request
    await client.aclose()
    assert calls == 0


async def test_generic_retries_then_succeeds():
    attempts = 0

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal attempts
        attempts += 1
        return httpx2.Response(500) if attempts < 3 else httpx2.Response(200)

    client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))
    adapter = GenericWebhookAdapter(
        "http://hook", [CheckStatus.DOWN], client, max_retries=3, backoff=0.001
    )
    await adapter.send(_event(CheckStatus.DOWN))  # 500, 500, 200
    await client.aclose()
    assert attempts == 3


async def test_generic_raises_after_exhausting_retries():
    attempts = 0

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal attempts
        attempts += 1
        return httpx2.Response(503)

    client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))
    adapter = GenericWebhookAdapter(
        "http://hook", [CheckStatus.DOWN], client, max_retries=3, backoff=0.001
    )
    with pytest.raises(httpx2.HTTPStatusError):
        await adapter.send(_event(CheckStatus.DOWN))
    await client.aclose()
    assert attempts == 3


# ---- Prometheus exporter ----------------------------------------------------- #
def test_render_metrics_contains_expected_series():
    servers = [MonitoredServer(id="s1", name="S1", url="http://x/mcp")]
    store = StateStore()
    store.update(_event(CheckStatus.DEGRADED, tools_checked=2, tools_failed=1))

    text = render_metrics(servers, store)
    assert "# TYPE mcpsonar_up gauge" in text
    assert 'mcpsonar_up{server_id="s1"} 0' in text  # degraded is not "up"
    assert 'mcpsonar_status_code{server_id="s1"} 1' in text  # degraded == 1
    assert 'mcpsonar_tools_failed{server_id="s1"} 1' in text
    assert 'name="S1"' in text


async def test_metrics_route_serves_prometheus_text():
    storage = await Storage.open(":memory:")
    server = await storage.create_server("S1", ServerConfig(url="http://x/mcp"))
    store = StateStore()
    store.update(_event(CheckStatus.UP, server_id=server.id))
    scheduler = Scheduler(storage, store)
    app = create_app(storage, store, scheduler, require_auth=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/metrics")
        assert resp.status_code == 200
        assert "text/plain" in resp.headers["content-type"]
        assert f'mcpsonar_up{{server_id="{server.id}"}} 1' in resp.text
    await scheduler.stop()
    await storage.close()
