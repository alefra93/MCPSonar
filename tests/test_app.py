"""Tests for the config loader (YAML on/off footgun) and the storage-backed dashboard app.

The dashboard routes are async and read from an aiosqlite Storage, so these drive the app
with httpx2's ASGITransport inside the test's own event loop (keeps the DB connection and the
request handling on one loop).
"""

from __future__ import annotations

import pytest
from httpx2 import ASGITransport, AsyncClient

from mcpsonar.dashboard import create_app
from mcpsonar.loader import ConfigError, load_config
from mcpsonar.models import CheckEvent, CheckStatus, ServerConfig
from mcpsonar.scheduler import Scheduler
from mcpsonar.state import StateStore
from mcpsonar.storage import Storage


def test_loader_reads_unquoted_on_as_string(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        """
servers:
  s1:
    url: "http://127.0.0.1:8000/mcp"
    webhooks:
      - type: generic
        url: "http://hook"
        on: [down, degraded]
""".lstrip(),
        encoding="utf-8",
    )
    config = load_config(cfg_file)
    generic = config.servers["s1"].webhooks[0]
    assert [s.value for s in generic.on] == ["down", "degraded"]


def test_loader_reports_directory_config_clearly(tmp_path):
    # Simulates the Docker bind-mount footgun: /config/config.yaml is a directory.
    (tmp_path / "config.yaml").mkdir()
    with pytest.raises(ConfigError, match="is a directory"):
        load_config(tmp_path / "config.yaml")


def test_loader_reports_missing_config_clearly(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yaml")


async def test_index_serves_the_management_shell():
    storage = await Storage.open(":memory:")
    scheduler = Scheduler(storage, StateStore())
    app = create_app(storage, StateStore(), scheduler, require_auth=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/")
        assert resp.status_code == 200
        # The page is a JS shell; data arrives via /api/status, not server-rendered HTML.
        assert "Add server" in resp.text and "/api/status" in resp.text
    await scheduler.stop()
    await storage.close()


async def test_api_status_reports_name_enabled_and_event():
    storage = await Storage.open(":memory:")
    server = await storage.create_server("Beta", ServerConfig(url="http://127.0.0.1:8000/mcp"))
    store = StateStore()
    store.update(
        CheckEvent(
            server_id=server.id,
            status=CheckStatus.UP,
            latency_ms=42.0,
            spec_version="2025-11-25",
            spec_version_supported=True,
        )
    )
    scheduler = Scheduler(storage, store)
    app = create_app(storage, store, scheduler, require_auth=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        data = (await client.get("/api/status")).json()
        assert data[server.id]["name"] == "Beta"
        assert data[server.id]["enabled"] is True
        assert data[server.id]["event"]["status"] == "up"

        metrics = (await client.get("/metrics")).text
        assert f'mcpsonar_up{{server_id="{server.id}"}} 1' in metrics
        assert 'name="Beta"' in metrics
    await scheduler.stop()
    await storage.close()
