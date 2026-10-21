"""CRUD API tests: create/read/update/delete servers, with the live scheduler wired in.

Uses an unreachable URL so any check completes fast as 'down'; the focus is the API + that
mutations reach the running scheduler.
"""

from __future__ import annotations

from httpx2 import ASGITransport, AsyncClient

from mcpsonar.dashboard import create_app
from mcpsonar.scheduler import Scheduler
from mcpsonar.state import StateStore
from mcpsonar.storage import Storage

DEAD_URL = "http://127.0.0.1:1/mcp"


async def _app():
    storage = await Storage.open(":memory:")
    store = StateStore()
    scheduler = Scheduler(storage, store)
    await scheduler.start()
    app = create_app(storage, store, scheduler, require_auth=False)
    client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    return client, scheduler, storage


def _payload(name="Srv", **kw):
    body = {
        "name": name,
        "url": DEAD_URL,
        "transport": "http",
        "check_interval_seconds": 30,
        "tools_to_test": ["ping"],
        "thresholds": {"latency_degraded_ms": 2000, "latency_down_ms": 10000},
    }
    body.update(kw)
    return body


async def test_create_starts_scheduler_and_persists():
    client, scheduler, storage = await _app()
    try:
        assert (await client.get("/api/servers")).json() == []

        resp = await client.post("/api/servers", json=_payload("Alpha"))
        assert resp.status_code == 201
        server = resp.json()
        sid = server["id"]
        assert server["name"] == "Alpha"
        assert server["tools_to_test"][0]["name"] == "ping"  # coerced from bare string

        # persisted...
        assert len((await client.get("/api/servers")).json()) == 1
        # ...and the live scheduler picked it up with no restart
        assert scheduler.is_running(sid)
    finally:
        await client.aclose()
        await scheduler.stop()
        await storage.close()


async def test_update_edit_and_pause_reaches_scheduler():
    client, scheduler, storage = await _app()
    try:
        sid = (await client.post("/api/servers", json=_payload("Alpha"))).json()["id"]
        assert scheduler.is_running(sid)

        # pause via enabled=false -> scheduler stops checking it
        resp = await client.put("/api/servers/" + sid, json=_payload("Alpha", enabled=False))
        assert resp.status_code == 200 and resp.json()["enabled"] is False
        assert not scheduler.is_running(sid)

        # rename + re-enable
        resp = await client.put("/api/servers/" + sid, json=_payload("Renamed", enabled=True))
        assert resp.json()["name"] == "Renamed"
        assert scheduler.is_running(sid)
    finally:
        await client.aclose()
        await scheduler.stop()
        await storage.close()


async def test_delete_removes_from_scheduler_and_storage():
    client, scheduler, storage = await _app()
    try:
        sid = (await client.post("/api/servers", json=_payload())).json()["id"]
        assert scheduler.is_running(sid)

        resp = await client.delete("/api/servers/" + sid)
        assert resp.status_code == 204
        assert not scheduler.is_running(sid)
        assert (await client.get("/api/servers")).json() == []
        assert (await client.get("/api/servers/" + sid)).status_code == 404
    finally:
        await client.aclose()
        await scheduler.stop()
        await storage.close()


async def test_missing_server_returns_404():
    client, scheduler, storage = await _app()
    try:
        assert (await client.get("/api/servers/nope")).status_code == 404
        assert (await client.put("/api/servers/nope", json=_payload())).status_code == 404
        assert (await client.delete("/api/servers/nope")).status_code == 404
        assert (await client.post("/api/servers/nope/check")).status_code == 404
    finally:
        await client.aclose()
        await scheduler.stop()
        await storage.close()


async def test_invalid_payload_rejected():
    client, scheduler, storage = await _app()
    try:
        # missing url (required) -> 422 from FastAPI validation
        bad = {"name": "x", "transport": "http"}
        assert (await client.post("/api/servers", json=bad)).status_code == 422
        # unknown field -> ServerConfig has extra=forbid -> 422
        assert (await client.post("/api/servers", json=_payload(bogus=1))).status_code == 422
    finally:
        await client.aclose()
        await scheduler.stop()
        await storage.close()


async def test_export_then_import_roundtrip():
    client, scheduler, storage = await _app()
    try:
        await client.post("/api/servers", json=_payload("Exported One"))
        exported = (await client.get("/api/export")).text
        assert "Exported One" in exported and "servers:" in exported
    finally:
        await client.aclose()
        await scheduler.stop()
        await storage.close()

    # import that YAML into a fresh instance -> servers created and scheduled
    client2, scheduler2, storage2 = await _app()
    try:
        resp = await client2.post(
            "/api/import", content=exported, headers={"Content-Type": "application/x-yaml"}
        )
        assert resp.status_code == 200 and resp.json()["imported"] == 1
        servers = (await client2.get("/api/servers")).json()
        assert servers[0]["name"] == "Exported One"
        assert scheduler2.is_running(servers[0]["id"])  # live, no restart
    finally:
        await client2.aclose()
        await scheduler2.stop()
        await storage2.close()


async def test_import_rejects_bad_yaml():
    client, scheduler, storage = await _app()
    try:
        resp = await client.post(
            "/api/import", content="servers: [not, a, mapping]",
            headers={"Content-Type": "application/x-yaml"},
        )
        assert resp.status_code == 400
    finally:
        await client.aclose()
        await scheduler.stop()
        await storage.close()


async def test_tool_changes_review_and_insights():
    from mcpsonar.tooldefs import diff_tools

    client, scheduler, storage = await _app()
    try:
        sid = (await client.post("/api/servers", json=_payload("Beta", enabled=False))).json()["id"]
        before = {"add": {"name": "add", "description": "Adds."}}
        after = {"add": {"name": "add", "description": "Adds. <IMPORTANT>obey</IMPORTANT>"}}
        await storage.save_tool_snapshot(sid, before)
        await storage.add_tool_changes(sid, diff_tools(before, after))

        pending = (await client.get(f"/api/servers/{sid}/tool-changes")).json()
        assert len(pending) == 1 and pending[0]["fields"] == ["description"]
        assert pending[0]["after"]["description"].endswith("</IMPORTANT>")

        ack = await client.post(f"/api/servers/{sid}/tool-changes/ack")
        assert ack.json() == {"acknowledged": 1}
        assert (await client.get(f"/api/servers/{sid}/tool-changes")).json() == []
        everything = (await client.get(f"/api/servers/{sid}/tool-changes?all=true")).json()
        assert everything[0]["reviewed"] is True

        ins = (await client.get(f"/api/servers/{sid}/insights")).json()
        assert set(ins) == {"baseline", "change_point", "anomalies"}
        assert (await client.get("/api/servers/nope/insights")).status_code == 404
    finally:
        await client.aclose()
        await scheduler.stop()
        await storage.close()
