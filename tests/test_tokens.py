"""API tokens for the CLI and automation: created only from a dashboard session, stored as
hashes, shown once, scoped read/write, revocable and expiring; a token can't mint tokens."""

from __future__ import annotations

import pytest
from httpx2 import ASGITransport, AsyncClient

from mcpsonar.auth import API_TOKEN_PREFIX, token_digest
from mcpsonar.dashboard import create_app
from mcpsonar.scheduler import Scheduler
from mcpsonar.state import StateStore
from mcpsonar.storage import Storage

SERVER = {"name": "s", "url": "http://127.0.0.1:1/mcp", "enabled": False}


@pytest.fixture
async def env():
    storage = await Storage.open(":memory:")
    store = StateStore()
    scheduler = Scheduler(storage, store)
    app = create_app(storage, store, scheduler, require_auth=True)
    admin = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await storage.create_admin("admin", "supersecret")
    await admin.post("/api/auth/login", json={"username": "admin", "password": "supersecret"})
    anon = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    yield admin, anon, storage
    await admin.aclose()
    await anon.aclose()
    await scheduler.stop()
    await storage.close()


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _create(admin, scope="read", **kw):
    r = await admin.post("/api/tokens", json={"name": f"t-{scope}", "scope": scope, **kw})
    assert r.status_code == 201, r.text
    return r.json()


async def test_token_shown_once_and_stored_hashed(env):
    admin, _, storage = env
    created = await _create(admin)
    token = created["token"]
    assert token.startswith(API_TOKEN_PREFIX) and len(token) > 40
    listed = (await admin.get("/api/tokens")).json()
    assert [t["id"] for t in listed] == [created["id"]]
    assert token not in str(listed) and "token" not in listed[0]
    cur = await storage._conn.execute("SELECT token_hash FROM api_tokens")
    assert [r[0] for r in await cur.fetchall()] == [token_digest(token)]


async def test_read_token_can_read_but_not_write(env):
    admin, anon, _ = env
    token = (await _create(admin, "read"))["token"]
    assert (await anon.get("/api/servers", headers=bearer(token))).status_code == 200
    r = await anon.post("/api/servers", json=SERVER, headers=bearer(token))
    assert r.status_code == 403 and "read-only" in r.json()["detail"]


async def test_write_token_can_change_servers(env):
    admin, anon, _ = env
    token = (await _create(admin, "write"))["token"]
    r = await anon.post("/api/servers", json=SERVER, headers=bearer(token))
    assert r.status_code == 201


@pytest.mark.parametrize("bad", ["mcps_not-a-real-token", "garbage", ""])
async def test_unknown_tokens_rejected(env, bad):
    _, anon, _ = env
    r = await anon.get("/api/servers", headers={"Authorization": f"Bearer {bad}"})
    assert r.status_code == 401


async def test_revoked_and_expired_tokens_rejected(env):
    admin, anon, storage = env
    created = await _create(admin)
    assert (await admin.delete(f"/api/tokens/{created['id']}")).status_code == 204
    assert (await anon.get("/api/servers", headers=bearer(created["token"]))).status_code == 401
    assert (await admin.delete(f"/api/tokens/{created['id']}")).status_code == 404
    _, expired = await storage.create_api_token("old", "read", "admin", ttl_s=-1)
    assert (await anon.get("/api/servers", headers=bearer(expired))).status_code == 401


async def test_tokens_cannot_manage_tokens(env):
    admin, anon, _ = env
    token = (await _create(admin, "write"))["token"]
    assert (await anon.get("/api/tokens", headers=bearer(token))).status_code == 403
    r = await anon.post("/api/tokens", json={"name": "x", "scope": "write"},
                        headers=bearer(token))
    assert r.status_code == 403


async def test_anonymous_cannot_manage_tokens(env):
    _, anon, _ = env
    assert (await anon.get("/api/tokens")).status_code == 401
    assert (await anon.post("/api/tokens", json={"name": "x"})).status_code == 401


async def test_expiry_and_last_used(env):
    admin, anon, _ = env
    created = await _create(admin, expires_in_days=30)
    assert created["expires_at"] - created["created_at"] == pytest.approx(30 * 86400, abs=5)
    assert created["last_used_at"] is None
    await anon.get("/api/servers", headers=bearer(created["token"]))
    listed = (await admin.get("/api/tokens")).json()
    assert listed[0]["last_used_at"] is not None


async def test_token_request_validation(env):
    admin, _, _ = env
    for body in ({"name": ""}, {"name": "x", "scope": "admin"},
                 {"name": "x", "expires_in_days": 0}, {"name": "x" * 65}):
        assert (await admin.post("/api/tokens", json=body)).status_code == 422


async def test_no_auth_instance_has_no_tokens():
    storage = await Storage.open(":memory:")
    store = StateStore()
    scheduler = Scheduler(storage, store)
    app = create_app(storage, store, scheduler, require_auth=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post("/api/tokens", json={"name": "x"})
        assert r.status_code == 400 and "no token" in r.json()["detail"]
    await scheduler.stop()
    await storage.close()


async def test_dashboard_offers_token_management(env):
    admin, _, _ = env
    page = (await admin.get("/")).text
    assert 'id="tokensOverlay"' in page and "createToken()" in page
