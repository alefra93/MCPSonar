"""Dashboard login: first-run setup, session gating, login/logout, password hashing,
bootstrap token, throttling and session revocation."""

from __future__ import annotations

import asyncio

from httpx2 import ASGITransport, AsyncClient

from mcpsonar.auth import (
    COOKIE_NAME,
    LEGACY_ITERATIONS,
    PBKDF2_ITERATIONS,
    LoginThrottle,
    hash_password,
    needs_rehash,
    token_digest,
    verify_password,
)
from mcpsonar.dashboard import create_app
from mcpsonar.scheduler import Scheduler
from mcpsonar.state import StateStore
from mcpsonar.storage import Storage


async def _client(require_auth=True, base_url="http://test", **kw):
    storage = await Storage.open(":memory:")
    store = StateStore()
    scheduler = Scheduler(storage, store)
    app = create_app(storage, store, scheduler, require_auth=require_auth, **kw)
    client = AsyncClient(transport=ASGITransport(app=app), base_url=base_url)
    return client, scheduler, storage


async def _close(client, scheduler, storage):
    await client.aclose()
    await scheduler.stop()
    await storage.close()


# ---- unit: hashing ---------------------------------------------------------- #
def test_password_hash_roundtrip():
    salt, h = hash_password("hunter2000")
    assert h.startswith(f"pbkdf2_sha256${PBKDF2_ITERATIONS}$")
    assert verify_password("hunter2000", salt, h)
    assert not verify_password("wrong", salt, h)
    assert not needs_rehash(h)


def test_legacy_v05_hash_still_verifies_and_needs_rehash():
    # v0.5 stored the bare hex digest of 200k-iteration PBKDF2.
    salt, encoded = hash_password("hunter2000", iterations=LEGACY_ITERATIONS)
    legacy = encoded.rsplit("$", 1)[1]
    assert verify_password("hunter2000", salt, legacy)
    assert needs_rehash(legacy)


def test_throttle_window():
    t = LoginThrottle(max_failures=3, window_s=60)
    for i in range(3):
        assert t.retry_after("ip", now=i) == 0
        t.failure("ip", now=i)
    assert t.retry_after("ip", now=3) > 0  # 3 failures inside the window: blocked
    assert t.retry_after("other", now=3) == 0  # per client, not global
    assert t.retry_after("ip", now=100) == 0  # window passed
    t.failure("ip", now=101)
    t.reset("ip")
    assert t.retry_after("ip", now=102) == 0


def test_throttle_memory_is_bounded():
    t = LoginThrottle(max_keys=5)
    for i in range(50):
        t.failure(f"ip{i}", now=i)
    assert len(t._failures) <= 5


# ---- full flow ------------------------------------------------------------- #
async def test_setup_then_protected_access_then_logout():
    client, scheduler, storage = await _client(require_auth=True)
    try:
        s = (await client.get("/api/auth/status")).json()
        assert s["auth_enabled"] and s["setup_required"] and not s["authenticated"]
        assert s["setup_token_required"] is False  # library default: no token configured
        assert (await client.get("/api/servers")).status_code == 401

        r = await client.post("/api/auth/setup", json={"username": "admin", "password": "supersecret"})
        assert r.status_code == 200
        assert (await client.get("/api/servers")).status_code == 200

        assert (await client.post(
            "/api/auth/setup", json={"username": "x", "password": "supersecret"}
        )).status_code == 400

        await client.post("/api/auth/logout")
        assert (await client.get("/api/servers")).status_code == 401
    finally:
        await _close(client, scheduler, storage)


async def test_logout_revokes_the_session_server_side():
    """A copied cookie must stop working after logout (v0.5 only cleared it client-side)."""
    client, scheduler, storage = await _client(require_auth=True)
    try:
        await client.post("/api/auth/setup", json={"username": "admin", "password": "supersecret"})
        stolen = client.cookies.get(COOKIE_NAME)
        assert stolen
        await client.post("/api/auth/logout")
        client.cookies.set(COOKIE_NAME, stolen)
        assert (await client.get("/api/servers")).status_code == 401
    finally:
        await _close(client, scheduler, storage)


async def test_session_tokens_are_stored_hashed_and_forged_tokens_rejected():
    client, scheduler, storage = await _client(require_auth=True)
    try:
        await client.post("/api/auth/setup", json={"username": "admin", "password": "supersecret"})
        token = client.cookies.get(COOKIE_NAME)
        cur = await storage._conn.execute("SELECT token_hash FROM sessions")
        stored = [r[0] for r in await cur.fetchall()]
        assert stored == [token_digest(token)] and token not in stored
        # Send ONLY the forged cookie: httpx2 >= 2.16 adds a cookie set without a domain
        # next to the server-set one instead of replacing it, and a request carrying the
        # valid session too is (correctly) authenticated.
        client.cookies.clear()
        client.cookies.set(COOKIE_NAME, "forged-" + token)
        assert (await client.get("/api/servers")).status_code == 401
    finally:
        await _close(client, scheduler, storage)


async def test_expired_session_rejected():
    client, scheduler, storage = await _client(require_auth=True)
    try:
        await storage.create_admin("admin", "supersecret")
        token = await storage.create_session("admin", ttl_s=-1)
        client.cookies.set(COOKIE_NAME, token)
        assert (await client.get("/api/servers")).status_code == 401
    finally:
        await _close(client, scheduler, storage)


async def test_login_rejects_bad_credentials():
    client, scheduler, storage = await _client(require_auth=True)
    try:
        await storage.create_admin("admin", "supersecret")
        r = await client.post("/api/auth/login", json={"username": "admin", "password": "nope"})
        assert r.status_code == 401
        unknown = await client.post("/api/auth/login", json={"username": "x", "password": "nope"})
        assert unknown.json() == r.json()  # same answer for unknown user and bad password
        r = await client.post("/api/auth/login", json={"username": "admin", "password": "supersecret"})
        assert r.status_code == 200
        assert (await client.get("/api/servers")).status_code == 200
    finally:
        await _close(client, scheduler, storage)


async def test_login_is_throttled_after_repeated_failures():
    client, scheduler, storage = await _client(require_auth=True)
    try:
        await storage.create_admin("admin", "supersecret")
        bad = {"username": "admin", "password": "wrong-password"}
        codes = [(await client.post("/api/auth/login", json=bad)).status_code for _ in range(11)]
        assert codes[:10] == [401] * 10 and codes[10] == 429
        # even the right password is refused while throttled
        r = await client.post("/api/auth/login", json={"username": "admin", "password": "supersecret"})
        assert r.status_code == 429 and int(r.headers["retry-after"]) > 0
    finally:
        await _close(client, scheduler, storage)


async def test_legacy_hash_is_upgraded_on_login():
    client, scheduler, storage = await _client(require_auth=True)
    try:
        salt, encoded = hash_password("supersecret", iterations=LEGACY_ITERATIONS)
        await storage._conn.execute(
            "INSERT INTO users (username, password_hash, salt, created_at) VALUES (?,?,?,?)",
            ("admin", encoded.rsplit("$", 1)[1], salt, "2026-01-01"),
        )
        await storage._conn.commit()
        r = await client.post("/api/auth/login", json={"username": "admin", "password": "supersecret"})
        assert r.status_code == 200
        cur = await storage._conn.execute("SELECT password_hash FROM users")
        assert not needs_rehash((await cur.fetchone())[0])
        await client.post("/api/auth/logout")
        r = await client.post("/api/auth/login", json={"username": "admin", "password": "supersecret"})
        assert r.status_code == 200  # still works with the upgraded hash
    finally:
        await _close(client, scheduler, storage)


async def test_overlong_password_rejected_without_hashing():
    client, scheduler, storage = await _client(require_auth=True)
    try:
        r = await client.post("/api/auth/login", json={"username": "a", "password": "x" * 5000})
        assert r.status_code == 422
    finally:
        await _close(client, scheduler, storage)


async def test_short_password_rejected_at_setup():
    client, scheduler, storage = await _client(require_auth=True)
    try:
        assert (await client.post(
            "/api/auth/setup", json={"username": "admin", "password": "short"}
        )).status_code == 400
    finally:
        await _close(client, scheduler, storage)


# ---- first-admin bootstrap -------------------------------------------------- #
async def test_setup_requires_the_setup_token_when_configured():
    client, scheduler, storage = await _client(require_auth=True, setup_token="s3t-up")
    try:
        assert (await client.get("/api/auth/status")).json()["setup_token_required"] is True
        creds = {"username": "admin", "password": "supersecret"}
        assert (await client.post("/api/auth/setup", json=creds)).status_code == 403
        wrong = {**creds, "setup_token": "guess"}
        assert (await client.post("/api/auth/setup", json=wrong)).status_code == 403
        assert not await storage.has_admin()
        ok = {**creds, "setup_token": "s3t-up"}
        assert (await client.post("/api/auth/setup", json=ok)).status_code == 200
        assert (await client.get("/api/auth/status")).json()["setup_token_required"] is False
    finally:
        await _close(client, scheduler, storage)


async def test_setup_token_guessing_is_throttled():
    client, scheduler, storage = await _client(require_auth=True, setup_token="s3t-up")
    try:
        bad = {"username": "admin", "password": "supersecret", "setup_token": "nope"}
        codes = [(await client.post("/api/auth/setup", json=bad)).status_code for _ in range(11)]
        assert codes[-1] == 429
    finally:
        await _close(client, scheduler, storage)


async def test_concurrent_first_admin_setup_creates_exactly_one_admin():
    client, scheduler, storage = await _client(require_auth=True)
    try:
        results = await asyncio.gather(*[
            client.post("/api/auth/setup", json={"username": f"user{i}", "password": "supersecret"})
            for i in range(5)
        ])
        assert sorted(r.status_code for r in results) == [200, 400, 400, 400, 400]
        cur = await storage._conn.execute("SELECT COUNT(*) FROM users")
        assert (await cur.fetchone())[0] == 1
    finally:
        await _close(client, scheduler, storage)


async def test_create_first_admin_is_atomic_at_storage_level():
    storage = await Storage.open(":memory:")
    try:
        made = await asyncio.gather(
            storage.create_first_admin("a", "supersecret"),
            storage.create_first_admin("b", "supersecret"),
        )
        assert sorted(made) == [False, True]
    finally:
        await storage.close()


# ---- cookie flags ----------------------------------------------------------- #
async def test_cookie_flags_http_vs_https():
    for base, secure in (("http://test", False), ("https://test", True)):
        client, scheduler, storage = await _client(require_auth=True, base_url=base)
        try:
            r = await client.post(
                "/api/auth/setup", json={"username": "admin", "password": "supersecret"}
            )
            cookie = r.headers["set-cookie"].lower()
            assert "httponly" in cookie and "samesite=lax" in cookie
            assert ("secure" in cookie.replace("samesite", "")) is secure
        finally:
            await _close(client, scheduler, storage)


async def test_cookie_secure_always():
    client, scheduler, storage = await _client(require_auth=True, cookie_secure="always")
    try:
        r = await client.post("/api/auth/setup", json={"username": "admin", "password": "supersecret"})
        assert "; secure" in r.headers["set-cookie"].lower()
    finally:
        await _close(client, scheduler, storage)


# ---- metrics + no-auth ------------------------------------------------------ #
async def test_metrics_public_even_with_auth():
    client, scheduler, storage = await _client(require_auth=True)
    try:
        assert (await client.get("/metrics")).status_code == 200  # Prometheus can scrape
    finally:
        await _close(client, scheduler, storage)


async def test_metrics_token_when_configured():
    client, scheduler, storage = await _client(require_auth=True, metrics_token="m-tok")
    try:
        assert (await client.get("/metrics")).status_code == 401
        bad = await client.get("/metrics", headers={"Authorization": "Bearer nope"})
        assert bad.status_code == 401
        ok = await client.get("/metrics", headers={"Authorization": "Bearer m-tok"})
        assert ok.status_code == 200
    finally:
        await _close(client, scheduler, storage)


async def test_no_auth_mode_leaves_everything_open():
    client, scheduler, storage = await _client(require_auth=False)
    try:
        assert (await client.get("/api/servers")).status_code == 200
        assert (await client.get("/api/auth/status")).json()["authenticated"] is True
    finally:
        await _close(client, scheduler, storage)
