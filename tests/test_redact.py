"""Credentials never leave the process: API reads, exports, check details, logs."""

from __future__ import annotations

import logging
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx2
import pytest
from httpx2 import ASGITransport, AsyncClient

from mcpsonar.check_engine import run_check
from mcpsonar.dashboard import create_app
from mcpsonar.models import CheckEvent, CheckStatus, ServerConfig
from mcpsonar.redact import (
    REDACTED,
    RedactedValueError,
    redact_config,
    redact_url,
    restore_secrets,
    scrub,
    secret_values,
)
from mcpsonar.scan import build_config
from mcpsonar.scheduler import Scheduler
from mcpsonar.state import StateStore
from mcpsonar.storage import Storage

TOKEN = "sk-live-0123456789abcdef"
KUMA_TOKEN = "Kx9fQ2mLp4ZrT7wB"


def _cfg(**kw):
    base = {
        "url": f"https://user:pa55word@mcp.example.com/mcp?api_key={TOKEN}&region=eu",
        "headers": {"Authorization": f"Bearer {TOKEN}", "X-Api-Key": "k-7777777"},
        "webhooks": [
            {"type": "uptime_kuma", "push_url": f"https://kuma.lan/api/push/{KUMA_TOKEN}"},
            {"type": "generic", "url": "https://hooks.slack.com/services/T0/B0/XYZsecret123"},
        ],
    }
    base.update(kw)
    return ServerConfig.model_validate(base)


# ---- pure ---------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "url, leaked",
    [
        (f"https://h/mcp?api_key={TOKEN}", TOKEN),
        (f"https://h/mcp?token={TOKEN}&x=1", TOKEN),
        ("https://user:pa55word@h/mcp", "pa55word"),
        (f"https://{TOKEN}@h/mcp", TOKEN),
        (f"https://actions.zapier.com/mcp/{TOKEN}/sse", TOKEN),
    ],
)
def test_redact_url_masks_credentials(url, leaked):
    out = redact_url(url)
    assert leaked not in out and REDACTED in out


def test_redact_url_keeps_ordinary_urls_readable():
    assert redact_url("https://mcp.example.com/mcp") == "https://mcp.example.com/mcp"
    assert redact_url("http://127.0.0.1:8000/v1/sse?x=1") == "http://127.0.0.1:8000/v1/sse?x=1"
    assert redact_url(None) is None


def test_webhook_urls_mask_whole_path():
    out = redact_url("https://hooks.slack.com/services/T0/B0/XYZsecret123", whole_path=True)
    assert out == f"https://hooks.slack.com/{REDACTED}"


def test_redact_config_masks_everything_secret():
    cfg = _cfg()
    dumped = str(redact_config(cfg))
    for secret in (TOKEN, "pa55word", "k-7777777", KUMA_TOKEN, "XYZsecret123"):
        assert secret not in dumped
    assert "region=eu" in dumped and "mcp.example.com" in dumped  # still useful
    stdio = ServerConfig(transport="stdio", command="npx", env={"GITHUB_TOKEN": TOKEN})
    assert redact_config(stdio)["env"] == {"GITHUB_TOKEN": REDACTED}


def test_restore_secrets_roundtrip():
    old = _cfg()
    edited = ServerConfig.model_validate({**redact_config(old), "check_interval_seconds": 30})
    restored = restore_secrets(edited, old)
    assert restored.url == old.url
    assert restored.headers == old.headers
    assert [w.model_dump() for w in restored.webhooks] == [w.model_dump() for w in old.webhooks]
    assert restored.check_interval_seconds == 30


def test_restore_keeps_real_edits():
    old = _cfg()
    data = redact_config(old)
    data["headers"]["Authorization"] = "Bearer new-token-value"
    data["url"] = "https://other.example.com/mcp"
    restored = restore_secrets(ServerConfig.model_validate(data), old)
    assert restored.headers["Authorization"] == "Bearer new-token-value"
    assert restored.headers["X-Api-Key"] == "k-7777777"
    assert restored.url == "https://other.example.com/mcp"


def test_placeholder_without_stored_secret_is_refused():
    with pytest.raises(RedactedValueError):
        restore_secrets(ServerConfig.model_validate(redact_config(_cfg())), None)


def test_scrub_removes_known_and_generic_secrets():
    cfg = _cfg()
    text = (f"HTTPStatusError: Client error '404 Not Found' for url "
            f"'https://mcp.example.com/mcp?api_key={TOKEN}' (Authorization: Bearer abcdefgh12345)")
    out = scrub(text, secret_values(cfg))
    assert TOKEN not in out and "abcdefgh12345" not in out
    assert "404 Not Found" in out  # the useful part survives


def test_scan_label_does_not_echo_api_key():
    _, label = build_config(f"https://h/mcp?api_key={TOKEN}", None, None, [], [])
    assert TOKEN not in label


# ---- API --------------------------------------------------------------------- #
@pytest.fixture
async def api():
    storage = await Storage.open(":memory:")
    store = StateStore()
    scheduler = Scheduler(storage, store)
    app = create_app(storage, store, scheduler, require_auth=False)
    client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    yield client, storage
    await client.aclose()
    await scheduler.stop()
    await storage.close()


def _body(**kw):
    return {"name": "S", "enabled": False, **_cfg().model_dump(mode="json"), **kw}


async def test_api_never_returns_secrets(api):
    client, storage = api
    created = await client.post("/api/servers", json=_body())
    assert created.status_code == 201
    sid = created.json()["id"]
    for path in ("/api/servers", f"/api/servers/{sid}", "/api/status", "/api/export"):
        text = (await client.get(path)).text
        for secret in (TOKEN, "pa55word", "k-7777777", KUMA_TOKEN, "XYZsecret123"):
            assert secret not in text, (path, secret)
    assert TOKEN not in created.text
    # ...while the stored config still has them, so monitoring keeps working
    stored = await storage.get_server(sid)
    assert stored.headers["Authorization"] == f"Bearer {TOKEN}"


async def test_editing_with_redacted_values_keeps_credentials(api):
    """The dashboard edit form sends back what it was shown (placeholders)."""
    client, storage = api
    sid = (await client.post("/api/servers", json=_body())).json()["id"]
    shown = (await client.get(f"/api/servers/{sid}")).json()
    shown.pop("id")
    shown["check_interval_seconds"] = 45
    assert (await client.put(f"/api/servers/{sid}", json=shown)).status_code == 200
    stored = await storage.get_server(sid)
    assert stored.check_interval_seconds == 45
    assert stored.to_server_config() == _cfg(check_interval_seconds=45)


async def test_export_redacts_unless_asked_and_redacted_import_is_refused(api):
    client, _ = api
    await client.post("/api/servers", json=_body())
    redacted = (await client.get("/api/export")).text
    assert TOKEN not in redacted
    r = await client.post("/api/import", content=redacted)
    assert r.status_code == 400 and "redacted" in r.json()["detail"]
    full = (await client.get("/api/export?include_secrets=true")).text
    assert TOKEN in full
    assert (await client.post("/api/import", content=full)).status_code == 200


# ---- check details + logs --------------------------------------------------- #
class _NotFound(BaseHTTPRequestHandler):
    def _nf(self):
        self.send_response(500)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_POST = do_DELETE = _nf

    def log_message(self, *args):
        pass


async def test_check_detail_does_not_leak_url_api_key():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = HTTPServer(("127.0.0.1", port), _NotFound)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        cfg = ServerConfig(url=f"http://127.0.0.1:{port}/mcp?api_key={TOKEN}")
        ev = (await run_check("s", cfg)).event
        assert ev.status == CheckStatus.DOWN and "500" in ev.detail, ev.detail
        assert TOKEN not in ev.detail
    finally:
        server.shutdown()


async def test_failed_webhook_log_does_not_leak_token(caplog):
    storage = await Storage.open(":memory:")
    try:
        def handler(request):
            return httpx2.Response(500)

        scheduler = Scheduler(storage, StateStore())
        scheduler._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))
        server = await storage.create_server(
            "S", _cfg(webhooks=[{"type": "uptime_kuma",
                                 "push_url": f"https://kuma.lan/api/push/{KUMA_TOKEN}"}])
        )
        from mcpsonar.adapters import build_push_adapters

        adapters = build_push_adapters(server, scheduler._client)
        with caplog.at_level(logging.DEBUG, logger="mcpsonar"):  # cli.py keeps httpx2 at WARNING
            await scheduler._emit(server.id, CheckEvent(server_id=server.id, status="down",
                                                        latency_ms=0), adapters,
                                  secret_values(server))
        assert "adapter uptime_kuma failed" in caplog.text
        assert KUMA_TOKEN not in caplog.text
        await scheduler.stop()
    finally:
        await storage.close()
