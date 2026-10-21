"""CRUD API for managing monitored servers at runtime.

Every mutation updates both the store (persistence) and the live scheduler, so adding a
server starts checking it immediately — no restart. These routes back the management UI.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import yaml
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from . import anomaly as ad
from .lint import lint_tool
from .loader import parse_config_text
from .models import CheckStatus, MonitoredServer, ServerConfig, ServerInput, TransportType
from .redact import RedactedValueError, check_no_placeholders, redact_config, restore_secrets
from .scheduler import Scheduler
from .services import inspect_server
from .state import StateStore
from .storage import Storage
from .websec import read_limited_body

MAX_HISTORY_LIMIT = 5000

_STDIO_REFUSED = (
    "stdio servers make mcpsonar run a command on this host, so they cannot be added or "
    "changed over an unauthenticated API. Enable the login (drop --no-auth), seed them from "
    "the YAML config (--config), or start with --allow-stdio-api if this port is reachable "
    "only by you."
)


def _same_process(a: ServerConfig, b: ServerConfig) -> bool:
    return (a.command, a.args, a.env) == (b.command, b.args, b.env)


def register_api(
    app: FastAPI,
    storage: Storage,
    store: StateStore,
    scheduler: Scheduler,
    *,
    allow_stdio: bool = True,
) -> None:
    background: set[asyncio.Task] = set()  # keep fire-and-forget tasks referenced

    def _guard_stdio(new: ServerConfig, old: MonitoredServer | None = None) -> None:
        """Refuse a new or changed stdio launch command when stdio is not allowed over the
        API. Pausing/renaming an existing (YAML-seeded) stdio server stays possible."""
        if allow_stdio or new.transport != TransportType.STDIO:
            return
        if old is not None and old.transport == TransportType.STDIO and _same_process(old, new):
            return
        raise HTTPException(403, _STDIO_REFUSED)

    def _secret_safe(cfg: ServerConfig, old: ServerConfig | None = None) -> ServerConfig:
        try:
            return restore_secrets(cfg, old)
        except RedactedValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    # Reads never return credentials (headers, env, URL keys, webhook tokens): see redact.py.
    # Writes accept the redacted placeholders back and keep the stored values.
    @app.get("/api/servers")
    async def list_servers():
        servers = await storage.list_servers()
        return [redact_config(s) for s in servers]

    @app.get("/api/servers/{server_id}")
    async def get_server(server_id: str):
        server = await storage.get_server(server_id)
        if server is None:
            raise HTTPException(404, "server not found")
        return redact_config(server)

    @app.post("/api/servers", status_code=201)
    async def create_server(payload: ServerInput):
        _guard_stdio(payload)
        cfg = _secret_safe(payload.to_server_config())
        server = await storage.create_server(payload.name, cfg, enabled=payload.enabled)
        scheduler.add(server)  # start checking immediately, no restart
        return redact_config(server)

    @app.put("/api/servers/{server_id}")
    async def update_server(server_id: str, payload: ServerInput):
        existing = await storage.get_server(server_id)
        if existing is None:
            raise HTTPException(404, "server not found")
        cfg = _secret_safe(payload.to_server_config(), existing.to_server_config())
        _guard_stdio(cfg, existing)
        server = await storage.update_server(server_id, payload.name, cfg, enabled=payload.enabled)
        if server is None:
            raise HTTPException(404, "server not found")
        await scheduler.update(server)  # restart its loop with the new config
        return redact_config(server)

    @app.delete("/api/servers/{server_id}", status_code=204)
    async def delete_server(server_id: str):
        await scheduler.remove(server_id)
        if not await storage.delete_server(server_id):
            raise HTTPException(404, "server not found")
        return JSONResponse(status_code=204, content=None)

    @app.post("/api/servers/{server_id}/check")
    async def check_now(server_id: str):
        server = await storage.get_server(server_id)
        if server is None:
            raise HTTPException(404, "server not found")
        event = await scheduler.run_once(server)
        return event.model_dump(mode="json")

    @app.get("/api/servers/{server_id}/tools")
    async def list_server_tools(server_id: str):
        """Connect to the server right now and return the tools it exposes, each with its full
        definition and any tool-poisoning findings."""
        server = await storage.get_server(server_id)
        if server is None:
            raise HTTPException(404, "server not found")
        found = await inspect_server(server.to_server_config(), server.name)
        if found.error:
            raise HTTPException(502, f"could not list tools: {found.error}")
        return [
            {
                "name": name,
                "title": d.get("title"),
                "description": d.get("description") or "",
                "definition": d,
                "findings": [f.to_dict() for f in found.tool_findings(name)],
            }
            for name, d in found.tools.items()
        ]

    @app.get("/api/servers/{server_id}/tool-changes")
    async def tool_changes(server_id: str, all: bool = False):
        """Tool add/remove/change events vs. the pinned baseline (pending only, or ``all``).

        Each change carries the lint ``findings`` of its new definition, so every interface
        tells a plain change from a *suspicious* one the same way."""
        if await storage.get_server(server_id) is None:
            raise HTTPException(404, "server not found")
        changes = await storage.list_tool_changes(server_id, include_reviewed=all)
        for change in changes:
            after = change.get("after")
            change["findings"] = [f.to_dict() for f in lint_tool(after)] if after else []
        return changes

    @app.post("/api/servers/{server_id}/tool-changes/ack")
    async def acknowledge_tool_changes(server_id: str):
        """Mark pending tool changes as reviewed: the current definitions become trusted."""
        server = await storage.get_server(server_id)
        if server is None:
            raise HTTPException(404, "server not found")
        count = await storage.acknowledge_tool_changes(server_id)
        current = store.get(server_id)
        if current is not None:
            store.update(current.model_copy(update={"tool_changes": 0}))
        # Re-check in the background so a 'degraded because of tool changes' clears promptly.
        task = asyncio.create_task(scheduler.run_once(server))
        background.add(task)
        task.add_done_callback(background.discard)
        return {"acknowledged": count}

    @app.get("/api/servers/{server_id}/insights")
    async def insights(
        server_id: str,
        minutes: int | None = Query(None, ge=1),
        limit: int = Query(500, ge=1, le=MAX_HISTORY_LIMIT),
    ):
        """Anomaly-detection view of a window of history: learned baseline, the most
        significant latency change point, and every anomaly reported in the window."""
        if await storage.get_server(server_id) is None:
            raise HTTPException(404, "server not found")
        since = (
            datetime.now(UTC) - timedelta(minutes=minutes)
            if minutes is not None
            else None
        )
        events = await storage.get_history(server_id, since=since, limit=limit)
        healthy = [e for e in events if e.status != CheckStatus.DOWN]
        baseline = ad.robust_baseline([e.latency_ms for e in healthy])
        cp = ad.find_change_point([e.latency_ms for e in healthy])
        return {
            "baseline": None
            if baseline is None
            else {"median_ms": baseline.median, "spread_ms": baseline.spread},
            "change_point": None
            if cp is None
            else {
                "at": healthy[cp.index].checked_at.isoformat(),
                "before_ms": cp.before_ms,
                "after_ms": cp.after_ms,
                "t_stat": cp.t_stat,
            },
            "anomalies": [
                {"checked_at": e.checked_at.isoformat(), **a.model_dump(mode="json")}
                for e in events
                for a in e.anomalies
            ],
        }

    @app.get("/api/servers/{server_id}/history")
    async def history(
        server_id: str,
        minutes: int | None = Query(None, ge=1),
        limit: int = Query(500, ge=1, le=MAX_HISTORY_LIMIT),
    ):
        server = await storage.get_server(server_id)
        if server is None:
            raise HTTPException(404, "server not found")
        since = (
            datetime.now(UTC) - timedelta(minutes=minutes)
            if minutes is not None
            else None
        )
        events = await storage.get_history(server_id, since=since, limit=limit)
        return [e.model_dump(mode="json") for e in events]

    @app.get("/api/export")
    async def export_yaml(include_secrets: bool = False) -> PlainTextResponse:
        """Export all servers as a YAML config (same shape as the seed file).

        Credentials are redacted unless ``include_secrets=true`` is asked for explicitly: an
        export is a file people attach to issues and drop into chats. A full backup is
        better taken from the SQLite file itself (see docs/configuration.md).
        """
        servers = await storage.list_servers()
        out: dict = {"servers": {}}
        for s in servers:
            key = s.name
            if key in out["servers"]:  # keep names unique in the exported file
                key = f"{s.name} ({s.id})"
            cfg = s.to_server_config()
            out["servers"][key] = (
                cfg.model_dump(mode="json") if include_secrets else redact_config(cfg)
            )
        text = yaml.safe_dump(out, sort_keys=False, allow_unicode=True)
        return PlainTextResponse(
            text,
            media_type="application/x-yaml",
            headers={"Content-Disposition": 'attachment; filename="mcpsonar-servers.yaml"'},
        )

    @app.post("/api/import")
    async def import_yaml(request: Request):
        """Import servers from a YAML config body; each becomes a new monitored server."""
        raw = await read_limited_body(request)
        try:
            config = parse_config_text(raw.decode("utf-8"))
        except Exception as exc:
            raise HTTPException(400, f"invalid YAML config: {exc}") from exc
        for name, cfg in config.servers.items():  # all-or-nothing: check before creating any
            _guard_stdio(cfg)
            try:
                check_no_placeholders(cfg)
            except RedactedValueError as exc:
                raise HTTPException(400, f"server '{name}': {exc}") from exc
        created = 0
        for name, cfg in config.servers.items():
            server = await storage.create_server(name=name, config=cfg)
            scheduler.add(server)
            created += 1
        return {"imported": created}
