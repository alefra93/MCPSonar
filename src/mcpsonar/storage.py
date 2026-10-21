"""SQLite persistence (via aiosqlite): monitored servers + check history.

Tables:

* ``servers`` — the monitors a user has added (survive restart). The check parameters are
  stored as a JSON blob of the :class:`ServerConfig` portion; identity/enabled are columns.
* ``checks``  — one row per completed check, for the history graphs (anomalies included).
* ``tool_baselines`` / ``tool_snapshots`` — the last-seen definition of every tool, per
  server (rug-pull detection diffs against these).
* ``tool_changes`` — every detected tool add/remove/change, until a human reviews it.
* ``probe_shapes`` — the last response *shape* of each probed tool (response drift).
* ``settings`` / ``users`` / ``sessions`` / ``api_tokens`` — the dashboard admin, its login
  sessions and the API tokens (hashes only).

Kept intentionally thin: hand-written SQL, no ORM.

**Schema versions.** The version lives in ``PRAGMA user_version`` and only moves forward,
through :data:`MIGRATIONS`, each applied in its own transaction. Before an existing database
file is migrated, a copy is saved next to it (``<db>.schema<N>.bak``). A database written
by a *newer* MCPSonar is refused instead of being misread.

**Connections.** A file database runs in WAL mode with two connections: one that writes,
only through :meth:`Storage._tx` (one writer at a time; a method's statements are committed
together or not at all), and one that only reads, so reads never queue behind a write. An
in-memory database (tests) uses one connection for both.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import json
import logging
import os
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path

import aiosqlite

from .auth import (
    hash_password,
    needs_rehash,
    new_api_token,
    new_session_token,
    token_digest,
    verify_password,
)
from .models import Anomaly, CheckEvent, CheckStatus, MonitoredServer, ServerConfig
from .tooldefs import ToolChange

# The schema as released in v0.7.0 (migration 1).
_SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS servers (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    config_json TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checks (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id              TEXT NOT NULL,
    status                 TEXT NOT NULL,
    checked_at             TEXT NOT NULL,
    latency_ms             REAL NOT NULL,
    tools_checked          INTEGER NOT NULL,
    tools_failed           INTEGER NOT NULL,
    tools_available        INTEGER NOT NULL DEFAULT 0,
    spec_version           TEXT,
    spec_version_supported INTEGER NOT NULL,
    detail                 TEXT,
    auth_required          INTEGER NOT NULL DEFAULT 0,
    tool_changes           INTEGER NOT NULL DEFAULT 0,
    tool_risks             INTEGER NOT NULL DEFAULT 0,
    anomalies_json         TEXT,
    latency_baseline_ms    REAL,
    latency_score          REAL
);
CREATE INDEX IF NOT EXISTS idx_checks_server_time ON checks (server_id, checked_at);
CREATE TABLE IF NOT EXISTS tool_baselines (
    server_id      TEXT PRIMARY KEY,
    established_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tool_snapshots (
    server_id       TEXT NOT NULL,
    name            TEXT NOT NULL,
    definition_json TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (server_id, name)
);
CREATE TABLE IF NOT EXISTS tool_changes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id    TEXT NOT NULL,
    detected_at  TEXT NOT NULL,
    kind         TEXT NOT NULL,
    tool_name    TEXT NOT NULL,
    fields_json  TEXT NOT NULL,
    before_json  TEXT,
    after_json   TEXT,
    acknowledged INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_tool_changes_server ON tool_changes (server_id, acknowledged);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt          TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS api_tokens (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    token_hash   TEXT UNIQUE NOT NULL,
    scope        TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_at   REAL NOT NULL,
    expires_at   REAL,
    last_used_at REAL
);
"""


@functools.cache
def _dummy_hash() -> tuple[str, str]:
    """Verified against when the username does not exist, so a wrong username costs the same
    time as a wrong password (no user enumeration by timing)."""
    return hash_password("mcpsonar-timing-equalizer", salt="00" * 16)


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


logger = logging.getLogger("mcpsonar.storage")


class StorageError(Exception):
    """The database cannot be used by this version of MCPSonar."""


def _statements(script: str) -> list[str]:
    # executescript() would COMMIT first: run DDL statement by statement, inside the
    # migration's own transaction.
    return [stmt.strip() for stmt in script.split(";") if stmt.strip()]


async def _columns(conn: aiosqlite.Connection, table: str) -> set[str]:
    cur = await conn.execute(f"PRAGMA table_info({table})")
    return {row[1] for row in await cur.fetchall()}


async def _m1_baseline(conn: aiosqlite.Connection) -> None:
    """Every table as of v0.7.0, and the columns earlier versions (v0.5, v0.6) lack.
    Idempotent: it upgrades a database from any earlier release, and creates a new one."""
    for stmt in _statements(_SCHEMA_V1):
        await conn.execute(stmt)
    columns = await _columns(conn, "checks")
    added = {
        "tools_available": "INTEGER NOT NULL DEFAULT 0",
        "auth_required": "INTEGER NOT NULL DEFAULT 0",
        "tool_changes": "INTEGER NOT NULL DEFAULT 0",
        "tool_risks": "INTEGER NOT NULL DEFAULT 0",
        "anomalies_json": "TEXT",
        "latency_baseline_ms": "REAL",
        "latency_score": "REAL",
    }
    for name, decl in added.items():
        if name not in columns:
            await conn.execute(f"ALTER TABLE checks ADD COLUMN {name} {decl}")


async def _m2_check_timings(conn: aiosqlite.Connection) -> None:
    if "timings_json" not in await _columns(conn, "checks"):
        await conn.execute("ALTER TABLE checks ADD COLUMN timings_json TEXT")


async def _m3_probe_shapes(conn: aiosqlite.Connection) -> None:
    await conn.execute(
        "CREATE TABLE IF NOT EXISTS probe_shapes (server_id TEXT NOT NULL, "
        "tool TEXT NOT NULL, shape_json TEXT NOT NULL, updated_at TEXT NOT NULL, "
        "PRIMARY KEY (server_id, tool))"
    )


Migration = Callable[[aiosqlite.Connection], Awaitable[None]]

#: (version, description, step). Append only: a released step is never edited.
MIGRATIONS: list[tuple[int, str, Migration]] = [
    (1, "schema of v0.7.0 (upgrades v0.5 / v0.6 databases)", _m1_baseline),
    (2, "per-phase timings on checks (v0.8)", _m2_check_timings),
    (3, "response shapes of probed tools (v0.8)", _m3_probe_shapes),
]
SCHEMA_VERSION = MIGRATIONS[-1][0]


async def schema_version(conn: aiosqlite.Connection) -> int:
    cur = await conn.execute("PRAGMA user_version")
    return (await cur.fetchone())[0]


async def _backup(conn: aiosqlite.Connection, path: Path, version: int) -> Path:
    target = path.with_name(f"{path.name}.schema{version}.bak")
    async with aiosqlite.connect(target) as dst:
        await conn.backup(dst)
    with contextlib.suppress(OSError):
        os.chmod(target, 0o600)  # holds password and token hashes, like the database
    return target


async def migrate(conn: aiosqlite.Connection, path: Path | None = None) -> int:
    """Bring the schema to :data:`SCHEMA_VERSION`; returns the version found. ``path``: the
    database file, backed up first if it already holds data (None: no backup)."""
    found = await schema_version(conn)
    if found > SCHEMA_VERSION:
        raise StorageError(
            f"this database has schema version {found}, newer than this MCPSonar supports "
            f"({SCHEMA_VERSION}): upgrade MCPSonar, or restore a backup taken before the "
            "upgrade"
        )
    pending = [m for m in MIGRATIONS if m[0] > found]
    if not pending:
        return found
    cur = await conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'")
    if path is not None and (await cur.fetchone())[0]:
        logger.info("database backed up to %s before migrating", await _backup(conn, path, found))
    for version, description, step in pending:
        await conn.execute("BEGIN IMMEDIATE")
        try:
            await step(conn)
            await conn.execute(f"PRAGMA user_version = {version}")
        except BaseException:
            await conn.execute("ROLLBACK")
            raise
        await conn.execute("COMMIT")
        logger.info("database schema migrated to version %d: %s", version, description)
    return found


class Storage:
    def __init__(self, conn: aiosqlite.Connection, read: aiosqlite.Connection) -> None:
        self._conn = conn  # writes, only inside _tx()
        self._read = read  # reads (the same connection for an in-memory database)
        self._write_lock = asyncio.Lock()

    # ---- lifecycle --------------------------------------------------------- #
    @classmethod
    async def open(cls, path: str | Path) -> Storage:
        memory = str(path) == ":memory:"
        if not memory:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        # isolation_level=None: no implicit transactions; _tx() and migrate() open them.
        conn = await aiosqlite.connect(path, isolation_level=None)
        try:
            conn.row_factory = aiosqlite.Row
            await conn.execute("PRAGMA busy_timeout = 5000")
            if not memory:
                await conn.execute("PRAGMA journal_mode = WAL")
                await conn.execute("PRAGMA synchronous = NORMAL")  # WAL: durable enough
            await migrate(conn, None if memory else Path(path))
        except BaseException:
            await conn.close()
            raise
        if memory:
            return cls(conn, conn)
        read = await aiosqlite.connect(path, isolation_level=None)
        read.row_factory = aiosqlite.Row
        await read.execute("PRAGMA busy_timeout = 5000")
        await read.execute("PRAGMA query_only = ON")
        return cls(conn, read)

    async def close(self) -> None:
        if self._read is not self._conn:
            await self._read.close()
        await self._conn.close()

    @contextlib.asynccontextmanager
    async def _tx(self) -> AsyncIterator[aiosqlite.Connection]:
        """One write transaction: everything inside commits together or rolls back."""
        async with self._write_lock:
            await self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                await self._conn.execute("ROLLBACK")
                raise
            await self._conn.execute("COMMIT")

    # ---- servers (CRUD) ---------------------------------------------------- #
    @staticmethod
    def _row_to_server(row: aiosqlite.Row) -> MonitoredServer:
        cfg = ServerConfig.model_validate_json(row["config_json"])
        return MonitoredServer(
            id=row["id"],
            name=row["name"],
            enabled=bool(row["enabled"]),
            **cfg.model_dump(),
        )

    async def list_servers(self) -> list[MonitoredServer]:
        cur = await self._read.execute("SELECT * FROM servers ORDER BY name")
        rows = await cur.fetchall()
        return [self._row_to_server(r) for r in rows]

    async def get_server(self, server_id: str) -> MonitoredServer | None:
        cur = await self._read.execute("SELECT * FROM servers WHERE id = ?", (server_id,))
        row = await cur.fetchone()
        return self._row_to_server(row) if row else None

    async def create_server(
        self, name: str, config: ServerConfig, enabled: bool = True
    ) -> MonitoredServer:
        server_id = _new_id()
        async with self._tx() as db:
            await db.execute(
                "INSERT INTO servers (id, name, enabled, config_json, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    server_id,
                    name,
                    int(enabled),
                    config.model_dump_json(),
                    datetime.now(UTC).isoformat(),
                ),
            )
        return MonitoredServer(id=server_id, name=name, enabled=enabled, **config.model_dump())

    async def update_server(
        self, server_id: str, name: str, config: ServerConfig, enabled: bool
    ) -> MonitoredServer | None:
        async with self._tx() as db:
            cur = await db.execute(
                "UPDATE servers SET name = ?, enabled = ?, config_json = ? WHERE id = ?",
                (name, int(enabled), config.model_dump_json(), server_id),
            )
        if cur.rowcount == 0:
            return None
        return MonitoredServer(id=server_id, name=name, enabled=enabled, **config.model_dump())

    async def delete_server(self, server_id: str) -> bool:
        async with self._tx() as db:
            cur = await db.execute("DELETE FROM servers WHERE id = ?", (server_id,))
            for table in ("checks", "tool_baselines", "tool_snapshots", "tool_changes",
                          "probe_shapes"):
                await db.execute(f"DELETE FROM {table} WHERE server_id = ?", (server_id,))
        return cur.rowcount > 0

    # ---- check history ----------------------------------------------------- #
    async def record_check(self, event: CheckEvent) -> None:
        async with self._tx() as db:
            await db.execute(
                "INSERT INTO checks (server_id, status, checked_at, latency_ms, tools_checked, "
                "tools_failed, tools_available, spec_version, spec_version_supported, detail, "
                "tool_changes, tool_risks, anomalies_json, latency_baseline_ms, latency_score, "
                "auth_required, timings_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event.server_id,
                    event.status.value,
                    event.checked_at.isoformat(),
                    event.latency_ms,
                    event.tools_checked,
                    event.tools_failed,
                    event.tools_available,
                    event.spec_version,
                    int(event.spec_version_supported),
                    event.detail,
                    event.tool_changes,
                    event.tool_risks,
                    json.dumps([a.model_dump(mode="json") for a in event.anomalies])
                    if event.anomalies
                    else None,
                    event.latency_baseline_ms,
                    event.latency_score,
                    int(event.auth_required),
                    json.dumps({"phases": event.timings_ms, "tools": event.tool_latency_ms})
                    if event.timings_ms is not None or event.tool_latency_ms
                    else None,
                ),
            )

    @staticmethod
    def _row_to_event(row: aiosqlite.Row) -> CheckEvent:
        return CheckEvent(
            server_id=row["server_id"],
            status=CheckStatus(row["status"]),
            checked_at=datetime.fromisoformat(row["checked_at"]),
            latency_ms=row["latency_ms"],
            tools_checked=row["tools_checked"],
            tools_failed=row["tools_failed"],
            tools_available=row["tools_available"],
            spec_version=row["spec_version"],
            spec_version_supported=bool(row["spec_version_supported"]),
            detail=row["detail"],
            tool_changes=row["tool_changes"],
            tool_risks=row["tool_risks"],
            anomalies=[Anomaly.model_validate(a) for a in json.loads(row["anomalies_json"])]
            if row["anomalies_json"]
            else [],
            latency_baseline_ms=row["latency_baseline_ms"],
            latency_score=row["latency_score"],
            auth_required=bool(row["auth_required"]),
            **Storage._timings(row["timings_json"]),
        )

    @staticmethod
    def _timings(raw: str | None) -> dict:
        if not raw:
            return {}
        data = json.loads(raw)
        return {"timings_ms": data.get("phases"), "tool_latency_ms": data.get("tools") or {}}

    async def get_history(
        self, server_id: str, since: datetime | None = None, limit: int = 500
    ) -> list[CheckEvent]:
        """Recent checks for a server, oldest→newest (ready to plot)."""
        if since is not None:
            cur = await self._read.execute(
                "SELECT * FROM (SELECT * FROM checks WHERE server_id = ? AND checked_at >= ? "
                "ORDER BY checked_at DESC, id DESC LIMIT ?) ORDER BY checked_at ASC, id ASC",
                (server_id, since.isoformat(), limit),
            )
        else:
            cur = await self._read.execute(
                "SELECT * FROM (SELECT * FROM checks WHERE server_id = ? "
                "ORDER BY checked_at DESC, id DESC LIMIT ?) ORDER BY checked_at ASC, id ASC",
                (server_id, limit),
            )
        rows = await cur.fetchall()
        return [self._row_to_event(r) for r in rows]

    async def anomaly_reported_since(self, server_id: str, kind: str, since: datetime) -> bool:
        """Whether a check at/after ``since`` already reported an anomaly of ``kind``
        (used to report a latency shift or a flapping episode once, not on every check)."""
        cur = await self._read.execute(
            "SELECT 1 FROM checks WHERE server_id = ? AND checked_at >= ? "
            "AND anomalies_json LIKE ? LIMIT 1",
            (server_id, since.isoformat(), f'%"kind": "{kind}"%'),
        )
        return await cur.fetchone() is not None

    async def prune_history(self, older_than: datetime) -> int:
        """Delete check rows older than a cutoff. Returns the number removed."""
        async with self._tx() as db:
            cur = await db.execute(
                "DELETE FROM checks WHERE checked_at < ?", (older_than.isoformat(),)
            )
        return cur.rowcount

    # ---- tool pinning (rug-pull detection) ---------------------------------- #
    async def get_tool_snapshot(self, server_id: str) -> dict[str, dict] | None:
        """Last-seen ``{tool name: normalized definition}``, or None if no baseline yet."""
        cur = await self._read.execute(
            "SELECT 1 FROM tool_baselines WHERE server_id = ?", (server_id,)
        )
        if await cur.fetchone() is None:
            return None
        cur = await self._read.execute(
            "SELECT name, definition_json FROM tool_snapshots WHERE server_id = ?", (server_id,)
        )
        return {r["name"]: json.loads(r["definition_json"]) for r in await cur.fetchall()}

    async def save_tool_snapshot(self, server_id: str, tools: dict[str, dict]) -> None:
        """Replace the last-seen tool definitions (and mark the baseline as established)."""
        now = datetime.now(UTC).isoformat()
        async with self._tx() as db:
            await db.execute(
                "INSERT OR IGNORE INTO tool_baselines (server_id, established_at) VALUES (?, ?)",
                (server_id, now),
            )
            await db.execute("DELETE FROM tool_snapshots WHERE server_id = ?", (server_id,))
            await db.executemany(
                "INSERT INTO tool_snapshots (server_id, name, definition_json, updated_at) "
                "VALUES (?, ?, ?, ?)",
                [(server_id, name, json.dumps(d, sort_keys=True), now) for name, d in tools.items()],
            )

    async def add_tool_changes(self, server_id: str, changes: list[ToolChange]) -> None:
        now = datetime.now(UTC).isoformat()
        async with self._tx() as db:
            await db.executemany(
                "INSERT INTO tool_changes (server_id, detected_at, kind, tool_name, fields_json, "
                "before_json, after_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        server_id,
                        now,
                        c.kind,
                        c.tool,
                        json.dumps(c.fields),
                        json.dumps(c.before) if c.before is not None else None,
                        json.dumps(c.after) if c.after is not None else None,
                    )
                    for c in changes
                ],
            )

    async def list_tool_changes(
        self, server_id: str, include_reviewed: bool = False, limit: int = 200
    ) -> list[dict]:
        """Detected tool changes, newest first."""
        where = "" if include_reviewed else " AND acknowledged = 0"
        cur = await self._read.execute(
            f"SELECT * FROM tool_changes WHERE server_id = ?{where} ORDER BY id DESC LIMIT ?",
            (server_id, limit),
        )
        return [
            {
                "id": r["id"],
                "detected_at": r["detected_at"],
                "kind": r["kind"],
                "tool": r["tool_name"],
                "fields": json.loads(r["fields_json"]),
                "before": json.loads(r["before_json"]) if r["before_json"] else None,
                "after": json.loads(r["after_json"]) if r["after_json"] else None,
                "reviewed": bool(r["acknowledged"]),
            }
            for r in await cur.fetchall()
        ]

    # ---- response drift ------------------------------------------------------ #
    async def get_probe_shapes(self, server_id: str) -> dict[str, dict]:
        """Last-seen response shape per probed tool (shapes only: no response content)."""
        cur = await self._read.execute(
            "SELECT tool, shape_json FROM probe_shapes WHERE server_id = ?", (server_id,)
        )
        return {r["tool"]: json.loads(r["shape_json"]) for r in await cur.fetchall()}

    async def save_probe_shape(self, server_id: str, tool: str, shape: dict) -> None:
        async with self._tx() as db:
            await db.execute(
                "INSERT INTO probe_shapes (server_id, tool, shape_json, updated_at) "
                "VALUES (?, ?, ?, ?) ON CONFLICT(server_id, tool) DO UPDATE SET "
                "shape_json = excluded.shape_json, updated_at = excluded.updated_at",
                (server_id, tool, json.dumps(shape, sort_keys=True), datetime.now(UTC).isoformat()),
            )

    async def count_pending_tool_changes(self, server_id: str) -> int:
        cur = await self._read.execute(
            "SELECT COUNT(*) AS n FROM tool_changes WHERE server_id = ? AND acknowledged = 0",
            (server_id,),
        )
        return (await cur.fetchone())["n"]

    async def acknowledge_tool_changes(self, server_id: str) -> int:
        """Mark every pending change as reviewed. Returns how many were acknowledged."""
        async with self._tx() as db:
            cur = await db.execute(
                "UPDATE tool_changes SET acknowledged = 1 WHERE server_id = ? AND acknowledged = 0",
                (server_id,),
            )
        return cur.rowcount

    # ---- settings + auth --------------------------------------------------- #
    async def get_setting(self, key: str) -> str | None:
        cur = await self._read.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = await cur.fetchone()
        return row["value"] if row else None

    async def set_setting(self, key: str, value: str) -> None:
        async with self._tx() as db:
            await db.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    async def has_admin(self) -> bool:
        cur = await self._read.execute("SELECT COUNT(*) AS n FROM users")
        return (await cur.fetchone())["n"] > 0

    async def create_admin(self, username: str, password: str) -> None:
        salt, pw_hash = await asyncio.to_thread(hash_password, password)
        async with self._tx() as db:
            await db.execute(
                "INSERT INTO users (username, password_hash, salt, created_at) VALUES (?, ?, ?, ?)",
                (username, pw_hash, salt, datetime.now(UTC).isoformat()),
            )

    async def create_first_admin(self, username: str, password: str) -> bool:
        """Create the admin only if no user exists yet, atomically. Returns False if one did
        (so two racing first-run setups can never both succeed)."""
        salt, pw_hash = await asyncio.to_thread(hash_password, password)
        async with self._tx() as db:
            cur = await db.execute(
                "INSERT INTO users (username, password_hash, salt, created_at) "
                "SELECT ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM users)",
                (username, pw_hash, salt, datetime.now(UTC).isoformat()),
            )
        return cur.rowcount == 1

    async def verify_credentials(self, username: str, password: str) -> bool:
        """Check a login. Hashing runs off the event loop; a hash weaker than the current
        policy (v0.5 and earlier) is upgraded in place after a successful check."""
        cur = await self._read.execute(
            "SELECT password_hash, salt FROM users WHERE username = ?", (username,)
        )
        row = await cur.fetchone()
        if row is None:
            await asyncio.to_thread(verify_password, password, *_dummy_hash())
            return False
        if not await asyncio.to_thread(verify_password, password, row["salt"], row["password_hash"]):
            return False
        if needs_rehash(row["password_hash"]):
            salt, pw_hash = await asyncio.to_thread(hash_password, password)
            async with self._tx() as db:
                await db.execute(
                    "UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
                    (pw_hash, salt, username),
                )
        return True

    # ---- sessions ------------------------------------------------------------ #
    async def create_session(self, username: str, ttl_s: float) -> str:
        """Start a session; returns the token for the cookie (only its hash is stored)."""
        token = new_session_token()
        now = time.time()
        async with self._tx() as db:
            await db.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            await db.execute(
                "INSERT INTO sessions (token_hash, username, created_at, expires_at) "
                "VALUES (?, ?, ?, ?)",
                (token_digest(token), username, now, now + ttl_s),
            )
        return token

    async def get_session_user(self, token: str) -> str | None:
        """The username of a live session, or None (unknown, revoked or expired)."""
        cur = await self._read.execute(
            "SELECT s.username FROM sessions s JOIN users u ON u.username = s.username "
            "WHERE s.token_hash = ? AND s.expires_at > ?",
            (token_digest(token), time.time()),
        )
        row = await cur.fetchone()
        return row["username"] if row else None

    async def delete_session(self, token: str) -> None:
        async with self._tx() as db:
            await db.execute(
                "DELETE FROM sessions WHERE token_hash = ?", (token_digest(token),)
            )

    # ---- API tokens (CLI / automation) ------------------------------------- #
    @staticmethod
    def _token_row(r: aiosqlite.Row) -> dict:
        return {
            "id": r["id"],
            "name": r["name"],
            "scope": r["scope"],
            "created_by": r["created_by"],
            "created_at": r["created_at"],
            "expires_at": r["expires_at"],
            "last_used_at": r["last_used_at"],
        }

    async def create_api_token(
        self, name: str, scope: str, created_by: str, ttl_s: float | None = None
    ) -> tuple[dict, str]:
        """Create a token; returns ``(metadata, token)``. The token itself is never stored
        (only its SHA-256), so this is the only time it can be shown."""
        token = new_api_token()
        now = time.time()
        token_id = _new_id()
        async with self._tx() as db:
            await db.execute(
                "INSERT INTO api_tokens (id, name, token_hash, scope, created_by, created_at, "
                "expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (token_id, name, token_digest(token), scope, created_by, now,
                 now + ttl_s if ttl_s else None),
            )
        cur = await self._read.execute("SELECT * FROM api_tokens WHERE id = ?", (token_id,))
        return self._token_row(await cur.fetchone()), token

    async def list_api_tokens(self) -> list[dict]:
        cur = await self._read.execute("SELECT * FROM api_tokens ORDER BY created_at")
        return [self._token_row(r) for r in await cur.fetchall()]

    async def revoke_api_token(self, token_id: str) -> bool:
        async with self._tx() as db:
            cur = await db.execute("DELETE FROM api_tokens WHERE id = ?", (token_id,))
        return cur.rowcount > 0

    async def get_api_token(self, token: str) -> dict | None:
        """The live token's metadata, or None (unknown, revoked or expired). Records use at
        most once a minute, so polling clients don't turn every read into a write."""
        now = time.time()
        cur = await self._read.execute(
            "SELECT * FROM api_tokens WHERE token_hash = ? "
            "AND (expires_at IS NULL OR expires_at > ?)",
            (token_digest(token), now),
        )
        row = await cur.fetchone()
        if row is None:
            return None
        if row["last_used_at"] is None or now - row["last_used_at"] > 60:
            async with self._tx() as db:
                await db.execute(
                    "UPDATE api_tokens SET last_used_at = ? WHERE id = ?", (now, row["id"])
                )
        return self._token_row(row)
