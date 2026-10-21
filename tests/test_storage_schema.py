"""Schema versions, migrations from real released databases, WAL and write transactions.

``tests/fixtures/db/v0.X.0.sql`` are dumps of databases created by the code of each
release tag (one server, one check, one tool snapshot, one setting; no credentials).
"""

from __future__ import annotations

import asyncio
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mcpsonar import storage as storage_mod
from mcpsonar.models import CheckEvent
from mcpsonar.storage import SCHEMA_VERSION, Storage, StorageError

FIXTURES = Path(__file__).parent / "fixtures" / "db"
RELEASES = ["v0.5.0", "v0.6.0", "v0.7.0"]


def _restore(release: str, db: Path) -> None:
    with sqlite3.connect(db) as conn:
        conn.executescript((FIXTURES / f"{release}.sql").read_text(encoding="utf-8"))
    conn.close()


def _layout(db: Path) -> dict[str, set[str]]:
    """Every table with its columns: what a migrated database must share with a new one."""
    conn = sqlite3.connect(db)
    try:
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")]
        return {t: {r[1] for r in conn.execute(f"PRAGMA table_info({t})")} for t in tables}
    finally:
        conn.close()


def _version(db: Path) -> int:
    conn = sqlite3.connect(db)
    try:
        return conn.execute("PRAGMA user_version").fetchone()[0]
    finally:
        conn.close()


async def test_new_database_is_current_in_wal_mode_without_backup(tmp_path):
    db = tmp_path / "new.db"
    s = await Storage.open(db)
    try:
        cur = await s._read.execute("PRAGMA journal_mode")
        assert (await cur.fetchone())[0] == "wal"
    finally:
        await s.close()
    assert _version(db) == SCHEMA_VERSION
    assert not list(tmp_path.glob("*.bak"))


@pytest.mark.parametrize("release", RELEASES)
async def test_released_database_is_migrated_with_its_data(release, tmp_path):
    db = tmp_path / "old.db"
    _restore(release, db)
    assert _version(db) == 0  # releases before v0.8 had no schema version

    s = await Storage.open(db)
    try:
        (server,) = await s.list_servers()
        assert server.name == "demo"
        (check,) = await s.get_history(server.id)
        assert check.latency_ms == 42.0 and check.timings_ms is None
        assert await s.get_tool_snapshot(server.id) == {
            "ping": {"name": "ping", "description": "Ping."}}
        assert await s.get_setting("fixture") == release
        # the v0.8 additions work on the migrated database
        await s.record_check(CheckEvent(server_id=server.id, status="up", latency_ms=5,
                                        timings_ms={"total": 9}))
        await s.save_probe_shape(server.id, "ping", {"size": 1})
        assert await s.get_probe_shapes(server.id) == {"ping": {"size": 1}}
    finally:
        await s.close()

    fresh = tmp_path / "fresh.db"
    await (await Storage.open(fresh)).close()
    assert _layout(db) == _layout(fresh)
    assert _version(db) == SCHEMA_VERSION

    backup = tmp_path / "old.db.schema0.bak"  # taken before migrating, untouched
    assert _version(backup) == 0 and "probe_shapes" not in _layout(backup)


async def test_reopening_a_current_database_changes_nothing(tmp_path):
    db = tmp_path / "m.db"
    _restore("v0.7.0", db)
    await (await Storage.open(db)).close()
    (tmp_path / "m.db.schema0.bak").unlink()
    await (await Storage.open(db)).close()
    assert not list(tmp_path.glob("*.bak"))


async def test_database_from_a_newer_mcpsonar_is_refused(tmp_path):
    db = tmp_path / "future.db"
    await (await Storage.open(db)).close()
    with sqlite3.connect(db) as conn:
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    conn.close()
    with pytest.raises(StorageError, match="newer than this MCPSonar"):
        await Storage.open(db)
    assert _version(db) == SCHEMA_VERSION + 1


async def test_failed_migration_rolls_back_and_keeps_the_version(tmp_path, monkeypatch):
    db = tmp_path / "m.db"
    _restore("v0.7.0", db)

    async def broken(conn):
        await conn.execute("CREATE TABLE half_done (x)")
        raise RuntimeError("boom")

    monkeypatch.setattr(storage_mod, "MIGRATIONS",
                        [*storage_mod.MIGRATIONS, (SCHEMA_VERSION + 1, "broken", broken)])
    monkeypatch.setattr(storage_mod, "SCHEMA_VERSION", SCHEMA_VERSION + 1)
    with pytest.raises(RuntimeError, match="boom"):
        await Storage.open(db)
    assert _version(db) == SCHEMA_VERSION  # the steps before it are kept
    assert "half_done" not in _layout(db)


async def test_concurrent_writes_are_serialized_and_atomic(tmp_path):
    s = await Storage.open(tmp_path / "m.db")
    try:
        snapshot = {f"t{i}": {"name": f"t{i}"} for i in range(20)}
        await asyncio.gather(*(
            coro
            for i in range(30)
            for coro in (
                s.save_tool_snapshot("s", snapshot),
                s.record_check(CheckEvent(server_id="s", status="up", latency_ms=i,
                                          checked_at=datetime(2026, 1, 1, 0, i, tzinfo=UTC))),
                s.set_setting(f"k{i}", "v"),
            )
        ))
        assert await s.get_tool_snapshot("s") == snapshot  # never a half-replaced snapshot
        assert len(await s.get_history("s")) == 30

        with pytest.raises(RuntimeError):
            async with s._tx() as db:
                await db.execute("DELETE FROM tool_snapshots WHERE server_id = 's'")
                raise RuntimeError("interrupted")
        assert await s.get_tool_snapshot("s") == snapshot  # rolled back
    finally:
        await s.close()


async def test_read_connection_cannot_write(tmp_path):
    s = await Storage.open(tmp_path / "m.db")
    try:
        with pytest.raises(sqlite3.OperationalError):
            await s._read.execute("DELETE FROM settings")
    finally:
        await s.close()


async def test_history_order_is_stable_for_equal_timestamps(tmp_path):
    # Windows clocks tick coarsely: two checks can share a timestamp. Insertion order wins.
    s = await Storage.open(tmp_path / "m.db")
    try:
        at = datetime(2026, 1, 1, tzinfo=UTC)
        for latency in (1.0, 2.0, 3.0):
            await s.record_check(CheckEvent(server_id="s", status="up", latency_ms=latency,
                                            checked_at=at))
        assert [e.latency_ms for e in await s.get_history("s")] == [1.0, 2.0, 3.0]
        assert [e.latency_ms for e in await s.get_history("s", limit=2)] == [2.0, 3.0]
    finally:
        await s.close()
