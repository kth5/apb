"""Unit tests for farm database creation and column migrations."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from apb.farm import core


def _columns(conn: sqlite3.Connection) -> list[str]:
    return [row[1] for row in conn.execute("PRAGMA table_info(builds)")]


def test_init_database_creates_full_schema() -> None:
    conn = core.init_database(":memory:")
    expected = ["id", "server_url", "server_arch", "pkgname", "status", "start_time", "end_time",
                "created_at", "queue_position", *(column for column, _type in core.BUILD_COLUMN_MIGRATIONS)]
    assert _columns(conn) == expected
    assert conn.execute("SELECT name FROM sqlite_master WHERE name = 'cached_artifacts'").fetchone()


def test_init_database_migrates_existing_database(tmp_path: Path) -> None:
    db_path = tmp_path / "farm.db"
    legacy = sqlite3.connect(db_path)
    legacy.execute(
        "CREATE TABLE builds (id TEXT PRIMARY KEY, server_url TEXT, server_arch TEXT, pkgname TEXT, "
        "status TEXT, start_time REAL, end_time REAL, created_at REAL, queue_position INTEGER, "
        "submission_group TEXT, epoch TEXT)"
    )
    legacy.execute("INSERT INTO builds (id, pkgname, status) VALUES ('b1', 'hello', 'completed')")
    legacy.commit()
    legacy.close()

    conn = core.init_database(db_path)
    columns = _columns(conn)
    assert {column for column, _type in core.BUILD_COLUMN_MIGRATIONS} <= set(columns)
    assert conn.execute("SELECT pkgname, build_timeout FROM builds WHERE id = 'b1'").fetchone() == (
        "hello",
        core.BUILD_TIMEOUT_DEFAULT,
    )
    conn.close()

    assert _columns(core.init_database(db_path)) == columns
