"""Unit tests for farm build queue scheduling and cancellation."""

from __future__ import annotations

import asyncio
import sqlite3
import time
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from apb.constants import BuildStatus
from apb.farm import core

pytestmark = pytest.mark.anyio


def _init_test_database() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute(
        """
        CREATE TABLE builds (
            id TEXT PRIMARY KEY,
            server_url TEXT,
            server_arch TEXT,
            pkgname TEXT,
            status TEXT,
            start_time REAL,
            end_time REAL,
            created_at REAL,
            queue_position INTEGER,
            submission_group TEXT,
            user_id INTEGER
        )
        """
    )
    conn.commit()
    return conn


def _insert_build(
    conn: sqlite3.Connection,
    build_id: str,
    *,
    status: str = BuildStatus.QUEUED,
    server_url: str | None = None,
    server_arch: str = "x86_64",
    pkgname: str = "test-pkg",
) -> None:
    conn.execute(
        """
        INSERT INTO builds
        (id, server_url, server_arch, pkgname, status, start_time, end_time, created_at, queue_position)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (build_id, server_url, server_arch, pkgname, status, None, None, time.time(), 1),
    )
    conn.commit()


def _make_build_info(build_id: str, arch: str = "x86_64") -> dict[str, Any]:
    return {
        "build_id": build_id,
        "pkgbuild_content": "pkgname=test-pkg",
        "pkgname": "test-pkg",
        "target_architectures": [arch],
        "source_files": [],
        "created_at": time.time(),
        "status": BuildStatus.QUEUED,
        "arch": arch,
    }


@pytest.fixture
def farm_queue_state(monkeypatch: pytest.MonkeyPatch):
    db = _init_test_database()
    monkeypatch.setattr(core, "build_database", db)
    monkeypatch.setattr(core, "build_queues", {})
    monkeypatch.setattr(core, "shutdown_event", asyncio.Event())
    yield db
    core.shutdown_event.set()
    core.clear_build_queues()


def test_get_farm_queue_position_and_removal(farm_queue_state: sqlite3.Connection) -> None:
    first = _make_build_info("build-1")
    second = _make_build_info("build-2")

    assert core.enqueue_build(first) == 1
    assert core.enqueue_build(second) == 2

    assert core.get_farm_queue_position("build-1") == 1
    assert core.get_farm_queue_position("build-2") == 2
    assert core.get_farm_queue_status_for_build("build-2") == {
        "queue_state": "farm",
        "queue_position": 2,
        "jobs_ahead": 1,
        "farm_queue_size": 2,
        "arch": "x86_64",
    }

    assert core.remove_from_build_queue("build-1") is True
    assert core.get_farm_queue_position("build-1") is None
    assert core.get_farm_queue_position("build-2") == 1
    assert core.remove_from_build_queue("missing") is False


def test_mixed_architecture_queue_positions(farm_queue_state: sqlite3.Connection) -> None:
    """Queue position is per architecture, not global across arches."""
    x86_a = _make_build_info("x86-a", arch="x86_64")
    aarch64_b = _make_build_info("aarch64-b", arch="aarch64")
    x86_c = _make_build_info("x86-c", arch="x86_64")

    assert core.enqueue_build(x86_a) == 1
    assert core.enqueue_build(aarch64_b) == 1
    assert core.enqueue_build(x86_c) == 2

    assert core.total_farm_queue_size() == 3
    assert core.get_farm_queue_status_for_build("x86-c") == {
        "queue_state": "farm",
        "queue_position": 2,
        "jobs_ahead": 1,
        "farm_queue_size": 2,
        "arch": "x86_64",
    }
    assert core.get_farm_queue_status_for_build("aarch64-b") == {
        "queue_state": "farm",
        "queue_position": 1,
        "jobs_ahead": 0,
        "farm_queue_size": 1,
        "arch": "aarch64",
    }


async def test_cancel_farm_queued_build(farm_queue_state: sqlite3.Connection) -> None:
    build_id = "cancel-me"
    _insert_build(farm_queue_state, build_id)
    core.enqueue_build(_make_build_info(build_id))

    result = await core.cancel_farm_queued_build(build_id)

    assert result == {
        "success": True,
        "message": f"Build {build_id} removed from farm queue",
    }
    assert core.build_queues == {}
    cursor = farm_queue_state.cursor()
    cursor.execute("SELECT status FROM builds WHERE id = ?", (build_id,))
    assert cursor.fetchone()[0] == BuildStatus.CANCELLED


async def test_cancel_farm_queued_build_returns_none_when_assigned(
    farm_queue_state: sqlite3.Connection,
) -> None:
    build_id = "assigned-build"
    _insert_build(
        farm_queue_state,
        build_id,
        server_url="http://127.0.0.1:9999",
        status=BuildStatus.BUILDING,
    )

    assert await core.cancel_farm_queued_build(build_id) is None


async def test_process_build_queue_waits_for_server_capacity(
    farm_queue_state: sqlite3.Connection,
) -> None:
    build_id = "waiting-build"
    _insert_build(farm_queue_state, build_id)
    core.enqueue_build(_make_build_info(build_id))

    with patch.object(core, "get_available_architectures", AsyncMock(return_value={"x86_64": ["http://server"]})), \
         patch.object(core, "get_best_server_for_arch", AsyncMock(return_value=None)) as mock_best_server, \
         patch.object(core, "forward_build_to_server", AsyncMock(return_value=True)) as mock_forward:
        core.shutdown_event.clear()
        task = asyncio.create_task(core.process_build_queue())
        await asyncio.sleep(0.2)
        core.shutdown_event.set()
        await task

    mock_best_server.assert_awaited()
    mock_forward.assert_not_awaited()
    assert core.total_farm_queue_size() == 1
    assert core.build_queues["x86_64"][0]["build_id"] == build_id


async def test_process_build_queue_assigns_when_capacity_opens(
    farm_queue_state: sqlite3.Connection,
) -> None:
    build_id = "ready-build"
    _insert_build(farm_queue_state, build_id)
    core.enqueue_build(_make_build_info(build_id))

    with patch.object(core, "get_available_architectures", AsyncMock(return_value={"x86_64": ["http://server"]})), \
         patch.object(core, "get_best_server_for_arch", AsyncMock(return_value="http://server")), \
         patch.object(core, "forward_build_to_server", AsyncMock(return_value=True)) as mock_forward:
        core.shutdown_event.clear()
        task = asyncio.create_task(core.process_build_queue())
        await asyncio.sleep(0.2)
        core.shutdown_event.set()
        await task

    mock_forward.assert_awaited_once()
    assert core.build_queues == {}


async def test_process_build_queue_skips_blocked_architecture(
    farm_queue_state: sqlite3.Connection,
) -> None:
    blocked = _make_build_info("blocked-x86", arch="x86_64")
    ready = _make_build_info("ready-aarch64", arch="aarch64")
    _insert_build(farm_queue_state, "blocked-x86", server_arch="x86_64")
    _insert_build(farm_queue_state, "ready-aarch64", server_arch="aarch64")
    core.enqueue_build(blocked)
    core.enqueue_build(ready)

    async def pick_server(architectures: list[str]) -> str | None:
        if architectures == ["x86_64"]:
            return None
        if architectures == ["aarch64"]:
            return "http://aarch64-server"
        return None

    with patch.object(
        core,
        "get_available_architectures",
        AsyncMock(return_value={"x86_64": ["http://x86"], "aarch64": ["http://aarch64-server"]}),
    ), patch.object(core, "get_best_server_for_arch", AsyncMock(side_effect=pick_server)), \
         patch.object(core, "forward_build_to_server", AsyncMock(return_value=True)) as mock_forward:
        core.shutdown_event.clear()
        task = asyncio.create_task(core.process_build_queue())
        await asyncio.sleep(0.2)
        core.shutdown_event.set()
        await task

    mock_forward.assert_awaited_once()
    forwarded_build_id = mock_forward.await_args.args[0]["build_id"]
    assert forwarded_build_id == "ready-aarch64"
    assert [build["build_id"] for build in core.build_queues.get("x86_64", [])] == ["blocked-x86"]
    assert "aarch64" not in core.build_queues


async def test_process_build_queue_drops_cancelled_build(
    farm_queue_state: sqlite3.Connection,
) -> None:
    build_id = "cancelled-build"
    _insert_build(farm_queue_state, build_id, status=BuildStatus.CANCELLED)
    core.enqueue_build(_make_build_info(build_id))

    with patch.object(core, "get_available_architectures", AsyncMock()) as mock_archs, \
         patch.object(core, "get_best_server_for_arch", AsyncMock()) as mock_best_server, \
         patch.object(core, "forward_build_to_server", AsyncMock()) as mock_forward:
        core.shutdown_event.clear()
        task = asyncio.create_task(core.process_build_queue())
        await asyncio.sleep(0.2)
        core.shutdown_event.set()
        await task

    mock_archs.assert_awaited()
    mock_best_server.assert_not_awaited()
    mock_forward.assert_not_awaited()
    assert core.build_queues == {}
