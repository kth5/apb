"""Unit tests for periodic SRCDEST cleanup on the build server."""

from __future__ import annotations

import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from apb.constants import BuildStatus
from apb.server import engine


def _set_mtime(path: Path, age_seconds: float) -> None:
    mtime = time.time() - age_seconds
    os.utime(path, (mtime, mtime))


@pytest.fixture
def srcdest_dir(tmp_path: Path) -> Path:
    srcdest = tmp_path / "srcdest"
    srcdest.mkdir()
    return srcdest


def test_cleanup_srcdest_sources_removes_old_entries_and_preserves_locks(srcdest_dir: Path):
    old_file = srcdest_dir / "old.tar.gz"
    old_file.write_bytes(b"old-source")
    _set_mtime(old_file, 40 * 86400)

    new_file = srcdest_dir / "new.tar.gz"
    new_file.write_bytes(b"new-source")
    _set_mtime(new_file, 86400)

    lock_file = srcdest_dir / ".apb-deadbeef.lock"
    lock_file.write_text("lock")
    _set_mtime(lock_file, 40 * 86400)

    old_dir = srcdest_dir / "old-checkout"
    old_dir.mkdir()
    (old_dir / "README").write_text("old")
    _set_mtime(old_dir, 40 * 86400)

    stats = engine.cleanup_srcdest_sources(srcdest_dir, retention_days=30)

    assert stats["removed_files"] == 1
    assert stats["removed_dirs"] == 1
    assert stats["freed_bytes"] >= len(b"old-source")
    assert not old_file.exists()
    assert new_file.exists()
    assert lock_file.exists()
    assert not old_dir.exists()


def test_cleanup_srcdest_noop_when_srcdest_undefined():
    with patch.object(engine, "cleanup_orphaned_srcdest_locks") as lock_cleanup_mock:
        with patch.object(engine, "get_makepkg_config", return_value={}):
            engine.cleanup_srcdest()

    lock_cleanup_mock.assert_not_called()


def test_cleanup_srcdest_runs_lock_and_source_cleanup(srcdest_dir: Path):
    old_file = srcdest_dir / "old.tar.gz"
    old_file.write_bytes(b"old")
    _set_mtime(old_file, 40 * 86400)

    engine.server_config = {"srcdest_retention_days": 30}

    with patch.object(engine, "get_makepkg_config", return_value={"SRCDEST": str(srcdest_dir)}):
        with patch.object(engine, "cleanup_orphaned_srcdest_locks") as lock_cleanup_mock:
            engine.cleanup_srcdest()

    lock_cleanup_mock.assert_called_once()
    assert not old_file.exists()


def test_cleanup_srcdest_skips_source_cleanup_during_active_builds(srcdest_dir: Path):
    old_file = srcdest_dir / "old.tar.gz"
    old_file.write_bytes(b"old")
    _set_mtime(old_file, 40 * 86400)

    engine.server_config = {"srcdest_retention_days": 30}
    engine.active_builds["build-1"] = {"status": BuildStatus.BUILDING}

    try:
        with patch.object(engine, "get_makepkg_config", return_value={"SRCDEST": str(srcdest_dir)}):
            with patch.object(engine, "cleanup_orphaned_srcdest_locks") as lock_cleanup_mock:
                engine.cleanup_srcdest()

        lock_cleanup_mock.assert_called_once()
        assert old_file.exists()
    finally:
        engine.active_builds.pop("build-1", None)


def test_monitor_srcdest_cleanup_returns_immediately_when_disabled():
    engine.server_config = {"srcdest_cleanup_interval": 0}

    with patch.object(engine, "cleanup_srcdest") as cleanup_mock:
        engine.monitor_srcdest_cleanup()

    cleanup_mock.assert_not_called()


def test_monitor_srcdest_cleanup_runs_once_before_waiting():
    engine.server_config = {"srcdest_cleanup_interval": 60}
    engine.shutdown_event.clear()

    with patch.object(engine, "cleanup_srcdest") as cleanup_mock:
        with patch.object(engine.shutdown_event, "wait", side_effect=lambda _interval: engine.shutdown_event.set()):
            engine.monitor_srcdest_cleanup()

    cleanup_mock.assert_called_once()
