"""Unit tests for buildroot auto-recreation drain and queue dispatch."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from apb.server import engine


@pytest.fixture(autouse=True)
def reset_buildroot_state():
    with engine.buildroot_state_lock:
        engine.finished_build_counter = 0
        engine.buildroot_state = engine.BUILDROOT_STATE_IDLE
        engine.in_flight_builds = 0
    engine.server_config = {"buildroot": "/tmp/apb-test-buildroot"}
    engine.shutdown_event.clear()
    yield
    engine.shutdown_event.set()
    with engine.buildroot_state_lock:
        engine.finished_build_counter = 0
        engine.buildroot_state = engine.BUILDROOT_STATE_IDLE
        engine.in_flight_builds = 0


def test_register_finished_build_increments_and_schedules_drain():
    engine.server_config["buildroot_autorecreate"] = 3

    engine.register_finished_build()
    engine.register_finished_build()
    with engine.buildroot_state_lock:
        assert engine.finished_build_counter == 2
        assert engine.buildroot_state == engine.BUILDROOT_STATE_IDLE

    engine.register_finished_build()
    with engine.buildroot_state_lock:
        assert engine.finished_build_counter == 3
        assert engine.buildroot_state == engine.BUILDROOT_STATE_DRAINING


def test_register_finished_build_noop_without_threshold():
    engine.register_finished_build()
    with engine.buildroot_state_lock:
        assert engine.finished_build_counter == 0
        assert engine.buildroot_state == engine.BUILDROOT_STATE_IDLE


def test_recreate_buildroot_removes_paths_and_resets_state(tmp_path: Path):
    buildroot = tmp_path / "buildroot"
    buildroot.mkdir()
    (buildroot / "root").mkdir()
    (buildroot / "apb-slot-0").mkdir()
    (buildroot / "apb-slot-0.lock").write_text("lock")

    removed: list[str] = []

    def fake_run(cmd, **kwargs):
        removed.append(cmd[-1])
        return MagicMock(returncode=0, stderr="")

    with patch.object(engine.subprocess, "run", side_effect=fake_run):
        with patch.object(engine, "setup_buildroot", return_value=True) as setup_mock:
            assert engine.recreate_buildroot(buildroot) is True

    setup_mock.assert_called_once_with(buildroot)
    assert str(buildroot / "root") in removed
    assert str(buildroot / "apb-slot-0") in removed
    assert str(buildroot / "apb-slot-0.lock") in removed
    with engine.buildroot_state_lock:
        assert engine.finished_build_counter == 0
        assert engine.buildroot_state == engine.BUILDROOT_STATE_IDLE


def test_recreate_buildroot_resets_state_on_setup_failure(tmp_path: Path):
    buildroot = tmp_path / "buildroot"
    buildroot.mkdir()

    with patch.object(engine, "_remove_buildroot_paths"):
        with patch.object(engine, "setup_buildroot", return_value=False):
            assert engine.recreate_buildroot(buildroot) is False

    with engine.buildroot_state_lock:
        assert engine.finished_build_counter == 0
        assert engine.buildroot_state == engine.BUILDROOT_STATE_IDLE


def test_get_queue_status_reports_drain_and_recreate():
    engine.server_config["buildroot_autorecreate"] = 1
    engine.register_finished_build()

    status = engine.get_queue_status()
    assert status["buildroot_recreation_state"] == engine.BUILDROOT_STATE_DRAINING
    assert status["server_busy_with_buildroot"] is True
    assert status["buildroot_recreation_count"] == 0
    assert status["buildroot_recreation_builds"] == []

    with engine.buildroot_state_lock:
        engine.buildroot_state = engine.BUILDROOT_STATE_RECREATING

    status = engine.get_queue_status()
    assert status["buildroot_recreation_state"] == engine.BUILDROOT_STATE_RECREATING
    assert status["buildroot_recreation_count"] == 1
    assert status["server_busy_with_buildroot"] is True


def test_wait_for_buildroot_drain_until_in_flight_zero():
    with engine.buildroot_state_lock:
        engine.buildroot_state = engine.BUILDROOT_STATE_DRAINING
        engine.in_flight_builds = 1

    def release_in_flight():
        time.sleep(0.15)
        with engine.buildroot_state_lock:
            engine.in_flight_builds = 0

    threading.Thread(target=release_in_flight, daemon=True).start()
    assert engine._wait_for_buildroot_drain() is True


def test_process_build_queue_recreates_when_draining_and_idle(tmp_path: Path):
    engine.server_config["buildroot"] = str(tmp_path)
    recreated = threading.Event()

    with engine.buildroot_state_lock:
        engine.buildroot_state = engine.BUILDROOT_STATE_DRAINING
        engine.in_flight_builds = 0

    def fake_recreate(path: Path) -> bool:
        recreated.set()
        engine.shutdown_event.set()
        return True

    with patch.object(engine, "recreate_buildroot", side_effect=fake_recreate) as recreate_mock:
        thread = threading.Thread(target=engine.process_build_queue, daemon=True)
        thread.start()
        assert recreated.wait(timeout=2)
        thread.join(timeout=2)

    recreate_mock.assert_called_once_with(tmp_path)


def test_process_build_queue_does_not_dequeue_while_draining_with_in_flight(tmp_path: Path):
    engine.server_config["buildroot"] = str(tmp_path)
    build_data = {
        "build_id": "test-build",
        "build_dir": tmp_path / "build",
        "pkgbuild_info": {"pkgname": "foo"},
    }

    with engine.buildroot_state_lock:
        engine.buildroot_state = engine.BUILDROOT_STATE_DRAINING
        engine.in_flight_builds = 1

    with patch.object(engine.build_queue, "get", side_effect=AssertionError("must not dequeue")) as get_mock:
        with patch.object(engine, "_wait_for_buildroot_drain", return_value=False):
            engine.shutdown_event.set()
            thread = threading.Thread(target=engine.process_build_queue, daemon=True)
            thread.start()
            thread.join(timeout=2)

    get_mock.assert_not_called()


def test_process_build_queue_tracks_in_flight_via_done_callback():
    build_data = {
        "build_id": "test-build",
        "build_dir": Path("/tmp/build"),
        "pkgbuild_info": {"pkgname": "foo"},
    }
    submitted = threading.Event()

    future_mock = MagicMock()

    def add_done_callback(callback):
        with engine.buildroot_state_lock:
            assert engine.in_flight_builds == 1
        callback(future_mock)

    future_mock.add_done_callback = add_done_callback

    def fake_submit(*args, **kwargs):
        submitted.set()
        engine.shutdown_event.set()
        return future_mock

    with patch.object(engine.build_queue, "get", return_value=build_data):
        with patch.object(engine.build_executor, "submit", side_effect=fake_submit):
            thread = threading.Thread(target=engine.process_build_queue, daemon=True)
            thread.start()
            assert submitted.wait(timeout=2)
            thread.join(timeout=2)

    with engine.buildroot_state_lock:
        assert engine.in_flight_builds == 0
