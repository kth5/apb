"""Unit tests for immediate failed build directory cleanup on the build server."""

from __future__ import annotations

from pathlib import Path

import pytest

from apb.constants import BuildStatus
from apb.server import engine


@pytest.fixture(autouse=True)
def reset_engine_build_state():
    saved_active = engine.active_builds.copy()
    saved_history = engine.build_history.copy()
    saved_outputs = engine.build_outputs.copy()
    try:
        engine.active_builds.clear()
        engine.build_history.clear()
        engine.build_outputs.clear()
        yield
    finally:
        engine.active_builds.clear()
        engine.active_builds.update(saved_active)
        engine.build_history.clear()
        engine.build_history.update(saved_history)
        engine.build_outputs.clear()
        engine.build_outputs.update(saved_outputs)
        engine.close_build_log("cleanup-test-build")


@pytest.fixture
def builds_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setitem(engine.server_config, "builds_dir", tmp_path)
    return tmp_path


def _seed_active_failed_build(build_id: str, builds_dir: Path) -> Path:
    build_dir = builds_dir / build_id
    build_dir.mkdir()
    (build_dir / "PKGBUILD").write_text("pkgname=test\n", encoding="utf-8")

    engine.active_builds[build_id] = {
        "build_id": build_id,
        "pkgname": "test",
        "status": BuildStatus.BUILDING,
        "start_time": 1.0,
    }
    engine.build_outputs[build_id] = ["starting build"]
    return build_dir


def test_cleanup_failed_build_dir_removes_directory(builds_dir: Path):
    build_id = "failed-build-1"
    build_dir = builds_dir / build_id
    build_dir.mkdir()
    (build_dir / "build.log").write_text("ERROR\n", encoding="utf-8")

    engine.cleanup_failed_build_dir(build_id, build_dir)

    assert not build_dir.exists()


def test_finalize_failed_build_cleans_up_directory(builds_dir: Path):
    build_id = "failed-build-2"
    build_dir = _seed_active_failed_build(build_id, builds_dir)

    engine.finalize_failed_build(build_id, build_dir, "package build failed", exit_code=2)

    assert engine.active_builds[build_id]["status"] == BuildStatus.FAILED
    assert engine.build_history[build_id]["logs"][0]["filename"] == "build.log"
    assert not build_dir.exists()


def test_finalize_failed_build_keeps_log_metadata_after_cleanup(builds_dir: Path):
    build_id = "failed-build-3"
    build_dir = _seed_active_failed_build(build_id, builds_dir)

    engine.finalize_failed_build(build_id, build_dir, "early failure")

    log_metadata = engine.build_history[build_id]["logs"][0]
    assert log_metadata["filename"] == "build.log"
    assert log_metadata["size"] > 0
    assert not build_dir.exists()
