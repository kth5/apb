"""Unit tests for full on-disk build.log and guest log truncation."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apb.constants import GUEST_BUILD_LOG_TAIL_LINES
from apb.farm import core
from apb.farm import routes as farm_routes
from apb.server import engine


def test_read_text_file_tail_returns_last_lines(tmp_path: Path):
    log_path = tmp_path / "build.log"
    lines = [f"line-{i}" for i in range(250)]
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    tail = core.read_text_file_tail(log_path, max_lines=100)
    tail_lines = [line for line in tail.splitlines() if line]

    assert len(tail_lines) == 100
    assert tail_lines[0] == "line-150"
    assert tail_lines[-1] == "line-249"


def test_read_text_file_tail_handles_short_files(tmp_path: Path):
    log_path = tmp_path / "build.log"
    log_path.write_text("a\nb\nc\n", encoding="utf-8")

    assert core.read_text_file_tail(log_path, max_lines=100).splitlines() == ["a", "b", "c"]


def test_append_build_log_writes_full_file_despite_memory_truncation(tmp_path: Path):
    build_id = "test-build-log-full"
    build_dir = tmp_path / build_id
    build_dir.mkdir()

    engine.build_outputs[build_id] = []
    engine.open_build_log(build_id, build_dir)

    try:
        for i in range(12000):
            message = f"output-line-{i}"
            engine.build_outputs[build_id].append(message)
            engine.append_build_log(build_id, message, build_dir)

        # Simulate in-memory cleanup truncation
        engine.build_outputs[build_id] = engine.build_outputs[build_id][-5000:]

        engine.close_build_log(build_id)
        log_path = build_dir / "build.log"
        disk_lines = log_path.read_text(encoding="utf-8").splitlines()

        assert len(engine.build_outputs[build_id]) == 5000
        assert len(disk_lines) == 12000
        assert disk_lines[0] == "output-line-0"
        assert disk_lines[-1] == "output-line-11999"
    finally:
        engine.close_build_log(build_id)
        engine.build_outputs.pop(build_id, None)


@pytest.fixture
def download_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    build_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    log_path = tmp_path / "build.log"
    lines = [f"log-line-{i}" for i in range(150)]
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    async def fake_get_cached_artifact(requested_build_id: str, filename: str):
        if requested_build_id == build_id and filename == "build.log":
            return {
                "file_path": log_path,
                "file_size": log_path.stat().st_size,
            }
        return None

    monkeypatch.setattr(core, "get_cached_artifact", fake_get_cached_artifact)

    app = FastAPI()
    app.include_router(farm_routes.router)
    return TestClient(app), build_id, log_path


def test_guest_build_log_download_is_truncated(download_client):
    client, build_id, _log_path = download_client

    response = client.get(f"/build/{build_id}/download/build.log")

    assert response.status_code == 200
    assert response.headers.get("X-APB-Log-Truncated") == "true"
    assert response.headers.get("X-APB-Log-Tail-Lines") == str(GUEST_BUILD_LOG_TAIL_LINES)
    assert "private, no-store" in response.headers.get("Cache-Control", "")
    assert "Authenticate" in response.text or "Log in" in response.text

    body_lines = [line for line in response.text.splitlines() if line.startswith("log-line-")]
    assert len(body_lines) == GUEST_BUILD_LOG_TAIL_LINES
    assert body_lines[0] == "log-line-50"
    assert body_lines[-1] == "log-line-149"


def test_authenticated_build_log_download_is_full(download_client):
    client, build_id, log_path = download_client
    fake_user = MagicMock()
    fake_user.username = "tester"

    async def fake_optional_user():
        return fake_user

    # Override the same dependency object the route registered with Depends(...)
    client.app.dependency_overrides[core.get_current_user_optional] = fake_optional_user
    try:
        response = client.get(f"/build/{build_id}/download/build.log")
    finally:
        client.app.dependency_overrides.pop(core.get_current_user_optional, None)

    assert response.status_code == 200
    assert response.headers.get("X-APB-Log-Truncated") is None
    assert "private, no-store" in response.headers.get("Cache-Control", "")
    assert response.content == log_path.read_bytes()
