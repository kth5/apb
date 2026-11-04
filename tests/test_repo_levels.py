"""Tests for testing/stage repository level selection across client, farm and server."""

from __future__ import annotations

import queue
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apb.multipart_compat import install_multipart_compat

install_multipart_compat()

from apb.client import cli
from apb.client.api import APBotClient
from apb.farm import core
from apb.server import engine
from apb.server import routes as server_routes
from apb.tarball import create_build_tarball
from apb.validation import RepoLevel, sections_for_level, validate_repo_level

pytestmark = pytest.mark.anyio

PACMAN_CONF = """[options]
Architecture = auto

#[stage-any]
#Include = /etc/pacman.d/mirrorlist

#[stage]
#Include = /etc/pacman.d/mirrorlist

#[testing-any]
#Include = /etc/pacman.d/mirrorlist

#[testing]
#SigLevel = Required
#Include = /etc/pacman.d/mirrorlist

[base]
Include = /etc/pacman.d/mirrorlist

[base-any]
Include = /etc/pacman.d/mirrorlist
"""

TESTING_ONLY_CONF = """[options]

#[testing]
#Include = /etc/pacman.d/mirrorlist

#[testing-any]
#Include = /etc/pacman.d/mirrorlist

[base]
Include = /etc/pacman.d/mirrorlist
"""


def _section_order(pacman_conf_text: str) -> list[str]:
    return [line.strip()[1:-1] for line in pacman_conf_text.splitlines() if engine.ACTIVE_SECTION_RE.match(line.strip())]


# Shared validation

def test_sections_for_level_is_cumulative_highest_priority_first() -> None:
    assert sections_for_level(RepoLevel.BASE) == []
    assert sections_for_level(RepoLevel.TESTING) == ["testing-any", "testing"]
    assert sections_for_level(RepoLevel.STAGE) == ["stage-any", "stage", "testing-any", "testing"]


@pytest.mark.parametrize(("value", "expected"), [
    (None, RepoLevel.BASE),
    ("", RepoLevel.BASE),
    ("base", RepoLevel.BASE),
    ("testing", RepoLevel.TESTING),
    ("Stage", RepoLevel.STAGE),
])
def test_validate_repo_level(value: str | None, expected: RepoLevel) -> None:
    assert validate_repo_level(value) == expected


def test_validate_repo_level_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="Invalid repository level"):
        validate_repo_level("staging")


# Server pacman.conf handling

def test_find_repo_level_blocks_uncomments_sections() -> None:
    blocks = engine.find_repo_level_blocks(PACMAN_CONF)

    assert set(blocks) == {"stage-any", "stage", "testing-any", "testing"}
    assert blocks["testing"] == ["[testing]", "SigLevel = Required", "Include = /etc/pacman.d/mirrorlist"]


def test_find_repo_level_blocks_ignores_headers_without_options() -> None:
    assert engine.find_repo_level_blocks("#[testing]\n\n[base]\nInclude = x\n") == {}


def test_available_repo_levels() -> None:
    assert engine.available_repo_levels(PACMAN_CONF) == [RepoLevel.TESTING, RepoLevel.STAGE]
    assert engine.available_repo_levels(TESTING_ONLY_CONF) == [RepoLevel.TESTING]
    assert engine.available_repo_levels("[base]\nInclude = x\n") == []


def test_available_repo_levels_requires_lower_levels() -> None:
    stage_only = "#[stage]\n#Include = x\n\n#[stage-any]\n#Include = x\n\n[base]\nInclude = x\n"
    assert engine.available_repo_levels(stage_only) == []


def test_compose_pacman_conf_stage_orders_sections_before_base() -> None:
    composed = engine.compose_pacman_conf(PACMAN_CONF, [], RepoLevel.STAGE)

    assert _section_order(composed) == ["options", "stage-any", "stage", "testing-any", "testing", "base", "base-any"]
    assert "#[" not in composed


def test_compose_pacman_conf_testing_leaves_stage_commented() -> None:
    composed = engine.compose_pacman_conf(PACMAN_CONF, [], RepoLevel.TESTING)

    assert _section_order(composed) == ["options", "testing-any", "testing", "base", "base-any"]
    assert "#[stage]" in composed
    assert "#[stage-any]" in composed


def test_compose_pacman_conf_moves_sections_listed_after_base() -> None:
    composed = engine.compose_pacman_conf(TESTING_ONLY_CONF, [], RepoLevel.TESTING)

    assert _section_order(composed) == ["options", "testing-any", "testing", "base"]


def test_compose_pacman_conf_puts_custom_repos_first() -> None:
    extra_repos = [{"name": "custom", "url": "https://repo.example.com/$arch"}]

    composed = engine.compose_pacman_conf(PACMAN_CONF, extra_repos, RepoLevel.TESTING)

    assert _section_order(composed) == ["options", "custom", "testing-any", "testing", "base", "base-any"]
    assert "Server = https://repo.example.com/$arch" in composed


def test_compose_pacman_conf_rejects_missing_sections() -> None:
    with pytest.raises(ValueError, match="stage-any, stage"):
        engine.compose_pacman_conf(TESTING_ONLY_CONF, [], RepoLevel.STAGE)


def test_create_custom_pacman_conf_writes_build_dir(tmp_path: Path) -> None:
    chroot_etc = tmp_path / "buildroot" / "root" / "etc"
    chroot_etc.mkdir(parents=True)
    (chroot_etc / "pacman.conf").write_text(PACMAN_CONF)
    build_dir = tmp_path / "build"
    build_dir.mkdir()
    messages: list[str] = []

    result = engine.create_custom_pacman_conf(tmp_path / "buildroot", build_dir, [], RepoLevel.STAGE, messages.append)

    assert result == build_dir / "pacman.conf"
    assert _section_order(result.read_text())[1:5] == ["stage-any", "stage", "testing-any", "testing"]
    assert (chroot_etc / "pacman.conf").read_text() == PACMAN_CONF


def test_get_repo_levels_reads_buildroot_conf(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    chroot_etc = tmp_path / "root" / "etc"
    chroot_etc.mkdir(parents=True)
    (chroot_etc / "pacman.conf").write_text(TESTING_ONLY_CONF)
    monkeypatch.setitem(engine.server_config, "buildroot", str(tmp_path))

    assert engine.get_repo_levels() == [RepoLevel.TESTING]


# Server routes

@pytest.fixture
def server_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(engine, "active_builds", {})
    monkeypatch.setattr(engine, "build_history", {})
    monkeypatch.setattr(engine, "build_queue", queue.Queue())
    monkeypatch.setitem(engine.server_config, "builds_dir", str(tmp_path / "builds"))
    monkeypatch.setattr(engine, "get_repo_levels", lambda: [RepoLevel.TESTING])
    app = FastAPI()
    app.include_router(server_routes.router)
    return TestClient(app)


def _build_tarball(tmp_path: Path) -> bytes:
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "PKGBUILD").write_text("pkgname=hello\npkgver=1\npkgrel=1\narch=(any)\n")
    tarball_path = tmp_path / "build.tar.gz"
    create_build_tarball(pkg_dir, tarball_path)
    return tarball_path.read_bytes()


def test_server_info_lists_repo_levels(server_client: TestClient) -> None:
    assert server_client.get("/").json()["repo_levels"] == ["testing"]


def test_server_rejects_unsupported_repo_level(server_client: TestClient) -> None:
    response = server_client.post("/build", data={"build_id": "b1", "repo_level": "stage"})

    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "Unsupported repository level"
    assert engine.build_queue.empty()


def test_server_rejects_invalid_repo_level(server_client: TestClient) -> None:
    response = server_client.post("/build", data={"build_id": "b1", "repo_level": "bogus"})

    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "Invalid repository level"


def test_server_queues_build_with_repo_level(server_client: TestClient, tmp_path: Path) -> None:
    response = server_client.post(
        "/build",
        data={"build_id": "b1", "repo_level": "testing"},
        files={"build_tarball": ("build.tar.gz", _build_tarball(tmp_path), "application/gzip")},
    )

    assert response.status_code == 200
    assert engine.build_queue.get_nowait()["repo_level"] == RepoLevel.TESTING
    assert server_client.get("/build/b1/status-api").json()["repo_level"] == "testing"


# Farm scheduling

def _tracked_server(url: str, repo_levels: list[str]) -> core.ServerStatus:
    return core.ServerStatus(url=url, last_response={"repo_levels": repo_levels})


@pytest.fixture
def tracked_servers(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[str]]:
    monkeypatch.setattr(core, "server_status_tracker", {
        "http://ppc-stage": _tracked_server("http://ppc-stage", ["testing", "stage"]),
        "http://ppc-plain": _tracked_server("http://ppc-plain", []),
        "http://x86-testing": _tracked_server("http://x86-testing", ["testing"]),
    })
    return {
        "powerpc": ["http://ppc-stage", "http://ppc-plain"],
        "x86_64": ["http://x86-testing"],
    }


def test_filter_archs_by_repo_level(tracked_servers: dict[str, list[str]]) -> None:
    assert core.filter_archs_by_repo_level(tracked_servers, RepoLevel.BASE) == tracked_servers
    assert core.filter_archs_by_repo_level(tracked_servers, RepoLevel.TESTING) == {
        "powerpc": ["http://ppc-stage"],
        "x86_64": ["http://x86-testing"],
    }
    assert core.filter_archs_by_repo_level(tracked_servers, RepoLevel.STAGE) == {"powerpc": ["http://ppc-stage"]}


async def test_find_repo_level_unsupported_archs(tracked_servers: dict[str, list[str]]) -> None:
    with patch.object(core, "get_available_architectures", AsyncMock(return_value=tracked_servers)):
        assert await core.find_repo_level_unsupported_archs(["powerpc", "x86_64"], RepoLevel.STAGE) == ["x86_64"]
        assert await core.find_repo_level_unsupported_archs(["powerpc", "x86_64"], RepoLevel.TESTING) == []
        assert await core.find_repo_level_unsupported_archs(["any"], RepoLevel.STAGE) == []
        assert await core.find_repo_level_unsupported_archs(["any"], RepoLevel.STAGE, "x86_64") == ["any"]


async def test_queue_builds_skips_servers_without_repo_level(
    farm_queue_state: sqlite3.Connection, tracked_servers: dict[str, list[str]]
) -> None:
    pkgbuild = "pkgname=test\npkgver=1\npkgrel=1\narch=(powerpc x86_64)\n"
    with patch.object(core, "get_available_architectures", AsyncMock(return_value=tracked_servers)):
        queued = await core.queue_builds_for_architectures(
            pkgbuild, "test", ["powerpc", "x86_64"], repo_level=RepoLevel.STAGE
        )

    assert [build["arch"] for build in queued] == ["powerpc"]
    assert queued[0]["repo_level"] == "stage"
    assert core.build_queue[0]["repo_level"] == RepoLevel.STAGE
    stored = farm_queue_state.execute("SELECT repo_level FROM builds WHERE id = ?", (queued[0]["build_id"],)).fetchone()
    assert stored == ("stage",)


async def test_get_best_server_for_arch_respects_repo_level(tracked_servers: dict[str, list[str]]) -> None:
    server_info = {"queue_status": {"current_builds_count": 0, "queued_builds": 0, "max_concurrent_builds": 3}}
    with patch.object(core, "get_available_architectures", AsyncMock(return_value=tracked_servers)), \
         patch.object(core, "get_server_info", AsyncMock(return_value=server_info)):
        assert await core.get_best_server_for_arch(["powerpc"], RepoLevel.STAGE) == "http://ppc-stage"
        assert await core.get_best_server_for_arch(["x86_64"], RepoLevel.STAGE) is None


@pytest.mark.parametrize(("repo_level", "expected"), [(RepoLevel.BASE, None), (RepoLevel.STAGE, "stage")])
async def test_forward_build_sends_repo_level(
    farm_queue_state: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    repo_level: RepoLevel,
    expected: str | None,
) -> None:
    farm_queue_state.execute("INSERT INTO builds (id, status) VALUES ('b1', 'queued')")
    post = AsyncMock(return_value=httpx.Response(200, json={}))
    monkeypatch.setattr(core, "http_session", SimpleNamespace(post=post))

    result = await core.forward_build_to_server(
        {"build_id": "b1", "original_tarball": b"tar", "repo_level": repo_level}, "http://server"
    )

    assert result is True
    assert post.await_args.kwargs["data"].get("repo_level") == expected


def test_farm_submit_rejects_arch_without_repo_level_server(
    farm_client: TestClient,
    farm_queue_state: sqlite3.Connection,
    tracked_servers: dict[str, list[str]],
    tmp_path: Path,
) -> None:
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "PKGBUILD").write_text("pkgname=hello\npkgver=1\npkgrel=1\narch=(powerpc x86_64)\n")
    tarball_path = tmp_path / "build.tar.gz"
    create_build_tarball(pkg_dir, tarball_path)

    async def fake_user() -> core.User:
        return core.User(id=1, username="tester", role=core.UserRole.USER, created_at=0.0)

    farm_client.app.dependency_overrides[core.require_auth] = fake_user
    with patch.object(core, "get_available_architectures", AsyncMock(return_value=tracked_servers)):
        response = farm_client.post(
            "/build",
            data={"repo_level": "stage"},
            files={"build_tarball": ("build.tar.gz", tarball_path.read_bytes(), "application/gzip")},
        )

    assert response.json() == {
        "error": "Unsupported repository level",
        "message": "No server supports repository level 'stage' for: x86_64",
        "pkgname": "hello",
        "repo_level": "stage",
        "unsupported_architectures": ["x86_64"],
    }
    assert core.build_queue == []


# Client

@pytest.mark.parametrize(("argv", "expected"), [
    ([], RepoLevel.BASE),
    (["--testing"], RepoLevel.TESTING),
    (["--stage"], RepoLevel.STAGE),
    (["--testing", "--stage"], RepoLevel.STAGE),
])
def test_resolve_repo_level(argv: list[str], expected: RepoLevel) -> None:
    assert cli.resolve_repo_level(cli.parse_args(argv)) == expected


def test_build_package_sends_repo_level(tmp_path: Path) -> None:
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "PKGBUILD").write_text("pkgname=hello\npkgver=1\npkgrel=1\narch=(any)\n")
    captured = {}

    def fake_post(url, files=None, data=None):
        captured.update(data=data)
        return httpx.Response(200, json={"build_id": "b1", "status": "queued"}, request=httpx.Request("POST", url))

    with patch("httpx.Client.post", side_effect=fake_post):
        APBotClient("http://server").build_package(pkg_dir, repo_level=RepoLevel.STAGE)

    assert captured["data"] == {"repo_level": "stage"}
