"""Unit tests for farm pkgname / architecture latest-build lookups and unified build list shapes."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apb.multipart_compat import install_multipart_compat

install_multipart_compat()

from apb.constants import BuildStatus
from apb.farm import core
from apb.farm import routes as farm_routes
from apb.client.cli import (
    _is_build_id,
    _resolve_pkgbuild_dir,
    download_latest_from_pkgbuild,
)
from apb.models import BuildListResponse, BuildSummary
from apb.server import routes as server_routes


def _summary(build_id: str, server_arch: str) -> BuildSummary:
    return BuildSummary(
        build_id=build_id,
        pkgname="hello",
        status=BuildStatus.COMPLETED,
        display_name="hello (1.0.0-1)",
        server_arch=server_arch,
    )


def _insert_build(
    conn: sqlite3.Connection,
    build_id: str,
    *,
    pkgname: str = "hello",
    server_arch: str = "x86_64",
    status: str = BuildStatus.COMPLETED,
    created_at: float | None = None,
    pkgver: str = "1.0.0",
    pkgrel: str = "1",
) -> None:
    conn.execute(
        """
        INSERT INTO builds
        (id, server_url, server_arch, pkgname, status, start_time, end_time, created_at,
         user_id, epoch, pkgver, pkgrel)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            build_id,
            "http://build-1:8000",
            server_arch,
            pkgname,
            status,
            created_at,
            created_at,
            created_at if created_at is not None else time.time(),
            1,
            None,
            pkgver,
            pkgrel,
        ),
    )
    conn.commit()


@pytest.fixture
def pkgname_db(farm_db: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch) -> sqlite3.Connection:
    farm_db.execute("INSERT INTO users (id, username) VALUES (1, 'builder')")
    farm_db.commit()
    monkeypatch.setattr(core, "obfuscate_server_url", lambda url: "ser---1")
    return farm_db


def test_get_latest_build_for_pkgname_per_arch(pkgname_db: sqlite3.Connection) -> None:
    _insert_build(pkgname_db, "old-x86", server_arch="x86_64", created_at=100.0)
    _insert_build(pkgname_db, "new-x86", server_arch="x86_64", created_at=200.0)
    _insert_build(pkgname_db, "arm-build", server_arch="aarch64", created_at=150.0)
    _insert_build(
        pkgname_db,
        "failed-x86",
        server_arch="x86_64",
        status=BuildStatus.FAILED,
        created_at=300.0,
    )

    latest = core.get_latest_build_for_pkgname("hello", arch="x86_64")
    assert latest is not None
    assert latest.build_id == "new-x86"

    by_arch = core.get_latest_builds_by_arch_for_pkgname("hello")
    assert by_arch.total == 2
    assert {b.server_arch: b.build_id for b in by_arch.builds} == {
        "aarch64": "arm-build",
        "x86_64": "new-x86",
    }


def test_get_latest_build_for_any_arch(pkgname_db: sqlite3.Connection) -> None:
    _insert_build(pkgname_db, "older", server_arch="powerpc64le", created_at=100.0)
    _insert_build(pkgname_db, "newer", server_arch="x86_64", created_at=200.0)

    latest = core.get_latest_build_for_pkgname("hello", arch="any")
    assert latest is not None
    assert latest.build_id == "newer"


def test_list_builds_total_counts_all_matches(pkgname_db: sqlite3.Connection) -> None:
    for index in range(5):
        _insert_build(pkgname_db, f"build-{index}", created_at=100.0 + index)
    _insert_build(pkgname_db, "failed", status=BuildStatus.FAILED, created_at=200.0)
    _insert_build(pkgname_db, "other", pkgname="other", created_at=300.0)

    listing = core.list_builds(pkgname="hello", status=BuildStatus.COMPLETED, limit=2)
    assert listing.pkgname == "hello"
    assert listing.total == 5
    assert [b.build_id for b in listing.builds] == ["build-4", "build-3"]
    assert core.list_builds(limit=1).total == 7


def test_list_builds_summary_shape(pkgname_db: sqlite3.Connection) -> None:
    _insert_build(pkgname_db, "b1", created_at=1_700_000_000.0)

    data = core.list_builds().model_dump(mode="json", exclude_none=True)
    build = data["builds"][0]
    assert "id" not in build
    assert build["build_id"] == "b1"
    assert build["created_at"] == "2023-11-14T22:13:20Z"
    assert build["server_url"] == "ser---1"
    assert build["display_name"] == "hello (1.0.0-1)"
    assert build["username"] == "builder"


def _route_client(router) -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_builds_latest_shape_matches_on_server_and_farm(
    pkgname_db: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _insert_build(pkgname_db, "b1", created_at=1_700_000_000.0)
    monkeypatch.setattr(server_routes.engine, "active_builds", {})
    monkeypatch.setattr(server_routes.engine, "build_history", {
        "b1": {
            "build_id": "b1",
            "pkgname": "hello",
            "status": BuildStatus.COMPLETED,
            "created_at": 1_700_000_000.0,
            "start_time": 1_700_000_000.0,
            "end_time": 1_700_000_000.0,
            "duration": 0.0,
            "arch": ["x86_64"],
            "extra_repos": [],
        },
    })

    server_data = _route_client(server_routes.router).get("/builds/latest").json()
    farm_data = _route_client(farm_routes.router).get("/builds/latest").json()

    assert server_data.keys() == farm_data.keys() == {"builds", "total"}
    assert server_data["total"] == farm_data["total"] == 1
    server_build, farm_build = server_data["builds"][0], farm_data["builds"][0]
    common = {"build_id", "pkgname", "status", "start_time", "end_time", "created_at", "duration"}
    assert common <= server_build.keys()
    assert common <= farm_build.keys()
    assert {key: server_build[key] for key in common} == {key: farm_build[key] for key in common}
    assert BuildListResponse.model_validate(server_data) == BuildListResponse.model_validate(
        {**farm_data, "builds": [{key: farm_build[key] for key in common}]}
    )


def test_server_status_api_hides_internal_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server_routes.engine, "active_builds", {
        "b1": {
            "build_id": "b1",
            "pkgname": "hello",
            "status": BuildStatus.QUEUED,
            "created_at": 1_700_000_000.0,
            "arch": ["x86_64"],
            "packages": [],
            "logs": [],
            "build_timeout": 7200,
            "extra_repos": [{"name": "internal", "server": "http://repo"}],
        },
    })

    data = _route_client(server_routes.router).get("/build/b1/status-api").json()
    assert data["build_id"] == "b1"
    assert data["arch"] == ["x86_64"]
    assert "extra_repos" not in data
    assert "artifacts_ready" not in data


def test_is_build_id() -> None:
    assert _is_build_id("48ea1df5-f7f3-477e-a7a7-36e526ea7cd3")
    assert not _is_build_id("/path/to/package")
    assert not _is_build_id("__PKGBUILD__")


def test_resolve_pkgbuild_dir(tmp_path: Path) -> None:
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "PKGBUILD").write_text("pkgname=hello\narch=('x86_64')\n", encoding="utf-8")

    assert _resolve_pkgbuild_dir(pkg_dir) == pkg_dir.resolve()
    assert _resolve_pkgbuild_dir(pkg_dir / "PKGBUILD") == pkg_dir.resolve()

    with pytest.raises(ValueError):
        _resolve_pkgbuild_dir(tmp_path / "missing")


def test_download_latest_from_pkgbuild(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "PKGBUILD").write_text(
        "pkgname=hello\npkgver=1.0.0\npkgrel=1\narch=('x86_64' 'aarch64')\n",
        encoding="utf-8",
    )
    output_dir = tmp_path / "output"

    client = MagicMock()
    client.get_latest_build_by_pkgname.side_effect = lambda pkgname, successful_only=True, arch=None: {
        "x86_64": _summary("build-x86", "x86_64"),
        "aarch64": _summary("build-arm", "aarch64"),
    }.get(arch)

    downloaded = []

    def fake_download(client_arg, build_id, out_dir, *, arch_prefix=""):
        downloaded.append((build_id, out_dir.name))
        return True

    monkeypatch.setattr("apb.client.cli._download_build_artifacts", fake_download)

    assert download_latest_from_pkgbuild(client, pkg_dir, output_dir) is True
    assert downloaded == [("build-x86", "x86_64"), ("build-arm", "aarch64")]
    assert client.get_latest_build_by_pkgname.call_count == 2


def test_download_latest_from_pkgbuild_any(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "PKGBUILD").write_text(
        "pkgname=hello\npkgver=1.0.0\npkgrel=1\narch=('any')\n",
        encoding="utf-8",
    )

    client = MagicMock()
    client.get_latest_build_by_pkgname.return_value = _summary("build-any", "x86_64")

    downloaded = []

    def fake_download(client_arg, build_id, out_dir, *, arch_prefix=""):
        downloaded.append((build_id, out_dir.name))
        return True

    monkeypatch.setattr("apb.client.cli._download_build_artifacts", fake_download)

    assert download_latest_from_pkgbuild(client, pkg_dir, tmp_path / "output") is True
    assert downloaded == [("build-any", "any")]
    client.get_latest_build_by_pkgname.assert_called_once_with(
        "hello", successful_only=True, arch="any"
    )
