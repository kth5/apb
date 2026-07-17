"""Unit tests for farm pkgname / architecture latest-build lookups."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from apb.constants import BuildStatus
from apb.farm import core
from apb.client.cli import (
    _is_build_id,
    _resolve_pkgbuild_dir,
    download_latest_from_pkgbuild,
)


def _init_pkgname_database() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT
        )
        """
    )
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
            user_id INTEGER,
            epoch TEXT,
            pkgver TEXT,
            pkgrel TEXT
        )
        """
    )
    conn.execute("INSERT INTO users (id, username) VALUES (1, 'builder')")
    conn.commit()
    return conn


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
def pkgname_db(monkeypatch: pytest.MonkeyPatch) -> sqlite3.Connection:
    db = _init_pkgname_database()
    monkeypatch.setattr(core, "build_database", db)
    monkeypatch.setattr(core, "obfuscate_server_url", lambda url: "ser---1")
    return db


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
    assert latest["build_id"] == "new-x86"

    by_arch = core.get_latest_builds_by_arch_for_pkgname("hello")
    assert {b["server_arch"]: b["build_id"] for b in by_arch} == {
        "aarch64": "arm-build",
        "x86_64": "new-x86",
    }


def test_get_latest_build_for_any_arch(pkgname_db: sqlite3.Connection) -> None:
    _insert_build(pkgname_db, "older", server_arch="powerpc64le", created_at=100.0)
    _insert_build(pkgname_db, "newer", server_arch="x86_64", created_at=200.0)

    latest = core.get_latest_build_for_pkgname("hello", arch="any")
    assert latest is not None
    assert latest["build_id"] == "newer"


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
        "x86_64": {"build_id": "build-x86", "display_name": "hello (1.0.0-1)", "server_arch": "x86_64"},
        "aarch64": {"build_id": "build-arm", "display_name": "hello (1.0.0-1)", "server_arch": "aarch64"},
    }.get(arch, {})

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
    client.get_latest_build_by_pkgname.return_value = {
        "build_id": "build-any",
        "display_name": "hello (1.0.0-1)",
        "server_arch": "x86_64",
    }

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
