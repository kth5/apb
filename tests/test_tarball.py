"""Tests for build directory tarball creation."""

import tarfile
from pathlib import Path

import pytest

from apb.tarball import create_build_tarball


def _write_package(build_path: Path) -> None:
    build_path.mkdir()
    (build_path / "PKGBUILD").write_text(
        "pkgname=foo\npkgver=1.0.0\nsource=('src/' 'foo.install')\n",
        encoding="utf-8",
    )
    (build_path / ".SRCINFO").write_text(
        "pkgbase = foo\n"
        "\tpkgver = 1.0.0\n"
        "\tsource = src/\n"
        "\tinstall = foo.install\n"
        "pkgname = foo\n",
        encoding="utf-8",
    )
    source_dir = build_path / "src"
    source_dir.mkdir()
    (source_dir / "module.py").write_text("VERSION = '1'\n", encoding="utf-8")
    (build_path / "foo.install").write_text("post_install() {\ntrue\n}\n", encoding="utf-8")
    (build_path / "junk.txt").write_text("do not pack\n", encoding="utf-8")
    (build_path / "ChangeLog").write_text("changelog\n", encoding="utf-8")


def test_create_build_tarball_includes_source_directories(tmp_path: Path) -> None:
    build_path = tmp_path / "package"
    _write_package(build_path)

    tarball_path = tmp_path / "build.tar.gz"
    create_build_tarball(build_path, tarball_path)

    with tarfile.open(tarball_path, "r:gz") as archive:
        members = archive.getnames()

    assert "PKGBUILD" in members
    assert "foo.install" in members
    assert any(member == "src" or member.startswith("src/") for member in members)
    assert "junk.txt" not in members
    assert "ChangeLog" not in members
    assert ".SRCINFO" not in members


def test_create_build_tarball_excludes_remote_sources(tmp_path: Path) -> None:
    build_path = tmp_path / "package"
    build_path.mkdir()
    (build_path / "PKGBUILD").write_text("pkgname=foo\n", encoding="utf-8")
    (build_path / "local.patch").write_text("diff\n", encoding="utf-8")
    (build_path / "cached-remote.tar.gz").write_text("cached\n", encoding="utf-8")
    (build_path / ".SRCINFO").write_text(
        "pkgbase = foo\n"
        "\tsource = local.patch\n"
        "\tsource = https://example.com/remote.tar.gz\n"
        "\tsource = cached-remote.tar.gz::https://example.com/cached.tar.gz\n"
        "\tsource = git+https://example.com/repo.git\n"
        "pkgname = foo\n",
        encoding="utf-8",
    )

    tarball_path = tmp_path / "build.tar.gz"
    create_build_tarball(build_path, tarball_path)

    with tarfile.open(tarball_path, "r:gz") as archive:
        members = set(archive.getnames())

    assert members == {"PKGBUILD", "local.patch"}


def test_create_build_tarball_includes_keys_directory(tmp_path: Path) -> None:
    build_path = tmp_path / "package"
    _write_package(build_path)
    keys_dir = build_path / "keys" / "pgp"
    keys_dir.mkdir(parents=True)
    (keys_dir / "key.asc").write_text("asc\n", encoding="utf-8")

    tarball_path = tmp_path / "build.tar.gz"
    create_build_tarball(build_path, tarball_path)

    with tarfile.open(tarball_path, "r:gz") as archive:
        members = archive.getnames()

    assert any(member == "keys" or member.startswith("keys/") for member in members)


def test_create_build_tarball_errors_on_missing_local_source(tmp_path: Path) -> None:
    build_path = tmp_path / "package"
    build_path.mkdir()
    (build_path / "PKGBUILD").write_text("pkgname=foo\n", encoding="utf-8")
    (build_path / ".SRCINFO").write_text(
        "pkgbase = foo\n\tsource = missing.patch\npkgname = foo\n",
        encoding="utf-8",
    )

    with pytest.raises(FileNotFoundError, match="missing.patch"):
        create_build_tarball(build_path, tmp_path / "build.tar.gz")
