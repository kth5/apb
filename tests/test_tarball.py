"""Tests for build directory tarball creation."""

import tarfile
from pathlib import Path

from apb.tarball import create_build_tarball


def test_create_build_tarball_includes_source_directories(tmp_path: Path) -> None:
    build_path = tmp_path / "package"
    build_path.mkdir()
    (build_path / "PKGBUILD").write_text("pkgname=foo\npkgver=1.0.0\n", encoding="utf-8")
    source_dir = build_path / "src"
    source_dir.mkdir()
    (source_dir / "module.py").write_text("VERSION = '1'\n", encoding="utf-8")

    tarball_path = tmp_path / "build.tar.gz"
    create_build_tarball(build_path, tarball_path)

    with tarfile.open(tarball_path, "r:gz") as archive:
        members = archive.getnames()

    assert "PKGBUILD" in members
    assert any(member.startswith("src/") for member in members)
