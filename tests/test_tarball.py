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


def test_create_build_tarball_excludes_output_and_artifacts(tmp_path: Path) -> None:
    build_path = tmp_path / "package"
    build_path.mkdir()
    (build_path / "PKGBUILD").write_text("pkgname=foo\npkgver=1.0.0\n", encoding="utf-8")
    (build_path / "foo-1.0.0-1-x86_64.pkg.tar.zst").write_bytes(b"package")
    (build_path / "build.log").write_text("old build output\n", encoding="utf-8")

    output_dir = build_path / "output"
    output_dir.mkdir()
    arch_dir = output_dir / "x86_64"
    arch_dir.mkdir()
    (arch_dir / "foo-1.0.0-1-x86_64.pkg.tar.zst").write_bytes(b"cached package")
    (arch_dir / "build.log").write_text("previous build\n", encoding="utf-8")

    pkg_dir = build_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "foo").write_text("makepkg artifact\n", encoding="utf-8")

    tarball_path = tmp_path / "build.tar.gz"
    create_build_tarball(build_path, tarball_path, exclude_paths=[output_dir])

    with tarfile.open(tarball_path, "r:gz") as archive:
        members = archive.getnames()

    assert "PKGBUILD" in members
    assert "output" not in members
    assert not any(name.startswith("output/") for name in members)
    assert "pkg" not in members
    assert "foo-1.0.0-1-x86_64.pkg.tar.zst" not in members
    assert "build.log" not in members
