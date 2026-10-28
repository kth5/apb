"""Tests for build directory tarball creation and extraction."""

import io
import tarfile
from pathlib import Path

import pytest

from apb.tarball import InvalidBuildTarball, create_build_tarball, extract_build_tarball


def _tarball_bytes(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


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


def test_create_build_tarball_without_artifact_skipping_keeps_signatures(tmp_path: Path) -> None:
    build_path = tmp_path / "package"
    build_path.mkdir()
    (build_path / "PKGBUILD").write_text("pkgname=foo\n", encoding="utf-8")
    (build_path / "foo.tar.gz.sig").write_bytes(b"signature")

    tarball_path = tmp_path / "build.tar.gz"
    create_build_tarball(build_path, tarball_path, skip_artifacts=False)

    with tarfile.open(tarball_path, "r:gz") as archive:
        assert set(archive.getnames()) == {"PKGBUILD", "foo.tar.gz.sig"}


@pytest.mark.parametrize("from_path", [False, True])
def test_extract_build_tarball_returns_pkgbuild_path(tmp_path: Path, from_path: bool) -> None:
    data = _tarball_bytes({"PKGBUILD": b"pkgname=foo\n", "foo.patch": b"diff"})
    source: bytes | Path = data
    if from_path:
        source = tmp_path / "build.tar.gz"
        source.write_bytes(data)
    dest = tmp_path / "dest"
    dest.mkdir()

    pkgbuild_path = extract_build_tarball(source, dest)

    assert pkgbuild_path == dest / "PKGBUILD"
    assert pkgbuild_path.read_text(encoding="utf-8") == "pkgname=foo\n"
    assert (dest / "foo.patch").read_bytes() == b"diff"


def test_extract_build_tarball_requires_pkgbuild(tmp_path: Path) -> None:
    with pytest.raises(InvalidBuildTarball, match="PKGBUILD"):
        extract_build_tarball(_tarball_bytes({"README": b"hi"}), tmp_path)


def test_extract_build_tarball_rejects_invalid_data(tmp_path: Path) -> None:
    with pytest.raises(InvalidBuildTarball, match="Could not extract"):
        extract_build_tarball(b"not a tarball", tmp_path)


def test_extract_build_tarball_rejects_path_traversal(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    data = _tarball_bytes({"PKGBUILD": b"pkgname=foo\n", "../escape": b"x"})

    with pytest.raises(InvalidBuildTarball):
        extract_build_tarball(data, dest)
    assert not (tmp_path / "escape").exists()
