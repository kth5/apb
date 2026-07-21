"""Tests for .SRCINFO parsing and local source selection."""

from pathlib import Path
from unittest.mock import patch

import pytest

from apb.srcinfo import (
    SrcinfoError,
    collect_tarball_paths,
    is_remote_source,
    local_path_for_source,
    parse_srcinfo_local_paths,
    read_or_generate_srcinfo,
)


def test_is_remote_source_detects_urls_and_vcs() -> None:
    assert is_remote_source("https://example.com/foo.tar.gz")
    assert is_remote_source("git+https://example.com/repo.git")
    assert is_remote_source("git://example.com/repo.git")
    assert not is_remote_source("foo.patch")
    assert not is_remote_source("src/")


def test_local_path_for_source_skips_remotes() -> None:
    assert local_path_for_source("https://example.com/a.tar.gz") is None
    assert local_path_for_source("foo.tar.gz::https://example.com/a.tar.gz") is None
    assert local_path_for_source("git+https://example.com/repo.git#tag=v1") is None
    assert local_path_for_source("foo.patch") == "foo.patch"
    assert local_path_for_source("renamed.patch::original.patch") == "renamed.patch"
    assert local_path_for_source("src/") == "src/"


def test_parse_srcinfo_local_paths_includes_sources_and_install() -> None:
    content = """
pkgbase = example
	pkgver = 1.0.0
	pkgrel = 1
	arch = x86_64
	arch = aarch64
	source = local.sh
	source = https://example.com/remote.tar.gz
	source = vendor.tar.gz::https://example.com/vendor.tar.gz
	source = git+https://example.com/repo.git
	source_x86_64 = x86.patch
	source_aarch64 = https://example.com/aarch64-only.tar.gz
	install = example.install
	changelog = ChangeLog
pkgname = example
"""
    paths = parse_srcinfo_local_paths(content)
    assert paths == {"local.sh", "x86.patch", "example.install"}


def test_read_or_generate_srcinfo_prefers_existing_file(tmp_path: Path) -> None:
    build_path = tmp_path / "pkg"
    build_path.mkdir()
    (build_path / ".SRCINFO").write_text("pkgbase = from-disk\n", encoding="utf-8")

    with patch("apb.srcinfo.subprocess.run") as mock_run:
        content = read_or_generate_srcinfo(build_path)

    assert content == "pkgbase = from-disk\n"
    mock_run.assert_not_called()


def test_read_or_generate_srcinfo_falls_back_to_makepkg(tmp_path: Path) -> None:
    build_path = tmp_path / "pkg"
    build_path.mkdir()

    with patch("apb.srcinfo.subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "pkgbase = generated\n"
        mock_run.return_value.stderr = ""
        content = read_or_generate_srcinfo(build_path)

    assert content == "pkgbase = generated\n"
    mock_run.assert_called_once()
    assert mock_run.call_args.args[0] == ["makepkg", "--printsrcinfo"]


def test_read_or_generate_srcinfo_errors_when_makepkg_fails(tmp_path: Path) -> None:
    build_path = tmp_path / "pkg"
    build_path.mkdir()

    with patch("apb.srcinfo.subprocess.run") as mock_run:
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = "bad PKGBUILD"
        with pytest.raises(SrcinfoError, match="makepkg --printsrcinfo failed"):
            read_or_generate_srcinfo(build_path)


def test_collect_tarball_paths_requires_local_sources(tmp_path: Path) -> None:
    build_path = tmp_path / "pkg"
    build_path.mkdir()
    (build_path / "PKGBUILD").write_text("pkgname=foo\n", encoding="utf-8")
    (build_path / ".SRCINFO").write_text(
        "pkgbase = foo\n\tsource = missing.sh\n",
        encoding="utf-8",
    )

    with pytest.raises(FileNotFoundError, match="missing.sh"):
        collect_tarball_paths(build_path)


def test_collect_tarball_paths_includes_keys_when_present(tmp_path: Path) -> None:
    build_path = tmp_path / "pkg"
    build_path.mkdir()
    (build_path / "PKGBUILD").write_text("pkgname=foo\n", encoding="utf-8")
    (build_path / "local.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (build_path / ".SRCINFO").write_text(
        "pkgbase = foo\n\tsource = local.sh\n",
        encoding="utf-8",
    )
    keys_dir = build_path / "keys" / "pgp"
    keys_dir.mkdir(parents=True)
    (keys_dir / "key.asc").write_text("key\n", encoding="utf-8")

    paths = collect_tarball_paths(build_path)
    names = {path.relative_to(build_path).as_posix() for path in paths}
    assert names == {"PKGBUILD", "local.sh", "keys"}
