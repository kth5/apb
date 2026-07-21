"""Tests for client package existence helpers."""

from pathlib import Path

from apb.client.helpers import check_package_exists, get_architectures_needing_build


def test_check_package_exists_missing_output_dir_with_pkgbuild_archs(tmp_path: Path):
    """Missing output dir must not raise when PKGBUILD archs are provided."""
    missing_dir = tmp_path / "does-not-exist"
    exists, _ = check_package_exists(
        missing_dir,
        ["hello"],
        "1.0.0",
        "1",
        "x86_64",
        pkgbuild_archs=["x86_64", "aarch64"],
    )
    assert exists is False


def test_get_architectures_needing_build_missing_output_dir(tmp_path: Path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(
        "pkgname='hello'\npkgver=1.0.0\npkgrel=1\narch=('x86_64' 'aarch64')\n",
        encoding="utf-8",
    )
    missing_dir = tmp_path / "output"
    archs = get_architectures_needing_build(pkgbuild, missing_dir, force=False)
    assert archs == ["x86_64", "aarch64"]
