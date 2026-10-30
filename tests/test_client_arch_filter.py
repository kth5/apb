"""Tests for --arch filtering on farm client submissions."""

from pathlib import Path
from unittest.mock import patch

import pytest

from apb.client.helpers import (
    get_architectures_needing_build,
    select_pkgbuild_architectures,
)
from apb.models import FarmBuildSubmitResponse, QueuedBuildInfo


def test_select_pkgbuild_architectures_no_filter():
    selected, missing = select_pkgbuild_architectures(["x86_64", "powerpc"], None)
    assert selected == ["x86_64", "powerpc"]
    assert missing == []


def test_select_pkgbuild_architectures_empty_filter():
    selected, missing = select_pkgbuild_architectures(["x86_64", "powerpc"], [])
    assert selected == ["x86_64", "powerpc"]
    assert missing == []


def test_select_pkgbuild_architectures_single_match():
    selected, missing = select_pkgbuild_architectures(
        ["x86_64", "powerpc"], ["powerpc"]
    )
    assert selected == ["powerpc"]
    assert missing == []


def test_select_pkgbuild_architectures_multiple_requested():
    selected, missing = select_pkgbuild_architectures(
        ["x86_64", "powerpc", "aarch64"],
        ["powerpc", "x86_64"],
    )
    assert selected == ["x86_64", "powerpc"]
    assert missing == []


def test_select_pkgbuild_architectures_unknown_requested():
    selected, missing = select_pkgbuild_architectures(
        ["x86_64", "powerpc"], ["riscv64"]
    )
    assert selected == []
    assert missing == ["riscv64"]


def test_select_pkgbuild_architectures_partial_unknown():
    selected, missing = select_pkgbuild_architectures(
        ["x86_64", "powerpc"], ["powerpc", "riscv64"]
    )
    assert selected == ["powerpc"]
    assert missing == ["riscv64"]


def test_get_architectures_needing_build_respects_arch_filter(tmp_path: Path):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "PKGBUILD").write_text(
        'pkgname=test\npkgver=1\npkgrel=1\narch=(x86_64 powerpc)\n',
        encoding="utf-8",
    )
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    all_needed = get_architectures_needing_build(pkg_dir / "PKGBUILD", output_dir)
    assert set(all_needed) == {"x86_64", "powerpc"}

    powerpc_only = get_architectures_needing_build(
        pkg_dir / "PKGBUILD", output_dir, arch_filter=["powerpc"]
    )
    assert powerpc_only == ["powerpc"]


def test_get_architectures_needing_build_arch_filter_no_match(tmp_path: Path):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "PKGBUILD").write_text(
        'pkgname=test\npkgver=1\npkgrel=1\narch=(x86_64 powerpc)\n',
        encoding="utf-8",
    )
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    result = get_architectures_needing_build(
        pkg_dir / "PKGBUILD", output_dir, arch_filter=["riscv64"]
    )
    assert result == []


def test_farm_submission_passes_arch_filter_to_form_data(tmp_path: Path):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "PKGBUILD").write_text(
        'pkgname=test\npkgver=1\npkgrel=1\narch=(x86_64 powerpc)\n',
        encoding="utf-8",
    )
    (pkg_dir / "test.sh").write_text("#!/bin/sh\n", encoding="utf-8")

    captured_form: dict = {}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"build_id": "test-id", "status": "queued"}

    def fake_post(url, files=None, data=None):
        captured_form.update(data or {})
        return FakeResponse()

    from apb.client.cli import submit_build

    with patch("httpx.Client.post", side_effect=fake_post):
        response = submit_build(
            "http://farm.example/",
            pkg_dir,
            architectures=["powerpc"],
        )

    assert response.build_id == "test-id"
    assert captured_form.get("architectures") == "powerpc"


def test_farm_cli_arch_filter_limits_needing_build(tmp_path: Path, monkeypatch):
    """When x86_64 artifact exists, --arch powerpc still submits only powerpc."""
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "PKGBUILD").write_text(
        'pkgname=test\npkgver=1\npkgrel=1\narch=(x86_64 powerpc)\n',
        encoding="utf-8",
    )

    output_dir = tmp_path / "output"
    x86_dir = output_dir / "x86_64"
    x86_dir.mkdir(parents=True)
    (x86_dir / "test-1-1-x86_64.pkg.tar.zst").write_bytes(b"x")

    submitted_architectures: list = []

    def fake_submit(*_args, architectures=None, **_kwargs):
        submitted_architectures.extend(architectures or [])
        return FarmBuildSubmitResponse(
            build_id="b1",
            status="queued",
            message="Queued 1 build(s) for processing",
            pkgname="test",
            target_architectures=["powerpc"],
            pkgbuild_architectures=["x86_64", "powerpc"],
            builds=[
                QueuedBuildInfo(
                    build_id="b1",
                    arch="powerpc",
                    status="queued",
                    pkgname="test",
                    submission_group="g1",
                    created_at=0.0,
                )
            ],
            submission_group="g1",
            created_at=0.0,
        )

    monkeypatch.setattr("apb.client.cli.submit_build", fake_submit)
    monkeypatch.setattr("apb.client.cli.load_config_with_source", lambda _c: ({"farm_url": "http://farm/"}, None))
    monkeypatch.setattr(
        "apb.client.cli.sys.argv",
        [
            "apb",
            "--farm",
            "--arch",
            "powerpc",
            "--detach",
            str(pkg_dir),
            "--output-dir",
            str(output_dir),
        ],
    )

    from apb.client.cli import main

    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    assert submitted_architectures == ["powerpc"]
