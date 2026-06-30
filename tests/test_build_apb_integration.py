"""Integration test: build the test package through farm, server, and client."""

from __future__ import annotations

import tarfile
from pathlib import Path

import pytest

from apb.client.api import APBotClient
from apb.client.cli import monitor_build, submit_build_to_farm
from apb.pkgbuild import parse_pkgbuild_file


def _find_package_artifact(output_dir: Path, pkgname: str, pkgver: str, pkgrel: str) -> Path:
    pattern = f"{pkgname}-{pkgver}-{pkgrel}-any.pkg.tar"
    matches = [
        path
        for path in output_dir.rglob("*.pkg.tar*")
        if path.name.startswith(pattern)
    ]
    if not matches:
        raise AssertionError(f"No package matching {pattern}* found under {output_dir}")
    return matches[0]


def _assert_test_package_contents(package_path: Path) -> None:
    expected_paths = (
        "usr/bin/apb-test",
        "usr/share/man/man1/apb-test.1",
    )
    with tarfile.open(package_path, "r:*") as archive:
        members = archive.getnames()

    for expected in expected_paths:
        assert any(member.endswith(expected) for member in members), (
            f"Expected {expected!r} in {package_path.name}, got members: {members[:20]}"
        )


@pytest.mark.integration
def test_build_test_package_via_farm(apb_integration) -> None:
    pkgbuild_info = parse_pkgbuild_file(apb_integration.build_path / "PKGBUILD")
    assert pkgbuild_info.pkgname == "apb-test-package"

    response = submit_build_to_farm(
        apb_integration.farm_url,
        apb_integration.build_path,
        architectures=["any"],
        auth_client=apb_integration.auth_client,
    )
    assert response is not None, "Farm did not accept the build submission"
    assert "error" not in response, response.get("message", response)
    assert response.get("build_id"), response

    build_id = response["build_id"]
    client = APBotClient(apb_integration.farm_url, apb_integration.auth_client)
    arch_output_dir = apb_integration.output_dir / "any"

    success = monitor_build(
        build_id,
        client,
        output_dir=arch_output_dir,
        verbose=False,
        arch="any",
        pkgname=pkgbuild_info.pkgname,
    )
    assert success, f"Build {build_id} did not complete successfully"

    package_path = _find_package_artifact(
        arch_output_dir,
        pkgbuild_info.pkgname,
        pkgbuild_info.pkgver,
        pkgbuild_info.pkgrel,
    )
    assert package_path.stat().st_size > 0
    _assert_test_package_contents(package_path)

    log_files = list(arch_output_dir.rglob("build.log"))
    assert log_files, "Expected build.log in output directory"
