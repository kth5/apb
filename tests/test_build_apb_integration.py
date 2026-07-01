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


def _read_log_excerpt(log_path: Path, *, max_chars: int = 8000) -> str:
    if not log_path.is_file():
        return f"(missing: {log_path})"
    text = log_path.read_text(encoding="utf-8", errors="replace")
    if len(text) <= max_chars:
        return text
    return f"{text[:max_chars]}\n... truncated ({len(text) - max_chars} more chars) ..."


def _format_build_failure(
    build_id: str,
    *,
    arch_output_dir: Path,
    server_log: Path,
    farm_log: Path,
) -> str:
    log_files = list(arch_output_dir.rglob("build.log"))
    build_log_excerpt = _read_log_excerpt(log_files[0]) if log_files else "(build.log not downloaded)"
    return (
        f"Build {build_id} did not complete successfully.\n\n"
        f"--- build.log ---\n{build_log_excerpt}\n\n"
        f"--- server.log ---\n{_read_log_excerpt(server_log)}\n\n"
        f"--- farm.log ---\n{_read_log_excerpt(farm_log)}"
    )


def _assert_test_package_contents(package_path: Path) -> None:
    expected_paths = (
        "usr/bin/apb-test",
        ("usr/share/man/man1/apb-test.1", "usr/share/man/man1/apb-test.1.gz"),
    )
    with tarfile.open(package_path, "r:*") as archive:
        members = archive.getnames()

    for expected in expected_paths:
        if isinstance(expected, tuple):
            assert any(member.endswith(path) for member in members for path in expected), (
                f"Expected one of {expected!r} in {package_path.name}, got members: {members[:20]}"
            )
        else:
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
    assert success, _format_build_failure(
        build_id,
        arch_output_dir=arch_output_dir,
        server_log=apb_integration.server_log,
        farm_log=apb_integration.farm_log,
    )

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
