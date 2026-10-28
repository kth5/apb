"""Client helpers and routing for PKGBUILD apb_arch_hint."""

from pathlib import Path
from unittest.mock import patch

import pytest

from apb.client.helpers import effective_any_server_arch, print_apb_arch_hint_notice
from apb.models import BuildSubmitResponse


def test_effective_any_server_arch_uses_hint(capsys) -> None:
    pkg_info = {"arch": ["any"], "apb_arch_hint": "powerpc"}
    servers = {"x86_64": ["http://x86"], "powerpc": ["http://ppc"]}

    server_arch, error = effective_any_server_arch(pkg_info, servers)

    assert error is None
    assert server_arch == "powerpc"


def test_effective_any_server_arch_hint_missing_servers() -> None:
    pkg_info = {"arch": ["any"], "apb_arch_hint": "powerpc"}
    servers = {"x86_64": ["http://x86"]}

    server_arch, error = effective_any_server_arch(pkg_info, servers)

    assert server_arch is None
    assert "apb_arch_hint" in error


def test_effective_any_server_arch_ignores_hint_for_multi_arch() -> None:
    pkg_info = {"arch": ["x86_64", "powerpc"], "apb_arch_hint": "powerpc"}
    servers = {"x86_64": ["http://x86"], "powerpc": ["http://ppc"]}

    server_arch, error = effective_any_server_arch(pkg_info, servers)

    assert error is None
    assert server_arch == "x86_64"


def test_print_apb_arch_hint_notice_any_only(capsys) -> None:
    print_apb_arch_hint_notice({"arch": ["any"], "apb_arch_hint": "powerpc"})
    assert "Using PKGBUILD apb_arch_hint: powerpc" in capsys.readouterr().out


def test_print_apb_arch_hint_notice_ignored_for_multi_arch(capsys) -> None:
    print_apb_arch_hint_notice({"arch": ["x86_64", "powerpc"], "apb_arch_hint": "powerpc"})
    out = capsys.readouterr().out
    assert "ignored" in out
    assert "arch=(any)" in out


def test_build_for_multiple_arches_any_uses_hint_server(tmp_path: Path, capsys) -> None:
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "PKGBUILD").write_text(
        "pkgname=test\npkgver=1\npkgrel=1\narch=(any)\napb_arch_hint=powerpc\n",
        encoding="utf-8",
    )

    submitted_urls: list[str] = []

    def fake_submit(server_url, *_args, **_kwargs):
        submitted_urls.append(server_url)
        return BuildSubmitResponse(build_id="build-id", status="queued")

    config = {"servers": {"x86_64": ["http://x86"], "powerpc": ["http://ppc"]}}

    with patch("apb.client.cli.submit_build", side_effect=fake_submit):
        from apb.client.cli import build_for_multiple_arches

        success = build_for_multiple_arches(
            pkg_dir, tmp_path / "output", config, detach=True, force=True
        )

    assert success is True
    assert submitted_urls == ["http://ppc"]
