"""Farm scheduling tests for PKGBUILD apb_arch_hint."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from apb.farm import core

pytestmark = pytest.mark.anyio


def _server_info(*, load: int = 0) -> dict:
    return {
        "queue_status": {
            "current_builds_count": load,
            "queued_builds": 0,
            "max_concurrent_builds": 3,
        }
    }


async def test_queue_any_package_uses_apb_arch_hint(farm_queue_state) -> None:
    pkgbuild = """pkgname=test
pkgver=1
pkgrel=1
arch=(any)
apb_arch_hint=powerpc
"""
    available = {
        "x86_64": ["http://x86-server"],
        "powerpc": ["http://powerpc-server"],
    }

    async def fake_server_info(url: str):
        if "x86" in url:
            return _server_info(load=0)
        return _server_info(load=5)

    with patch.object(core, "get_available_architectures", AsyncMock(return_value=available)), \
         patch.object(core, "get_server_info", AsyncMock(side_effect=fake_server_info)):
        queued = await core.queue_builds_for_architectures(pkgbuild, "test", ["any"])

    assert len(queued) == 1
    assert queued[0]["arch"] == "powerpc"


async def test_queue_any_package_hint_without_servers_queues_nothing(farm_queue_state) -> None:
    pkgbuild = """pkgname=test
pkgver=1
pkgrel=1
arch=(any)
apb_arch_hint=powerpc
"""
    with patch.object(
        core,
        "get_available_architectures",
        AsyncMock(return_value={"x86_64": ["http://x86-server"]}),
    ):
        queued = await core.queue_builds_for_architectures(pkgbuild, "test", ["any"])

    assert queued == []


async def test_queue_multi_arch_ignores_apb_arch_hint(farm_queue_state) -> None:
    pkgbuild = """pkgname=test
pkgver=1
pkgrel=1
arch=(x86_64 powerpc)
apb_arch_hint=powerpc
"""
    available = {
        "x86_64": ["http://x86-server"],
        "powerpc": ["http://powerpc-server"],
    }

    with patch.object(core, "get_available_architectures", AsyncMock(return_value=available)), \
         patch.object(core, "get_server_info", AsyncMock(return_value=_server_info())):
        queued = await core.queue_builds_for_architectures(
            pkgbuild, "test", ["x86_64", "powerpc"]
        )

    assert len(queued) == 2
    assert {build["arch"] for build in queued} == {"x86_64", "powerpc"}
