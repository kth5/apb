"""Tests for shared endpoint paths and streaming downloads."""

import asyncio
from pathlib import Path

import httpx
import pytest

from apb.upstream import (
    build_download_path,
    download,
    download_async,
    pkgname_latest_path,
    upstream_url,
)


def _transport(status_code: int = 200, content: bytes = b"payload") -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: httpx.Response(status_code, content=content))


def test_upstream_url_keeps_base_path_prefix() -> None:
    assert upstream_url("http://farm/apb/", build_download_path("id", "build.log")) == (
        "http://farm/apb/build/id/download/build.log"
    )


def test_pkgname_latest_path_with_and_without_arch() -> None:
    assert pkgname_latest_path("foo") == "/builds/pkgname/foo/latest"
    assert pkgname_latest_path("foo", "aarch64") == "/builds/pkgname/foo/arch/aarch64/latest"


def test_download_returns_bytes_without_dest() -> None:
    with httpx.Client(transport=_transport()) as client:
        assert download(client, "http://server/file") == b"payload"


def test_download_writes_dest_atomically(tmp_path: Path) -> None:
    dest = tmp_path / "out" / "foo.pkg.tar.zst"
    with httpx.Client(transport=_transport()) as client:
        assert download(client, "http://server/file", dest) == dest

    assert dest.read_bytes() == b"payload"
    assert not dest.with_name(f"{dest.name}.part").exists()


def test_download_error_leaves_no_file(tmp_path: Path) -> None:
    dest = tmp_path / "foo.pkg.tar.zst"
    with httpx.Client(transport=_transport(status_code=404)) as client:
        with pytest.raises(httpx.HTTPStatusError):
            download(client, "http://server/file", dest)

    assert list(tmp_path.iterdir()) == []


def test_download_async_returns_bytes() -> None:
    async def run() -> bytes:
        async with httpx.AsyncClient(transport=_transport()) as client:
            return await download_async(client, "http://server/file")

    assert asyncio.run(run()) == b"payload"
