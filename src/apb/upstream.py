"""APB endpoint paths and streaming downloads shared by client and farm."""

import io
import os
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterator, Optional, Union

import httpx

BUILD_SUBMIT_PATH = "/build"
BUILDS_LATEST_PATH = "/builds/latest"
ADMIN_CLEANUP_PATH = "/admin/cleanup"
DOWNLOAD_CHUNK_SIZE = 64 * 1024


def upstream_url(base_url: str, path: str) -> str:
    """Join a base URL (which may carry a path prefix) with an absolute endpoint path."""
    return f"{base_url.rstrip('/')}{path}"


def build_status_page_path(build_id: str) -> str:
    return f"/build/{build_id}/status"


def build_status_path(build_id: str) -> str:
    return f"/build/{build_id}/status-api"


def build_output_path(build_id: str) -> str:
    return f"/build/{build_id}/output"


def build_stream_path(build_id: str) -> str:
    return f"/build/{build_id}/stream"


def build_cancel_path(build_id: str) -> str:
    return f"/build/{build_id}/cancel"


def build_download_path(build_id: str, filename: str) -> str:
    return f"/build/{build_id}/download/{filename}"


def pkgname_builds_path(pkgname: str) -> str:
    return f"/builds/pkgname/{pkgname}"


def pkgname_latest_path(pkgname: str, arch: Optional[str] = None) -> str:
    if arch:
        return f"/builds/pkgname/{pkgname}/arch/{arch}/latest"
    return f"/builds/pkgname/{pkgname}/latest"


def pkgname_latest_by_arch_path(pkgname: str) -> str:
    return f"/builds/pkgname/{pkgname}/latest-by-arch"


@contextmanager
def _download_sink(dest: Optional[Path]) -> Iterator[BinaryIO]:
    """Yield a writable sink; a file target is written to ``*.part`` and renamed on success."""
    if dest is None:
        yield io.BytesIO()
        return

    dest.parent.mkdir(parents=True, exist_ok=True)
    part_path = dest.with_name(f"{dest.name}.part")
    try:
        with open(part_path, "wb") as handle:
            yield handle
        os.replace(part_path, dest)
    finally:
        part_path.unlink(missing_ok=True)


def _download_result(sink: BinaryIO, dest: Optional[Path]) -> Union[bytes, Path]:
    return dest if dest is not None else sink.getvalue()


def download(
    client: httpx.Client,
    url: str,
    dest: Optional[Path] = None,
    **request_kwargs,
) -> Union[bytes, Path]:
    """Stream ``url`` into ``dest`` (returns the path) or into memory (returns bytes).

    Raises httpx.HTTPError on transport errors and non-2xx responses.
    """
    with client.stream("GET", url, **request_kwargs) as response:
        response.raise_for_status()
        with _download_sink(dest) as sink:
            for chunk in response.iter_bytes(chunk_size=DOWNLOAD_CHUNK_SIZE):
                sink.write(chunk)
            return _download_result(sink, dest)


async def download_async(
    client: httpx.AsyncClient,
    url: str,
    dest: Optional[Path] = None,
    **request_kwargs,
) -> Union[bytes, Path]:
    """Async variant of :func:`download`."""
    async with client.stream("GET", url, **request_kwargs) as response:
        response.raise_for_status()
        with _download_sink(dest) as sink:
            async for chunk in response.aiter_bytes(chunk_size=DOWNLOAD_CHUNK_SIZE):
                sink.write(chunk)
            return _download_result(sink, dest)
