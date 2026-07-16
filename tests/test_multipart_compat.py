"""Tests for defnull multipart compatibility with FastAPI/Starlette."""

from __future__ import annotations

import asyncio
import types

import httpx
import pytest
from starlette.datastructures import Headers

from apb import multipart_compat


def test_form_upload_runtime_ready_with_kludex(monkeypatch) -> None:
    monkeypatch.setattr(multipart_compat, "has_kludex_multipart", lambda: True)
    monkeypatch.setattr(multipart_compat, "has_defnull_multipart", lambda: False)
    assert multipart_compat.form_upload_runtime_ready() is True


def test_starlette_parse_options_header_returns_bytes() -> None:
    fake_multipart = types.ModuleType("multipart")
    fake_multipart.__version__ = "1.3.1"
    fake_multipart.parse_options_header = lambda header, options=None, unquote=None: (
        "multipart/form-data",
        {"boundary": "abc", "charset": "utf-8"},
    )
    fake_multipart.PushMultipartParser = object

    import apb.multipart_compat as compat

    original_loader = compat._load_defnull_multipart
    compat._load_defnull_multipart = lambda: fake_multipart
    try:
        primary, params = compat._starlette_parse_options_header(
            "multipart/form-data; boundary=abc; charset=utf-8"
        )
    finally:
        compat._load_defnull_multipart = original_loader

    assert primary == b"multipart/form-data"
    assert params[b"boundary"] == b"abc"
    assert params[b"charset"] == b"utf-8"


def test_install_multipart_compat_patches_fastapi_for_defnull(monkeypatch) -> None:
    fake_multipart = types.ModuleType("multipart")
    fake_multipart.__version__ = "1.3.1"
    fake_multipart.parse_options_header = lambda header, options=None, unquote=None: (
        "multipart/form-data",
        {"boundary": "test"},
    )
    fake_multipart.PushMultipartParser = object
    fake_multipart.MultipartSegment = object
    fake_multipart.MultipartError = Exception

    monkeypatch.setattr(multipart_compat, "_installed", False)
    monkeypatch.setattr(multipart_compat, "has_kludex_multipart", lambda: False)
    monkeypatch.setattr(multipart_compat, "has_defnull_multipart", lambda: True)
    monkeypatch.setattr(multipart_compat, "_load_defnull_multipart", lambda: fake_multipart)

    multipart_compat.install_multipart_compat()

    from fastapi.dependencies.utils import ensure_multipart_is_installed

    ensure_multipart_is_installed()

    import starlette.formparsers as formparsers
    import starlette.requests as requests_module

    assert formparsers.parse_options_header is multipart_compat._starlette_parse_options_header
    assert requests_module.parse_options_header is multipart_compat._starlette_parse_options_header
    assert formparsers.FormParser is not None
    assert formparsers.MultiPartParser is not None


def test_multipart_parser_skips_empty_stream_chunks() -> None:
    try:
        import multipart as defnull_multipart

        if not hasattr(defnull_multipart, "PushMultipartParser"):
            pytest.skip("defnull multipart not installed")
    except ImportError:
        pytest.skip("defnull multipart not installed")

    if multipart_compat.has_kludex_multipart():
        pytest.skip("test requires defnull multipart compatibility layer")

    multipart_compat._installed = False
    multipart_compat.install_multipart_compat()

    from starlette.formparsers import MultiPartParser

    req = httpx.Request(
        "POST",
        "http://test/build",
        files=[("build_tarball", ("build.tar.gz", b"payload", "application/gzip"))],
        data={"architectures": "any"},
    )
    body = req.read()
    chunks = [body[i : i + 13] for i in range(0, len(body), 13)]
    chunks_with_empty: list[bytes] = []
    for chunk in chunks:
        chunks_with_empty.extend([b"", chunk, b""])
    headers = Headers({"content-type": req.headers["content-type"]})

    async def stream():
        for chunk in chunks_with_empty:
            yield chunk

    async def parse_form():
        parser = MultiPartParser(headers, stream())
        return await parser.parse()

    form = asyncio.run(parse_form())
    upload = form.get("build_tarball")
    assert upload is not None
    assert upload.filename == "build.tar.gz"
    assert form.get("architectures") == "any"
    payload = asyncio.run(upload.read())
    assert payload == b"payload"


def test_install_multipart_compat_skips_when_kludex_present(monkeypatch) -> None:
    monkeypatch.setattr(multipart_compat, "_installed", False)
    monkeypatch.setattr(multipart_compat, "has_kludex_multipart", lambda: True)

    import fastapi.dependencies.utils as utils

    original = utils.ensure_multipart_is_installed
    multipart_compat.install_multipart_compat()
    assert utils.ensure_multipart_is_installed is original
