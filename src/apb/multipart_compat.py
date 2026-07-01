"""Compatibility layer for defnull multipart>=1.3 with FastAPI/Starlette."""

from __future__ import annotations

import importlib.metadata as metadata
from collections.abc import AsyncGenerator
from tempfile import SpooledTemporaryFile
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl

if TYPE_CHECKING:
    from starlette.datastructures import FormData, Headers

MIN_MULTIPART_VERSION = (1, 3)
_installed = False


def _parse_release_version(raw_version: str) -> tuple[int, ...] | None:
    parts: list[int] = []
    for segment in raw_version.split("."):
        digits = ""
        for char in segment:
            if char.isdigit():
                digits += char
            elif digits:
                break
            else:
                break
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts) if parts else None


def defnull_multipart_version() -> tuple[int, ...] | None:
    try:
        return _parse_release_version(metadata.version("multipart"))
    except metadata.PackageNotFoundError:
        pass

    try:
        import multipart

        raw_version = getattr(multipart, "__version__", None)
        if isinstance(raw_version, str):
            return _parse_release_version(raw_version)
    except ImportError:
        pass

    return None


def has_kludex_multipart() -> bool:
    try:
        import python_multipart
        from python_multipart.multipart import parse_options_header

        return bool(parse_options_header)
    except (ImportError, AssertionError):
        pass

    try:
        import multipart

        if hasattr(multipart, "PushMultipartParser"):
            return False
        from multipart.multipart import parse_options_header

        return bool(parse_options_header)
    except (ImportError, AssertionError):
        return False


def has_defnull_multipart() -> bool:
    if has_kludex_multipart():
        return False

    version = defnull_multipart_version()
    if version is None or version < MIN_MULTIPART_VERSION:
        return False

    try:
        import multipart

        return bool(getattr(multipart, "PushMultipartParser", None))
    except ImportError:
        return False


def form_upload_runtime_ready() -> bool:
    if has_kludex_multipart():
        return True
    if not has_defnull_multipart():
        return False

    install_multipart_compat()
    try:
        from fastapi.dependencies.utils import ensure_multipart_is_installed

        ensure_multipart_is_installed()
    except RuntimeError:
        return False

    import starlette.formparsers as formparsers

    return formparsers.multipart is not None and formparsers.parse_options_header is not None


def install_multipart_compat() -> None:
    global _installed
    if _installed or has_kludex_multipart() or not has_defnull_multipart():
        _installed = True
        return

    _patch_fastapi_multipart_check()
    _patch_starlette_formparsers()
    _installed = True


def _patch_fastapi_multipart_check() -> None:
    import fastapi.dependencies.utils as utils

    original = utils.ensure_multipart_is_installed

    def ensure_multipart_is_installed() -> None:
        if has_kludex_multipart() or has_defnull_multipart():
            return
        original()

    utils.ensure_multipart_is_installed = ensure_multipart_is_installed


def _load_defnull_multipart():
    import multipart as defnull_multipart

    if not hasattr(defnull_multipart, "PushMultipartParser"):
        raise RuntimeError("defnull multipart>=1.3 is not installed")
    return defnull_multipart


def _starlette_parse_options_header(
    header: str | bytes | None,
    options: dict | None = None,
    unquote=None,
) -> tuple[bytes, dict[bytes, bytes]]:
    """Adapt defnull header parsing to the bytes API Starlette expects."""
    defnull_multipart = _load_defnull_multipart()
    if header is None:
        return b"", {}
    if isinstance(header, bytes):
        header = header.decode("latin-1")

    primary, params = defnull_multipart.parse_options_header(header, options, unquote)
    primary_bytes = primary.encode("latin-1") if isinstance(primary, str) else primary
    byte_params: dict[bytes, bytes] = {}
    for key, value in params.items():
        key_bytes = key.encode("latin-1") if isinstance(key, str) else key
        if isinstance(value, str):
            byte_params[key_bytes] = value.encode("latin-1")
        else:
            byte_params[key_bytes] = value
    return primary_bytes, byte_params


def _patch_starlette_formparsers() -> None:
    defnull_multipart = _load_defnull_multipart()
    import starlette.formparsers as formparsers
    from starlette.datastructures import FormData, Headers, UploadFile

    MultiPartException = formparsers.MultiPartException

    class FormParser:
        def __init__(
            self,
            headers: Headers,
            stream: AsyncGenerator[bytes, None],
            *,
            max_fields: int | float = 1000,
            max_part_size: int = 1024 * 1024,
        ) -> None:
            self.headers = headers
            self.stream = stream
            self.max_fields = max_fields
            self.max_part_size = max_part_size

        async def parse(self) -> FormData:
            body = bytearray()
            async for chunk in self.stream:
                if not chunk:
                    continue
                body.extend(chunk)
                if len(body) > self.max_part_size * self.max_fields:
                    raise MultiPartException(
                        f"Too many fields. Maximum number of fields is {self.max_fields}."
                    )

            content_type = self.headers.get("Content-Type", "")
            _, params = defnull_multipart.parse_options_header(content_type)
            charset = params.get("charset", "utf-8")
            items = [
                (name, value)
                for name, value in parse_qsl(body.decode(charset), keep_blank_values=True)
            ]
            if len(items) > self.max_fields:
                raise MultiPartException(
                    f"Too many fields. Maximum number of fields is {self.max_fields}."
                )
            return FormData(items)

    class MultiPartParser:
        spool_max_size = 1024 * 1024
        max_part_size = 1024 * 1024

        def __init__(
            self,
            headers: Headers,
            stream: AsyncGenerator[bytes, None],
            *,
            max_files: int | float = 1000,
            max_fields: int | float = 1000,
            max_part_size: int = 1024 * 1024,
        ) -> None:
            self.headers = headers
            self.stream = stream
            self.max_files = max_files
            self.max_fields = max_fields
            self.max_part_size = max_part_size
            self._files_to_close_on_error: list[SpooledTemporaryFile[bytes]] = []

        async def parse(self) -> FormData:
            content_type = self.headers.get("Content-Type", "")
            _, params = defnull_multipart.parse_options_header(content_type)
            boundary = params.get("boundary")
            if not boundary:
                raise MultiPartException("Missing boundary in multipart.")

            charset = params.get("charset", "utf-8")
            parser = defnull_multipart.PushMultipartParser(boundary=boundary)
            items: list[tuple[str, str | UploadFile]] = []
            current_segment = None
            current_file: SpooledTemporaryFile[bytes] | None = None
            current_data = bytearray()
            file_count = 0
            field_count = 0
            chunk_iter = self.stream.__aiter__()

            async def read(chunk_size: int) -> bytes:
                try:
                    chunk = await chunk_iter.__anext__()
                except StopAsyncIteration:
                    return b""
                return chunk or b""

            def finalize_segment() -> None:
                nonlocal current_segment, current_file, current_data, file_count, field_count
                if current_segment is None:
                    return

                name = current_segment.name or ""
                if current_segment.filename:
                    assert current_file is not None
                    current_file.seek(0)
                    items.append(
                        (
                            name,
                            UploadFile(
                                file=current_file,
                                size=current_segment.size,
                                filename=current_segment.filename,
                                headers=Headers(
                                    raw=[
                                        (key.lower().encode("latin-1"), value.encode("latin-1"))
                                        for key, value in current_segment.headerlist
                                    ]
                                ),
                            ),
                        )
                    )
                else:
                    if len(current_data) > self.max_part_size:
                        raise MultiPartException(
                            f"Part exceeded maximum size of {int(self.max_part_size / 1024)}KB."
                        )
                    items.append((name, current_data.decode(charset)))

                current_segment = None
                current_file = None
                current_data = bytearray()

            try:
                async for event in parser.parse_async(read):
                    if isinstance(event, defnull_multipart.MultipartSegment):
                        finalize_segment()
                        if event.filename:
                            file_count += 1
                            if file_count > self.max_files:
                                raise MultiPartException(
                                    f"Too many files. Maximum number of files is {self.max_files}."
                                )
                            current_file = SpooledTemporaryFile(max_size=self.spool_max_size)
                            self._files_to_close_on_error.append(current_file)
                        else:
                            field_count += 1
                            if field_count > self.max_fields:
                                raise MultiPartException(
                                    f"Too many fields. Maximum number of fields is {self.max_fields}."
                                )
                        current_segment = event
                    elif event is None:
                        finalize_segment()
                    elif isinstance(event, (bytes, bytearray)):
                        if current_segment is None:
                            continue
                        if current_file is not None:
                            current_file.write(event)
                        else:
                            current_data.extend(event)
            except defnull_multipart.MultipartError as exc:
                for file in self._files_to_close_on_error:
                    file.close()
                raise MultiPartException(str(exc)) from exc
            except OSError as exc:
                for file in self._files_to_close_on_error:
                    file.close()
                raise exc

            finalize_segment()
            return FormData(items)

    formparsers.multipart = defnull_multipart
    formparsers.parse_options_header = _starlette_parse_options_header
    formparsers.FormParser = FormParser
    formparsers.MultiPartParser = MultiPartParser

    import starlette.requests as requests_module

    requests_module.parse_options_header = _starlette_parse_options_header
    requests_module.FormParser = FormParser
    requests_module.MultiPartParser = MultiPartParser
