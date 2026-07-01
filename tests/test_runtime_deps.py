"""Tests for runtime dependency detection helpers."""

from __future__ import annotations

import sys

from tests.conftest import (
    _parse_release_version,
    has_form_upload_support,
    runtime_dependency_skip_reason,
)


def test_parse_release_version() -> None:
    assert _parse_release_version("1.3.1") == (1, 3, 1)
    assert _parse_release_version("1.2.2") == (1, 2, 2)
    assert _parse_release_version("invalid") is None


def test_has_form_upload_support_requires_multipart_1_3(monkeypatch) -> None:
    monkeypatch.setattr("tests.conftest._multipart_release_version", lambda: (1, 3, 1))
    monkeypatch.setitem(sys.modules, "multipart", type("multipart", (), {"MultipartParser": object()})())
    assert has_form_upload_support() is True

    monkeypatch.setattr("tests.conftest._multipart_release_version", lambda: (1, 2, 2))
    assert has_form_upload_support() is False


def test_runtime_dependency_skip_reason_none_when_multipart_available(monkeypatch) -> None:
    monkeypatch.setattr("tests.conftest.has_form_upload_support", lambda: True)
    assert runtime_dependency_skip_reason() is None


def test_runtime_dependency_skip_reason_for_missing_multipart(monkeypatch) -> None:
    monkeypatch.setattr("tests.conftest.has_form_upload_support", lambda: False)
    monkeypatch.setattr("tests.conftest._multipart_release_version", lambda: None)
    monkeypatch.setattr("tests.conftest._multipart_module_path", lambda _name: None)

    reason = runtime_dependency_skip_reason()
    assert reason is not None
    assert "multipart>=1.3" in reason
    assert "multipart: not found" in reason


def test_runtime_dependency_skip_reason_for_old_multipart(monkeypatch) -> None:
    monkeypatch.setattr("tests.conftest.has_form_upload_support", lambda: False)
    monkeypatch.setattr("tests.conftest._multipart_release_version", lambda: (1, 2, 2))
    monkeypatch.setattr(
        "tests.conftest._multipart_module_path",
        lambda _name: "/usr/lib/python3.14/site-packages/multipart.py",
    )

    reason = runtime_dependency_skip_reason()
    assert reason is not None
    assert "older than 1.3" in reason
