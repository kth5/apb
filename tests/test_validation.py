"""Tests for shared input validation."""

import pytest

from apb.constants import BUILD_TIMEOUT_DEFAULT, BUILD_TIMEOUT_MAX, BUILD_TIMEOUT_MIN
from apb.validation import validate_build_timeout


def test_validate_build_timeout_defaults_when_unset() -> None:
    assert validate_build_timeout(None) == BUILD_TIMEOUT_DEFAULT
    assert validate_build_timeout(None, default=1234) == 1234


@pytest.mark.parametrize("value", [BUILD_TIMEOUT_MIN, BUILD_TIMEOUT_DEFAULT, BUILD_TIMEOUT_MAX])
def test_validate_build_timeout_accepts_bounds(value: int) -> None:
    assert validate_build_timeout(value) == value


@pytest.mark.parametrize("value", [0, BUILD_TIMEOUT_MIN - 1, BUILD_TIMEOUT_MAX + 1])
def test_validate_build_timeout_rejects_out_of_range(value: int) -> None:
    with pytest.raises(ValueError, match="Build timeout must be between"):
        validate_build_timeout(value)
