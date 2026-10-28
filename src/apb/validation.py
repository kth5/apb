"""Shared input validation."""

from typing import Optional

from apb.constants import BUILD_TIMEOUT_DEFAULT, BUILD_TIMEOUT_MAX, BUILD_TIMEOUT_MIN


def validate_build_timeout(value: Optional[int], default: int = BUILD_TIMEOUT_DEFAULT) -> int:
    """Return a build timeout in seconds, or ``default`` when ``value`` is None.

    Raises ValueError when ``value`` is outside BUILD_TIMEOUT_MIN..BUILD_TIMEOUT_MAX.
    """
    if value is None:
        return default
    if not BUILD_TIMEOUT_MIN <= value <= BUILD_TIMEOUT_MAX:
        raise ValueError(f"Build timeout must be between {BUILD_TIMEOUT_MIN} and {BUILD_TIMEOUT_MAX} seconds")
    return value
