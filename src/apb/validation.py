"""Shared input validation."""

from enum import Enum
from typing import Dict, List, Optional, Tuple

from apb.constants import BUILD_TIMEOUT_DEFAULT, BUILD_TIMEOUT_MAX, BUILD_TIMEOUT_MIN


class RepoLevel(str, Enum):
    """ArchPOWER repository level a build runs against; each level includes the ones below it."""

    BASE = "base"
    TESTING = "testing"
    STAGE = "stage"


# Sections each level adds on top of the one below it, highest pacman priority first
REPO_LEVEL_SECTIONS: Dict[RepoLevel, Tuple[str, ...]] = {
    RepoLevel.TESTING: ("testing-any", "testing"),
    RepoLevel.STAGE: ("stage-any", "stage"),
}

REPO_LEVEL_ORDER: Tuple[RepoLevel, ...] = (RepoLevel.BASE, RepoLevel.TESTING, RepoLevel.STAGE)


def validate_build_timeout(value: Optional[int], default: int = BUILD_TIMEOUT_DEFAULT) -> int:
    """Return a build timeout in seconds, or ``default`` when ``value`` is None.

    Raises ValueError when ``value`` is outside BUILD_TIMEOUT_MIN..BUILD_TIMEOUT_MAX.
    """
    if value is None:
        return default
    if not BUILD_TIMEOUT_MIN <= value <= BUILD_TIMEOUT_MAX:
        raise ValueError(f"Build timeout must be between {BUILD_TIMEOUT_MIN} and {BUILD_TIMEOUT_MAX} seconds")
    return value


def validate_repo_level(value: Optional[str]) -> RepoLevel:
    """Return the RepoLevel for a form value; None or empty means BASE.

    Raises ValueError for unknown levels.
    """
    if not value:
        return RepoLevel.BASE
    try:
        return RepoLevel(value.strip().lower())
    except ValueError:
        allowed = ", ".join(level.value for level in RepoLevel)
        raise ValueError(f"Invalid repository level '{value}' (allowed: {allowed})") from None


def sections_for_level(level: RepoLevel) -> List[str]:
    """pacman sections to enable for ``level``, cumulative and highest priority first."""
    included = REPO_LEVEL_ORDER[1:REPO_LEVEL_ORDER.index(level) + 1]
    return [section for included_level in reversed(included) for section in REPO_LEVEL_SECTIONS[included_level]]
