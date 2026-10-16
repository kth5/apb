"""Unified PKGBUILD parsing."""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set

logger = logging.getLogger(__name__)

# Pacman Server URL placeholders; leave intact in apb_extra_repos so they match
# admin-configured URLs and expand at pacman runtime.
_PACMAN_URL_VARS = frozenset({"arch", "repo"})


@dataclass
class PkgbuildInfo:
    pkgname: str = "unknown"
    pkgver: str = "1.0.0"
    pkgrel: str = "1"
    epoch: Optional[str] = None
    arch: List[str] = field(default_factory=lambda: ["x86_64"])
    pkgname_list: List[str] = field(default_factory=list)
    extra_repos: List[str] = field(default_factory=list)
    apb_output_timeout: Optional[int] = None


_VAR_REF_PATTERN = re.compile(r"\$\{([^}]+)\}|\$(\w+)")


def _strip_value(value: str) -> str:
    return value.strip().strip("'\"")


def _substitute_variables(
    text: str,
    variables: dict[str, str],
    *,
    preserve: Optional[Set[str]] = None,
) -> str:
    preserve_names = preserve or set()

    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        if name in preserve_names:
            return match.group(0)
        return variables.get(name, "")

    return _VAR_REF_PATTERN.sub(replace, text)


def _resolve_value(
    value: str,
    variables: dict[str, str],
    *,
    preserve: Optional[Set[str]] = None,
) -> str:
    """Resolve a scalar PKGBUILD assignment value with bash-like variable expansion."""
    value = value.strip()
    if not value:
        return ""

    if value[0] == "'" and value.endswith("'") and len(value) >= 2:
        return value[1:-1]

    if value[0] == '"' and value.endswith('"') and len(value) >= 2:
        return _substitute_variables(value[1:-1], variables, preserve=preserve)

    return _substitute_variables(_strip_value(value), variables, preserve=preserve)


def _parens_balanced(text: str) -> bool:
    """Return True when parentheses are balanced outside of quoted strings."""
    depth = 0
    in_single = False
    in_double = False
    i = 0
    while i < len(text):
        char = text[i]
        if in_single:
            if char == "'":
                in_single = False
        elif in_double:
            if char == "\\" and i + 1 < len(text):
                i += 2
                continue
            if char == '"':
                in_double = False
        elif char == "'":
            in_single = True
        elif char == '"':
            in_double = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                return True
        i += 1
    return depth <= 0


def _read_assignment_value(lines: List[str], start_idx: int, initial_value: str) -> tuple[str, int]:
    """Collect a full assignment value, joining multi-line arrays until ')'."""
    value = initial_value.strip()
    idx = start_idx
    if not value.startswith("(") or _parens_balanced(value):
        return value, idx

    parts = [value]
    idx += 1
    while idx < len(lines):
        parts.append(lines[idx].strip())
        joined = " ".join(parts)
        if _parens_balanced(joined):
            return joined, idx
        idx += 1
    return " ".join(parts), idx


def _parse_array(
    value: str,
    variables: Optional[dict[str, str]] = None,
    *,
    preserve: Optional[Set[str]] = None,
) -> List[str]:
    value = value.strip()
    if value.startswith("(") and value.endswith(")"):
        value = value[1:-1].strip()
    elif value.startswith("(") and not _parens_balanced(value):
        # Incomplete array (e.g. lone "("); treat as empty rather than ['(']
        return []
    if not value:
        return []

    if variables is None:
        return [_strip_value(item) for item in re.split(r"\s+", value) if item.strip("'\"")]

    return [
        _resolve_value(item, variables, preserve=preserve)
        for item in re.split(r"\s+", value)
        if item.strip("'\"")
    ]


def _extract_assignment(line: str) -> Optional[tuple[str, str]]:
    if "=" not in line or line.strip().startswith("#"):
        return None
    key, value = line.split("=", 1)
    return key.strip(), value.strip()


_TOP_LEVEL_ARCH_PATTERN = re.compile(r"^arch=")


def parse_pkgbuild(content: str) -> PkgbuildInfo:
    """Parse PKGBUILD content into structured package information."""
    info = PkgbuildInfo()
    pkgbase: Optional[str] = None
    variables: dict[str, str] = {}
    lines = content.splitlines()
    line_idx = 0
    arch_assigned = False

    while line_idx < len(lines):
        raw_line = lines[line_idx]
        line = raw_line.strip()
        assignment = _extract_assignment(line)
        if not assignment:
            line_idx += 1
            continue
        key, value = assignment
        value, line_idx = _read_assignment_value(lines, line_idx, value)

        if key == "pkgbase":
            pkgbase = _resolve_value(value, variables)
            variables[key] = pkgbase
        elif key == "pkgname":
            if value.startswith("("):
                names = _parse_array(value, variables)
                info.pkgname_list = names
                if names:
                    info.pkgname = names[0]
                    variables[key] = names[0]
            else:
                name = _resolve_value(value, variables)
                info.pkgname = name
                info.pkgname_list = [name]
                variables[key] = name
        elif key == "pkgver":
            info.pkgver = _resolve_value(value, variables)
            variables[key] = info.pkgver
        elif key == "pkgrel":
            info.pkgrel = _resolve_value(value, variables)
            variables[key] = info.pkgrel
        elif key == "epoch":
            info.epoch = _resolve_value(value, variables)
            variables[key] = info.epoch
        elif key == "arch":
            if _TOP_LEVEL_ARCH_PATTERN.match(raw_line) and not arch_assigned:
                info.arch = _parse_array(value, variables) or info.arch
                if info.arch:
                    variables[key] = info.arch[0]
                arch_assigned = True
        elif key == "apb_extra_repos":
            info.extra_repos = _parse_array(
                value,
                variables,
                preserve=set(_PACMAN_URL_VARS),
            )
        elif key == "apb_output_timeout":
            timeout_str = _resolve_value(value.split("#", 1)[0], variables)
            try:
                timeout_value = int(timeout_str)
                if timeout_value < 60:
                    logger.warning("apb_output_timeout %s too low, ignoring", timeout_value)
                elif timeout_value > 86400:
                    logger.warning("apb_output_timeout %s too high, ignoring", timeout_value)
                else:
                    info.apb_output_timeout = timeout_value
            except ValueError:
                logger.warning("Invalid apb_output_timeout value '%s', ignoring", timeout_str)
        elif not value.startswith("("):
            variables[key] = _resolve_value(value, variables)

        line_idx += 1

    if pkgbase:
        info.pkgname = pkgbase
        if not info.pkgname_list:
            info.pkgname_list = [pkgbase]

    if not info.pkgname_list and info.pkgname != "unknown":
        info.pkgname_list = [info.pkgname]

    return info


def parse_pkgbuild_file(pkgbuild_path: Path) -> PkgbuildInfo:
    """Parse a PKGBUILD file from disk."""
    try:
        content = pkgbuild_path.read_text(encoding="utf-8")
        return parse_pkgbuild(content)
    except OSError as exc:
        logger.error("Error parsing PKGBUILD %s: %s", pkgbuild_path, exc)
        return PkgbuildInfo()


def pkgbuild_info_to_dict(info: PkgbuildInfo) -> dict:
    """Convert PkgbuildInfo to a plain dict for legacy call sites."""
    return {
        "pkgname": info.pkgname,
        "pkgver": info.pkgver,
        "pkgrel": info.pkgrel,
        "epoch": info.epoch,
        "arch": info.arch,
        "pkgname_list": info.pkgname_list,
        "extra_repos": info.extra_repos,
        "apb_output_timeout": info.apb_output_timeout,
    }
