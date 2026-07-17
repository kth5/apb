"""Unified PKGBUILD parsing."""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


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


def _substitute_variables(text: str, variables: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        return variables.get(name, "")

    return _VAR_REF_PATTERN.sub(replace, text)


def _resolve_value(value: str, variables: dict[str, str]) -> str:
    """Resolve a scalar PKGBUILD assignment value with bash-like variable expansion."""
    value = value.strip()
    if not value:
        return ""

    if value[0] == "'" and value.endswith("'") and len(value) >= 2:
        return value[1:-1]

    if value[0] == '"' and value.endswith('"') and len(value) >= 2:
        return _substitute_variables(value[1:-1], variables)

    return _substitute_variables(_strip_value(value), variables)


def _parse_array(value: str, variables: Optional[dict[str, str]] = None) -> List[str]:
    value = value.strip()
    if value.startswith("(") and value.endswith(")"):
        value = value[1:-1].strip()
    if not value:
        return []

    if variables is None:
        return [_strip_value(item) for item in re.split(r"\s+", value) if item.strip("'\"")]

    return [
        _resolve_value(item, variables)
        for item in re.split(r"\s+", value)
        if item.strip("'\"")
    ]


def _extract_assignment(line: str) -> Optional[tuple[str, str]]:
    if "=" not in line or line.strip().startswith("#"):
        return None
    key, value = line.split("=", 1)
    return key.strip(), value.strip()


def parse_pkgbuild(content: str) -> PkgbuildInfo:
    """Parse PKGBUILD content into structured package information."""
    info = PkgbuildInfo()
    pkgbase: Optional[str] = None
    variables: dict[str, str] = {}

    for raw_line in content.splitlines():
        line = raw_line.strip()
        assignment = _extract_assignment(line)
        if not assignment:
            continue
        key, value = assignment

        if key == "pkgbase":
            pkgbase = _resolve_value(value, variables)
            variables[key] = pkgbase
        elif key == "pkgname":
            if value.startswith("("):
                names = _parse_array(value, variables)
                info.pkgname_list = names
                if names:
                    info.pkgname = names[0]
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
            info.arch = _parse_array(value, variables) or info.arch
        elif key == "apb_extra_repos":
            info.extra_repos = _parse_array(value, variables)
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
