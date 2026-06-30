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


def _strip_value(value: str) -> str:
    return value.strip().strip("'\"")


def _parse_array(value: str) -> List[str]:
    value = value.strip()
    if value.startswith("(") and value.endswith(")"):
        value = value[1:-1].strip()
    if not value:
        return []
    return [_strip_value(item) for item in re.split(r"\s+", value) if item.strip("'\"")]


def _extract_assignment(line: str) -> Optional[tuple[str, str]]:
    if "=" not in line or line.strip().startswith("#"):
        return None
    key, value = line.split("=", 1)
    return key.strip(), value.strip()


def parse_pkgbuild(content: str) -> PkgbuildInfo:
    """Parse PKGBUILD content into structured package information."""
    info = PkgbuildInfo()
    pkgbase: Optional[str] = None

    for raw_line in content.splitlines():
        line = raw_line.strip()
        assignment = _extract_assignment(line)
        if not assignment:
            continue
        key, value = assignment

        if key == "pkgbase":
            pkgbase = _strip_value(value)
        elif key == "pkgname":
            if value.startswith("("):
                names = _parse_array(value)
                info.pkgname_list = names
                if names:
                    info.pkgname = names[0]
            else:
                name = _strip_value(value)
                info.pkgname = name
                info.pkgname_list = [name]
        elif key == "pkgver":
            info.pkgver = _strip_value(value)
        elif key == "pkgrel":
            info.pkgrel = _strip_value(value)
        elif key == "epoch":
            info.epoch = _strip_value(value)
        elif key == "arch":
            info.arch = _parse_array(value) or info.arch
        elif key == "apb_extra_repos":
            info.extra_repos = _parse_array(value)
        elif key == "apb_output_timeout":
            timeout_str = value.split("#", 1)[0].strip().strip("'\"")
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
