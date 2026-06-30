"""Architecture detection and filename suffix mapping."""

import logging
import platform
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

ARCH_SUFFIX_MAP: Dict[str, str] = {
    "espresso": "powerpc",
}

MACHINE_ARCH_MAPPING: Dict[str, str] = {
    "ppc64le": "powerpc64le",
    "ppc64": "powerpc64",
    "ppc": "powerpc",
    "x86_64": "x86_64",
    "aarch64": "aarch64",
    "armv7h": "armv7h",
    "armv6h": "armv6h",
}

POWERPC_ARCHES = frozenset({"powerpc", "espresso"})


def package_arch_suffix(arch: str) -> str:
    return ARCH_SUFFIX_MAP.get(arch, arch)


def resolve_server_architecture(*, architecture_override: Optional[str] = None) -> str:
    """Determine server architecture from override, pacman.conf, or machine."""
    if architecture_override:
        logger.info("Using command-line architecture override: %s", architecture_override)
        return architecture_override

    pacman_conf_path = Path("/etc/pacman.conf")
    if pacman_conf_path.exists():
        with open(pacman_conf_path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line.startswith("Architecture") and "=" in line:
                    arch_value = line.split("=", 1)[1].strip()
                    if arch_value and arch_value != "auto":
                        logger.info("Found Architecture=%s in /etc/pacman.conf", arch_value)
                        return arch_value

    machine_arch = platform.machine()
    mapped_arch = MACHINE_ARCH_MAPPING.get(machine_arch, machine_arch)
    logger.info("Mapped machine architecture '%s' to '%s'", machine_arch, mapped_arch)
    return mapped_arch
