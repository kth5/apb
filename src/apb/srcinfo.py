"""Parse .SRCINFO metadata for build tarball file selection."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Optional, Set

_SRCINFO_ASSIGNMENT = re.compile(r"^([a-zA-Z0-9_]+)\s*=\s*(.*)$")
_VCS_PREFIXES = ("git+", "svn+", "hg+", "bzr+", "fossil+")


class SrcinfoError(RuntimeError):
    """Raised when .SRCINFO cannot be read or generated."""


def is_remote_source(uri: str) -> bool:
    """Return True if a source URI is fetched remotely by makepkg."""
    if "://" in uri:
        return True
    return any(uri.startswith(prefix) for prefix in _VCS_PREFIXES)


def local_path_for_source(source_entry: str) -> Optional[str]:
    """
    Return the startdir-relative path makepkg expects for a local source.

    Remote sources return None (build servers download them).
    """
    if "::" in source_entry:
        filename, uri = source_entry.split("::", 1)
    else:
        filename, uri = source_entry, source_entry

    if is_remote_source(uri):
        return None
    return filename


def parse_srcinfo_local_paths(content: str) -> Set[str]:
    """
    Collect local source paths and install scriptlets from .SRCINFO content.

    Includes architecture-specific source_* entries. Excludes changelog and remotes.
    """
    paths: Set[str] = set()

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        match = _SRCINFO_ASSIGNMENT.match(line)
        if not match:
            continue

        key, value = match.group(1), match.group(2).strip()
        if key == "install":
            if value:
                paths.add(value)
            continue

        if key != "source" and not key.startswith("source_"):
            continue

        local_path = local_path_for_source(value)
        if local_path:
            paths.add(local_path)

    return paths


def read_or_generate_srcinfo(build_path: Path) -> str:
    """Prefer an on-disk .SRCINFO; otherwise run makepkg --printsrcinfo."""
    srcinfo_path = build_path / ".SRCINFO"
    if srcinfo_path.is_file():
        return srcinfo_path.read_text(encoding="utf-8")

    try:
        result = subprocess.run(
            ["makepkg", "--printsrcinfo"],
            cwd=build_path,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise SrcinfoError(
            "No .SRCINFO found and makepkg is not available to generate one"
        ) from exc

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        message = "makepkg --printsrcinfo failed"
        if detail:
            message = f"{message}: {detail}"
        raise SrcinfoError(message)

    return result.stdout


def collect_tarball_paths(build_path: Path) -> list[Path]:
    """
    Resolve files and directories that belong in a build submission tarball.

    Always includes PKGBUILD. Includes keys/ when present. Local sources and
    install scripts come from .SRCINFO. Missing required paths raise FileNotFoundError.
    """
    pkgbuild_path = build_path / "PKGBUILD"
    if not pkgbuild_path.is_file():
        raise FileNotFoundError(f"PKGBUILD not found in {build_path}")

    srcinfo_content = read_or_generate_srcinfo(build_path)
    relative_paths = parse_srcinfo_local_paths(srcinfo_content)

    selected: list[Path] = [pkgbuild_path]
    missing: list[str] = []

    for relative in sorted(relative_paths):
        path = build_path / relative
        if not path.exists():
            missing.append(relative)
            continue
        selected.append(path)

    if missing:
        missing_list = ", ".join(missing)
        raise FileNotFoundError(
            f"Local source(s) listed in .SRCINFO missing from {build_path}: {missing_list}"
        )

    keys_dir = build_path / "keys"
    if keys_dir.is_dir():
        selected.append(keys_dir)

    return selected
