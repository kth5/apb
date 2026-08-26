"""Build directory tarball creation."""

import tarfile
from pathlib import Path
from typing import Iterable, Optional

EXCLUDED_NAMES = frozenset({"pkg", ".git", ".svn", "__pycache__"})
EXCLUDED_SUFFIXES = (".pkg.tar.zst", ".pkg.tar.xz", ".pkg.tar.gz", ".sig", ".log")


def create_build_tarball(
    build_path: Path,
    tarball_path: Path,
    exclude_paths: Optional[Iterable[Path]] = None,
) -> None:
    """Pack a build directory into a gzip tarball for upload."""
    excluded = {path.resolve() for path in exclude_paths or ()}

    with tarfile.open(tarball_path, "w:gz") as archive:
        for item in build_path.iterdir():
            if item.name in EXCLUDED_NAMES:
                continue
            if item.resolve() in excluded:
                continue
            if item.is_file() and item.name.endswith(EXCLUDED_SUFFIXES):
                continue
            archive.add(item, arcname=item.name)
