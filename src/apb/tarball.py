"""Build directory tarball creation."""

import tarfile
from pathlib import Path


def create_build_tarball(build_path: Path, tarball_path: Path) -> None:
    """Pack a build directory into a gzip tarball for upload."""
    with tarfile.open(tarball_path, "w:gz") as archive:
        for item in build_path.iterdir():
            archive.add(item, arcname=item.name)
