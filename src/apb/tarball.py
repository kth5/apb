"""Build directory tarball creation."""

import tarfile
from pathlib import Path

from apb.srcinfo import collect_tarball_paths


def create_build_tarball(build_path: Path, tarball_path: Path) -> None:
    """
    Pack PKGBUILD, local sources, install scripts, and keys/ for upload.

    File selection is driven by .SRCINFO (or makepkg --printsrcinfo). Remote
    sources are omitted; build servers download them.
    """
    build_path = build_path.resolve()
    members = collect_tarball_paths(build_path)

    with tarfile.open(tarball_path, "w:gz") as archive:
        for member in members:
            archive.add(member, arcname=member.relative_to(build_path).as_posix())
