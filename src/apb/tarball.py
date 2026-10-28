"""Build directory tarball creation and extraction."""

import io
import tarfile
from pathlib import Path
from typing import Iterable, Optional, Union

EXCLUDED_NAMES = frozenset({"pkg", ".git", ".svn", "__pycache__"})
EXCLUDED_SUFFIXES = (".pkg.tar.zst", ".pkg.tar.xz", ".pkg.tar.gz", ".sig", ".log")


class InvalidBuildTarball(ValueError):
    """Raised when a build tarball cannot be extracted or lacks a PKGBUILD."""


def create_build_tarball(
    build_path: Path,
    tarball_path: Path,
    exclude_paths: Optional[Iterable[Path]] = None,
    *,
    skip_artifacts: bool = True,
) -> None:
    """Pack a build directory into a gzip tarball for upload.

    With ``skip_artifacts`` disabled every top-level entry is packed, which is
    needed when the directory holds user-supplied sources such as ``*.sig``.
    """
    excluded = {path.resolve() for path in exclude_paths or ()}

    with tarfile.open(tarball_path, "w:gz") as archive:
        for item in build_path.iterdir():
            if item.resolve() in excluded:
                continue
            if skip_artifacts and item.name in EXCLUDED_NAMES:
                continue
            if skip_artifacts and item.is_file() and item.name.endswith(EXCLUDED_SUFFIXES):
                continue
            archive.add(item, arcname=item.name)


def extract_build_tarball(source: Union[bytes, Path], dest: Path) -> Path:
    """Extract a gzip build tarball into ``dest`` and return the PKGBUILD path.

    Members are filtered with the ``data`` extraction filter, so absolute paths,
    links escaping ``dest`` and special files are rejected.
    """
    try:
        archive = (
            tarfile.open(fileobj=io.BytesIO(source), mode="r:gz")
            if isinstance(source, bytes)
            else tarfile.open(source, mode="r:gz")
        )
        with archive:
            archive.extractall(path=dest, filter="data")
    except (tarfile.TarError, OSError) as exc:
        raise InvalidBuildTarball(f"Could not extract tarball: {exc}") from exc

    pkgbuild_path = dest / "PKGBUILD"
    if not pkgbuild_path.is_file():
        raise InvalidBuildTarball("Tarball must contain a PKGBUILD file")
    return pkgbuild_path
