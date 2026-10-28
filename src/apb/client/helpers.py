"""Client helper functions for local package checks."""

import logging
from pathlib import Path
from typing import List, Optional, Tuple

from apb.arch import package_arch_suffix
from apb.pkgbuild import parse_pkgbuild_file, pkgbuild_arch_is_any_only, pkgbuild_info_to_dict

logger = logging.getLogger(__name__)


def parse_pkgbuild_info(pkgbuild_path: Path) -> dict:
    return pkgbuild_info_to_dict(parse_pkgbuild_file(pkgbuild_path))


def check_package_exists(output_dir: Path, pkgname_list: List[str], pkgver: str, pkgrel: str, arch: str, pkgbuild_archs: List[str] = None, epoch: str = None) -> tuple[bool, str]:
    """
    Check if package files already exist in the output directory.

    Args:
        output_dir: Output directory path
        pkgname_list: List of package names to check
        pkgver: Package version
        pkgrel: Package release
        arch: Target architecture (can be "any" to check all architectures)
        pkgbuild_archs: List of architectures from PKGBUILD arch=() array
        epoch: Package epoch (optional)

    Returns:
        Tuple of (exists, found_filename_or_summary)
    """
    # Use PKGBUILD architectures or fallback to common ones
    if pkgbuild_archs:
        potential_suffixes = [package_arch_suffix(a) for a in pkgbuild_archs]
        # Remove duplicates while preserving order
        potential_suffixes = list(dict.fromkeys(potential_suffixes))
    else:
        # Fallback to common architectures if PKGBUILD archs not provided
        potential_suffixes = ['x86_64', 'aarch64', 'armv7h', 'armv6h', 'powerpc', 'powerpc64le', 'powerpc64', 'espresso', 'any']

    # Helper function to construct version string with epoch
    def construct_version_string():
        if epoch:
            return f"{epoch}:{pkgver}-{pkgrel}"
        else:
            return f"{pkgver}-{pkgrel}"

    version_string = construct_version_string()

    if arch == "any":
        # For "any" architecture, check if package exists with any architecture suffix
        # First check if output directory exists
        if not output_dir.exists():
            return False, "Package not found for any architecture"

        found_packages = []
        missing_packages = []

        # Look for packages in all subdirectories of output_dir
        for pkgname in pkgname_list:
            package_found = False

            # Check "any" subdirectory first for arch=(any) packages
            any_arch_dir = output_dir / "any"
            if any_arch_dir.is_dir() and not package_found:
                package_filename = f"{pkgname}-{version_string}-any.pkg.tar.zst"
                package_path = any_arch_dir / package_filename
                if package_path.exists():
                    found_packages.append(f"{package_filename} (found in any)")
                    package_found = True
                    break

            # Check all architecture subdirectories
            if not package_found:
                try:
                    for arch_dir in output_dir.iterdir():
                        if arch_dir.is_dir() and arch_dir.name != "any" and not package_found:  # Skip "any" as we checked it above
                            # Try different architecture suffixes
                            for potential_suffix in potential_suffixes:
                                package_filename = f"{pkgname}-{version_string}-{potential_suffix}.pkg.tar.zst"
                                package_path = arch_dir / package_filename
                                if package_path.exists():
                                    found_packages.append(f"{package_filename} (found in {arch_dir.name})")
                                    package_found = True
                                    break
                                else:
                                    found_packages.append(f"{package_filename} (not found in {arch_dir.name})")
                except (OSError, FileNotFoundError):
                    # Directory doesn't exist or can't be read
                    pass

            # Also check main output directory with common suffixes
            if not package_found:
                for potential_suffix in potential_suffixes:
                    package_filename = f"{pkgname}-{version_string}-{potential_suffix}.pkg.tar.zst"
                    package_path = output_dir / package_filename
                    if package_path.exists():
                        found_packages.append(package_filename)
                        package_found = True
                        break

            if not package_found:
                missing_packages.append(pkgname)

        # All packages must exist to consider the build complete
        if not missing_packages:
            if len(found_packages) == 1:
                return True, found_packages[0]
            else:
                return True, f"{len(found_packages)} packages found"

        return False, f"Missing {len(missing_packages)} packages for any architecture"
    else:
        # Get the actual suffix used in package filenames
        arch_suffix = package_arch_suffix(arch)

        found_packages = []
        missing_packages = []

        # Check each package name in the list
        for pkgname in pkgname_list:
            # Standard Arch Linux package filename format
            package_filename = f"{pkgname}-{version_string}-{arch_suffix}.pkg.tar.zst"

            # Check in architecture-specific output directory first
            arch_output_dir = output_dir / arch
            package_path = arch_output_dir / package_filename

            if package_path.exists():
                found_packages.append(package_filename)
                continue

            # Check in main output directory as fallback
            main_package_path = output_dir / package_filename
            if main_package_path.exists():
                found_packages.append(package_filename)
                continue

            # Package not found
            missing_packages.append(package_filename)

        # All packages must exist to consider the build complete
        if not missing_packages:
            if len(found_packages) == 1:
                return True, found_packages[0]
            else:
                return True, f"{len(found_packages)} packages found"

        return False, f"Missing {len(missing_packages)} packages"


def should_skip_build(output_dir: Path, pkgbuild_path: Path, arch: str, force: bool = False) -> tuple[bool, str]:
    """
    Determine if a build should be skipped because the package already exists.

    Args:
        output_dir: Output directory path
        pkgbuild_path: Path to PKGBUILD file
        arch: Target architecture
        force: Whether to force rebuild even if package exists

    Returns:
        Tuple of (should_skip, reason)
    """
    if force:
        return False, "Force rebuild requested"

    pkg_info = parse_pkgbuild_info(pkgbuild_path)

    # Use pkgname_list for filename checking, fallback to main pkgname if empty
    pkgname_list = pkg_info.get("pkgname_list", [])
    if not pkgname_list:
        pkgname_list = [pkg_info["pkgname"]]

    exists, found_filename = check_package_exists(output_dir, pkgname_list, pkg_info["pkgver"],
                                                 pkg_info["pkgrel"], arch, pkg_info.get("arch", []), pkg_info.get("epoch"))
    if exists:
        return True, f"Package already exists: {found_filename}"

    return False, "Package not found, proceeding with build"


def print_apb_arch_hint_notice(pkg_info: dict) -> None:
    """Print how apb_arch_hint applies for this PKGBUILD (farm and config client paths)."""
    hint = pkg_info.get("apb_arch_hint")
    if not hint:
        return
    archs = pkg_info.get("arch") or []
    if pkgbuild_arch_is_any_only(archs):
        print(f"Using PKGBUILD apb_arch_hint: {hint}")
    else:
        print(
            f"Warning: apb_arch_hint={hint} ignored (only applies when arch=(any))"
        )


def effective_any_server_arch(pkg_info: dict, servers: dict) -> tuple[Optional[str], Optional[str]]:
    """
    Resolve which configured server architecture to use for arch=(any).

    Returns (server_arch, error_message). error_message is set when a hint was
    required but no matching servers exist.
    """
    archs = pkg_info.get("arch") or []
    hint = pkg_info.get("apb_arch_hint") if pkgbuild_arch_is_any_only(archs) else None

    if hint:
        server_urls = servers.get(hint) or []
        if not server_urls:
            return None, (
                f"No servers configured for apb_arch_hint '{hint}' "
                f"(available: {', '.join(sorted(servers.keys())) or 'none'})"
            )
        return hint, None

    available_server_archs = [key for key, urls in servers.items() if urls]
    if not available_server_archs:
        return None, "No servers available for any architecture"
    return available_server_archs[0], None


def select_pkgbuild_architectures(
    pkgbuild_archs: List[str],
    arch_filter: Optional[List[str]] = None,
) -> Tuple[List[str], List[str]]:
    """
    Intersect PKGBUILD arch=() with a client --arch request.

    Returns:
        (selected architectures in PKGBUILD order, requested names not in PKGBUILD)
    """
    if not arch_filter:
        return list(pkgbuild_archs), []

    requested = set(arch_filter)
    selected = [arch for arch in pkgbuild_archs if arch in requested]
    missing = sorted(requested - set(pkgbuild_archs))
    return selected, missing


def get_architectures_needing_build(
    pkgbuild_path: Path,
    output_dir: Path,
    force: bool = False,
    arch_filter: Optional[List[str]] = None,
) -> List[str]:
    """
    Get list of architectures that need building (don't have existing packages).

    Args:
        pkgbuild_path: Path to PKGBUILD file
        output_dir: Output directory to check for existing packages
        force: Force rebuild even if packages exist
        arch_filter: If set, only consider these architectures (must appear in PKGBUILD)

    Returns:
        List of architectures that need building
    """
    pkg_info = parse_pkgbuild_info(pkgbuild_path)
    pkgbuild_archs = pkg_info.get("arch", ["x86_64"])
    target_archs, _missing = select_pkgbuild_architectures(pkgbuild_archs, arch_filter)
    if arch_filter and not target_archs:
        return []

    if force:
        # If force is specified, all selected architectures need building
        return target_archs

    # Special handling for "any" architecture
    if "any" in target_archs:
        # For "any" architecture packages, check if we already have a package built for ANY architecture
        should_skip, reason = should_skip_build(output_dir, pkgbuild_path, "any", force)
        if should_skip:
            # Package already exists for some architecture, no need to build
            return []
        else:
            # No package exists, need to build for "any" architecture
            return ["any"]

    # Regular handling for specific architectures
    architectures_needing_build = []

    for arch in target_archs:
        should_skip, reason = should_skip_build(output_dir, pkgbuild_path, arch, force)
        if not should_skip:
            architectures_needing_build.append(arch)

    return architectures_needing_build

