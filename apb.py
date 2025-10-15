#!/usr/bin/env python3
"""
APB Client - A Python library and command-line tool for interacting with APB Servers and APB Farm instances.
"""

import argparse
import json
import os
import sys
import time
import threading
import queue
import getpass
import tarfile
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Generator, Any
from urllib.parse import urljoin
import requests
import re
from datetime import datetime

# Version information
VERSION = "2025-10-14"


def parse_pkgbuild_info(pkgbuild_path: Path) -> Dict[str, Any]:
    """
    Parse PKGBUILD file to extract package information including name, version, and architectures.

    Args:
        pkgbuild_path: Path to PKGBUILD file

    Returns:
        Dictionary with pkgname (using pkgbase if defined, ignoring pkgname completely), pkgver, pkgrel, arch, and pkgname_list for filename checking
    """
    try:
        with open(pkgbuild_path, 'r') as f:
            content = f.read()

        info = {
            "pkgname": "unknown",
            "pkgver": "1.0.0",
            "pkgrel": "1",
            "epoch": None,
            "arch": ["x86_64"],
            "pkgname_list": []  # For filename checking
        }
        pkgbase = None

        lines = content.split('\n')
        i = 0
        while i < len(lines):
            line = lines[i].strip()

            if line.startswith('pkgbase='):
                pkgbase = line.split('=', 1)[1].strip('\'"')
            elif line.startswith('pkgname='):
                pkgname_value = line.split('=', 1)[1].strip()
                # Handle array format: pkgname=('pkg1' 'pkg2')
                if pkgname_value.startswith('(') and pkgname_value.endswith(')'):
                    # Extract all package names from array
                    array_content = pkgname_value[1:-1].strip()
                    pkgname_list = [pkg.strip('\'"') for pkg in array_content.split() if pkg.strip('\'"')]
                    info["pkgname_list"] = pkgname_list
                    # Set first package name as default
                    if pkgname_list:
                        info["pkgname"] = pkgname_list[0]
                else:
                    # Handle simple format: pkgname=package
                    pkg = pkgname_value.strip('\'"')
                    info["pkgname"] = pkg
                    info["pkgname_list"] = [pkg]
            elif line.startswith('pkgver='):
                info["pkgver"] = line.split('=', 1)[1].strip('\'"')
            elif line.startswith('pkgrel='):
                info["pkgrel"] = line.split('=', 1)[1].strip('\'"')
            elif line.startswith('epoch='):
                info["epoch"] = line.split('=', 1)[1].strip('\'"')
            elif line.startswith('arch='):
                arch_str = line.split('=', 1)[1].strip()
                if arch_str.startswith('(') and arch_str.endswith(')'):
                    arch_str = arch_str[1:-1]
                info["arch"] = [a.strip('\'"') for a in arch_str.split()]

            i += 1

        # If pkgbase is defined, use it as pkgname but preserve actual package names for filename checking
        if pkgbase:
            info["pkgname"] = pkgbase
            # Only override pkgname_list if it's empty (no pkgname array was found)
            if not info.get("pkgname_list"):
                info["pkgname_list"] = [pkgbase]

        return info
    except Exception as e:
        print(f"Error parsing PKGBUILD {pkgbuild_path}: {e}")
        return {
            "pkgname": "unknown",
            "pkgver": "1.0.0",
            "pkgrel": "1",
            "epoch": None,
            "arch": ["x86_64"],
            "pkgname_list": []
        }


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
    # Architecture mappings for package filename suffixes
    # Some architectures produce packages with different suffixes
    arch_suffix_map = {
        'espresso': 'powerpc',  # espresso builds produce powerpc packages
    }

    # Use PKGBUILD architectures or fallback to common ones
    if pkgbuild_archs:
        potential_suffixes = [arch_suffix_map.get(a, a) for a in pkgbuild_archs]
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
        package_arch_suffix = arch_suffix_map.get(arch, arch)

        found_packages = []
        missing_packages = []

        # Check each package name in the list
        for pkgname in pkgname_list:
            # Standard Arch Linux package filename format
            package_filename = f"{pkgname}-{version_string}-{package_arch_suffix}.pkg.tar.zst"

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


def get_architectures_needing_build(pkgbuild_path: Path, output_dir: Path, force: bool = False) -> List[str]:
    """
    Get list of architectures that need building (don't have existing packages).

    Args:
        pkgbuild_path: Path to PKGBUILD file
        output_dir: Output directory to check for existing packages
        force: Force rebuild even if packages exist

    Returns:
        List of architectures that need building
    """
    pkg_info = parse_pkgbuild_info(pkgbuild_path)
    target_archs = pkg_info.get("arch", ["x86_64"])

    if force:
        # If force is specified, all architectures need building
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


class APBAuthClient:
    """Handles authentication for APB client"""

    def __init__(self, farm_url: str, config_path: Optional[Path] = None):
        self.farm_url = farm_url.rstrip('/')
        self.config_path = config_path or Path.home() / ".apb" / "auth.json"
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self._token = None
        self._load_token()

    def _load_token(self):
        """Load stored token from config file"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    data = json.load(f)
                    farm_tokens = data.get('tokens', {})
                    self._token = farm_tokens.get(self.farm_url)
        except Exception as e:
            print(f"Warning: Could not load stored token: {e}")

    def _save_token(self, token: str):
        """Save token to config file"""
        try:
            # Load existing config
            config = {}
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    config = json.load(f)

            # Update token for this farm
            if 'tokens' not in config:
                config['tokens'] = {}
            config['tokens'][self.farm_url] = token

            # Save config
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)

            # Set restrictive permissions
            self.config_path.chmod(0o600)
            self._token = token

        except Exception as e:
            print(f"Warning: Could not save token: {e}")

    def _clear_token(self):
        """Clear stored token"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    config = json.load(f)

                if 'tokens' in config and self.farm_url in config['tokens']:
                    del config['tokens'][self.farm_url]

                    with open(self.config_path, 'w') as f:
                        json.dump(config, f, indent=2)

            self._token = None
        except Exception as e:
            print(f"Warning: Could not clear token: {e}")

    def login(self, username: str, password: str) -> bool:
        """Login with username and password"""
        try:
            response = requests.post(
                f"{self.farm_url}/auth/login",
                json={"username": username, "password": password},
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                token = data.get('token')
                if token:
                    self._save_token(token)
                    print(f"Successfully logged in as {username}")
                    return True
            else:
                try:
                    error_data = response.json()
                    print(f"Login failed: {error_data.get('detail', 'Unknown error')}")
                except:
                    print(f"Login failed: HTTP {response.status_code}")
                return False

        except Exception as e:
            print(f"Login error: {e}")
            return False

    def logout(self) -> bool:
        """Logout (revoke current token)"""
        if not self._token:
            return True

        try:
            response = requests.post(
                f"{self.farm_url}/auth/logout",
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=30
            )

            # Clear token regardless of response
            self._clear_token()

            if response.status_code == 200:
                print("Successfully logged out")
                return True
            else:
                print(f"Logout response: HTTP {response.status_code}")
                return True  # Still consider it successful since we cleared local token

        except Exception as e:
            print(f"Logout error: {e}")
            self._clear_token()  # Clear local token anyway
            return True

    def get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for requests"""
        if self._token:
            return {"Authorization": f"Bearer {self._token}"}
        return {}

    def is_authenticated(self) -> bool:
        """Check if we have a stored token"""
        return self._token is not None

    def get_user_info(self) -> Optional[Dict[str, Any]]:
        """Get current user information"""
        if not self._token:
            return None

        try:
            response = requests.get(
                f"{self.farm_url}/auth/me",
                headers=self.get_auth_headers(),
                timeout=30
            )

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                # Token is invalid, clear it
                self._clear_token()
                return None
            else:
                print(f"Failed to get user info: HTTP {response.status_code}")
                return None

        except Exception as e:
            print(f"Error getting user info: {e}")
            return None


class APBotClient:
    """Main client class for interacting with APB servers."""

    def __init__(self, server_url: str, auth_client: Optional[APBAuthClient] = None):
        """Initialize APBotClient with server URL and optional authentication."""
        self.server_url = server_url.rstrip('/')
        self.session = requests.Session()
        self.auth_client = auth_client

        # Set User-Agent header to identify the client
        self.session.headers.update({
            'User-Agent': f'APB-Client/{VERSION}'
        })

        # Set authentication headers if available
        if self.auth_client:
            headers = self.auth_client.get_auth_headers()
            self.session.headers.update(headers)

    def build_package(self, build_path: Path) -> str:
        """
        Submit a build request to the server using a tarball of all files in the build directory.

        Args:
            build_path: Path to directory containing PKGBUILD and source files

        Returns:
            Build UUID provided by APB Farm

        Raises:
            requests.HTTPError: On HTTP errors
            requests.RequestException: On connection errors
            ValueError: On invalid response or missing PKGBUILD
        """
        # Ensure we have a PKGBUILD
        pkgbuild_path = build_path / "PKGBUILD"
        if not pkgbuild_path.exists():
            raise ValueError(f"PKGBUILD not found in {build_path}")

        # Create a temporary tarball containing all files (excluding subdirectories except keys/)
        with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as temp_tarball:
            try:
                with tarfile.open(temp_tarball.name, 'w:gz') as tar:
                    # Add all files from the build directory, excluding subdirectories except keys/
                    for item in build_path.iterdir():
                        if item.is_file():
                            # Add file with just its name (not full path)
                            tar.add(item, arcname=item.name)
                        elif item.is_dir() and item.name == "keys":
                            # Add keys/ directory and all its contents recursively
                            tar.add(item, arcname=item.name)

                # Submit the tarball using streaming to avoid memory issues
                with open(temp_tarball.name, 'rb') as f:
                    files_data = [('build_tarball', ('build.tar.gz', f, 'application/gzip'))]

                    # Submit build request
                    url = urljoin(self.server_url, '/build')
                    response = self.session.post(url, files=files_data)
                    response.raise_for_status()

                result = response.json()
                if 'build_id' not in result:
                    raise ValueError("Invalid response: missing build_id")

                return result['build_id']

            finally:
                # Clean up temporary file
                try:
                    os.unlink(temp_tarball.name)
                except OSError:
                    pass

    def get_build_status(self, build_id: str) -> Dict:
        """
        Get the current status of a build.

        Args:
            build_id: Build UUID

        Returns:
            Build status information
        """
        url = urljoin(self.server_url, f'/build/{build_id}/status')
        response = self.session.get(url, params={'format': 'json'})
        response.raise_for_status()
        return response.json()

    def cancel_build(self, build_id: str) -> bool:
        """
        Cancel a running build.

        Args:
            build_id: Build UUID

        Returns:
            True if cancellation was successful
        """
        url = urljoin(self.server_url, f'/build/{build_id}/cancel')
        try:
            response = self.session.post(url)
            response.raise_for_status()
            return True
        except requests.RequestException:
            return False

    def download_file(self, build_id: str, filename: str, output_dir: Path) -> bool:
        """
        Download a file from a build.

        Args:
            build_id: Build UUID
            filename: Name of the file to download
            output_dir: Directory to save the file

        Returns:
            True if download was successful
        """
        url = urljoin(self.server_url, f'/build/{build_id}/download/{filename}')

        try:
            response = self.session.get(url, stream=True)
            response.raise_for_status()

            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = output_dir / filename

            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            return True
        except requests.RequestException:
            return False

    def download_latest_build_files(self, pkgname: str, output_dir: Path,
                                   successful_only: bool = True) -> bool:
        """
        Download all files from the latest build of a package.

        Args:
            pkgname: Package name
            output_dir: Directory to save files
            successful_only: Only consider successful builds

        Returns:
            True if download was successful
        """
        try:
            latest_build = self.get_latest_build_by_pkgname(pkgname, successful_only)
            if not latest_build:
                return False

            build_id = latest_build['build_id']

            # Get build status to find package files
            status = self.get_build_status(build_id)

            # Download all package files
            if 'packages' in status and status['packages']:
                for package in status['packages']:
                    if not self.download_file(build_id, package['filename'], output_dir):
                        return False

            # Download all log files
            if 'logs' in status and status['logs']:
                for log in status['logs']:
                    if not self.download_file(build_id, log['filename'], output_dir):
                        return False

            return True
        except requests.RequestException:
            return False

    def get_build_by_id(self, build_id: str) -> Dict:
        """
        Get detailed information about a build.

        Args:
            build_id: Build UUID

        Returns:
            Detailed build information
        """
        return self.get_build_status(build_id)

    def get_builds_by_pkgname(self, pkgname: str, limit: int = 5) -> Dict:
        """
        Get builds for a specific package.

        Args:
            pkgname: Package name
            limit: Maximum number of builds to return

        Returns:
            Build history for the package
        """
        url = urljoin(self.server_url, f'/builds/package/{pkgname}')
        response = self.session.get(url, params={'limit': limit})
        response.raise_for_status()
        return response.json()

    def get_latest_build_by_pkgname(self, pkgname: str, successful_only: bool = True) -> Dict:
        """
        Get the latest build for a specific package.

        Args:
            pkgname: Package name
            successful_only: Only consider successful builds

        Returns:
            Latest build information
        """
        builds = self.get_builds_by_pkgname(pkgname, limit=10)
        if not builds.get('builds'):
            return {}

        for build in builds['builds']:
            if not successful_only or build['status'] == 'completed':
                return build

        return {}

    def get_build_output(self, build_id: str, start_index: int = 0, limit: int = 50) -> Dict:
        """
        Get build output/logs.

        Args:
            build_id: Build UUID
            start_index: Starting line index
            limit: Maximum number of lines

        Returns:
            Build output with metadata
        """
        url = urljoin(self.server_url, f'/build/{build_id}/output')
        params = {'start_index': start_index, 'limit': limit}
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json()

    def stream_output(self, build_id: str) -> Generator[str, None, None]:
        """
        Stream build output in real-time.

        Args:
            build_id: Build UUID

        Yields:
            Output lines
        """
        url = urljoin(self.server_url, f'/build/{build_id}/stream')

        try:
            response = self.session.get(url, stream=True)
            response.raise_for_status()

            for line in response.iter_lines(decode_unicode=True):
                if line:
                    yield line + '\n'
        except requests.RequestException:
            pass

    def stream_build_updates(self, build_id: str) -> Generator[Dict, None, None]:
        """
        Stream build status updates in real-time.

        Args:
            build_id: Build UUID

        Yields:
            Status updates
        """
        consecutive_errors = 0
        max_consecutive_errors = 3

        while True:
            try:
                status = self.get_build_status(build_id)
                consecutive_errors = 0  # Reset error count on success
                yield status

                if status['status'] in ['completed', 'failed', 'cancelled']:
                    break

                time.sleep(5)
            except requests.RequestException as e:
                consecutive_errors += 1
                if consecutive_errors >= max_consecutive_errors:
                    raise e
                # Wait longer before retrying on error
                time.sleep(10)

    def get_latest_successful_build_id(self, is_interactive: bool = True) -> str:
        """
        Get the build ID of the latest successful build for a package.

        Args:
            is_interactive: Whether to prompt user for input if multiple packages found

        Returns:
            Build ID of the latest successful build
        """
        # This would need to be implemented based on server capabilities
        # For now, return empty string
        return ""

    def cleanup_server(self) -> bool:
        """
        Trigger server cleanup.

        Returns:
            True if cleanup was triggered successfully
        """
        url = urljoin(self.server_url, '/cleanup')
        try:
            response = self.session.post(url)
            response.raise_for_status()
            return True
        except requests.RequestException:
            return False


def load_config(config_path: Optional[Path] = None) -> Dict:
    """
    Load configuration from file.

    Args:
        config_path: Specific config file path

    Returns:
        Configuration dictionary
    """
    config_locations = [
        Path("./apb.json"),
        Path("/etc/apb/apb.json"),
        Path.home() / ".apb" / "apb.json",
        Path.home() / ".apb-farm" / "apb.json"
    ]

    if config_path:
        config_locations.insert(0, config_path)

    for config_file in config_locations:
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                continue

    # Default configuration
    return {
        "servers": {
            "x86_64": ["http://localhost:8000"]
        },
        "default_server": "http://localhost:8000",
        "default_arch": "x86_64",
        "output_dir": "./output",
        "farm_url": "http://localhost:8080"
    }


def submit_build(server_url: str, build_path: Path, auth_client: Optional[APBAuthClient] = None) -> Optional[str]:
    """
    Submit a build to a server using a tarball of the build directory.

    Args:
        server_url: Server URL
        build_path: Path to directory containing PKGBUILD and source files
        auth_client: Optional authentication client

    Returns:
        Build ID if successful, None otherwise
    """
    try:
        client = APBotClient(server_url, auth_client)
        return client.build_package(build_path)
    except requests.RequestException:
        return None


def submit_build_to_farm(server_url: str, build_path: Path, architectures: List[str] = None, auth_client: Optional[APBAuthClient] = None, build_timeout: Optional[int] = None) -> Optional[Dict]:
    """
    Submit a build to a farm server using a tarball and return the full response.

    Args:
        server_url: Farm server URL
        build_path: Path to directory containing PKGBUILD and source files
        architectures: Optional list of architectures to build for
        auth_client: Optional authentication client for farm access
        build_timeout: Optional build timeout in seconds (admin only)

    Returns:
        Full response dictionary if successful, None otherwise
    """
    try:
        # Validate timeout parameter if provided
        if build_timeout is not None:
            if build_timeout < 300 or build_timeout > 14400:
                raise ValueError("Build timeout must be between 300 and 14400 seconds (5 minutes to 4 hours)")

        # Ensure we have a PKGBUILD
        pkgbuild_path = build_path / "PKGBUILD"
        if not pkgbuild_path.exists():
            raise ValueError(f"PKGBUILD not found in {build_path}")

        client = APBotClient(server_url, auth_client)

        # Create a temporary tarball containing all files (excluding subdirectories except keys/)
        with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as temp_tarball:
            try:
                with tarfile.open(temp_tarball.name, 'w:gz') as tar:
                    # Add all files from the build directory, excluding subdirectories except keys/
                    for item in build_path.iterdir():
                        if item.is_file():
                            # Add file with just its name (not full path)
                            tar.add(item, arcname=item.name)
                        elif item.is_dir() and item.name == "keys":
                            # Add keys/ directory and all its contents recursively
                            tar.add(item, arcname=item.name)

                # Prepare form data
                form_data = {}
                if architectures:
                    # Include architectures list as form data to tell farm which architectures to build
                    form_data['architectures'] = ','.join(architectures)
                if build_timeout is not None:
                    # Include build timeout (only allowed for admin users)
                    form_data['build_timeout'] = str(build_timeout)

                # Submit the tarball using streaming to avoid memory issues
                with open(temp_tarball.name, 'rb') as f:
                    files_data = [('build_tarball', ('build.tar.gz', f, 'application/gzip'))]

                    # Submit build request
                    url = urljoin(server_url, '/build')
                    response = client.session.post(url, files=files_data, data=form_data)
                    response.raise_for_status()

                return response.json()

            finally:
                # Clean up temporary file
                try:
                    os.unlink(temp_tarball.name)
                except OSError:
                    pass

    except requests.RequestException as e:
        print(f"Error submitting build to farm: {e}")
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_detail = e.response.json()
                print(f"Farm error response: {error_detail}")
                # Handle authentication errors specifically
                if e.response.status_code == 401:
                    print("Authentication required. Please login first using: apb --farm --login")
                elif e.response.status_code == 403:
                    print("Access denied. You may not have permission to submit builds.")
            except:
                print(f"Farm HTTP {e.response.status_code} response: {e.response.text}")
                if e.response.status_code == 401:
                    print("Authentication required. Please login first using: apb --farm --login")
        return None


def monitor_farm_builds(builds: List[Dict], client: APBotClient, output_dir: Path = None,
                       verbose: bool = False, pkgbuild_path: Path = None, auth_client: Optional[APBAuthClient] = None) -> bool:
    """
    Monitor multiple builds from a farm submission.

    Args:
        builds: List of build information dictionaries
        client: Client instance
        output_dir: Base output directory
        verbose: Enable verbose output
        pkgbuild_path: Path to PKGBUILD file (to check original architecture)

    Returns:
        True if all builds were successful
    """
    print(f"Monitoring {len(builds)} build(s)...")

    build_results = {}
    arch_build_info = {}

    # Set up build tracking
    for build in builds:
        arch = build['arch']
        build_id = build['build_id']
        arch_build_info[arch] = {
            'build_id': build_id,
            'status': 'submitted'
        }

    # Show summary of submitted builds
    print("\n=== Build Summary ===")
    for build in builds:
        print(f"[{build['arch']}] Build ID: {build['build_id']}")
    print("====================\n")

    # Thread-safe queue for results
    result_queue = queue.Queue()

    # Event to signal all threads to stop
    stop_event = threading.Event()

    # Thread function to monitor a single build
    def monitor_build_thread(build_info):
        arch = build_info['arch']
        build_id = build_info['build_id']

        try:
            # Check if original package had arch=(any) to determine output folder
            is_any_arch_package = False
            if pkgbuild_path and pkgbuild_path.exists():
                pkg_info = parse_pkgbuild_info(pkgbuild_path)
                original_archs = pkg_info.get("arch", [])
                is_any_arch_package = "any" in original_archs

            if output_dir:
                if is_any_arch_package:
                    arch_output_dir = output_dir / "any"
                else:
                    arch_output_dir = output_dir / arch
            else:
                arch_output_dir = None

            print(f"[{arch}] Starting monitoring...")

            # Monitor with enhanced error handling for server unavailability
            last_status = None
            consecutive_errors = 0
            max_consecutive_errors = 5
            server_unavailable_count = 0
            max_server_unavailable = 8  # More lenient for farm builds

            while not stop_event.is_set():
                try:
                    status = client.get_build_status(build_id)

                    # Check if server is unavailable but we have cached data
                    if status.get('server_unavailable'):
                        server_unavailable_count += 1
                        if server_unavailable_count >= max_server_unavailable:
                            print(f"[{arch}] Server has been unavailable for {server_unavailable_count} consecutive checks")
                            cached_status = status.get('status', 'unknown')
                            print(f"[{arch}] Last known status: {cached_status}")

                            # If we have a final status, use it
                            if cached_status in ['completed', 'failed', 'cancelled']:
                                success = cached_status == 'completed'
                                print(f"[{arch}] Build appears to be {'SUCCESS' if success else 'FAILED'} based on cached data")
                                result_queue.put((arch, success))
                                arch_build_info[arch]['status'] = cached_status
                                break
                            else:
                                print(f"[{arch}] Giving up monitoring due to prolonged server unavailability")
                                result_queue.put((arch, False))
                                arch_build_info[arch]['status'] = 'failed_server_unavailable'
                                break
                        else:
                            print(f"[{arch}] Server unavailable ({server_unavailable_count}/{max_server_unavailable}), using cached data")
                            if verbose:
                                print(f"[{arch}] Cached status: {status.get('status', 'unknown')}")
                    else:
                        server_unavailable_count = 0  # Reset counter on successful response

                    consecutive_errors = 0  # Reset error count on success

                    if status['status'] != last_status:
                        print(f"[{arch}] Status: {status['status']}")
                        last_status = status['status']
                        arch_build_info[arch]['status'] = status['status']

                    if status['status'] in ['completed', 'failed', 'cancelled']:
                        # Download results if output_dir provided
                        if arch_output_dir and status['status'] in ['completed', 'failed']:
                            try:
                                downloaded_files = []

                                # Check if server is unavailable
                                if status.get('server_unavailable'):
                                    print(f"[{arch}] Server unavailable - cannot download build artifacts")
                                    print(f"[{arch}] You may need to download files manually when server recovers")
                                else:
                                    # Download packages (for successful builds)
                                    if 'packages' in status and status['packages']:
                                        for package in status['packages']:
                                            if client.download_file(build_id, package['filename'], arch_output_dir):
                                                print(f"[{arch}] Downloaded: {package['filename']}")
                                                downloaded_files.append(package['filename'])
                                            else:
                                                print(f"[{arch}] Failed to download: {package['filename']}")

                                    # Download logs (for all builds, including failed ones)
                                    if 'logs' in status and status['logs']:
                                        for log in status['logs']:
                                            if client.download_file(build_id, log['filename'], arch_output_dir):
                                                print(f"[{arch}] Downloaded: {log['filename']}")
                                                downloaded_files.append(log['filename'])
                                            else:
                                                print(f"[{arch}] Failed to download: {log['filename']}")

                                    if downloaded_files:
                                        print(f"[{arch}] Downloaded {len(downloaded_files)} files")
                                    else:
                                        print(f"[{arch}] No files available for download")

                            except requests.RequestException as e:
                                if "503" in str(e) or "502" in str(e):
                                    print(f"[{arch}] Server unavailable - cannot download build artifacts: {e}")
                                    print(f"[{arch}] You may need to download files manually when server recovers")
                                else:
                                    print(f"[{arch}] Error downloading files: {e}")

                        # Build finished
                        success = status['status'] == 'completed'
                        print(f"[{arch}] Build {'SUCCESS' if success else 'FAILED'}")
                        result_queue.put((arch, success))
                        arch_build_info[arch]['status'] = 'completed' if success else 'failed'
                        break

                    # Wait before next status check
                    stop_event.wait(5)

                except requests.RequestException as e:
                    if "503" in str(e) or "502" in str(e):
                        # Server unavailable - these are expected during outages
                        server_unavailable_count += 1
                        if server_unavailable_count >= max_server_unavailable:
                            print(f"[{arch}] Server has been unavailable for {server_unavailable_count} consecutive attempts")
                            print(f"[{arch}] Build may be running but server is unreachable")
                            result_queue.put((arch, False))
                            arch_build_info[arch]['status'] = 'failed_server_unavailable'
                            break
                        else:
                            print(f"[{arch}] Server unavailable (attempt {server_unavailable_count}/{max_server_unavailable}), retrying...")
                    elif "404" in str(e):
                        # Build not found - could be because server is unavailable or build was never submitted
                        consecutive_errors += 1
                        if consecutive_errors >= max_consecutive_errors:
                            print(f"[{arch}] Build not found (404) after {max_consecutive_errors} attempts")
                            print(f"[{arch}] Server may be unavailable or build was not submitted")
                            result_queue.put((arch, False))
                            arch_build_info[arch]['status'] = 'failed'
                            break
                        else:
                            print(f"[{arch}] Build not found (404), retrying... (attempt {consecutive_errors}/{max_consecutive_errors})")
                    else:
                        consecutive_errors += 1
                        if consecutive_errors >= max_consecutive_errors:
                            print(f"[{arch}] Error monitoring build after {max_consecutive_errors} attempts: {e}")
                            result_queue.put((arch, False))
                            arch_build_info[arch]['status'] = 'failed'
                            break

                    # Wait longer before retrying on error
                    stop_event.wait(10)

        except Exception as e:
            print(f"[{arch}] Error in build thread: {e}")
            result_queue.put((arch, False))
            arch_build_info[arch]['status'] = 'failed'

    # Start monitoring threads
    threads = []
    for build in builds:
        thread = threading.Thread(target=monitor_build_thread, args=(build,))
        thread.daemon = True
        thread.start()
        threads.append(thread)

    cancelled_by_user = False

    try:
        # Wait for all builds to complete
        completed_builds = 0
        while completed_builds < len(builds):
            try:
                # Wait for a build to complete
                arch, success = result_queue.get(timeout=1)
                build_results[arch] = success
                completed_builds += 1
            except queue.Empty:
                # Check if any threads are still alive
                alive_threads = [t for t in threads if t.is_alive()]
                if not alive_threads:
                    # All threads finished but we didn't get all results
                    break
                continue

    except KeyboardInterrupt:
        print("\n--- Build monitoring interrupted by user ---")
        cancelled_by_user = True

        # Signal all threads to stop
        stop_event.set()

        # Cancel all builds
        print("\nCancelling all builds...")
        for build in builds:
            arch = build['arch']
            build_id = build['build_id']
            if arch_build_info.get(arch, {}).get('status') not in ['completed', 'failed', 'cancelled']:
                try:
                    if client.cancel_build(build_id):
                        print(f"[{arch}] Build cancelled successfully")
                        arch_build_info[arch]['status'] = 'cancelled'
                    else:
                        print(f"[{arch}] Failed to cancel build")
                except Exception as cancel_error:
                    print(f"[{arch}] Error cancelling build: {cancel_error}")

        # Fill in results for builds that didn't complete
        for build in builds:
            arch = build['arch']
            if arch not in build_results:
                build_results[arch] = False

    # Wait for all threads to finish
    for thread in threads:
        thread.join(timeout=1)

    # Show final summary
    print("\n=== Final Results ===")
    for build in builds:
        arch = build['arch']
        build_id = build['build_id']
        status = arch_build_info[arch]['status'].upper()
        print(f"[{arch}] {status} (Build ID: {build_id})")
    print("====================")

    successful_builds = sum(1 for success in build_results.values() if success)
    total_builds = len(build_results)
    cancelled_builds = sum(1 for info in arch_build_info.values() if info.get('status') == 'cancelled')

    if cancelled_by_user:
        print(f"Overall result: {successful_builds}/{total_builds} builds successful ({cancelled_builds} cancelled by user)")
    else:
        print(f"Overall result: {successful_builds}/{total_builds} builds successful")

    return all(build_results.values())


def monitor_build(build_id: str, client: APBotClient, output_dir: Path = None,
                 verbose: bool = False, allow_toggle: bool = True,
                 status_callback = None, pkgname: str = None, arch: str = None) -> bool:
    """
    Monitor a build with optional real-time output and automatic downloading.

    Args:
        build_id: Build ID to monitor
        client: Client instance
        output_dir: Directory to download results
        verbose: Enable verbose output
        allow_toggle: Allow toggling output display
        status_callback: Callback for status updates
        pkgname: Package name to display
        arch: Architecture being built (for display purposes)

    Returns:
        True if build was successful
    """
    arch_prefix = f"[{arch}] " if arch else ""

    if verbose:
        print(f"{arch_prefix}Monitoring build: {build_id}")

    # Get initial build info with retry logic
    max_retries = 10
    retry_delay = 1.0
    server_unavailable_count = 0
    max_server_unavailable = 5  # Maximum consecutive server unavailable responses

    for attempt in range(max_retries):
        try:
            initial_status = client.get_build_status(build_id)

            # Check if server is unavailable but we have cached data
            if initial_status.get('server_unavailable'):
                server_unavailable_count += 1
                if server_unavailable_count >= max_server_unavailable:
                    print(f"{arch_prefix}Server has been unavailable for {server_unavailable_count} consecutive checks")
                    print(f"{arch_prefix}Last known status: {initial_status.get('status', 'unknown')}")
                    last_update = initial_status.get('last_status_update')
                    if last_update:
                        try:
                            last_update_str = datetime.fromtimestamp(last_update).strftime('%Y-%m-%d %H:%M:%S')
                            print(f"{arch_prefix}Last status update: {last_update_str}")
                        except:
                            print(f"{arch_prefix}Last status update: {last_update}")

                    # Check if build might be completed based on cached data
                    cached_status = initial_status.get('status', 'unknown')
                    if cached_status in ['completed', 'failed', 'cancelled']:
                        print(f"{arch_prefix}Build appears to be {cached_status} based on cached data")
                        return cached_status == 'completed'
                    else:
                        print(f"{arch_prefix}Build status unclear due to server unavailability")
                        return False
                else:
                    print(f"{arch_prefix}Server unavailable (attempt {server_unavailable_count}/{max_server_unavailable}), using cached data")
                    if verbose:
                        print(f"{arch_prefix}Cached status: {initial_status.get('status', 'unknown')}")
            else:
                server_unavailable_count = 0  # Reset counter on successful response

            if not pkgname:
                pkgname = initial_status.get('pkgname', 'unknown')

            if verbose:
                print(f"{arch_prefix}Package: {pkgname}")
                print(f"{arch_prefix}Initial status: {initial_status['status']}")
            break
        except requests.RequestException as e:
            if "503" in str(e) or "502" in str(e):
                # Server unavailable - these are expected during outages
                server_unavailable_count += 1
                if server_unavailable_count >= max_server_unavailable:
                    print(f"{arch_prefix}Server has been unavailable for {server_unavailable_count} consecutive attempts")
                    print(f"{arch_prefix}Build may be running but server is unreachable")
                    return False
                else:
                    print(f"{arch_prefix}Server unavailable (attempt {server_unavailable_count}/{max_server_unavailable}), retrying...")
            elif "404" in str(e):
                # Build not found - could be because server is unavailable or build was never submitted
                print(f"{arch_prefix}Build not found (404). Server may be unavailable or build was not submitted.")
                if attempt < max_retries - 1:
                    print(f"{arch_prefix}Retrying in {retry_delay:.1f} seconds...")
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 1.5, 10.0)
                    continue
                else:
                    print(f"{arch_prefix}Build not found after {max_retries} attempts")
                    return False
            else:
                if attempt < max_retries - 1:
                    if verbose:
                        print(f"{arch_prefix}Waiting for build to be available (attempt {attempt + 1}/{max_retries}): {e}")
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 1.5, 5.0)
                else:
                    print(f"{arch_prefix}Error getting build status after {max_retries} attempts: {e}")
                    return False

    # Monitor build progress
    last_status = None
    consecutive_server_errors = 0
    max_consecutive_server_errors = 10

    try:
        for update in client.stream_build_updates(build_id):
            # Check if server is unavailable
            if update.get('server_unavailable'):
                consecutive_server_errors += 1
                if consecutive_server_errors >= max_consecutive_server_errors:
                    print(f"{arch_prefix}Server has been unavailable for {consecutive_server_errors} consecutive status checks")
                    print(f"{arch_prefix}Last known status: {update.get('status', 'unknown')}")

                    # If we have a final status, use it
                    cached_status = update.get('status', 'unknown')
                    if cached_status in ['completed', 'failed', 'cancelled']:
                        print(f"{arch_prefix}Build appears to be {cached_status} based on cached data")
                        last_status = cached_status
                        break
                    else:
                        print(f"{arch_prefix}Giving up monitoring due to prolonged server unavailability")
                        return False
                else:
                    if verbose:
                        print(f"{arch_prefix}Server unavailable ({consecutive_server_errors}/{max_consecutive_server_errors}), status: {update.get('status', 'unknown')}")
            else:
                consecutive_server_errors = 0  # Reset on successful response

            if update['status'] != last_status:
                print(f"{arch_prefix}Status: {update['status']}")
                last_status = update['status']

                if status_callback:
                    status_callback(update)

            if update['status'] in ['completed', 'failed', 'cancelled']:
                break
    except KeyboardInterrupt:
        print(f"\n{arch_prefix}Build interrupted by user. Cancelling build...")
        try:
            if client.cancel_build(build_id):
                print(f"{arch_prefix}Build cancelled successfully")
                last_status = 'cancelled'
            else:
                print(f"{arch_prefix}Failed to cancel build - it may continue running")
        except Exception as e:
            print(f"{arch_prefix}Error cancelling build: {e}")

        # Re-raise the KeyboardInterrupt to allow calling code to handle it
        raise
    except requests.RequestException as e:
        if "503" in str(e) or "502" in str(e):
            print(f"{arch_prefix}Server became unavailable during monitoring: {e}")
            # Try to get final status
            try:
                final_status = client.get_build_status(build_id)
                if final_status.get('server_unavailable'):
                    cached_status = final_status.get('status', 'unknown')
                    print(f"{arch_prefix}Using cached status: {cached_status}")
                    last_status = cached_status
                else:
                    last_status = final_status['status']
                    print(f"{arch_prefix}Final status: {last_status}")
            except requests.RequestException:
                print(f"{arch_prefix}Unable to get final status due to server unavailability")
                return False
        else:
            print(f"{arch_prefix}Error monitoring build: {e}")
            # Try to get final status
            try:
                final_status = client.get_build_status(build_id)
                last_status = final_status['status']
                print(f"{arch_prefix}Final status: {last_status}")
            except requests.RequestException:
                print(f"{arch_prefix}Unable to get final status")
                return False

    # Download results if output_dir provided
    if output_dir and last_status in ['completed', 'failed']:
        try:
            final_status = client.get_build_status(build_id)
            downloaded_files = []

            # Check if server is unavailable
            if final_status.get('server_unavailable'):
                print(f"{arch_prefix}Server unavailable - cannot download build artifacts")
                print(f"{arch_prefix}You may need to download files manually when server recovers")
                return last_status == 'completed'

            # Download packages (for successful builds)
            if 'packages' in final_status and final_status['packages']:
                for package in final_status['packages']:
                    if client.download_file(build_id, package['filename'], output_dir):
                        print(f"{arch_prefix}Downloaded: {package['filename']}")
                        downloaded_files.append(package['filename'])
                    else:
                        print(f"{arch_prefix}Failed to download: {package['filename']}")

            # Download logs (for all builds, including failed ones)
            if 'logs' in final_status and final_status['logs']:
                for log in final_status['logs']:
                    if client.download_file(build_id, log['filename'], output_dir):
                        print(f"{arch_prefix}Downloaded: {log['filename']}")
                        downloaded_files.append(log['filename'])
                    else:
                        print(f"{arch_prefix}Failed to download: {log['filename']}")

            if downloaded_files:
                print(f"{arch_prefix}Downloaded {len(downloaded_files)} files")
            else:
                print(f"{arch_prefix}No files available for download")

        except requests.RequestException as e:
            if "503" in str(e) or "502" in str(e):
                print(f"{arch_prefix}Server unavailable - cannot download build artifacts: {e}")
                print(f"{arch_prefix}You may need to download files manually when server recovers")
            else:
                print(f"{arch_prefix}Error downloading files: {e}")

    return last_status == 'completed'


def build_for_multiple_arches(build_path: Path, output_dir: Path, config: Dict,
                            verbose: bool = False, detach: bool = False,
                            specific_arch: str = None, force: bool = False, auth_client: Optional[APBAuthClient] = None) -> bool:
    """
    Build a package for multiple architectures using available servers.

    Args:
        build_path: Path to package directory
        output_dir: Output directory
        config: Configuration dictionary
        verbose: Enable verbose output
        detach: Don't wait for completion
        specific_arch: Build for specific architecture only
        force: Force rebuild even if package exists

    Returns:
        True if all builds were successful
    """
    pkgbuild_path = build_path / "PKGBUILD"
    if not pkgbuild_path.exists():
        print(f"Error: PKGBUILD not found in {build_path}")
        return False

    servers = config.get("servers", {})

    # Use architectures from PKGBUILD if no specific architecture is requested
    if specific_arch:
        architectures = [specific_arch]
    else:
        # Parse PKGBUILD to get target architectures
        pkg_info = parse_pkgbuild_info(pkgbuild_path)
        pkgbuild_archs = pkg_info.get("arch", ["x86_64"])

        # Filter to only include architectures we have servers for
        # Special case: "any" architecture can be built on any available server
        if "any" in pkgbuild_archs:
            # For "any" architecture, we can use any available server
            architectures = ["any"]
        else:
            # For specific architectures, only use those we have servers for
            architectures = [arch for arch in pkgbuild_archs if arch in servers]

        if not architectures:
            print(f"Error: No servers configured for PKGBUILD architectures: {pkgbuild_archs}")
            print(f"Available server architectures: {list(servers.keys())}")
            return False

    # Show which architectures will be built
    print(f"Building for architectures: {', '.join(architectures)}")

    build_results = []
    arch_build_info = {}  # Track build info for each architecture

    # Submit builds for all architectures
    for arch in architectures:
        # Special handling for "any" architecture
        if arch == "any":
            # For "any" architecture, we can use any available server
            # Pick the first available server architecture
            available_server_archs = [k for k, v in servers.items() if v]
            if not available_server_archs:
                print(f"[{arch}] No servers available for any architecture")
                continue
            # Use the first available server architecture
            server_arch = available_server_archs[0]
            server_urls = servers[server_arch]
            if verbose:
                print(f"[{arch}] Using {server_arch} servers for 'any' architecture build")
        else:
            if arch not in servers:
                print(f"[{arch}] No servers configured for architecture: {arch}")
                continue

            server_urls = servers[arch]
            if not server_urls:
                print(f"[{arch}] No servers available for architecture: {arch}")
                continue

        # Check if package already exists (unless force is specified)
        should_skip, reason = should_skip_build(output_dir, pkgbuild_path, arch, force)
        if should_skip:
            print(f"[{arch}] Skipping build: {reason}")
            if not force:
                print(f"[{arch}] Use --force to rebuild existing packages")
            arch_build_info[arch] = {
                'build_id': None,
                'server_url': None,
                'status': 'skipped'
            }
            continue

        if verbose and not force:
            print(f"[{arch}] {reason}")

        # Try each server for this architecture
        build_successful = False
        for server_url in server_urls:
            try:
                if verbose:
                    print(f"[{arch}] Submitting build to {server_url}...")

                build_id = submit_build(server_url, build_path, auth_client)
                if build_id:
                    print(f"[{arch}] Build submitted: {build_id}")
                    arch_build_info[arch] = {
                        'build_id': build_id,
                        'server_url': server_url,
                        'status': 'submitted'
                    }
                    build_successful = True
                    break

            except Exception as e:
                if verbose:
                    print(f"[{arch}] Error with server {server_url}: {e}")
                continue

        if not build_successful:
            print(f"[{arch}] Failed to submit build")
            arch_build_info[arch] = {
                'build_id': None,
                'server_url': None,
                'status': 'failed'
            }

    # Show summary of submitted builds
    print("\n=== Build Summary ===")
    for arch, info in arch_build_info.items():
        if info['build_id']:
            print(f"[{arch}] Build ID: {info['build_id']}")
        else:
            print(f"[{arch}] Build submission failed")
    print("====================\n")

    if detach:
        print("Builds submitted. Exiting without waiting for completion.")
        return True

    # Monitor all builds
    builds_to_monitor = {arch: info for arch, info in arch_build_info.items()
                        if info['build_id'] and info['status'] != 'skipped'}

    if builds_to_monitor:
        print("Monitoring build progress...")
    cancelled_by_user = False

    for arch, info in arch_build_info.items():
        if not info['build_id']:
            if info['status'] == 'skipped':
                build_results.append(True)  # Treat skipped as successful
            else:
                build_results.append(False)
            continue

        try:
            client = APBotClient(info['server_url'], auth_client)
            # For "any" architecture, download to "any" subdirectory
            if arch == "any":
                arch_output_dir = output_dir / "any"
            else:
                arch_output_dir = output_dir / arch

            print(f"\n--- Starting monitoring for {arch} ---")
            success = monitor_build(
                info['build_id'],
                client,
                arch_output_dir,
                verbose,
                arch=arch
            )
            print(f"--- Finished monitoring for {arch}: {'SUCCESS' if success else 'FAILED'} ---\n")

            build_results.append(success)
            arch_build_info[arch]['status'] = 'completed' if success else 'failed'

        except KeyboardInterrupt:
            print(f"\n--- Build monitoring interrupted for {arch} ---")
            cancelled_by_user = True
            build_results.append(False)
            arch_build_info[arch]['status'] = 'cancelled'

            # Cancel all remaining builds
            print("\nCancelling all remaining builds...")
            for remaining_arch, remaining_info in arch_build_info.items():
                if remaining_info['build_id'] and remaining_info.get('status') not in ['completed', 'failed', 'cancelled']:
                    try:
                        remaining_client = APBotClient(remaining_info['server_url'], auth_client)
                        if remaining_client.cancel_build(remaining_info['build_id']):
                            print(f"[{remaining_arch}] Build cancelled successfully")
                            arch_build_info[remaining_arch]['status'] = 'cancelled'
                        else:
                            print(f"[{remaining_arch}] Failed to cancel build")
                    except Exception as cancel_error:
                        print(f"[{remaining_arch}] Error cancelling build: {cancel_error}")
            break

        except Exception as e:
            print(f"[{arch}] Error monitoring build: {e}")
            build_results.append(False)
            arch_build_info[arch]['status'] = 'failed'

    # Show final summary
    print("\n=== Final Results ===")
    for arch, info in arch_build_info.items():
        status_display = info['status'].upper()
        if info['build_id']:
            print(f"[{arch}] {status_display} (Build ID: {info['build_id']})")
        else:
            print(f"[{arch}] {status_display}")
    print("====================")

    successful_builds = sum(1 for result in build_results if result)
    total_builds = len(build_results)
    skipped_builds = sum(1 for info in arch_build_info.values() if info.get('status') == 'skipped')
    cancelled_builds = sum(1 for info in arch_build_info.values() if info.get('status') == 'cancelled')

    if skipped_builds > 0:
        if cancelled_by_user:
            print(f"Overall result: {successful_builds}/{total_builds} builds successful ({skipped_builds} skipped, {cancelled_builds} cancelled by user)")
        else:
            print(f"Overall result: {successful_builds}/{total_builds} builds successful ({skipped_builds} skipped)")
    else:
        if cancelled_by_user:
            print(f"Overall result: {successful_builds}/{total_builds} builds successful ({cancelled_builds} cancelled by user)")
        else:
            print(f"Overall result: {successful_builds}/{total_builds} builds successful")

    return all(build_results)


def main():
    """Main command-line interface."""
    parser = argparse.ArgumentParser(description="APB Client - Build packages using APB servers")

    # Basic options
    parser.add_argument("pkgbuild_path", nargs="?", type=Path,
                       help="Path to PKGBUILD or package directory")
    parser.add_argument("--server", type=str, help="Server URL")
    parser.add_argument("--arch", type=str, help="Target architecture(s) (comma-separated)")
    parser.add_argument("--config", type=Path, help="Path to configuration file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--quiet", action="store_true", help="Suppress output except errors")

    # Authentication options
    parser.add_argument("--login", action="store_true", help="Login to farm")
    parser.add_argument("--logout", action="store_true", help="Logout from farm")
    parser.add_argument("--auth-status", action="store_true", help="Show authentication status")
    parser.add_argument("--username", type=str, help="Username for login")

    # Build options
    parser.add_argument("--output-dir", type=Path, default=Path("./output"),
                       help="Output directory for downloaded files")
    parser.add_argument("--detach", action="store_true",
                       help="Submit build and exit (don't wait for completion)")
    parser.add_argument("--no-download", action="store_true",
                       help="Don't download build results")
    parser.add_argument("--force", action="store_true",
                       help="Force rebuild even if package exists")
    parser.add_argument("--build-timeout", type=int,
                       help="Build timeout in seconds (300-14400, admin only)")

    # Monitoring options
    parser.add_argument("--monitor", type=str, help="Monitor existing build")
    parser.add_argument("--download", type=str, help="Download build results")
    parser.add_argument("--status", type=str, help="Check build status")
    parser.add_argument("--cancel", type=str, help="Cancel running build")

    # Advanced options
    parser.add_argument("--farm", action="store_true", help="Use APB Farm instead of direct server")
    parser.add_argument("--list-servers", action="store_true", help="List available servers")
    parser.add_argument("--cleanup", action="store_true", help="Trigger server cleanup")
    parser.add_argument("--test-arch", action="store_true", help="Test architecture compatibility")

    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)

    # Determine server URL
    if args.server:
        server_url = args.server
    elif args.farm:
        server_url = config.get("farm_url", "http://localhost:8080")
    else:
        server_url = config.get("default_server", "http://localhost:8000")

    # Setup authentication for farm connections
    auth_client = None
    if args.farm or server_url == config.get("farm_url"):
        auth_client = APBAuthClient(server_url)
    elif any([args.login, args.logout, args.auth_status]) and config.get("farm_url"):
        # For auth operations, automatically use farm_url from config even if --farm wasn't specified
        farm_url = config.get("farm_url")
        auth_client = APBAuthClient(farm_url)
        # Update server_url to match for consistency in auth operations
        server_url = farm_url

    # Handle authentication operations
    if args.login:
        if not auth_client:
            print("Error: Login is only supported for farm connections.")
            print("Either use --farm flag or configure farm_url in your apb.json file.")
            sys.exit(1)

        username = args.username or input("Username: ")
        password = getpass.getpass("Password: ")

        if auth_client.login(username, password):
            print("Login successful!")
            # Show user info
            user_info = auth_client.get_user_info()
            if user_info:
                print(f"Logged in as: {user_info['username']} ({user_info['role']})")
        else:
            print("Login failed!")
            sys.exit(1)
        sys.exit(0)

    if args.logout:
        if not auth_client:
            print("Error: Logout is only supported for farm connections.")
            print("Either use --farm flag or configure farm_url in your apb.json file.")
            sys.exit(1)

        if auth_client.logout():
            print("Logout successful!")
        else:
            print("Logout failed!")
        sys.exit(0)

    if args.auth_status:
        if not auth_client:
            print("Authentication is only supported for farm connections.")
            print("Either use --farm flag or configure farm_url in your apb.json file.")
            sys.exit(0)

        if auth_client.is_authenticated():
            user_info = auth_client.get_user_info()
            if user_info:
                print(f"Authenticated as: {user_info['username']} ({user_info['role']})")
                print(f"Farm URL: {server_url}")
            else:
                print("Authentication token is invalid")
        else:
            print("Not authenticated")
            print(f"Farm URL: {server_url}")
            print("Use --login to authenticate")
        sys.exit(0)

    client = APBotClient(server_url, auth_client)

    # Handle monitoring operations
    if args.monitor:
        # Create architecture-specific output directory if downloads are enabled
        output_dir = None
        if not args.no_download:
            # Try to get architecture from build status or use command line arg or default
            try:
                status = client.get_build_status(args.monitor)
                status_arch = status.get('server_arch') or status.get('arch')
                if isinstance(status_arch, list):
                    status_arch = status_arch[0] if status_arch else None
                build_arch = status_arch or (args.arch.split(',')[0] if args.arch else None) or config.get("default_arch", "powerpc64le")
            except:
                build_arch = (args.arch.split(',')[0] if args.arch else None) or config.get("default_arch", "powerpc64le")
            output_dir = args.output_dir / build_arch

        try:
            success = monitor_build(args.monitor, client, output_dir,
                                  args.verbose, allow_toggle=True)
            sys.exit(0 if success else 1)
        except KeyboardInterrupt:
            print("\nBuild monitoring interrupted by user")
            sys.exit(1)

    if args.download:
        try:
            status = client.get_build_status(args.download)
            downloaded_files = []

            # Determine architecture for output directory
            # Try to get arch from status (prefer server_arch for farm builds), command line arg, or use default
            status_arch = status.get('server_arch') or status.get('arch')
            if isinstance(status_arch, list):
                status_arch = status_arch[0] if status_arch else None

            build_arch = status_arch or (args.arch.split(',')[0] if args.arch else None) or config.get("default_arch")
            arch_output_dir = args.output_dir / build_arch

            # Download packages (for successful builds)
            if 'packages' in status and status['packages']:
                for package in status['packages']:
                    if client.download_file(args.download, package['filename'], arch_output_dir):
                        print(f"Downloaded: {package['filename']}")
                        downloaded_files.append(package['filename'])
                    else:
                        print(f"Failed to download: {package['filename']}")

            # Download logs (for all builds, including failed ones)
            if 'logs' in status and status['logs']:
                for log in status['logs']:
                    if client.download_file(args.download, log['filename'], arch_output_dir):
                        print(f"Downloaded: {log['filename']}")
                        downloaded_files.append(log['filename'])
                    else:
                        print(f"Failed to download: {log['filename']}")

            if not downloaded_files:
                print("No files available for download")
                sys.exit(1)

            sys.exit(0)
        except requests.RequestException as e:
            print(f"Error: {e}")
            sys.exit(1)

    if args.status:
        try:
            status = client.get_build_status(args.status)
            print(f"Build ID: {status['build_id']}")
            print(f"Package: {status.get('pkgname', 'unknown')}")
            print(f"Status: {status['status']}")
            if 'duration' in status:
                print(f"Duration: {status['duration']:.1f}s")
            sys.exit(0)
        except requests.RequestException as e:
            print(f"Error: {e}")
            sys.exit(1)

    if args.cancel:
        if client.cancel_build(args.cancel):
            print("Build cancelled successfully")
            sys.exit(0)
        else:
            print("Failed to cancel build")
            sys.exit(1)

    if args.list_servers:
        if args.server or args.farm:
            print(f"Testing server: {server_url}")
            try:
                # Try to get server info
                response = client.session.get(urljoin(server_url, '/farm'))
                if response.status_code == 200:
                    farm_info = response.json()
                    print(f"  Status: {farm_info.get('status', 'unknown')}")
                    print(f"  Version: {farm_info.get('version', 'unknown')}")
                    if 'servers' in farm_info:
                        print(f"  Managed servers: {len(farm_info['servers'])}")
                        for server in farm_info['servers']:
                            print(f"    {server.get('arch', 'unknown')}: {server.get('status', 'unknown')}")
                else:
                    # Try direct server endpoint
                    response = client.session.get(urljoin(server_url, '/'))
                    if response.status_code == 200:
                        print(f"  Status: Server accessible (HTTP {response.status_code})")
                    else:
                        print(f"  Status: Server returned HTTP {response.status_code}")
            except Exception as e:
                print(f"  Status: Error - {e}")
        else:
            print("Configured servers:")
            for arch, servers in config.get("servers", {}).items():
                print(f"  {arch}:")
                for server in servers:
                    print(f"    {server}")
        sys.exit(0)

    if args.cleanup:
        if client.cleanup_server():
            print("Server cleanup triggered")
            sys.exit(0)
        else:
            print("Failed to trigger cleanup")
            sys.exit(1)

    # Handle build submission
    if not args.pkgbuild_path:
        # Try to find PKGBUILD in current directory
        current_pkgbuild = Path("./PKGBUILD")
        if current_pkgbuild.exists():
            args.pkgbuild_path = Path(".")
        else:
            print("Error: No PKGBUILD path provided and none found in current directory")
            sys.exit(1)

    build_path = args.pkgbuild_path
    if build_path.is_file():
        build_path = build_path.parent

    # If --server or --farm is specified, use that server directly
    if args.server or args.farm:
        pkgbuild_path = build_path / "PKGBUILD"
        if not pkgbuild_path.exists():
            print(f"Error: PKGBUILD not found in {build_path}")
            sys.exit(1)



        # For farm submissions, check which architectures need building
        if args.farm:
            # Get architectures that need building
            architectures_needing_build = get_architectures_needing_build(pkgbuild_path, args.output_dir, args.force)

            if not architectures_needing_build:
                print("All packages already exist in output directory")
                if not args.force:
                    print("Use --force to rebuild existing packages")
                sys.exit(0)

            # Show which architectures need building
            if args.verbose:
                pkg_info = parse_pkgbuild_info(pkgbuild_path)
                all_archs = pkg_info.get("arch", ["x86_64"])
                skipped_archs = [arch for arch in all_archs if arch not in architectures_needing_build]

                if skipped_archs:
                    print(f"Skipping existing packages for architectures: {', '.join(skipped_archs)}")
                print(f"Building for architectures: {', '.join(architectures_needing_build)}")
        else:
            # For direct server submissions, use original logic
            target_arch = args.arch if args.arch and ',' not in args.arch else None
            if not target_arch:
                target_arch = config.get("default_arch")

            # Check if package already exists (unless force is specified)
            should_skip, reason = should_skip_build(args.output_dir, pkgbuild_path, target_arch, args.force)
            if should_skip:
                print(f"Skipping build: {reason}")
                if not args.force:
                    print("Use --force to rebuild existing packages")
                sys.exit(0)

            if args.verbose and not args.force:
                print(reason)

        try:
            if args.verbose:
                print(f"Submitting build to {server_url}...")
                if not args.farm and target_arch:
                    print(f"Target architecture: {target_arch}")

            if args.farm:
                # Handle farm submission with multiple architectures
                response = submit_build_to_farm(server_url, build_path, architectures_needing_build, auth_client, args.build_timeout)
                if response:
                    if 'builds' in response and response['builds']:
                        # Multi-architecture farm response
                        builds = response['builds']

                        if builds:
                            print(f"Monitoring {len(builds)} build(s): {response['message']}")
                        else:
                            print("No builds to monitor (all packages already exist)")
                            sys.exit(0)

                        if not args.detach and builds:
                            # Give the farm a moment to process the builds
                            time.sleep(0.5)

                            # Create base output directory if downloads are enabled
                            output_dir = None
                            if not args.no_download:
                                output_dir = args.output_dir

                            try:
                                success = monitor_farm_builds(builds, client, output_dir, args.verbose, pkgbuild_path, auth_client)
                                sys.exit(0 if success else 1)
                            except KeyboardInterrupt:
                                print("\nBuilds interrupted by user")
                                sys.exit(1)
                        else:
                            # Show submitted builds and exit
                            for build in builds:
                                print(f"[{build['arch']}] Build ID: {build['build_id']}")
                            sys.exit(0)
                    elif 'error' in response:
                        print(f"Error: {response['message']}")
                        if 'available_architectures' in response:
                            print(f"Available architectures: {', '.join(response['available_architectures'])}")
                        if 'target_architectures' in response:
                            print(f"Requested architectures: {', '.join(response['target_architectures'])}")
                        if 'pkgbuild_architectures' in response:
                            print(f"PKGBUILD architectures: {', '.join(response['pkgbuild_architectures'])}")
                        sys.exit(1)
                    else:
                        # Single build or legacy response
                        build_id = response.get('build_id')
                        if build_id:
                            print(f"Build submitted: {build_id}")

                            if not args.detach:
                                # Give the farm a moment to process the build
                                time.sleep(0.5)

                                # Create architecture-specific output directory if downloads are enabled
                                output_dir = None
                                if not args.no_download:
                                    # Determine architecture for output directory (use first needed architecture)
                                    build_arch = architectures_needing_build[0] if architectures_needing_build else config.get("default_arch")
                                    output_dir = args.output_dir / build_arch

                                try:
                                    # Use first needed architecture for display
                                    display_arch = architectures_needing_build[0] if architectures_needing_build else None
                                    success = monitor_build(build_id, client, output_dir,
                                                          args.verbose, allow_toggle=True, arch=display_arch)
                                    sys.exit(0 if success else 1)
                                except KeyboardInterrupt:
                                    print("\nBuild interrupted by user")
                                    sys.exit(1)
                            else:
                                print(f"Build submitted: {build_id}")
                                sys.exit(0)
                        else:
                            print("Failed to submit build")
                            sys.exit(1)
                else:
                    print("Failed to submit build")
                    sys.exit(1)
            else:
                # Handle direct server submission (single architecture)
                build_id = submit_build(server_url, build_path, auth_client)
                if build_id:
                    print(f"Build submitted: {build_id}")

                    if not args.detach:
                        # Give the farm a moment to process the build
                        time.sleep(0.5)

                        # Create architecture-specific output directory if downloads are enabled
                        output_dir = None
                        if not args.no_download:
                            # Determine architecture for output directory
                            build_arch = target_arch or config.get("default_arch")
                            output_dir = args.output_dir / build_arch

                        try:
                            success = monitor_build(build_id, client, output_dir,
                                                  args.verbose, allow_toggle=True, arch=target_arch)
                            sys.exit(0 if success else 1)
                        except KeyboardInterrupt:
                            print("\nBuild interrupted by user")
                            sys.exit(1)
                    else:
                        print(f"Build submitted: {build_id}")
                        sys.exit(0)
                else:
                    print("Failed to submit build")
                    sys.exit(1)
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)

    # Build for multiple architectures or specific architecture using config
    try:
        if args.arch:
            architectures = [arch.strip() for arch in args.arch.split(",")]
            if len(architectures) == 1:
                # Single architecture build
                success = build_for_multiple_arches(
                    build_path, args.output_dir, config,
                    args.verbose, args.detach, architectures[0], args.force, auth_client
                )
            else:
                # Multiple architectures - build sequentially
                success = True
                for arch in architectures:
                    print(f"\n{'='*50}")
                    print(f"Building for architecture: {arch}")
                    print(f"{'='*50}")
                    arch_success = build_for_multiple_arches(
                        build_path, args.output_dir, config,
                        args.verbose, args.detach, arch, args.force, auth_client
                    )
                    success = success and arch_success
                    if not arch_success:
                        print(f"Build failed for architecture: {arch}")
        else:
            success = build_for_multiple_arches(
                build_path, args.output_dir, config,
                args.verbose, args.detach, None, args.force, auth_client
            )
    except KeyboardInterrupt:
        print("\nBuilds interrupted by user")
        sys.exit(1)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
