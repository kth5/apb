"""APB HTTP API client."""

import json
import logging
import os
import queue
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional
from urllib.parse import urljoin

import httpx

from apb import VERSION
from apb.http import create_sync_client
from apb.tarball import create_build_tarball

if True:
    from apb.client.auth import APBAuthClient

logger = logging.getLogger(__name__)

class APBotClient:
    """Main client class for interacting with APB servers."""

    def __init__(self, server_url: str, auth_client: Optional[APBAuthClient] = None):
        """Initialize APBotClient with server URL and optional authentication."""
        self.server_url = server_url.rstrip('/')
        self.session = create_sync_client(component="Client")
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
            httpx.HTTPStatusError: On HTTP error responses
            httpx.HTTPError: On connection errors
            ValueError: On invalid response or missing PKGBUILD
        """
        # Ensure we have a PKGBUILD
        pkgbuild_path = build_path / "PKGBUILD"
        if not pkgbuild_path.exists():
            raise ValueError(f"PKGBUILD not found in {build_path}")

        with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as temp_tarball:
            try:
                create_build_tarball(build_path, Path(temp_tarball.name))

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

    def wait_for_farm_artifacts(
        self,
        build_id: str,
        timeout: float = 300.0,
        poll_interval: float = 2.0,
    ) -> bool:
        """
        Wait until the farm has cached all build artifacts locally.

        The client must not download artifacts until the farm reports
        ``artifacts_ready`` in the build status response.
        """
        deadline = time.time() + timeout

        while time.time() < deadline:
            status = self.get_build_status(build_id)
            build_status = status.get("status", "unknown")

            if status.get("artifacts_ready"):
                return True

            if build_status not in ("completed", "failed"):
                return False

            time.sleep(poll_interval)

        return False

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
        except httpx.HTTPError:
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
            with self.session.stream("GET", url) as response:
                response.raise_for_status()

                output_dir.mkdir(parents=True, exist_ok=True)
                output_path = output_dir / filename

                with open(output_path, "wb") as handle:
                    for chunk in response.iter_bytes(chunk_size=8192):
                        handle.write(chunk)

            return True
        except httpx.HTTPError:
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
        except httpx.HTTPError:
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
        url = urljoin(self.server_url, f'/builds/pkgname/{pkgname}')
        response = self.session.get(url, params={'limit': limit})
        response.raise_for_status()
        return response.json()

    def get_latest_build_by_pkgname(self, pkgname: str, successful_only: bool = True,
                                    arch: Optional[str] = None) -> Dict:
        """
        Get the latest build for a specific package.

        Args:
            pkgname: Package name
            successful_only: Only consider successful builds
            arch: Optional architecture. Use 'any' for arch=('any') packages
                  (matches latest build regardless of server_arch).

        Returns:
            Latest build information, or empty dict if none found
        """
        def _normalize_build(build: Dict) -> Dict:
            if build and 'build_id' not in build and 'id' in build:
                build['build_id'] = build['id']
            return build

        if arch:
            url = urljoin(self.server_url, f'/builds/pkgname/{pkgname}/arch/{arch}/latest')
        else:
            url = urljoin(self.server_url, f'/builds/pkgname/{pkgname}/latest')

        try:
            response = self.session.get(url, params={'successful_only': successful_only})
            if response.status_code == 200:
                return _normalize_build(response.json())
        except httpx.HTTPError:
            pass

        # Fall back to list endpoint for older servers or empty results
        try:
            builds = self.get_builds_by_pkgname(pkgname, limit=50)
        except httpx.HTTPError:
            return {}

        if not builds.get('builds'):
            return {}

        for build in builds['builds']:
            if successful_only and build.get('status') != 'completed':
                continue
            if arch and arch != 'any' and build.get('server_arch') != arch:
                continue
            return _normalize_build(build)
        return {}

    def get_latest_builds_by_pkgname_per_arch(self, pkgname: str,
                                              successful_only: bool = True) -> Dict[str, Dict]:
        """
        Get the latest build for each architecture of a package.

        Returns:
            Mapping of server_arch -> build info
        """
        def _normalize_build(build: Dict) -> Dict:
            if build and 'build_id' not in build and 'id' in build:
                build['build_id'] = build['id']
            return build

        builds: List[Dict] = []
        url = urljoin(self.server_url, f'/builds/pkgname/{pkgname}/latest-by-arch')
        try:
            response = self.session.get(url, params={'successful_only': successful_only})
            if response.status_code == 200:
                builds = response.json().get('builds', [])
        except httpx.HTTPError:
            builds = []

        if not builds:
            try:
                listed = self.get_builds_by_pkgname(pkgname, limit=100).get('builds', [])
            except httpx.HTTPError:
                return {}
            latest: Dict[str, Dict] = {}
            for build in listed:
                if successful_only and build.get('status') != 'completed':
                    continue
                arch = build.get('server_arch')
                if arch and arch not in latest:
                    latest[arch] = build
            builds = list(latest.values())

        result: Dict[str, Dict] = {}
        for build in builds:
            build = _normalize_build(build)
            arch = build.get('server_arch')
            if arch:
                result[arch] = build
        return result

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
            with self.session.stream("GET", url) as response:
                response.raise_for_status()

                for line in response.iter_lines():
                    if line:
                        yield f"{line}\n"
        except httpx.HTTPError:
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
            except httpx.HTTPError as e:
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
        except httpx.HTTPError:
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

