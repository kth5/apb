"""APB HTTP API client."""

import logging
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Generator, Iterable, List, Optional

import httpx
from pydantic import ValidationError

from apb.constants import BuildStatus
from apb.http import create_sync_client
from apb.models import (
    BuildListResponse,
    BuildStatusResponse,
    BuildSubmitResponse,
    BuildSummary,
    FarmBuildSubmitResponse,
)
from apb.tarball import create_build_tarball
from apb.validation import validate_build_timeout
from apb.upstream import (
    ADMIN_CLEANUP_PATH,
    BUILD_SUBMIT_PATH,
    build_cancel_path,
    build_download_path,
    build_output_path,
    build_status_path,
    build_stream_path,
    download,
    pkgname_builds_path,
    pkgname_latest_by_arch_path,
    pkgname_latest_path,
    upstream_url,
)

if True:
    from apb.client.auth import APBAuthClient

logger = logging.getLogger(__name__)


class BuildRejectedError(ValueError):
    """The farm answered the submission with an ``error`` payload instead of queuing builds."""

    def __init__(self, detail: Dict[str, Any]):
        super().__init__(detail.get("message") or detail.get("error"))
        self.detail = detail


class APBotClient:
    """Main client class for interacting with APB servers."""

    def __init__(self, server_url: str, auth_client: Optional[APBAuthClient] = None):
        """Initialize APBotClient with server URL and optional authentication."""
        self.server_url = server_url.rstrip('/')
        self.session = create_sync_client(component="Client")
        self.auth_client = auth_client

        # Set authentication headers if available
        if self.auth_client:
            headers = self.auth_client.get_auth_headers()
            self.session.headers.update(headers)

    def build_package(
        self,
        build_path: Path,
        exclude_paths: Optional[Iterable[Path]] = None,
        architectures: Optional[List[str]] = None,
        build_timeout: Optional[int] = None,
    ) -> BuildSubmitResponse:
        """
        Submit a tarball of the build directory to a server or farm.

        Args:
            build_path: Path to directory containing PKGBUILD and source files
            exclude_paths: Paths left out of the tarball (e.g. the output directory)
            architectures: PKGBUILD architectures the farm should queue (farm only)
            build_timeout: Build timeout in seconds (admin only on the farm)

        Returns:
            FarmBuildSubmitResponse when the farm queued per-architecture builds,
            otherwise the server's BuildSubmitResponse

        Raises:
            httpx.HTTPError: On HTTP error responses or connection errors
            BuildRejectedError: When the farm refuses to queue the submission
            ValueError: On invalid response, build timeout or missing PKGBUILD
        """
        if not (build_path / "PKGBUILD").exists():
            raise ValueError(f"PKGBUILD not found in {build_path}")

        form_data: Dict[str, str] = {}
        if architectures:
            form_data['architectures'] = ','.join(architectures)
        if build_timeout is not None:
            form_data['build_timeout'] = str(validate_build_timeout(build_timeout))

        url = upstream_url(self.server_url, BUILD_SUBMIT_PATH)
        with tempfile.TemporaryDirectory() as temp_dir:
            tarball_path = Path(temp_dir) / "build.tar.gz"
            create_build_tarball(build_path, tarball_path, exclude_paths=exclude_paths)
            with tarball_path.open('rb') as tarball:
                files_data = [('build_tarball', ('build.tar.gz', tarball, 'application/gzip'))]
                response = self.session.post(url, files=files_data, data=form_data)
        response.raise_for_status()

        payload = response.json()
        if "error" in payload:
            raise BuildRejectedError(payload)
        response_model = FarmBuildSubmitResponse if "builds" in payload else BuildSubmitResponse
        try:
            return response_model.model_validate(payload)
        except ValidationError as exc:
            raise ValueError(f"Invalid build submit response: {exc}") from exc

    def get_build_status(self, build_id: str) -> BuildStatusResponse:
        """
        Get the current status of a build.

        Args:
            build_id: Build UUID

        Returns:
            Build status reported by the server or farm
        """
        url = upstream_url(self.server_url, build_status_path(build_id))
        response = self.session.get(url)
        response.raise_for_status()
        return BuildStatusResponse.model_validate(response.json())

    def wait_for_farm_artifacts(
        self,
        build_id: str,
        timeout: float = 300.0,
        poll_interval: float = 2.0,
    ) -> Optional[BuildStatusResponse]:
        """
        Wait until the farm has cached all build artifacts locally.

        The client must not download artifacts until the farm reports
        ``artifacts_ready`` in the build status response. Build servers do not
        report ``artifacts_ready``; their artifacts are ready immediately.

        Returns:
            The status once artifacts are ready, or None on timeout or when the
            build has not finished
        """
        deadline = time.time() + timeout

        while time.time() < deadline:
            status = self.get_build_status(build_id)
            if status.status not in (BuildStatus.COMPLETED, BuildStatus.FAILED):
                return None
            if status.artifacts_ready is not False:
                return status
            time.sleep(poll_interval)

        return None

    def cancel_build(self, build_id: str) -> bool:
        """
        Cancel a running build.

        Args:
            build_id: Build UUID

        Returns:
            True if cancellation was successful
        """
        url = upstream_url(self.server_url, build_cancel_path(build_id))
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
        url = upstream_url(self.server_url, build_download_path(build_id, filename))

        try:
            download(self.session, url, output_dir / Path(filename).name)
            return True
        except (httpx.HTTPError, OSError):
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

            build_id = latest_build.build_id

            status = self.get_build_status(build_id)
            return all(
                self.download_file(build_id, artifact.filename, output_dir)
                for artifact in [*status.packages, *status.logs]
            )
        except httpx.HTTPError:
            return False

    def get_build_by_id(self, build_id: str) -> BuildStatusResponse:
        """
        Get detailed information about a build.

        Args:
            build_id: Build UUID

        Returns:
            Build status including packages and logs
        """
        return self.get_build_status(build_id)

    def get_builds_by_pkgname(self, pkgname: str, limit: int = 20,
                              status: Optional[str] = None) -> BuildListResponse:
        """
        Get builds for a specific package.

        Args:
            pkgname: Package name
            limit: Maximum number of builds to return (1-100)
            status: Optional build status filter

        Returns:
            Build history for the package, newest first
        """
        url = upstream_url(self.server_url, pkgname_builds_path(pkgname))
        params: Dict[str, Any] = {'limit': limit}
        if status:
            params['status'] = status
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return BuildListResponse.model_validate(response.json())

    def _list_pkgname_builds(self, pkgname: str, successful_only: bool) -> List[BuildSummary]:
        status = BuildStatus.COMPLETED if successful_only else None
        try:
            return self.get_builds_by_pkgname(pkgname, limit=100, status=status).builds
        except httpx.HTTPError:
            return []

    def get_latest_build_by_pkgname(self, pkgname: str, successful_only: bool = True,
                                    arch: Optional[str] = None) -> Optional[BuildSummary]:
        """
        Get the latest build for a specific package.

        Args:
            pkgname: Package name
            successful_only: Only consider successful builds
            arch: Optional architecture. Use 'any' for arch=('any') packages
                  (matches latest build regardless of server_arch).

        Returns:
            Latest build, or None if none found
        """
        url = upstream_url(self.server_url, pkgname_latest_path(pkgname, arch))

        try:
            response = self.session.get(url, params={'successful_only': successful_only})
            if response.status_code == 200:
                return BuildSummary.model_validate(response.json())
        except httpx.HTTPError:
            pass

        # Build servers have no per-arch latest endpoint; fall back to the list endpoint
        return next(
            (
                build for build in self._list_pkgname_builds(pkgname, successful_only)
                if not arch or arch == 'any' or build.server_arch == arch
            ),
            None,
        )

    def get_latest_builds_by_pkgname_per_arch(self, pkgname: str,
                                              successful_only: bool = True) -> Dict[str, BuildSummary]:
        """
        Get the latest build for each architecture of a package.

        Returns:
            Mapping of server_arch -> latest build
        """
        builds: List[BuildSummary] = []
        url = upstream_url(self.server_url, pkgname_latest_by_arch_path(pkgname))
        try:
            response = self.session.get(url, params={'successful_only': successful_only})
            if response.status_code == 200:
                builds = BuildListResponse.model_validate(response.json()).builds
        except httpx.HTTPError:
            pass

        if not builds:
            builds = self._list_pkgname_builds(pkgname, successful_only)

        latest: Dict[str, BuildSummary] = {}
        for build in builds:
            if build.server_arch and build.server_arch not in latest:
                latest[build.server_arch] = build
        return latest

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
        url = upstream_url(self.server_url, build_output_path(build_id))
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
        url = upstream_url(self.server_url, build_stream_path(build_id))

        try:
            with self.session.stream("GET", url) as response:
                response.raise_for_status()

                for line in response.iter_lines():
                    if line:
                        yield f"{line}\n"
        except httpx.HTTPError:
            pass

    def stream_build_updates(self, build_id: str) -> Generator[BuildStatusResponse, None, None]:
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

                if status.status in BuildStatus.TERMINAL:
                    break

                time.sleep(5)
            except httpx.HTTPError as e:
                consecutive_errors += 1
                if consecutive_errors >= max_consecutive_errors:
                    raise e
                # Wait longer before retrying on error
                time.sleep(10)

    def cleanup_server(self) -> bool:
        """
        Trigger in-memory build data cleanup on the server.

        Returns:
            True if cleanup was triggered successfully
        """
        url = upstream_url(self.server_url, ADMIN_CLEANUP_PATH)
        try:
            response = self.session.post(url)
            response.raise_for_status()
            return True
        except httpx.HTTPError:
            return False

