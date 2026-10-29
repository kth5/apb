"""APB client CLI and orchestration functions."""

import argparse
import getpass
import logging
import re
import sys
import threading
from pathlib import Path
from typing import Dict, Iterable, List, NamedTuple, Optional, Tuple

import httpx

from apb.config import load_config
from apb.constants import (
    BUILD_TIMEOUT_MAX,
    BUILD_TIMEOUT_MIN,
    DEFAULT_FARM_URL,
    DEFAULT_SERVER_URL,
    BuildStatus,
)
from apb.models import BuildStatusResponse, BuildSubmitResponse, FarmBuildSubmitResponse
from apb.upstream import upstream_url

from apb.client.api import APBotClient, BuildRejectedError
from apb.client.auth import CLI_MFA_METHODS, CLI_SETUP_METHODS, APBAuthClient
from apb.client.helpers import (
    effective_any_server_arch,
    get_architectures_needing_build,
    parse_pkgbuild_info,
    print_apb_arch_hint_notice,
    select_pkgbuild_architectures,
    should_skip_build,
)

logger = logging.getLogger(__name__)

_BUILD_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

POLL_INTERVAL = 5
ERROR_RETRY_INTERVAL = 10
MAX_STATUS_ERRORS = 5
MAX_SERVER_UNAVAILABLE = 8
STATUS_SKIPPED = "skipped"
STATUS_SUBMITTED = "submitted"
STATUS_SERVER_UNAVAILABLE = "failed_server_unavailable"
STATUS_INTERRUPTED = "interrupted"
PKGBUILD_DOWNLOAD = "__PKGBUILD__"


class MonitorTarget(NamedTuple):
    """A submitted build to monitor; downloads are skipped when output_dir is None."""

    build_id: str
    client: APBotClient
    output_dir: Optional[Path] = None
    arch: Optional[str] = None


def _arch_prefix(arch: Optional[str]) -> str:
    return f"[{arch}] " if arch else ""


def _format_farm_queue_message(status: BuildStatusResponse, *, arch_prefix: str = "") -> Optional[str]:
    if status.status != BuildStatus.QUEUED or status.queue_state != "farm":
        return None

    queue_position = status.queue_position
    if not queue_position:
        return None

    jobs_ahead = status.jobs_ahead if status.jobs_ahead is not None else max(queue_position - 1, 0)
    farm_queue_size = status.farm_queue_size or queue_position
    if jobs_ahead == 0:
        return (
            f"{arch_prefix}Queued on farm (position {queue_position}/{farm_queue_size}, "
            f"next when a server slot opens)"
        )
    return (
        f"{arch_prefix}Queued on farm: position {queue_position}/{farm_queue_size}, "
        f"{jobs_ahead} job(s) ahead"
    )


def _print_submitted_build_queue_info(response: FarmBuildSubmitResponse) -> None:
    print("\n=== Build Summary ===")
    if response.queue_status and response.queue_status.message:
        print(response.queue_status.message)

    for build in response.builds:
        if build.queue_position is not None:
            jobs_ahead = build.jobs_ahead if build.jobs_ahead is not None else max(build.queue_position - 1, 0)
            print(
                f"[{build.arch}] Build queued at farm position {build.queue_position} "
                f"({jobs_ahead} job(s) ahead): {build.build_id}"
            )
        else:
            print(f"[{build.arch}] Build ID: {build.build_id}")
    print("====================\n")


def _maybe_print_farm_queue_status(
    status: BuildStatusResponse,
    *,
    arch_prefix: str = "",
    last_message: Optional[str],
) -> Optional[str]:
    message = _format_farm_queue_message(status, arch_prefix=arch_prefix)
    if message and message != last_message:
        print(message)
        return message
    return last_message


def _download_build_artifacts(
    client: APBotClient,
    build_id: str,
    output_dir: Path,
    *,
    arch_prefix: str = "",
) -> bool:
    """Wait for the farm to cache artifacts, then download packages and logs."""
    try:
        final_status = client.wait_for_farm_artifacts(build_id)
    except httpx.HTTPError as exc:
        print(f"{arch_prefix}Error getting build status for download: {exc}")
        return False

    if not final_status:
        print(f"{arch_prefix}Build artifacts are not ready for download")
        return False

    if final_status.server_unavailable:
        print(f"{arch_prefix}Server unavailable - cannot download build artifacts")
        print(f"{arch_prefix}You may need to download files manually when server recovers")
        return False

    downloaded_files = []
    for artifact in [*final_status.packages, *final_status.logs]:
        if client.download_file(build_id, artifact.filename, output_dir):
            print(f"{arch_prefix}Downloaded: {artifact.filename}")
            downloaded_files.append(artifact.filename)
        else:
            print(f"{arch_prefix}Failed to download: {artifact.filename}")

    if downloaded_files:
        print(f"{arch_prefix}Downloaded {len(downloaded_files)} files")
        return True

    print(f"{arch_prefix}No files available for download")
    return False


def _is_build_id(value: str) -> bool:
    return bool(_BUILD_ID_RE.match(value.strip()))


def parse_arch_list(value: Optional[str]) -> List[str]:
    """Split a comma-separated --arch value into unique architecture names."""
    if not value:
        return []
    return list(dict.fromkeys(arch.strip() for arch in value.split(",") if arch.strip()))


def _select_requested_archs(pkgbuild_archs: List[str], arch_filter: Optional[List[str]]) -> List[str]:
    """Intersect PKGBUILD arch=() with --arch, printing what does not match."""
    selected, missing = select_pkgbuild_architectures(pkgbuild_archs, arch_filter)
    if missing:
        print(f"Warning: architectures not in PKGBUILD arch=(): {', '.join(missing)}")
    if not selected:
        print("Error: No matching architectures between --arch and PKGBUILD arch=()")
    return selected


def _resolve_pkgbuild_dir(path: Optional[Path]) -> Path:
    """Resolve a PKGBUILD file or package directory to its containing directory."""
    if path is None:
        path = Path(".")
    path = path.resolve()
    if path.is_file() and path.name == "PKGBUILD":
        return path.parent
    if path.is_dir() and (path / "PKGBUILD").exists():
        return path
    raise ValueError(f"PKGBUILD not found at {path}")


def download_latest_from_pkgbuild(
    client: APBotClient,
    pkgbuild_dir: Path,
    output_dir: Path,
    arch_filter: Optional[List[str]] = None,
) -> bool:
    """
    Download the latest successful farm build for each PKGBUILD architecture.

    Uses the pkgname/pkgbase the farm stores, and downloads into output_dir/<arch>/.
    For arch=('any'), artifacts go under output_dir/any/.
    """
    pkgbuild_path = pkgbuild_dir / "PKGBUILD"
    pkg_info = parse_pkgbuild_info(pkgbuild_path)
    pkgname = pkg_info.get("pkgname", "unknown")
    pkgbuild_archs = pkg_info.get("arch") or []

    if not pkgbuild_archs:
        print(f"Error: No architectures found in {pkgbuild_path}")
        return False

    if pkgname == "unknown":
        print(f"Error: Could not determine pkgname from {pkgbuild_path}")
        return False

    target_archs = _select_requested_archs(pkgbuild_archs, arch_filter)
    if not target_archs:
        return False

    print(f"Package: {pkgname}")
    print(f"Architectures: {', '.join(target_archs)}")

    results = []
    for arch in target_archs:
        arch_prefix = f"[{arch}] "
        latest = client.get_latest_build_by_pkgname(pkgname, successful_only=True, arch=arch)
        if not latest:
            print(f"{arch_prefix}No successful build found on farm")
            results.append(False)
            continue

        display_name = latest.display_name or pkgname
        server_arch = latest.server_arch or arch
        print(f"{arch_prefix}Latest build: {latest.build_id} ({display_name}, server_arch={server_arch})")

        arch_output_dir = output_dir / ("any" if arch == "any" else arch)
        success = _download_build_artifacts(client, latest.build_id, arch_output_dir, arch_prefix=arch_prefix)
        results.append(success)

    if not results:
        return False
    return all(results)


def _print_submit_http_error(server_url: str, exc: httpx.HTTPError) -> None:
    print(f"Error submitting build to {server_url}: {exc}")
    if not isinstance(exc, httpx.HTTPStatusError):
        return

    try:
        print(f"Error response: {exc.response.json()}")
    except ValueError:
        print(f"HTTP {exc.response.status_code} response: {exc.response.text}")
    if exc.response.status_code == 401:
        print("Authentication required. Please login first using: apb --farm --login")
    elif exc.response.status_code == 403:
        print("Access denied. You may not have permission to submit builds.")


def _print_build_rejected(exc: BuildRejectedError) -> None:
    print(f"Error: {exc}")
    for key, label in (
        ("available_architectures", "Available architectures"),
        ("target_architectures", "Requested architectures"),
        ("pkgbuild_architectures", "PKGBUILD architectures"),
        ("invalid_repositories", "Invalid repositories"),
    ):
        if exc.detail.get(key):
            print(f"{label}: {', '.join(exc.detail[key])}")


def submit_build(
    server_url: str,
    build_path: Path,
    auth_client: Optional[APBAuthClient] = None,
    exclude_paths: Optional[List[Path]] = None,
    architectures: Optional[List[str]] = None,
    build_timeout: Optional[int] = None,
) -> Optional[BuildSubmitResponse]:
    """
    Submit a tarball of the build directory to a server or farm.

    Args:
        server_url: Server or farm URL
        build_path: Path to directory containing PKGBUILD and source files
        auth_client: Optional authentication client for farm access
        exclude_paths: Paths left out of the tarball
        architectures: PKGBUILD architectures the farm should queue (farm only)
        build_timeout: Optional build timeout in seconds (admin only on the farm)

    Returns:
        Submit response (FarmBuildSubmitResponse for farms), or None after printing the error
    """
    client = APBotClient(server_url, auth_client)
    try:
        return client.build_package(
            build_path,
            exclude_paths=exclude_paths,
            architectures=architectures,
            build_timeout=build_timeout,
        )
    except BuildRejectedError as exc:
        _print_build_rejected(exc)
    except httpx.HTTPError as exc:
        _print_submit_http_error(server_url, exc)
    except ValueError as exc:
        print(f"Error: {exc}")
    return None


def _status_error_code(exc: httpx.HTTPError) -> Optional[int]:
    return exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else None


def _poll_build(target: MonitorTarget, stop_event: threading.Event) -> str:
    """Poll a build until it reaches a terminal state and return the final status.

    Returns STATUS_SERVER_UNAVAILABLE when the server stays unreachable, and the last
    seen status (or STATUS_INTERRUPTED) when stop_event is set.
    """
    arch_prefix = _arch_prefix(target.arch)
    last_status: Optional[str] = None
    last_queue_message: Optional[str] = None
    status_errors = 0
    server_unavailable_count = 0

    while not stop_event.is_set():
        try:
            status = target.client.get_build_status(target.build_id)
        except httpx.HTTPError as exc:
            if _status_error_code(exc) in (502, 503):
                server_unavailable_count += 1
                if server_unavailable_count >= MAX_SERVER_UNAVAILABLE:
                    print(f"{arch_prefix}Server has been unavailable for {server_unavailable_count} consecutive attempts")
                    print(f"{arch_prefix}Build may be running but server is unreachable")
                    return STATUS_SERVER_UNAVAILABLE
                print(f"{arch_prefix}Server unavailable (attempt {server_unavailable_count}/{MAX_SERVER_UNAVAILABLE}), retrying...")
            else:
                status_errors += 1
                reason = "Build not found (404)" if _status_error_code(exc) == 404 else f"Error getting build status: {exc}"
                if status_errors >= MAX_STATUS_ERRORS:
                    print(f"{arch_prefix}{reason}, giving up after {status_errors} attempts")
                    return BuildStatus.FAILED
                print(f"{arch_prefix}{reason}, retrying (attempt {status_errors}/{MAX_STATUS_ERRORS})")
            stop_event.wait(ERROR_RETRY_INTERVAL)
            continue

        status_errors = 0
        if status.server_unavailable:
            server_unavailable_count += 1
            if server_unavailable_count >= MAX_SERVER_UNAVAILABLE:
                print(f"{arch_prefix}Server has been unavailable for {server_unavailable_count} consecutive checks")
                print(f"{arch_prefix}Last known status: {status.status}")
                if status.status in BuildStatus.TERMINAL:
                    return status.status
                print(f"{arch_prefix}Giving up monitoring due to prolonged server unavailability")
                return STATUS_SERVER_UNAVAILABLE
            print(
                f"{arch_prefix}Server unavailable ({server_unavailable_count}/{MAX_SERVER_UNAVAILABLE}), "
                f"cached status: {status.status}"
            )
        else:
            server_unavailable_count = 0

        if status.status != last_status:
            print(f"{arch_prefix}Status: {status.status}")
            last_status = status.status

        last_queue_message = _maybe_print_farm_queue_status(
            status,
            arch_prefix=arch_prefix,
            last_message=last_queue_message,
        )

        if status.status in BuildStatus.TERMINAL:
            return status.status

        stop_event.wait(POLL_INTERVAL)

    return last_status or STATUS_INTERRUPTED


def _monitor_target(target: MonitorTarget, stop_event: threading.Event, *, verbose: bool) -> Tuple[str, bool]:
    """Monitor one build, download its artifacts, and return (final status, is_successful)."""
    arch_prefix = _arch_prefix(target.arch)
    if verbose:
        print(f"{arch_prefix}Monitoring build: {target.build_id}")

    final_status = _poll_build(target, stop_event)
    if stop_event.is_set():
        return final_status, False

    is_downloaded = True
    if target.output_dir and final_status in (BuildStatus.COMPLETED, BuildStatus.FAILED):
        is_downloaded = _download_build_artifacts(
            target.client,
            target.build_id,
            target.output_dir,
            arch_prefix=arch_prefix,
        )

    is_completed = final_status == BuildStatus.COMPLETED
    print(f"{arch_prefix}Build {'SUCCESS' if is_completed else 'FAILED'}")
    return final_status, is_completed and is_downloaded


def monitor_builds(targets: List[MonitorTarget], *, verbose: bool = False) -> Dict[str, Tuple[str, bool]]:
    """
    Monitor submitted builds in parallel and download their artifacts.

    On Ctrl-C every unfinished build is cancelled.

    Args:
        targets: Builds to monitor
        verbose: Enable verbose output

    Returns:
        Mapping of build ID to (final status, is_successful)
    """
    results: Dict[str, Tuple[str, bool]] = {}
    stop_event = threading.Event()

    def run(target: MonitorTarget) -> None:
        try:
            outcome = _monitor_target(target, stop_event, verbose=verbose)
        except Exception as exc:
            print(f"{_arch_prefix(target.arch)}Error monitoring build: {exc}")
            outcome = (BuildStatus.FAILED, False)
        results.setdefault(target.build_id, outcome)

    threads = [threading.Thread(target=run, args=(target,), daemon=True) for target in targets]
    for thread in threads:
        thread.start()

    try:
        for thread in threads:
            while thread.is_alive():
                thread.join(timeout=1)
    except KeyboardInterrupt:
        print("\n--- Build monitoring interrupted by user ---")
        stop_event.set()
        print("Cancelling unfinished builds...")
        for target in targets:
            if results.get(target.build_id, ("", False))[0] in BuildStatus.TERMINAL:
                continue
            arch_prefix = _arch_prefix(target.arch)
            if target.client.cancel_build(target.build_id):
                print(f"{arch_prefix}Build cancelled successfully")
                results[target.build_id] = (BuildStatus.CANCELLED, False)
            else:
                print(f"{arch_prefix}Failed to cancel build - it may continue running")
        for thread in threads:
            thread.join(timeout=1)

    for target in targets:
        results.setdefault(target.build_id, (STATUS_INTERRUPTED, False))
    return results


def _print_final_results(rows: Iterable[Tuple[str, Optional[str], str, bool]]) -> None:
    """Print one line per architecture: (arch, build_id, status, is_successful)."""
    rows = list(rows)
    print("\n=== Final Results ===")
    for arch, build_id, status, _is_successful in rows:
        suffix = f" (Build ID: {build_id})" if build_id else ""
        print(f"[{arch}] {status.upper()}{suffix}")
    print("====================")

    successful_count = sum(1 for row in rows if row[3])
    skipped_count = sum(1 for row in rows if row[2] == STATUS_SKIPPED)
    cancelled_count = sum(1 for row in rows if row[2] == BuildStatus.CANCELLED)
    notes = [
        note for count, note in (
            (skipped_count, f"{skipped_count} skipped"),
            (cancelled_count, f"{cancelled_count} cancelled by user"),
        ) if count
    ]
    notes_suffix = f" ({', '.join(notes)})" if notes else ""
    print(f"Overall result: {successful_count}/{len(rows)} builds successful{notes_suffix}")


def monitor_build(build_id: str, client: APBotClient, output_dir: Optional[Path] = None,
                  verbose: bool = False, arch: Optional[str] = None) -> bool:
    """
    Monitor a single build and download its artifacts into output_dir.

    Args:
        build_id: Build ID to monitor
        client: Client instance
        output_dir: Directory to download results (None disables downloads)
        verbose: Enable verbose output
        arch: Architecture being built (for display purposes)

    Returns:
        True if the build completed and its artifacts were downloaded
    """
    target = MonitorTarget(build_id, client, output_dir, arch)
    _status, is_successful = monitor_builds([target], verbose=verbose)[build_id]
    return is_successful


def _arch_output_dir(output_dir: Optional[Path], arch: Optional[str]) -> Optional[Path]:
    if output_dir is None:
        return None
    return output_dir / arch if arch else output_dir


def _status_output_arch(status: Optional[BuildStatusResponse], fallback_arch: Optional[str]) -> Optional[str]:
    """Pick the output subdirectory architecture from a build status, else fallback_arch."""
    if status and status.server_arch:
        return status.server_arch
    if status and status.arch:
        return status.arch[0]
    return fallback_arch


def _monitor_submission(
    response: BuildSubmitResponse,
    client: APBotClient,
    *,
    output_dir: Optional[Path],
    arch: Optional[str],
    is_any_package: bool = False,
    verbose: bool = False,
    detach: bool = False,
) -> bool:
    """Report a farm or server submission, then monitor it unless detached.

    Farm submissions fan out into one build per architecture; arch=(any) packages
    download into output_dir/any. A server submission is one build for ``arch``.
    """
    if isinstance(response, FarmBuildSubmitResponse) and response.builds:
        print(f"Monitoring {len(response.builds)} build(s): {response.message}")
        _print_submitted_build_queue_info(response)
        builds = [(build.arch, build.build_id) for build in response.builds]
    else:
        print(f"Build submitted: {response.build_id}")
        builds = [(arch, response.build_id)]

    if detach:
        return True

    targets = [
        MonitorTarget(
            build_id,
            client,
            _arch_output_dir(output_dir, "any" if is_any_package else build_arch),
            build_arch,
        )
        for build_arch, build_id in builds
    ]
    results = monitor_builds(targets, verbose=verbose)

    if isinstance(response, FarmBuildSubmitResponse):
        _print_final_results(
            (target.arch, target.build_id, *results[target.build_id]) for target in targets
        )
    return all(is_successful for _status, is_successful in results.values())


class ArchSubmission(NamedTuple):
    """Outcome of submitting one architecture of a config-based build."""

    arch: str
    status: str
    build_id: Optional[str] = None
    server_url: Optional[str] = None


def _skip_existing_build(
    output_dir: Path,
    pkgbuild_path: Path,
    arch: str,
    *,
    force: bool,
    verbose: bool,
    arch_prefix: str = "",
) -> bool:
    """Return True (after explaining why) when the package already exists in output_dir."""
    should_skip, reason = should_skip_build(output_dir, pkgbuild_path, arch, force)
    if should_skip:
        print(f"{arch_prefix}Skipping build: {reason}")
        if not force:
            print(f"{arch_prefix}Use --force to rebuild existing packages")
        return True
    if verbose and not force:
        print(f"{arch_prefix}{reason}")
    return False


def _resolve_config_architectures(pkg_info: dict, servers: Dict, specific_arch: Optional[str]) -> List[str]:
    """Pick the architectures to build: the requested ones, else PKGBUILD arch=() entries with servers."""
    requested = parse_arch_list(specific_arch)
    if requested:
        return requested

    pkgbuild_archs = pkg_info.get("arch") or ["x86_64"]
    print_apb_arch_hint_notice(pkg_info)
    if "any" in pkgbuild_archs:
        return ["any"]

    architectures = [arch for arch in pkgbuild_archs if arch in servers]
    if not architectures:
        print(f"Error: No servers configured for PKGBUILD architectures: {pkgbuild_archs}")
        print(f"Available server architectures: {list(servers.keys())}")
    return architectures


def _config_server_urls(arch: str, pkg_info: dict, servers: Dict, *, verbose: bool) -> List[str]:
    """Return the configured servers for arch; arch=(any) uses the apb_arch_hint or first available arch."""
    if arch == "any":
        server_arch, error = effective_any_server_arch(pkg_info, servers)
        if error:
            print(f"[{arch}] {error}")
            return []
        if verbose:
            print(f"[{arch}] Using {server_arch} servers for 'any' architecture build")
        return servers[server_arch]

    server_urls = servers.get(arch) or []
    if not server_urls:
        print(f"[{arch}] No servers configured for architecture: {arch}")
    return server_urls


def _submit_config_build(
    arch: str,
    *,
    build_path: Path,
    pkg_info: dict,
    servers: Dict,
    output_dir: Path,
    auth_client: Optional[APBAuthClient],
    build_timeout: Optional[int],
    force: bool,
    verbose: bool,
) -> ArchSubmission:
    """Submit one architecture to the first configured server that accepts it."""
    server_urls = _config_server_urls(arch, pkg_info, servers, verbose=verbose)
    if not server_urls:
        return ArchSubmission(arch, BuildStatus.FAILED)

    arch_prefix = _arch_prefix(arch)
    if _skip_existing_build(
        output_dir, build_path / "PKGBUILD", arch, force=force, verbose=verbose, arch_prefix=arch_prefix
    ):
        return ArchSubmission(arch, STATUS_SKIPPED)

    for server_url in server_urls:
        if verbose:
            print(f"{arch_prefix}Submitting build to {server_url}...")
        response = submit_build(
            server_url, build_path, auth_client, exclude_paths=[output_dir], build_timeout=build_timeout
        )
        if response:
            print(f"{arch_prefix}Build submitted: {response.build_id}")
            return ArchSubmission(arch, STATUS_SUBMITTED, response.build_id, server_url)

    print(f"{arch_prefix}Failed to submit build")
    return ArchSubmission(arch, BuildStatus.FAILED)


def build_for_multiple_arches(build_path: Path, output_dir: Path, config: Dict,
                              verbose: bool = False, detach: bool = False,
                              specific_arch: Optional[str] = None, force: bool = False,
                              auth_client: Optional[APBAuthClient] = None,
                              build_timeout: Optional[int] = None,
                              download: bool = True) -> bool:
    """
    Build a package for multiple architectures using the servers in the configuration.

    Args:
        build_path: Path to package directory
        output_dir: Output directory
        config: Configuration dictionary
        verbose: Enable verbose output
        detach: Don't wait for completion
        specific_arch: Comma-separated architectures to build (default: PKGBUILD arch=())
        force: Force rebuild even if package exists
        auth_client: Optional authentication client
        build_timeout: Optional build timeout in seconds
        download: Download build results into output_dir/<arch>

    Returns:
        True if all builds were submitted (detach) or completed successfully
    """
    pkgbuild_path = build_path / "PKGBUILD"
    if not pkgbuild_path.exists():
        print(f"Error: PKGBUILD not found in {build_path}")
        return False

    servers = config.get("servers", {})
    pkg_info = parse_pkgbuild_info(pkgbuild_path)
    architectures = _resolve_config_architectures(pkg_info, servers, specific_arch)
    if not architectures:
        return False

    print(f"Building for architectures: {', '.join(architectures)}")
    submissions = [
        _submit_config_build(
            arch,
            build_path=build_path,
            pkg_info=pkg_info,
            servers=servers,
            output_dir=output_dir,
            auth_client=auth_client,
            build_timeout=build_timeout,
            force=force,
            verbose=verbose,
        )
        for arch in architectures
    ]

    print("\n=== Build Summary ===")
    for submission in submissions:
        if submission.build_id:
            print(f"[{submission.arch}] Build ID: {submission.build_id}")
        elif submission.status == STATUS_SKIPPED:
            print(f"[{submission.arch}] Skipped")
        else:
            print(f"[{submission.arch}] Build submission failed")
    print("====================\n")

    if detach:
        print("Builds submitted. Exiting without waiting for completion.")
        return all(submission.status != BuildStatus.FAILED for submission in submissions)

    targets = [
        MonitorTarget(
            submission.build_id,
            APBotClient(submission.server_url, auth_client),
            output_dir / submission.arch if download else None,
            submission.arch,
        )
        for submission in submissions
        if submission.build_id
    ]
    if targets:
        print("Monitoring build progress...")
    results = monitor_builds(targets, verbose=verbose)

    rows = [
        (submission.arch, submission.build_id, *results[submission.build_id])
        if submission.build_id
        else (submission.arch, None, submission.status, submission.status == STATUS_SKIPPED)
        for submission in submissions
    ]
    _print_final_results(rows)
    return all(row[3] for row in rows)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse the apb command line."""
    parser = argparse.ArgumentParser(description="APB Client - Build packages using APB servers")

    # Basic options
    parser.add_argument("pkgbuild_path", nargs="?", type=Path,
                       help="Path to PKGBUILD or package directory")
    parser.add_argument("--server", type=str, help="Server URL")
    parser.add_argument(
        "--arch",
        type=str,
        help="Target architecture(s) (comma-separated); with --farm, limits which PKGBUILD arch=() entries are queued",
    )
    parser.add_argument("--config", type=Path, help="Path to configuration file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--quiet", action="store_true", help="Suppress output except errors")

    # Authentication options
    parser.add_argument("--login", action="store_true", help="Login to farm")
    parser.add_argument("--logout", action="store_true", help="Logout from farm")
    parser.add_argument("--auth-status", action="store_true", help="Show authentication status")
    parser.add_argument("--username", type=str, help="Username for login")
    parser.add_argument("--2fa-method", dest="mfa_method", choices=sorted(CLI_MFA_METHODS),
                       help="Second factor for --login (default: connected security key, then authenticator code)")
    parser.add_argument("--2fa-setup", dest="mfa_setup", choices=CLI_SETUP_METHODS,
                       help="Add an authenticator app (QR code in the terminal) or a connected security key; "
                            "with --login, log in first")

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
                       help=f"Build timeout in seconds ({BUILD_TIMEOUT_MIN}-{BUILD_TIMEOUT_MAX}, admin only)")

    # Monitoring options
    parser.add_argument("--monitor", type=str, help="Monitor existing build")
    parser.add_argument("--download", nargs="?", const=PKGBUILD_DOWNLOAD, metavar="BUILD_ID_OR_PATH",
                       help="Download build results by build ID, or latest builds from PKGBUILD (with --farm)")
    parser.add_argument("--status", type=str, help="Check build status")
    parser.add_argument("--cancel", type=str, help="Cancel running build")

    # Advanced options
    parser.add_argument("--farm", action="store_true", help="Use APB Farm instead of direct server")
    parser.add_argument("--list-servers", action="store_true", help="List available servers")
    parser.add_argument("--cleanup", action="store_true", help="Trigger in-memory build data cleanup on the server")
    parser.add_argument("--test-arch", action="store_true", help="Test architecture compatibility")

    return parser.parse_args(argv)


class CliContext(NamedTuple):
    """Parsed arguments plus the connection they resolve to."""

    args: argparse.Namespace
    config: Dict
    server_url: str
    auth_client: Optional[APBAuthClient]
    client: APBotClient

    @property
    def fallback_arch(self) -> Optional[str]:
        requested = parse_arch_list(self.args.arch)
        return requested[0] if requested else self.config.get("default_arch")


def resolve_context(args: argparse.Namespace) -> CliContext:
    """Load the configuration and pick the server or farm to talk to.

    Auth commands fall back to the configured farm_url when neither --server nor --farm points at a farm.
    """
    config = load_config(args.config)
    farm_url = config.get("farm_url")

    if args.server:
        server_url = args.server
    elif args.farm:
        server_url = farm_url or DEFAULT_FARM_URL
    else:
        server_url = config.get("default_server", DEFAULT_SERVER_URL)

    is_farm = args.farm or server_url == farm_url
    is_auth_command = args.login or args.logout or args.auth_status or args.mfa_setup
    if not is_farm and is_auth_command and farm_url:
        server_url = farm_url
        is_farm = True

    auth_client = APBAuthClient(server_url) if is_farm else None
    return CliContext(args, config, server_url, auth_client, APBotClient(server_url, auth_client))


def _print_farm_only(message: str) -> None:
    print(message)
    print("Either use --farm flag or configure farm_url in your apb.json file.")


def _print_user(prefix: str, user_info: Dict) -> None:
    print(f"{prefix}: {user_info['username']} ({user_info['role']})")


def run_login(ctx: CliContext) -> int:
    if not ctx.auth_client:
        _print_farm_only("Error: Login is only supported for farm connections.")
        return 1

    username = ctx.args.username or input("Username: ")
    password = getpass.getpass("Password: ")
    is_logged_in = ctx.auth_client.login(
        username, password, mfa_method=ctx.args.mfa_method, setup_method=ctx.args.mfa_setup
    )
    if not is_logged_in:
        print("Two-factor setup failed!" if ctx.auth_client.is_authenticated() else "Login failed!")
        return 1

    print("Login successful!")
    user_info = ctx.auth_client.get_user_info()
    if user_info:
        _print_user("Logged in as", user_info)
        if not user_info.get("mfa_enabled"):
            print("Two-factor authentication is not enabled. Add it with --2fa-setup totp or --2fa-setup key.")
    return 0


def run_mfa_setup(ctx: CliContext) -> int:
    if not ctx.auth_client:
        _print_farm_only("Error: Two-factor setup is only supported for farm connections.")
        return 1
    return 0 if ctx.auth_client.setup_mfa(ctx.args.mfa_setup) else 1


def run_logout(ctx: CliContext) -> int:
    if not ctx.auth_client:
        _print_farm_only("Error: Logout is only supported for farm connections.")
        return 1

    print("Logout successful!" if ctx.auth_client.logout() else "Logout failed!")
    return 0


def run_auth_status(ctx: CliContext) -> int:
    if not ctx.auth_client:
        _print_farm_only("Authentication is only supported for farm connections.")
        return 0

    if not ctx.auth_client.is_authenticated():
        print("Not authenticated")
        print(f"Farm URL: {ctx.server_url}")
        print("Use --login to authenticate")
        return 0

    user_info = ctx.auth_client.get_user_info()
    if not user_info:
        print("Authentication token is invalid")
        return 0
    _print_user("Authenticated as", user_info)
    print(f"Farm URL: {ctx.server_url}")
    return 0


def _build_output_dir(ctx: CliContext, build_id: str) -> Path:
    """Output directory for a build: output_dir/<arch> when the build's architecture is known."""
    try:
        status = ctx.client.get_build_status(build_id)
    except httpx.HTTPError:
        status = None
    return _arch_output_dir(ctx.args.output_dir, _status_output_arch(status, ctx.fallback_arch))


def run_monitor(ctx: CliContext) -> int:
    build_id = ctx.args.monitor
    output_dir = None if ctx.args.no_download else _build_output_dir(ctx, build_id)
    return 0 if monitor_build(build_id, ctx.client, output_dir, ctx.args.verbose) else 1


def _run_pkgbuild_download(ctx: CliContext) -> int:
    if not ctx.auth_client:
        print("Error: PKGBUILD-based download requires --farm (or farm_url as the active server)")
        return 1

    target = ctx.args.download
    try:
        pkgbuild_dir = _resolve_pkgbuild_dir(ctx.args.pkgbuild_path if target == PKGBUILD_DOWNLOAD else Path(target))
    except ValueError as exc:
        print(f"Error: {exc}")
        return 1

    try:
        is_successful = download_latest_from_pkgbuild(
            ctx.client, pkgbuild_dir, ctx.args.output_dir, arch_filter=parse_arch_list(ctx.args.arch) or None
        )
    except httpx.HTTPError as exc:
        print(f"Error: {exc}")
        return 1
    return 0 if is_successful else 1


def run_download(ctx: CliContext) -> int:
    target = ctx.args.download
    if target == PKGBUILD_DOWNLOAD or (target and not _is_build_id(target)):
        return _run_pkgbuild_download(ctx)

    try:
        is_downloaded = _download_build_artifacts(ctx.client, target, _build_output_dir(ctx, target))
    except httpx.HTTPError as exc:
        print(f"Error: {exc}")
        return 1
    return 0 if is_downloaded else 1


def run_status(ctx: CliContext) -> int:
    try:
        status = ctx.client.get_build_status(ctx.args.status)
    except httpx.HTTPError as exc:
        print(f"Error: {exc}")
        return 1

    print(f"Build ID: {status.build_id}")
    print(f"Package: {status.pkgname}")
    print(f"Status: {status.status}")
    if status.duration is not None:
        print(f"Duration: {status.duration:.1f}s")
    return 0


def run_cancel(ctx: CliContext) -> int:
    if ctx.client.cancel_build(ctx.args.cancel):
        print("Build cancelled successfully")
        return 0
    print("Failed to cancel build")
    return 1


def _print_server_reachability(ctx: CliContext) -> None:
    print(f"Testing server: {ctx.server_url}")
    try:
        response = ctx.client.session.get(upstream_url(ctx.server_url, "/farm"))
        if response.status_code == 200:
            farm_info = response.json()
            print(f"  Status: {farm_info.get('status', 'unknown')}")
            print(f"  Version: {farm_info.get('version', 'unknown')}")
            if "servers" in farm_info:
                print(f"  Managed servers: {len(farm_info['servers'])}")
                for server in farm_info["servers"]:
                    print(f"    {server.get('arch', 'unknown')}: {server.get('status', 'unknown')}")
            return

        response = ctx.client.session.get(upstream_url(ctx.server_url, "/"))
        if response.status_code == 200:
            print(f"  Status: Server accessible (HTTP {response.status_code})")
        else:
            print(f"  Status: Server returned HTTP {response.status_code}")
    except (httpx.HTTPError, ValueError) as exc:
        print(f"  Status: Error - {exc}")


def run_list_servers(ctx: CliContext) -> int:
    if ctx.args.server or ctx.args.farm:
        _print_server_reachability(ctx)
        return 0

    print("Configured servers:")
    for arch, servers in ctx.config.get("servers", {}).items():
        print(f"  {arch}:")
        for server in servers:
            print(f"    {server}")
    return 0


def run_cleanup(ctx: CliContext) -> int:
    if ctx.client.cleanup_server():
        print("In-memory build data cleanup triggered")
        return 0
    print("Failed to trigger cleanup")
    return 1

def _submit_and_monitor(
    ctx: CliContext,
    build_path: Path,
    *,
    arch: str,
    architectures: Optional[List[str]] = None,
    is_any_package: bool = False,
) -> int:
    """Submit build_path to the active server or farm, then monitor and download unless detached."""
    args = ctx.args
    if args.verbose:
        print(f"Submitting build to {ctx.server_url}...")

    response = submit_build(
        ctx.server_url,
        build_path,
        ctx.auth_client,
        exclude_paths=[args.output_dir],
        architectures=architectures,
        build_timeout=args.build_timeout,
    )
    if not response:
        print("Failed to submit build")
        return 1

    is_successful = _monitor_submission(
        response,
        ctx.client,
        output_dir=None if args.no_download else args.output_dir,
        arch=arch,
        is_any_package=is_any_package,
        verbose=args.verbose,
        detach=args.detach,
    )
    return 0 if is_successful else 1


def run_farm_build(ctx: CliContext, build_path: Path) -> int:
    """Queue the PKGBUILD architectures that are missing from output_dir on the farm."""
    args = ctx.args
    pkgbuild_path = build_path / "PKGBUILD"
    pkg_info = parse_pkgbuild_info(pkgbuild_path)
    pkgbuild_archs = pkg_info.get("arch") or []
    arch_filter = parse_arch_list(args.arch) or None
    if arch_filter and not _select_requested_archs(pkgbuild_archs, arch_filter):
        return 1

    architectures = get_architectures_needing_build(pkgbuild_path, args.output_dir, args.force, arch_filter=arch_filter)
    if not architectures:
        print("All packages already exist in output directory")
        if not args.force:
            print("Use --force to rebuild existing packages")
        return 0

    print_apb_arch_hint_notice(pkg_info)
    if args.verbose:
        skipped_archs = [arch for arch in pkgbuild_archs or ["x86_64"] if arch not in architectures]
        if skipped_archs:
            print(f"Skipping existing packages for architectures: {', '.join(skipped_archs)}")
        print(f"Building for architectures: {', '.join(architectures)}")

    return _submit_and_monitor(
        ctx,
        build_path,
        arch=architectures[0],
        architectures=architectures,
        is_any_package="any" in pkgbuild_archs,
    )


def run_direct_build(ctx: CliContext, build_path: Path) -> int:
    """Build a single architecture on the --server given on the command line."""
    args = ctx.args
    requested = parse_arch_list(args.arch)
    target_arch = requested[0] if len(requested) == 1 else ctx.config.get("default_arch")
    if not target_arch:
        print("Error: direct server builds need --arch or default_arch in the configuration")
        return 1

    if _skip_existing_build(
        args.output_dir, build_path / "PKGBUILD", target_arch, force=args.force, verbose=args.verbose
    ):
        return 0

    if args.verbose:
        print(f"Target architecture: {target_arch}")
    return _submit_and_monitor(ctx, build_path, arch=target_arch)


def run_config_build(ctx: CliContext, build_path: Path) -> int:
    """Build on the per-architecture servers from the configuration."""
    args = ctx.args
    try:
        is_successful = build_for_multiple_arches(
            build_path,
            args.output_dir,
            ctx.config,
            verbose=args.verbose,
            detach=args.detach,
            specific_arch=args.arch,
            force=args.force,
            auth_client=ctx.auth_client,
            build_timeout=args.build_timeout,
            download=not args.no_download,
        )
    except KeyboardInterrupt:
        print("\nBuilds interrupted by user")
        return 1
    return 0 if is_successful else 1


def run_build(ctx: CliContext) -> int:
    try:
        build_path = _resolve_pkgbuild_dir(ctx.args.pkgbuild_path)
    except ValueError as exc:
        print(f"Error: {exc}")
        return 1

    if ctx.args.farm:
        return run_farm_build(ctx, build_path)
    if ctx.args.server:
        return run_direct_build(ctx, build_path)
    return run_config_build(ctx, build_path)


def run(ctx: CliContext) -> int:
    """Run the command selected by the arguments and return the process exit code."""
    args = ctx.args
    commands = (
        (args.login, run_login),
        (args.logout, run_logout),
        (args.auth_status, run_auth_status),
        (args.mfa_setup, run_mfa_setup),
        (args.monitor, run_monitor),
        (args.download is not None, run_download),
        (args.status, run_status),
        (args.cancel, run_cancel),
        (args.list_servers, run_list_servers),
        (args.cleanup, run_cleanup),
    )
    for is_requested, command in commands:
        if is_requested:
            return command(ctx)
    return run_build(ctx)


def main() -> None:
    """Main command-line interface."""
    sys.exit(run(resolve_context(parse_args())))


if __name__ == "__main__":
    main()