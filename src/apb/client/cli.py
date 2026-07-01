"""APB client CLI and orchestration functions."""

import argparse
import json
import logging
import os
import queue
import sys
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urljoin

import httpx

from apb.config import load_config
from apb.tarball import create_build_tarball

from apb.client.api import APBotClient
from apb.client.auth import APBAuthClient
from apb.client.helpers import (
    get_architectures_needing_build,
    parse_pkgbuild_info,
    should_skip_build,
)

logger = logging.getLogger(__name__)


def _format_farm_queue_message(status: Dict, *, arch_prefix: str = "") -> Optional[str]:
    if status.get("status") != "queued" or status.get("queue_state") != "farm":
        return None

    queue_position = status.get("queue_position")
    if not queue_position:
        return None

    jobs_ahead = status.get("jobs_ahead", max(queue_position - 1, 0))
    farm_queue_size = status.get("farm_queue_size", queue_position)
    if jobs_ahead == 0:
        return (
            f"{arch_prefix}Queued on farm (position {queue_position}/{farm_queue_size}, "
            f"next when a server slot opens)"
        )
    return (
        f"{arch_prefix}Queued on farm: position {queue_position}/{farm_queue_size}, "
        f"{jobs_ahead} job(s) ahead"
    )


def _print_submitted_build_queue_info(builds: List[Dict], queue_status: Optional[Dict] = None) -> None:
    if queue_status and queue_status.get("message"):
        print(queue_status["message"])

    for build in builds:
        arch = build.get("arch", "?")
        build_id = build["build_id"]
        queue_position = build.get("queue_position")
        if queue_position is not None:
            jobs_ahead = build.get("jobs_ahead", max(queue_position - 1, 0))
            print(
                f"[{arch}] Build queued at farm position {queue_position} "
                f"({jobs_ahead} job(s) ahead): {build_id}"
            )
        else:
            print(f"[{arch}] Build ID: {build_id}")


def _maybe_print_farm_queue_status(
    status: Dict,
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
    if not client.wait_for_farm_artifacts(build_id):
        print(f"{arch_prefix}Timed out waiting for the farm to cache build artifacts")
        return False

    try:
        final_status = client.get_build_status(build_id)
    except httpx.HTTPError as exc:
        print(f"{arch_prefix}Error getting build status for download: {exc}")
        return False

    if final_status.get("server_unavailable"):
        print(f"{arch_prefix}Server unavailable - cannot download build artifacts")
        print(f"{arch_prefix}You may need to download files manually when server recovers")
        return False

    downloaded_files = []

    if final_status.get("packages"):
        for package in final_status["packages"]:
            if client.download_file(build_id, package["filename"], output_dir):
                print(f"{arch_prefix}Downloaded: {package['filename']}")
                downloaded_files.append(package["filename"])
            else:
                print(f"{arch_prefix}Failed to download: {package['filename']}")

    if final_status.get("logs"):
        for log in final_status["logs"]:
            if client.download_file(build_id, log["filename"], output_dir):
                print(f"{arch_prefix}Downloaded: {log['filename']}")
                downloaded_files.append(log["filename"])
            else:
                print(f"{arch_prefix}Failed to download: {log['filename']}")

    if downloaded_files:
        print(f"{arch_prefix}Downloaded {len(downloaded_files)} files")
        return True

    print(f"{arch_prefix}No files available for download")
    return False


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
    except httpx.HTTPError:
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

        with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as temp_tarball:
            try:
                create_build_tarball(build_path, Path(temp_tarball.name))

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

    except httpx.HTTPError as e:
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
    _print_submitted_build_queue_info(builds)
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
            last_queue_message = None
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

                    last_queue_message = _maybe_print_farm_queue_status(
                        status,
                        arch_prefix=f"[{arch}] ",
                        last_message=last_queue_message,
                    )

                    if status['status'] in ['completed', 'failed', 'cancelled']:
                        # Download results if output_dir provided
                        if arch_output_dir and status['status'] in ['completed', 'failed']:
                            _download_build_artifacts(
                                client,
                                build_id,
                                arch_output_dir,
                                arch_prefix=f"[{arch}] ",
                            )

                        # Build finished
                        success = status['status'] == 'completed'
                        print(f"[{arch}] Build {'SUCCESS' if success else 'FAILED'}")
                        result_queue.put((arch, success))
                        arch_build_info[arch]['status'] = 'completed' if success else 'failed'
                        break

                    # Wait before next status check
                    stop_event.wait(5)

                except httpx.HTTPError as e:
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
    last_queue_message = None

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

            last_queue_message = _maybe_print_farm_queue_status(
                initial_status,
                arch_prefix=arch_prefix,
                last_message=None,
            )
            break
        except httpx.HTTPError as e:
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

            last_queue_message = _maybe_print_farm_queue_status(
                update,
                arch_prefix=arch_prefix,
                last_message=last_queue_message,
            )

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
    except httpx.HTTPError as e:
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
            except httpx.HTTPError:
                print(f"{arch_prefix}Unable to get final status due to server unavailability")
                return False
        else:
            print(f"{arch_prefix}Error monitoring build: {e}")
            # Try to get final status
            try:
                final_status = client.get_build_status(build_id)
                last_status = final_status['status']
                print(f"{arch_prefix}Final status: {last_status}")
            except httpx.HTTPError:
                print(f"{arch_prefix}Unable to get final status")
                return False

    if output_dir and last_status in ['completed', 'failed']:
        if not _download_build_artifacts(
            client,
            build_id,
            output_dir,
            arch_prefix=arch_prefix,
        ):
            return False

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

            # Determine architecture for output directory
            status_arch = status.get('server_arch') or status.get('arch')
            if isinstance(status_arch, list):
                status_arch = status_arch[0] if status_arch else None

            build_arch = status_arch or (args.arch.split(',')[0] if args.arch else None) or config.get("default_arch")
            arch_output_dir = args.output_dir / build_arch

            if not _download_build_artifacts(client, args.download, arch_output_dir):
                sys.exit(1)

            sys.exit(0)
        except httpx.HTTPError as e:
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
        except httpx.HTTPError as e:
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
                            _print_submitted_build_queue_info(
                                builds,
                                response.get("queue_status"),
                            )
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