"""APB server build engine and state."""

import asyncio
import configparser
import errno
import fcntl
import gc
import glob
import hashlib
import json
import logging
import os
import platform
import queue
import resource
import select
import shutil
import signal
import subprocess
import sys
import tarfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil

from apb.arch import resolve_server_architecture
from apb.constants import (
    BUILD_TIMEOUT_DEFAULT,
    MAX_BUILD_OUTPUTS,
    MAX_FILE_SIZE,
    MAX_REQUEST_SIZE,
    BuildStatus,
)
from apb.pkgbuild import parse_pkgbuild_file, pkgbuild_info_to_dict

logger = logging.getLogger(__name__)

DEFAULT_HOST = "localhost"
DEFAULT_PORT = 8000
DEFAULT_BUILDROOT = Path.home() / ".apb" / "buildroot"
DEFAULT_BUILDS_DIR = Path.home() / ".apb" / "builds"
DEFAULT_MAX_CONCURRENT = 3
BUILD_TIMEOUT = BUILD_TIMEOUT_DEFAULT

# Global state
build_queue = queue.Queue()
active_builds: Dict[str, Dict] = {}
build_history: Dict[str, Dict] = {}
build_executor = ThreadPoolExecutor(max_workers=DEFAULT_MAX_CONCURRENT)
build_outputs: Dict[str, List[str]] = {}
build_streams: Dict[str, List] = {}
build_log_handles: Dict[str, Any] = {}  # build_id -> open file handle for build.log
server_config = {}
shutdown_event = threading.Event()
build_counter = 0  # Counter for buildroot recreation
running_processes: Dict[str, subprocess.Popen] = {}  # Track running build processes
buildroot_recreation_builds: Dict[str, bool] = {}  # Track builds doing buildroot recreation

OUTPUT_READ_CHUNK = 65536
LOG_FLUSH_INTERVAL_SECONDS = 0.5


def open_build_log(build_id: str, build_dir: Path):
    """Open build.log for writing; truncates any existing file."""
    close_build_log(build_id)
    log_path = build_dir / "build.log"
    # Block-buffered; callers flush periodically so high-volume builds are not I/O-bound
    handle = open(log_path, "w", encoding="utf-8", buffering=8192)
    build_log_handles[build_id] = handle
    return log_path


def append_build_log(build_id: str, message: str, build_dir: Optional[Path] = None) -> None:
    """Append a line to the on-disk build.log (full log, independent of memory truncation)."""
    handle = build_log_handles.get(build_id)
    if handle is not None:
        try:
            handle.write(message + "\n")
            return
        except Exception as e:
            logger.warning(f"Failed writing to build.log handle for {build_id}: {e}")

    if build_dir is not None:
        try:
            with open(build_dir / "build.log", "a", encoding="utf-8") as log_file:
                log_file.write(message + "\n")
        except Exception as e:
            logger.warning(f"Failed appending to build.log for {build_id}: {e}")


def flush_build_log(build_id: str) -> None:
    """Flush the on-disk build.log handle if open."""
    handle = build_log_handles.get(build_id)
    if handle is None:
        return
    try:
        handle.flush()
    except Exception as e:
        logger.warning(f"Failed flushing build.log for {build_id}: {e}")


def close_build_log(build_id: str) -> Optional[Path]:
    """Close the build.log handle if open. Returns the log path when known."""
    handle = build_log_handles.pop(build_id, None)
    if handle is None:
        return None
    log_path = Path(handle.name)
    try:
        handle.flush()
        handle.close()
    except Exception as e:
        logger.warning(f"Failed closing build.log for {build_id}: {e}")
    return log_path


def register_build_log_artifact(build_id: str, build_dir: Path) -> Path:
    """Attach build.log metadata to the active build record."""
    close_build_log(build_id)
    log_file = build_dir / "build.log"
    if not log_file.exists():
        log_file.write_text("", encoding="utf-8")
    active_builds[build_id]["logs"] = [{
        "filename": "build.log",
        "size": log_file.stat().st_size,
        "download_url": f"/build/{build_id}/download/build.log"
    }]
    return log_file


def consume_process_output_chunk(chunk: bytes, partial: bytearray, on_line) -> None:
    """Decode a stdout chunk into complete lines, retaining any trailing partial line."""
    if not chunk:
        return
    partial.extend(chunk)
    while True:
        newline_at = partial.find(b"\n")
        if newline_at < 0:
            break
        line = bytes(partial[:newline_at]).decode("utf-8", errors="replace").rstrip("\r")
        del partial[:newline_at + 1]
        on_line(line)


def flush_partial_process_output(partial: bytearray, on_line) -> None:
    """Emit any remaining partial line after EOF."""
    if not partial:
        return
    line = bytes(partial).decode("utf-8", errors="replace").rstrip("\r")
    partial.clear()
    if line:
        on_line(line)


def set_fd_nonblocking(fd: int) -> None:
    """Set a file descriptor to non-blocking mode."""
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)


def drain_process_stdout(stdout_fd: int, partial: bytearray, on_line) -> bool:
    """
    Non-blocking drain of all currently available stdout bytes.

    Returns False when EOF is reached, True otherwise.
    """
    while True:
        try:
            chunk = os.read(stdout_fd, OUTPUT_READ_CHUNK)
        except BlockingIOError:
            return True
        except OSError as e:
            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                return True
            logger.error(f"Error reading process stdout: {e}")
            return False
        if not chunk:
            flush_partial_process_output(partial, on_line)
            return False
        consume_process_output_chunk(chunk, partial, on_line)

# Resource monitoring
resource_monitor_thread = None
last_cleanup_time = time.time()


def monitor_resources():
    """Monitor system resources and cleanup if needed"""
    global last_cleanup_time

    while not shutdown_event.is_set():
        try:
            # Check memory usage
            memory = psutil.virtual_memory()
            if memory.percent > 90:
                logger.warning(f"High memory usage: {memory.percent}%")
                cleanup_build_data()

            # Check disk space
            disk = psutil.disk_usage(server_config.get("builds_dir", "/tmp"))
            if (disk.used / disk.total) > 0.95:
                logger.warning(f"High disk usage: {(disk.used / disk.total) * 100:.1f}%")
                cleanup_old_builds()

            # Regular cleanup every hour
            if time.time() - last_cleanup_time > 3600:
                cleanup_build_data()
                last_cleanup_time = time.time()

            # Check for hung processes
            current_time = time.time()
            for build_id, build_info in list(active_builds.items()):
                if (build_info["status"] == BuildStatus.BUILDING and
                    "start_time" in build_info):

                    # Get timeout for this specific build, fallback to global if not set
                    timeout_for_build = build_info.get("build_timeout", BUILD_TIMEOUT)

                    if current_time - build_info["start_time"] > timeout_for_build:
                        logger.warning(f"Build {build_id} exceeded timeout ({timeout_for_build}s), terminating")
                        terminate_build(build_id)

            time.sleep(30)  # Check every 30 seconds

        except Exception as e:
            logger.error(f"Error in resource monitor: {e}")
            time.sleep(60)


def cleanup_build_data():
    """Clean up build data to free memory"""
    global build_outputs

    try:
        # Clean up old build outputs
        current_time = time.time()
        builds_to_clean = []

        for build_id, build_info in build_history.items():
            if (build_info.get("end_time", 0) and
                current_time - build_info["end_time"] > 3600):  # 1 hour old
                builds_to_clean.append(build_id)

        for build_id in builds_to_clean:
            if build_id in build_outputs:
                del build_outputs[build_id]
            if build_id in build_streams:
                del build_streams[build_id]

        # Limit build history
        if len(build_history) > 100:
            # Keep only the 50 most recent builds
            sorted_builds = sorted(
                build_history.items(),
                key=lambda x: x[1].get("end_time", x[1].get("created_at", 0)),
                reverse=True
            )
            build_history.clear()
            for build_id, build_info in sorted_builds[:50]:
                build_history[build_id] = build_info

        # Limit in-memory output lines for live /output and SSE (build.log on disk stays complete)
        for build_id in list(build_outputs.keys()):
            if len(build_outputs[build_id]) > MAX_BUILD_OUTPUTS:
                # Keep only the last 5000 lines in memory
                build_outputs[build_id] = build_outputs[build_id][-5000:]

        # Force garbage collection
        gc.collect()

        logger.info(f"Cleaned up build data: {len(builds_to_clean)} old builds removed")

    except Exception as e:
        logger.error(f"Error cleaning up build data: {e}")


def cleanup_old_builds():
    """Clean up old build directories"""
    try:
        builds_dir = Path(server_config.get("builds_dir", "/tmp"))
        current_time = time.time()
        week_ago = current_time - (7 * 24 * 60 * 60)

        cleaned_count = 0
        for build_dir in builds_dir.iterdir():
            if build_dir.is_dir():
                try:
                    if build_dir.stat().st_mtime < week_ago:
                        shutil.rmtree(build_dir)
                        cleaned_count += 1

                        # Remove from build_history if present
                        if build_dir.name in build_history:
                            del build_history[build_dir.name]

                except Exception as e:
                    logger.error(f"Error cleaning up {build_dir}: {e}")

        logger.info(f"Cleaned up {cleaned_count} old build directories")

    except Exception as e:
        logger.error(f"Error cleaning up old builds: {e}")


def terminate_build(build_id: str):
    """Terminate a specific build"""
    try:
        if build_id in running_processes:
            process = running_processes[build_id]

            # Check if this build is doing buildroot recreation
            is_buildroot_recreation = buildroot_recreation_builds.get(build_id, False)

            # Use longer timeout for buildroot recreation (5 minutes vs 10 seconds)
            termination_timeout = 300 if is_buildroot_recreation else 10

            process.terminate()
            try:
                process.wait(timeout=termination_timeout)
                if is_buildroot_recreation:
                    logger.info(f"Build {build_id} (buildroot recreation) terminated gracefully after SIGTERM")
                else:
                    logger.info(f"Build {build_id} terminated gracefully after SIGTERM")
            except subprocess.TimeoutExpired:
                # For buildroot recreation, this is somewhat expected and shouldn't be an ERROR
                if is_buildroot_recreation:
                    logger.warning(f"Build {build_id} (buildroot recreation) did not respond to SIGTERM within {termination_timeout}s, sending SIGKILL")
                else:
                    logger.warning(f"Build {build_id} did not respond to SIGTERM within {termination_timeout}s, sending SIGKILL")
                process.kill()

            del running_processes[build_id]
            # Clean up buildroot recreation tracking
            if build_id in buildroot_recreation_builds:
                del buildroot_recreation_builds[build_id]

        if build_id in active_builds:
            active_builds[build_id]["status"] = BuildStatus.CANCELLED
            active_builds[build_id]["end_time"] = time.time()
            if "start_time" in active_builds[build_id]:
                active_builds[build_id]["duration"] = (
                    active_builds[build_id]["end_time"] - active_builds[build_id]["start_time"]
                )

            # Move to history
            build_history[build_id] = active_builds[build_id].copy()
            del active_builds[build_id]

        logger.info(f"Build {build_id} terminated successfully")

    except Exception as e:
        # Use appropriate log level based on the type of error
        if "timed out" in str(e).lower() and buildroot_recreation_builds.get(build_id, False):
            logger.warning(f"Expected timeout during buildroot recreation for build {build_id}: {e}")
        else:
            logger.error(f"Error terminating build {build_id}: {e}")

        # Clean up tracking even on error
        if build_id in buildroot_recreation_builds:
            del buildroot_recreation_builds[build_id]


def get_system_info() -> Dict[str, Any]:
    """Get system information for server status"""
    try:
        cpu_count = psutil.cpu_count()
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        load_avg = os.getloadavg()

        boot_time = psutil.boot_time()
        uptime_seconds = time.time() - boot_time
        uptime_days = int(uptime_seconds // 86400)
        uptime_hours = int((uptime_seconds % 86400) // 3600)
        uptime_minutes = int((uptime_seconds % 3600) // 60)

        return {
            "architecture": platform.machine(),
            "cpu": {
                "model": platform.processor() or "Unknown",
                "cores": cpu_count,
                "usage_percent": cpu_percent,
                "load_average": list(load_avg)
            },
            "memory": {
                "total": memory.total,
                "available": memory.available,
                "used": memory.used,
                "percentage": memory.percent
            },
            "disk": {
                "total": disk.total,
                "used": disk.used,
                "free": disk.free,
                "percentage": (disk.used / disk.total) * 100
            },
            "uptime": f"{uptime_days} days, {uptime_hours} hours, {uptime_minutes} minutes",
            "process_info": {
                "pid": os.getpid(),
                "thread_count": threading.active_count(),
                "open_files": len(psutil.Process().open_files()),
                "memory_usage": psutil.Process().memory_info().rss
            }
        }
    except Exception as e:
        logger.error(f"Error getting system info: {e}")
        return {
            "architecture": platform.machine(),
            "cpu": {"model": "Unknown", "cores": 1, "usage_percent": 0, "load_average": [0.0, 0.0, 0.0]},
            "memory": {"total": 0, "available": 0, "used": 0, "percentage": 0.0},
            "disk": {"total": 0, "used": 0, "free": 0, "percentage": 0.0},
            "uptime": "Unknown",
            "process_info": {"pid": os.getpid(), "thread_count": 0, "open_files": 0, "memory_usage": 0}
        }


def get_server_architecture() -> str:
    try:
        return resolve_server_architecture(
            architecture_override=server_config.get("architecture_override"),
        )
    except Exception as e:
        logger.error(f"Error determining server architecture: {e}")
        return platform.machine()


def get_queue_status() -> Dict[str, Any]:
    """Get build queue status"""
    current_builds = len([b for b in active_builds.values() if b["status"] == BuildStatus.BUILDING])
    queued_builds = len([b for b in active_builds.values() if b["status"] == BuildStatus.QUEUED])

    # Count builds doing buildroot recreation
    buildroot_recreation_count = len(buildroot_recreation_builds)

    # Get current build info
    current_build = None
    buildroot_recreation_builds_info = []

    for build_id, build_info in active_builds.items():
        if build_info["status"] == BuildStatus.BUILDING:
            is_buildroot_recreation = build_id in buildroot_recreation_builds
            build_details = {
                "build_id": build_id,
                "pkgname": build_info.get("pkgname", "unknown"),
                "status": "building",
                "start_time": build_info.get("start_time", time.time()),
                "buildroot_recreation": is_buildroot_recreation
            }

            if not current_build:
                current_build = build_details

            if is_buildroot_recreation:
                buildroot_recreation_builds_info.append(build_details)

    return {
        "current_builds_count": current_builds,
        "queued_builds": queued_builds,
        "max_concurrent_builds": server_config.get("max_concurrent", DEFAULT_MAX_CONCURRENT),
        "current_build": current_build,
        "total_active_builds": len(active_builds),
        "build_history_count": len(build_history),
        "buildroot_recreation_count": buildroot_recreation_count,
        "buildroot_recreation_builds": buildroot_recreation_builds_info,
        "server_busy_with_buildroot": buildroot_recreation_count > 0
    }


def parse_pkgbuild(pkgbuild_path: Path) -> Dict[str, Any]:
    return pkgbuild_info_to_dict(parse_pkgbuild_file(pkgbuild_path))


def import_local_gpg_keys(pkgbuild_path: Path, log_output_func) -> bool:
    """Import GPG keys from local keys/ subdirectory relative to PKGBUILD"""
    try:
        # Look for keys/ subdirectory relative to PKGBUILD location
        keys_dir = pkgbuild_path.parent / "keys" / "pgp"

        if not keys_dir.exists():
            log_output_func("No keys/ subdirectory found, skipping GPG key import")
            return True

        # Find all .asc files in the keys/pgp directory
        key_files = list(keys_dir.glob("*.asc"))

        if not key_files:
            log_output_func("No .asc key files found in keys/pgp/ directory")
            return True

        log_output_func(f"Importing {len(key_files)} GPG keys from local keys/ directory")

        # Import each key file
        for key_file in key_files:
            log_output_func(f"Importing GPG key from {key_file.name}")

            cmd = ["gpg", "--import", str(key_file)]
            log_output_func(f"Running: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60  # 1 minute timeout per key
            )

            # Log GPG output
            if result.stdout:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        log_output_func(f"GPG: {line}")

            if result.stderr:
                for line in result.stderr.split('\n'):
                    if line.strip():
                        log_output_func(f"GPG: {line}")

            if result.returncode != 0:
                log_output_func(f"Warning: Failed to import GPG key from {key_file.name} (exit code {result.returncode})")
                # Continue with other keys even if one fails
                continue

        log_output_func("Local GPG key import completed")
        return True

    except subprocess.TimeoutExpired:
        log_output_func("Error: GPG key import timed out")
        return False
    except Exception as e:
        log_output_func(f"Error importing local GPG keys: {e}")
        return False


def setup_buildroot(buildroot_path: Path) -> bool:
    """Setup buildroot using mkarchroot"""
    try:
        root_path = buildroot_path / "root"

        # Create buildroot directory
        buildroot_path.mkdir(parents=True, exist_ok=True)

        # Create buildroot using mkarchroot if it doesn't exist
        if not root_path.exists():
            cmd = [
                "sudo", "mkarchroot",
                str(root_path),
                "base", "base-devel", "ccache"
            ]

            logger.info(f"Setting up buildroot: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                logger.error(f"Failed to setup buildroot: {result.stderr}")
                return False

        # Always copy host configuration files into the chroot after mkarchroot
        chroot_etc = root_path / "etc"

        for conf_name in ("makepkg.conf", "pacman.conf"):
            host_conf = Path("/etc") / conf_name
            chroot_conf = chroot_etc / conf_name
            if host_conf.exists():
                logger.info(f"Copying host /etc/{conf_name} to chroot")
                try:
                    cmd = ["sudo", "cp", str(host_conf), str(chroot_conf)]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode != 0:
                        logger.error(f"Failed to copy {conf_name}: {result.stderr}")
                        return False
                except Exception as e:
                    logger.error(f"Failed to copy {conf_name}: {e}")
                    return False
            else:
                logger.warning(f"Host /etc/{conf_name} not found")

        return True
    except Exception as e:
        logger.error(f"Error setting up buildroot: {e}")
        return False


def get_makepkg_config() -> Dict[str, str]:
    """Parse /etc/makepkg.conf for SRCDEST and CCACHE_DIR"""
    config = {}
    try:
        with open('/etc/makepkg.conf', 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('SRCDEST=') and not line.startswith('#'):
                    config['SRCDEST'] = line.split('=', 1)[1].strip('\'"')
                elif line.startswith('export CCACHE_DIR=') and not line.startswith('#'):
                    config['CCACHE_DIR'] = line.split('=', 1)[1].strip('\'"')
    except Exception as e:
        logger.error(f"Error reading makepkg.conf: {e}")

    return config


def create_custom_pacman_conf(buildroot_path: Path, build_dir: Path, extra_repos: List[Dict], log_output_func) -> Optional[Path]:
    """Create a modified pacman.conf with custom repositories in the build directory"""
    try:
        if not extra_repos:
            return None

        chroot_pacman_conf = buildroot_path / "root" / "etc" / "pacman.conf"

        if not chroot_pacman_conf.exists():
            log_output_func("Warning: pacman.conf not found in buildroot")
            return None

        # Read current pacman.conf
        with open(chroot_pacman_conf, 'r') as f:
            lines = f.readlines()

        # Find the [core] section and insert custom repos before it
        new_lines = []
        inserted_repos = False

        for line in lines:
            # Insert custom repos before the first [section] (usually [core])
            if line.strip().startswith('[') and not inserted_repos:
                # Add custom repositories as highest priority
                for repo in extra_repos:
                    repo_name = repo['name']
                    repo_url = repo['url']
                    new_lines.append(f"\n# Custom repository: {repo_name}\n")
                    new_lines.append(f"[{repo_name}]\n")
                    new_lines.append(f"SigLevel = Required\n")
                    new_lines.append(f"Server = {repo_url}\n")

                inserted_repos = True

            new_lines.append(line)

        # If no sections found, append at the end
        if not inserted_repos:
            new_lines.append("\n# Custom repositories\n")
            for repo in extra_repos:
                repo_name = repo['name']
                repo_url = repo['url']
                new_lines.append(f"[{repo_name}]\n")
                new_lines.append(f"SigLevel = Required\n")
                new_lines.append(f"Server = {repo_url}\n")

        # Write modified pacman.conf to build directory
        custom_pacman_conf = build_dir / "pacman.conf"
        with open(custom_pacman_conf, 'w') as f:
            f.writelines(new_lines)

        log_output_func(f"Created custom pacman.conf with {len(extra_repos)} custom repositories")
        return custom_pacman_conf

    except Exception as e:
        log_output_func(f"Error creating custom pacman.conf: {e}")
        return None


def download_repo_gpg_keys(extra_repos: List[Dict], log_output_func) -> bool:
    """Download and trust GPG keys for custom repositories"""
    try:
        if not extra_repos:
            return True

        buildroot_path = Path(server_config["buildroot"])

        for repo in extra_repos:
            gpg_key_id = repo.get('gpg_key_id')
            if not gpg_key_id:
                log_output_func(f"Warning: No GPG key ID for repository {repo['name']}")
                continue

            # Check if pacman-key already knows about the key
            cmd = ["sudo","pacman-key", "--list-keys", gpg_key_id]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                log_output_func(f"GPG key {gpg_key_id} already known to pacman-key")
                continue

            log_output_func(f"Downloading GPG key {gpg_key_id} for repository {repo['name']}")

            # Download the GPG key
            cmd = ["sudo","pacman-key", "--recv-keys", gpg_key_id]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                log_output_func(f"Failed to download GPG key {gpg_key_id}: {result.stderr}")
                return False

            # Refresh pacman keys in target chroot
            cmd = ["sudo","pacman-key", "--lsign-key", gpg_key_id ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                log_output_func(f"Failed to sign GPG key {gpg_key_id}: {result.stderr}")
                return False

        log_output_func(f"Successfully trusted GPG keys for {len(extra_repos)} repositories")
        return True

    except Exception as e:
        log_output_func(f"Error downloading GPG keys: {e}")
        return False


def lock_srcdest(srcdest_path: str, pkgname: str) -> Optional[int]:
    """Lock SRCDEST directory with package-specific lock file"""
    try:
        pkgname_hash = hashlib.md5(b'{pkgname}').hexdigest()
        lock_file = os.path.join(srcdest_path, f'.apb-{pkgname_hash}.lock')

        # Try to acquire lock
        fd = os.open(lock_file, os.O_CREAT | os.O_WRONLY | os.O_TRUNC)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except (OSError, IOError) as e:
            # Lock failed - check if it's an orphaned lock
            os.close(fd)

            # Check if any process is actually holding the lock file
            try:
                import subprocess
                result = subprocess.run(['lsof', lock_file],
                                      capture_output=True, text=True, timeout=5)
                if result.returncode != 0:
                    # No process is holding the lock - it's orphaned
                    logger.warning(f"Detected orphaned SRCDEST lock file {lock_file}, removing it")
                    try:
                        os.unlink(lock_file)
                        # Try to acquire lock again after cleanup
                        fd = os.open(lock_file, os.O_CREAT | os.O_WRONLY | os.O_TRUNC)
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        logger.info(f"Successfully acquired SRCDEST lock after cleanup")
                        return fd
                    except Exception as cleanup_error:
                        logger.error(f"Failed to clean up orphaned lock: {cleanup_error}")
                        if 'fd' in locals():
                            try:
                                os.close(fd)
                            except:
                                pass
                        return None
                else:
                    # A process is actually holding the lock
                    logger.debug(f"SRCDEST lock is held by another process")
                    return None
            except FileNotFoundError:
                # lsof not available - use file age as fallback
                try:
                    stat_info = os.stat(lock_file)
                    age_seconds = time.time() - stat_info.st_mtime
                    # If lock file is older than 5 minutes, consider it orphaned
                    if age_seconds > 300:
                        logger.warning(f"SRCDEST lock file is {age_seconds:.0f}s old, considering it orphaned")
                        try:
                            os.unlink(lock_file)
                            # Try to acquire lock again after cleanup
                            fd = os.open(lock_file, os.O_CREAT | os.O_WRONLY | os.O_TRUNC)
                            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            logger.info(f"Successfully acquired SRCDEST lock after age-based cleanup")
                            return fd
                        except Exception as cleanup_error:
                            logger.error(f"Failed to clean up old lock: {cleanup_error}")
                            return None
                    else:
                        logger.debug(f"SRCDEST lock file is recent ({age_seconds:.0f}s old), assuming it's valid")
                        return None
                except Exception as stat_error:
                    logger.debug(f"Could not check lock file age: {stat_error}")
                    return None
            except Exception as lsof_error:
                logger.debug(f"Could not check lock file status: {lsof_error}")
                return None

    except (OSError, IOError) as e:
        logger.error(f"Error accessing SRCDEST lock file: {e}")
        return None


def cleanup_orphaned_srcdest_locks():
    """Clean up orphaned SRCDEST lock files during server startup"""
    try:
        makepkg_config = get_makepkg_config()
        if 'SRCDEST' not in makepkg_config:
            return

        srcdest_path = makepkg_config['SRCDEST']

        # Find all APB lock files with the pattern .apb-*.lock
        import glob
        lock_pattern = os.path.join(srcdest_path, '.apb-*.lock')
        lock_files = glob.glob(lock_pattern)

        if not lock_files:
            return

        logger.info(f"Found {len(lock_files)} existing SRCDEST lock files: {[os.path.basename(f) for f in lock_files]}")

        cleaned_count = 0
        for lock_file in lock_files:
            try:
                # Check if any process is holding the lock
                try:
                    import subprocess
                    result = subprocess.run(['lsof', lock_file],
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode != 0:
                        # No process is holding the lock - it's orphaned
                        logger.warning(f"Removing orphaned SRCDEST lock file {os.path.basename(lock_file)} from previous session")
                        os.unlink(lock_file)
                        cleaned_count += 1
                        logger.info(f"Orphaned SRCDEST lock {os.path.basename(lock_file)} cleaned up successfully")
                    else:
                        logger.warning(f"SRCDEST lock {os.path.basename(lock_file)} is held by another process - not removing")
                        # Log which process is holding it
                        for line in result.stdout.split('\n'):
                            if line.strip():
                                logger.info(f"Lock held by: {line.strip()}")
                except FileNotFoundError:
                    # lsof not available - use file age as fallback
                    try:
                        stat_info = os.stat(lock_file)
                        age_seconds = time.time() - stat_info.st_mtime
                        # If lock file is older than 5 minutes, consider it orphaned
                        if age_seconds > 300:
                            logger.warning(f"SRCDEST lock file {os.path.basename(lock_file)} is {age_seconds:.0f}s old, removing orphaned lock from previous session")
                            os.unlink(lock_file)
                            cleaned_count += 1
                            logger.info(f"Old SRCDEST lock {os.path.basename(lock_file)} cleaned up successfully")
                        else:
                            logger.info(f"SRCDEST lock file {os.path.basename(lock_file)} is recent ({age_seconds:.0f}s old), leaving in place")
                    except Exception as stat_error:
                        logger.warning(f"Could not check lock file {os.path.basename(lock_file)} age: {stat_error}")
                        logger.info(f"Leaving lock file {os.path.basename(lock_file)} in place to be safe")
                except Exception as e:
                    logger.warning(f"Could not check SRCDEST lock {os.path.basename(lock_file)} status during startup: {e}")
                    logger.info(f"Leaving lock file {os.path.basename(lock_file)} in place to be safe")
            except Exception as lock_error:
                logger.error(f"Error processing lock file {lock_file}: {lock_error}")

        if cleaned_count > 0:
            logger.info(f"SRCDEST lock cleanup completed: removed {cleaned_count} orphaned lock files")

    except Exception as e:
        logger.error(f"Error during SRCDEST lock cleanup: {e}")


def unlock_srcdest(lock_fd: int):
    """Unlock SRCDEST directory"""
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
    except Exception as e:
        logger.error(f"Error unlocking SRCDEST: {e}")


def finalize_failed_build(build_id: str, build_dir: Path, reason: str, exit_code: int = 1):
    """Finalize a failed build with proper logging and cleanup"""
    try:
        # Update build status
        active_builds[build_id]["status"] = BuildStatus.FAILED
        active_builds[build_id]["exit_code"] = exit_code
        active_builds[build_id]["end_time"] = time.time()
        active_builds[build_id]["duration"] = active_builds[build_id]["end_time"] - active_builds[build_id]["start_time"]

        error_message = f"ERROR: {reason}"
        if build_id in build_outputs:
            build_outputs[build_id].append(error_message)
        else:
            build_outputs[build_id] = [error_message]
        append_build_log(build_id, error_message, build_dir)
        register_build_log_artifact(build_id, build_dir)

        # Send completion event to streams
        for stream_queue in build_streams.get(build_id, []):
            try:
                stream_queue.put_nowait(("complete", {
                    "status": active_builds[build_id]["status"],
                    "exit_code": active_builds[build_id]["exit_code"]
                }))
            except queue.Full:
                pass  # Drop completion event if queue is full
            except:
                pass

        # Move to history
        build_history[build_id] = active_builds[build_id].copy()

        logger.info(f"Build {build_id} failed: {reason}")

    except Exception as e:
        logger.error(f"Error finalizing failed build {build_id}: {e}")
        close_build_log(build_id)


def build_package(build_id: str, build_dir: Path, pkgbuild_info: Dict[str, Any], build_timeout: int = BUILD_TIMEOUT, extra_repos: List[Dict] = None):
    """Build package using makechrootpkg"""
    global build_counter

    logger.info(f"build_package called for build {build_id}")

    try:
        # Update build status
        active_builds[build_id]["status"] = BuildStatus.BUILDING
        active_builds[build_id]["start_time"] = time.time()

        # Add to build outputs and open full on-disk log
        build_outputs[build_id] = []
        open_build_log(build_id, build_dir)

        def log_output(message: str):
            build_outputs[build_id].append(message)
            append_build_log(build_id, message, build_dir)
            # Send to streams asynchronously
            for stream_queue in build_streams.get(build_id, []):
                try:
                    stream_queue.put_nowait(("output", message))  # Non-blocking
                except queue.Full:
                    pass  # Drop messages if queue is full
                except:
                    pass

        log_output(f"Starting build for {pkgbuild_info['pkgname']}")
        logger.info(f"Build {build_id} status updated to BUILDING")

        # Check if buildroot needs recreation
        buildroot_path = Path(server_config["buildroot"])
        should_recreate = False

        if server_config.get("buildroot_autorecreate"):
            build_counter += 1
            if build_counter >= server_config["buildroot_autorecreate"]:
                should_recreate = True
                build_counter = 0
                log_output(f"Recreating buildroot after {server_config['buildroot_autorecreate']} builds")

        # Recreate buildroot if needed
        if should_recreate:
            # Mark this build as doing buildroot recreation
            buildroot_recreation_builds[build_id] = True
            log_output("Removing existing buildroot for recreation")
            try:
                root_path = buildroot_path / "root"
                if root_path.exists():
                    log_output("Removing existing buildroot directory...")
                    # Use subprocess to avoid blocking the main thread
                    result = subprocess.run(['sudo', 'rm', '-rf', str(root_path)],
                                          capture_output=True, text=True, timeout=300)
                    if result.returncode != 0:
                        log_output(f"Warning: Could not remove buildroot: {result.stderr}")
                        # Continue anyway - mkarchroot might handle it

                log_output("Setting up new buildroot...")
                if not setup_buildroot(buildroot_path):
                    # Don't fail the build - just log the warning and continue
                    log_output("Warning: Failed to recreate buildroot, continuing with existing buildroot")
                    build_counter = 0  # Reset counter to avoid immediate retry
                else:
                    log_output("Buildroot recreation completed successfully")
            except Exception as e:
                log_output(f"Warning: Could not recreate buildroot: {e}")
                log_output("Continuing with existing buildroot")
                build_counter = 0  # Reset counter to avoid immediate retry
            finally:
                # Clear buildroot recreation flag
                if build_id in buildroot_recreation_builds:
                    del buildroot_recreation_builds[build_id]
                log_output("Buildroot recreation phase completed, proceeding with package build")

        # Get makepkg config
        makepkg_config = get_makepkg_config()

        # Lock SRCDEST if it exists with timeout
        srcdest_lock = None
        if 'SRCDEST' in makepkg_config:
            log_output(f"Attempting to acquire SRCDEST lock for {makepkg_config['SRCDEST']} (package: {pkgbuild_info['pkgname']})")
            srcdest_lock = lock_srcdest(makepkg_config['SRCDEST'], pkgbuild_info['pkgname'])
            if srcdest_lock is None:
                log_output("Waiting for SRCDEST lock...")
                # Wait for lock with timeout to prevent infinite waiting
                lock_start_time = time.time()
                while srcdest_lock is None and not shutdown_event.is_set():
                    if time.time() - lock_start_time > 600:  # 10 minute timeout
                        log_output("SRCDEST lock timeout after 10 minutes, continuing without lock")
                        break
                    time.sleep(5)  # Check every 5 seconds instead of 1
                    srcdest_lock = lock_srcdest(makepkg_config['SRCDEST'], pkgbuild_info['pkgname'])

            if srcdest_lock is not None:
                log_output("SRCDEST lock acquired successfully")
            else:
                log_output("Proceeding without SRCDEST lock (timeout or unavailable)")

        try:
            # Import GPG keys from local keys/ directory if it exists
            log_output("Checking for local GPG keys...")
            pkgbuild_path = build_dir / "PKGBUILD"
            if not import_local_gpg_keys(pkgbuild_path, log_output):
                log_output("Local GPG key import failed, continuing build (may fail during source validation)")

            # Handle custom repositories
            custom_pacman_conf = None
            if extra_repos:
                log_output(f"Setting up {len(extra_repos)} custom repositories...")

                # Download and trust GPG keys for custom repositories
                if not download_repo_gpg_keys(extra_repos, log_output):
                    log_output("ERROR: Failed to download GPG keys for custom repositories")
                    if srcdest_lock:
                        unlock_srcdest(srcdest_lock)
                    finalize_failed_build(build_id, build_dir, "Failed to download GPG keys for custom repositories")
                    return

                # Create custom pacman.conf with custom repositories
                custom_pacman_conf = create_custom_pacman_conf(buildroot_path, build_dir, extra_repos, log_output)
                if custom_pacman_conf is None:
                    log_output("ERROR: Failed to create custom pacman.conf for custom repositories")
                    if srcdest_lock:
                        unlock_srcdest(srcdest_lock)
                    finalize_failed_build(build_id, build_dir, "Failed to create custom pacman.conf for custom repositories")
                    return

            # Build makechrootpkg command with correct flags
            # Check if we need to prefix with ppc32 for PowerPC architectures
            server_arch = get_server_architecture()
            if server_arch in ["powerpc", "espresso"]:
                cmd = ["sudo", "ppc32", "makechrootpkg", "-cuT", "-r", str(buildroot_path)]
                log_output(f"Using ppc32 prefix for {server_arch} architecture to ensure 32-bit detection")
            else:
                cmd = ["sudo", "makechrootpkg", "-cuT", "-r", str(buildroot_path)]

            # Add bind mounts
            if 'CCACHE_DIR' in makepkg_config:
                cmd.extend(["-d", makepkg_config['CCACHE_DIR']])
            if 'SRCDEST' in makepkg_config:
                cmd.extend(["-d", makepkg_config['SRCDEST']])

            # Add custom pacman.conf and gpgdir if we have custom repositories
            if custom_pacman_conf:
                cmd.extend(["-D", f"{custom_pacman_conf}:/etc/pacman.conf"])
                cmd.extend(["-D", "/etc/pacman.d/gnupg:/etc/pacman.d/gnupg"])

            log_output(f"Running: {' '.join(cmd)}")

            # Execute build with timeout management (binary stdout so select/os.read drain the pipe fast)
            process = subprocess.Popen(
                cmd,
                cwd=build_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
                preexec_fn=os.setsid  # Create new process group for better cleanup
            )
            running_processes[build_id] = process  # Track the process
            stdout_fd = process.stdout.fileno()
            set_fd_nonblocking(stdout_fd)
            partial_output = bytearray()
            last_flush_time = time.time()

            def emit_output_line(line: str):
                nonlocal last_output_time
                log_output(line)
                last_output_time = time.time()

            # Stream output with timeout management
            start_time = time.time()
            last_output_time = start_time

            # Calculate output timeout - use PKGBUILD variable if set, otherwise default to 30 minutes
            output_timeout = pkgbuild_info.get("apb_output_timeout") or 1800  # Default 1800 seconds = 30 minutes

            while True:
                try:
                    # Check for shutdown or timeout
                    current_time = time.time()
                    if shutdown_event.is_set():
                        log_output("Build cancelled due to server shutdown")
                        process.terminate()
                        break

                    # Check overall build timeout
                    if current_time - start_time > build_timeout:
                        log_output(f"Build timed out after {build_timeout} seconds")
                        process.terminate()
                        break

                    # Check for output timeout (no output for configured time = hung build)
                    if current_time - last_output_time > output_timeout:
                        log_output(f"Build appears to be hung (no output for {output_timeout} seconds), terminating")
                        process.terminate()
                        break

                    try:
                        process_done = process.poll() is not None
                        # Wait briefly for data when the process is still running
                        wait_timeout = 0.0 if process_done else 1.0
                        if select.select([stdout_fd], [], [], wait_timeout)[0]:
                            if not drain_process_stdout(stdout_fd, partial_output, emit_output_line):
                                flush_build_log(build_id)
                                break
                        elif process_done:
                            # Process exited and pipe is idle: final non-blocking drain/EOF check
                            if not drain_process_stdout(stdout_fd, partial_output, emit_output_line):
                                flush_build_log(build_id)
                                break
                            flush_partial_process_output(partial_output, emit_output_line)
                            flush_build_log(build_id)
                            break

                        if time.time() - last_flush_time >= LOG_FLUSH_INTERVAL_SECONDS:
                            flush_build_log(build_id)
                            last_flush_time = time.time()

                    except Exception as e:
                        logger.error(f"Error reading process output: {e}")
                        break

                except KeyboardInterrupt:
                    log_output("Build interrupted")
                    process.terminate()
                    break

            flush_build_log(build_id)

            # Wait for process to finish with timeout
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                logger.warning(f"Build process {build_id} did not terminate gracefully, killing")
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except:
                    process.kill()
                process.wait()

            # Check if build was successful
            if process.returncode == 0:
                active_builds[build_id]["status"] = BuildStatus.COMPLETED
                active_builds[build_id]["exit_code"] = 0
                log_output("Build completed successfully")

                # Find built packages
                packages = []
                for pkg_file in build_dir.glob("*.pkg.tar.*"):
                    packages.append({
                        "filename": pkg_file.name,
                        "size": pkg_file.stat().st_size,
                        "download_url": f"/build/{build_id}/download/{pkg_file.name}"
                    })

                active_builds[build_id]["packages"] = packages

            else:
                active_builds[build_id]["status"] = BuildStatus.FAILED
                active_builds[build_id]["exit_code"] = process.returncode
                log_output(f"Build failed with exit code {process.returncode}")

        finally:
            if srcdest_lock:
                unlock_srcdest(srcdest_lock)
            if build_id in running_processes:
                del running_processes[build_id] # Ensure process is removed from tracking

        # Finalize build
        active_builds[build_id]["end_time"] = time.time()
        active_builds[build_id]["duration"] = active_builds[build_id]["end_time"] - active_builds[build_id]["start_time"]

        log_output(f"Build {build_id} finished")
        register_build_log_artifact(build_id, build_dir)

        # Send completion event to streams
        for stream_queue in build_streams.get(build_id, []):
            try:
                stream_queue.put_nowait(("complete", {
                    "status": active_builds[build_id]["status"],
                    "exit_code": active_builds[build_id].get("exit_code", 1)
                }))
            except queue.Full:
                pass  # Drop completion event if queue is full
            except:
                pass

        # Move to history
        build_history[build_id] = active_builds[build_id].copy()

    except Exception as e:
        logger.error(f"Build error: {e}")
        # Release SRCDEST lock if it was acquired
        if 'srcdest_lock' in locals() and srcdest_lock:
            unlock_srcdest(srcdest_lock)
        active_builds[build_id]["status"] = BuildStatus.FAILED
        active_builds[build_id]["end_time"] = time.time()
        active_builds[build_id]["duration"] = active_builds[build_id]["end_time"] - active_builds[build_id]["start_time"]
        active_builds[build_id]["exit_code"] = 1

        error_message = f"Build failed: {str(e)}"
        if build_id in build_outputs:
            build_outputs[build_id].append(error_message)
        else:
            build_outputs[build_id] = [error_message]
        append_build_log(build_id, error_message, build_dir)
        register_build_log_artifact(build_id, build_dir)

        # Move to history
        build_history[build_id] = active_builds[build_id].copy()

    finally:
        close_build_log(build_id)


def process_build_queue():
    """Process builds from queue"""
    logger.info("Build queue processor thread started")
    while not shutdown_event.is_set():
        try:
            # Get build from queue
            if logger.level <= logging.DEBUG:
                logger.debug(f"Checking queue for builds (queue size: {build_queue.qsize()})")
            build_data = build_queue.get(timeout=1)

            build_id = build_data["build_id"]
            logger.info(f"Processing build {build_id} from queue")

            # Submit to executor
            if logger.level <= logging.DEBUG:
                logger.debug(f"Executor state - max_workers: {build_executor._max_workers}, active threads: {len(build_executor._threads)}")
            future = build_executor.submit(
                build_package,
                build_data["build_id"],
                build_data["build_dir"],
                build_data["pkgbuild_info"],
                build_data.get("build_timeout", BUILD_TIMEOUT),
                build_data.get("extra_repos", [])
            )
            logger.info(f"Build {build_id} submitted to executor")

        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Error processing build queue: {e}")
            # Log more details about the error
            import traceback
            logger.error(f"Queue processor traceback: {traceback.format_exc()}")

    logger.info("Build queue processor thread stopped")


# Queue processor is now started in the lifespan manager


