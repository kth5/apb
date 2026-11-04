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
import re
import resource
import select
import shutil
import signal
import subprocess
import sys
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
from apb.upstream import build_download_path
from apb.validation import REPO_LEVEL_ORDER, REPO_LEVEL_SECTIONS, RepoLevel, sections_for_level

logger = logging.getLogger(__name__)

DEFAULT_HOST = "localhost"
DEFAULT_PORT = 8000
DEFAULT_BUILDROOT = Path.home() / ".apb" / "buildroot"
DEFAULT_BUILDS_DIR = Path.home() / ".apb" / "builds"
DEFAULT_MAX_CONCURRENT = 3
DEFAULT_SRCDEST_CLEANUP_INTERVAL = 86400
DEFAULT_SRCDEST_RETENTION_DAYS = 30
BUILD_TIMEOUT = BUILD_TIMEOUT_DEFAULT
HOST_CONF_DIR = Path("/etc")

# Kept on disk after a failed build so the farm and clients can still download it
FAILED_BUILD_RETAINED_FILES = {"build.log"}

ACTIVE_SECTION_RE = re.compile(r"^\[([^\]]+)\]$")
COMMENTED_SECTION_RE = re.compile(r"^#\s*\[([^\]]+)\]$")
COMMENTED_OPTION_RE = re.compile(r"^#\s*((?:Include|Server|SigLevel|Usage|CacheServer)\s*=.*)$")
LEVEL_APPLIED_CONF_NAME = ".apb-pacman.conf"
REPO_LEVEL_SECTION_NAMES = frozenset(section for sections in REPO_LEVEL_SECTIONS.values() for section in sections)

# Global state
build_queue = queue.Queue()
chroot_slots: queue.Queue = queue.Queue()
active_builds: Dict[str, Dict] = {}
build_history: Dict[str, Dict] = {}
build_executor = ThreadPoolExecutor(max_workers=DEFAULT_MAX_CONCURRENT)
build_outputs: Dict[str, List[str]] = {}
build_streams: Dict[str, List] = {}
build_log_handles: Dict[str, Any] = {}  # build_id -> open file handle for build.log
server_config = {}
shutdown_event = threading.Event()
running_processes: Dict[str, subprocess.Popen] = {}  # Track running build processes

BUILDROOT_STATE_IDLE = "idle"
BUILDROOT_STATE_DRAINING = "draining"
BUILDROOT_STATE_RECREATING = "recreating"

buildroot_state_lock = threading.Lock()
level_buildroot_lock = threading.Lock()
finished_build_counter = 0
buildroot_state = BUILDROOT_STATE_IDLE
in_flight_builds = 0


def init_chroot_slots(count: int) -> None:
    """Reset the pool of makechrootpkg copy names (one per concurrent build slot)."""
    global chroot_slots
    chroot_slots = queue.Queue()
    for index in range(count):
        chroot_slots.put(f"apb-slot-{index}")


init_chroot_slots(DEFAULT_MAX_CONCURRENT)

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
        "download_url": build_download_path(build_id, "build.log")
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


def cleanup_failed_build_dir(build_id: str, build_dir: Path) -> None:
    """Purge sources and artifacts of a failed build, keeping build.log downloadable."""
    if build_id in running_processes:
        logger.info("Skipping cleanup for %s while build process is still tracked", build_id)
        return

    build_info = active_builds.get(build_id) or build_history.get(build_id)
    if not build_info or build_info.get("status") != BuildStatus.FAILED:
        return

    if not build_dir.is_dir():
        return

    removed_count = 0
    for entry in build_dir.iterdir():
        if entry.name in FAILED_BUILD_RETAINED_FILES:
            continue
        try:
            if entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry)
            else:
                entry.unlink()
            removed_count += 1
        except Exception as exc:
            logger.error("Error removing %s for failed build %s: %s", entry, build_id, exc)

    logger.info(
        "Cleaned up failed build %s: removed %s entries, retained %s",
        build_id,
        removed_count,
        ", ".join(sorted(FAILED_BUILD_RETAINED_FILES)),
    )


def stop_tracked_build_process(build_id: str) -> None:
    """Stop and untrack a build subprocess if it is still running."""
    process = running_processes.pop(build_id, None)
    if process is None or process.poll() is not None:
        return

    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.kill()
    except ProcessLookupError:
        pass
    except Exception as exc:
        logger.warning("Error stopping build process for %s: %s", build_id, exc)
        try:
            process.kill()
        except Exception:
            pass


def terminate_build(build_id: str):
    """Terminate a specific build"""
    try:
        if build_id in running_processes:
            process = running_processes[build_id]

            process.terminate()
            try:
                process.wait(timeout=10)
                logger.info(f"Build {build_id} terminated gracefully after SIGTERM")
            except subprocess.TimeoutExpired:
                logger.warning(
                    f"Build {build_id} did not respond to SIGTERM within 10s, sending SIGKILL"
                )
                process.kill()

            del running_processes[build_id]

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
        logger.error(f"Error terminating build {build_id}: {e}")


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

    with buildroot_state_lock:
        recreation_state = buildroot_state
        buildroot_recreation_count = 1 if recreation_state == BUILDROOT_STATE_RECREATING else 0
        server_busy_with_buildroot = recreation_state in (
            BUILDROOT_STATE_DRAINING,
            BUILDROOT_STATE_RECREATING,
        )

    current_build = None

    for build_id, build_info in active_builds.items():
        if build_info["status"] == BuildStatus.BUILDING:
            build_details = {
                "build_id": build_id,
                "pkgname": build_info.get("pkgname", "unknown"),
                "status": "building",
                "start_time": build_info.get("start_time", time.time()),
                "buildroot_recreation": False,
            }

            if not current_build:
                current_build = build_details

    return {
        "current_builds_count": current_builds,
        "queued_builds": queued_builds,
        "max_concurrent_builds": server_config.get("max_concurrent", DEFAULT_MAX_CONCURRENT),
        "current_build": current_build,
        "total_active_builds": len(active_builds),
        "build_history_count": len(build_history),
        "buildroot_recreation_count": buildroot_recreation_count,
        "buildroot_recreation_builds": [],
        "buildroot_recreation_state": recreation_state,
        "server_busy_with_buildroot": server_busy_with_buildroot,
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
        srcdest_override = get_srcdest_override()

        makepkg_host_conf = get_makepkg_conf_path()
        conf_sources = (
            ("makepkg.conf", makepkg_host_conf),
            ("pacman.conf", HOST_CONF_DIR / "pacman.conf"),
        )
        for conf_name, host_conf in conf_sources:
            chroot_conf = chroot_etc / conf_name
            if host_conf.exists():
                logger.info("Copying host %s to chroot", host_conf)
                source_conf = host_conf
                staged_conf = None
                try:
                    if conf_name == "makepkg.conf" and srcdest_override:
                        logger.info(f"Overriding chroot SRCDEST with {srcdest_override}")
                        staged_conf = stage_makepkg_conf_override(
                            host_conf, buildroot_path, srcdest_override
                        )
                        source_conf = staged_conf

                    cmd = ["sudo", "cp", str(source_conf), str(chroot_conf)]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode != 0:
                        logger.error(f"Failed to copy {conf_name}: {result.stderr}")
                        return False
                except Exception as e:
                    logger.error(f"Failed to copy {conf_name}: {e}")
                    return False
                finally:
                    if staged_conf is not None:
                        staged_conf.unlink(missing_ok=True)
            else:
                logger.warning("Host %s not found", host_conf)

        return True
    except Exception as e:
        logger.error(f"Error setting up buildroot: {e}")
        return False


def register_finished_build() -> None:
    """Count a finished build toward buildroot auto-recreation."""
    threshold = server_config.get("buildroot_autorecreate")
    if not threshold:
        return

    global finished_build_counter, buildroot_state
    with buildroot_state_lock:
        finished_build_counter += 1
        if finished_build_counter >= threshold and buildroot_state == BUILDROOT_STATE_IDLE:
            buildroot_state = BUILDROOT_STATE_DRAINING
            logger.info(
                "Buildroot recreation scheduled after %s finished builds (threshold %s)",
                finished_build_counter,
                threshold,
            )


def _remove_buildroot_paths(buildroot_path: Path) -> None:
    """Remove root, per-slot chroot copies and repo-level chroots under the buildroot."""
    paths_to_remove = [buildroot_path / "root"]
    for slot_path in buildroot_path.glob("apb-slot-*"):
        paths_to_remove.append(slot_path)
    for lock_path in buildroot_path.glob("apb-slot-*.lock"):
        paths_to_remove.append(lock_path)
    for level in REPO_LEVEL_ORDER[1:]:
        paths_to_remove.append(get_level_buildroot(buildroot_path, level))

    for path in paths_to_remove:
        if not path.exists():
            continue
        logger.info("Removing buildroot path: %s", path)
        result = subprocess.run(
            ["sudo", "rm", "-rf", str(path)],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Could not remove {path}: {result.stderr}")


def recreate_buildroot(buildroot_path: Path) -> bool:
    """Remove and recreate the buildroot after all in-flight builds have finished."""
    global finished_build_counter, buildroot_state

    with buildroot_state_lock:
        buildroot_state = BUILDROOT_STATE_RECREATING

    success = False
    try:
        logger.info("Recreating buildroot at %s", buildroot_path)
        _remove_buildroot_paths(buildroot_path)
        success = setup_buildroot(buildroot_path)
        if success:
            logger.info("Buildroot recreation completed successfully")
        else:
            logger.warning("Failed to recreate buildroot; continuing with existing buildroot if present")
    except Exception as exc:
        logger.warning("Could not recreate buildroot: %s", exc)
    finally:
        with buildroot_state_lock:
            finished_build_counter = 0
            buildroot_state = BUILDROOT_STATE_IDLE

    return success


def get_makepkg_conf_path() -> Path:
    """Path to the host makepkg.conf for this server instance"""
    configured = server_config.get("makepkg_conf")
    if configured:
        return Path(configured)
    return HOST_CONF_DIR / "makepkg.conf"


def parse_makepkg_conf(conf_path: Optional[Path] = None) -> Dict[str, str]:
    """Parse a makepkg.conf for SRCDEST and CCACHE_DIR"""
    conf_path = conf_path or get_makepkg_conf_path()
    config = {}
    try:
        with open(conf_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('SRCDEST=') and not line.startswith('#'):
                    config['SRCDEST'] = line.split('=', 1)[1].strip('\'"')
                elif line.startswith('export CCACHE_DIR=') and not line.startswith('#'):
                    config['CCACHE_DIR'] = line.split('=', 1)[1].strip('\'"')
    except Exception as e:
        logger.error(f"Error reading {conf_path}: {e}")

    return config


def get_srcdest_override() -> Optional[str]:
    """Return the SRCDEST configured via the command line, if any"""
    srcdest = server_config.get("srcdest")
    return str(srcdest) if srcdest else None


def get_makepkg_config() -> Dict[str, str]:
    """Effective makepkg settings from the configured makepkg.conf with --srcdest override applied"""
    config = parse_makepkg_conf()

    srcdest_override = get_srcdest_override()
    if srcdest_override:
        config['SRCDEST'] = srcdest_override

    return config


def apply_srcdest_override(conf_text: str, srcdest: str) -> str:
    """Replace or append the SRCDEST assignment in makepkg.conf content"""
    assignment = f'SRCDEST="{srcdest}"'
    lines = conf_text.splitlines()
    replaced = False

    for index, line in enumerate(lines):
        if line.strip().startswith('SRCDEST='):
            lines[index] = assignment
            replaced = True

    if not replaced:
        lines.append(assignment)

    return "\n".join(lines) + "\n"


def stage_makepkg_conf_override(host_conf: Path, staging_dir: Path, srcdest: str) -> Path:
    """Write a copy of makepkg.conf carrying the SRCDEST override, ready to be copied into a chroot"""
    conf_text = host_conf.read_text(encoding="utf-8")
    staged_conf = staging_dir / ".makepkg.conf.apb"
    staged_conf.write_text(apply_srcdest_override(conf_text, srcdest), encoding="utf-8")
    # The chroot copy inherits this mode, and makepkg runs as an unprivileged user inside it
    staged_conf.chmod(0o644)
    return staged_conf


def _commented_level_sections(lines: List[str]) -> Dict[str, Tuple[range, List[str]]]:
    """Map commented-out repo-level sections to their line range and uncommented lines.

    A section counts only when its header is followed directly by at least one
    commented Include/Server/SigLevel/Usage/CacheServer line.
    """
    sections: Dict[str, Tuple[range, List[str]]] = {}
    index = 0
    while index < len(lines):
        header = COMMENTED_SECTION_RE.match(lines[index].strip())
        name = header.group(1) if header else None
        if name not in REPO_LEVEL_SECTION_NAMES or name in sections:
            index += 1
            continue
        end = index + 1
        options = []
        while end < len(lines) and (option := COMMENTED_OPTION_RE.match(lines[end].strip())):
            options.append(option.group(1))
            end += 1
        if options:
            sections[name] = (range(index, end), [f"[{name}]", *options])
        index = end
    return sections


def find_repo_level_blocks(pacman_conf_text: str) -> Dict[str, List[str]]:
    """Commented-out repo-level sections in a pacman.conf, as uncommented lines."""
    return {name: block for name, (_, block) in _commented_level_sections(pacman_conf_text.splitlines()).items()}


def available_repo_levels(pacman_conf_text: str) -> List[RepoLevel]:
    """Levels above BASE whose sections, and those of every level below, can be enabled."""
    blocks = find_repo_level_blocks(pacman_conf_text)
    levels = []
    for level in REPO_LEVEL_ORDER[1:]:
        if not all(section in blocks for section in REPO_LEVEL_SECTIONS[level]):
            break
        levels.append(level)
    return levels


def compose_pacman_conf(pacman_conf_text: str, extra_repos: List[Dict], repo_level: RepoLevel) -> str:
    """Return pacman.conf with custom repos and the level's sections in front of the first repository.

    Raises ValueError when a section required by ``repo_level`` is not commented out in the input.
    """
    lines = pacman_conf_text.splitlines()
    level_sections = _commented_level_sections(lines)
    enabled_sections = sections_for_level(repo_level)
    missing_sections = [section for section in enabled_sections if section not in level_sections]
    if missing_sections:
        raise ValueError(f"pacman.conf has no commented-out sections for: {', '.join(missing_sections)}")

    removed_lines = {index for section in enabled_sections for index in level_sections[section][0]}
    kept_lines = [line for index, line in enumerate(lines) if index not in removed_lines]

    inserted_lines: List[str] = []
    for repo in extra_repos:
        inserted_lines += [
            f"# Custom repository: {repo['name']}",
            f"[{repo['name']}]",
            "SigLevel = Required",
            f"Server = {repo['url']}",
            "",
        ]
    for section in enabled_sections:
        inserted_lines += [*level_sections[section][1], ""]

    first_repo_index = next(
        (
            index for index, line in enumerate(kept_lines)
            if (section := ACTIVE_SECTION_RE.match(line.strip())) and section.group(1) != "options"
        ),
        None,
    )
    if first_repo_index is None:
        new_lines = kept_lines + [""] + inserted_lines
    else:
        new_lines = kept_lines[:first_repo_index] + inserted_lines + kept_lines[first_repo_index:]
    return "\n".join(new_lines).rstrip("\n") + "\n"


def get_buildroot_pacman_conf_path() -> Path:
    """pacman.conf builds start from: the buildroot copy, or the host file before the buildroot exists."""
    buildroot_conf = Path(server_config.get("buildroot", DEFAULT_BUILDROOT)) / "root" / "etc" / "pacman.conf"
    return buildroot_conf if buildroot_conf.exists() else HOST_CONF_DIR / "pacman.conf"


def get_repo_levels() -> List[RepoLevel]:
    """Repository levels above BASE this server can build against."""
    try:
        return available_repo_levels(get_buildroot_pacman_conf_path().read_text())
    except OSError as e:
        logger.warning(f"Cannot read pacman.conf for repository levels: {e}")
        return []


def chroot_arch_prefix(server_arch: str) -> List[str]:
    """Personality wrapper so chroot tools detect 32-bit PowerPC."""
    return ["ppc32"] if server_arch in ("powerpc", "espresso") else []


def get_level_buildroot(buildroot_path: Path, repo_level: RepoLevel) -> Path:
    """makechrootpkg -r directory for ``repo_level``; BASE uses the buildroot itself."""
    return buildroot_path if repo_level == RepoLevel.BASE else buildroot_path / repo_level.value


def _run_chroot_command(cmd: List[str], log_output_func, timeout: int) -> bool:
    log_output_func(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        log_output_func(f"Command timed out after {timeout} seconds")
        return False
    if result.returncode != 0:
        log_output_func(f"Command failed with exit code {result.returncode}: {result.stderr.strip()}")
        return False
    return True


def ensure_level_buildroot(buildroot_path: Path, repo_level: RepoLevel, log_output_func) -> Optional[Path]:
    """Return the makechrootpkg -r directory for ``repo_level``, preparing its chroot when needed.

    Testing and stage builds use their own chroot, copied from the base root on first use,
    whose pacman.conf has the level's sections enabled; makechrootpkg -u then syncs their
    databases into every build copy. The chroot is updated again when the host sections change.
    """
    if repo_level == RepoLevel.BASE:
        return buildroot_path

    level_buildroot = get_level_buildroot(buildroot_path, repo_level)
    level_root = level_buildroot / "root"
    base_root = buildroot_path / "root"

    with level_buildroot_lock:
        try:
            composed = compose_pacman_conf((base_root / "etc" / "pacman.conf").read_text(), [], repo_level)
        except (OSError, ValueError) as e:
            log_output_func(f"Cannot prepare pacman.conf for repository level '{repo_level.value}': {e}")
            return None

        # arch-nspawn rewrites CacheDir in the chroot's copy, so compare against the last applied input
        applied_conf = level_buildroot / LEVEL_APPLIED_CONF_NAME
        if level_root.exists() and applied_conf.exists() and applied_conf.read_text() == composed:
            return level_buildroot

        level_buildroot.mkdir(parents=True, exist_ok=True)
        applied_conf.unlink(missing_ok=True)
        if not level_root.exists():
            log_output_func(f"Creating {repo_level.value} chroot {level_root} from {base_root}")
            if not _run_chroot_command(
                ["sudo", "cp", "-a", "--reflink=auto", str(base_root), str(level_root)],
                log_output_func,
                timeout=1800,
            ):
                subprocess.run(["sudo", "rm", "-rf", str(level_root)], capture_output=True, text=True)
                return None
        else:
            log_output_func(f"Updating pacman.conf of {repo_level.value} chroot {level_root}")

        staged_conf = level_buildroot / ".pacman.conf.apb"
        staged_conf.write_text(composed)
        try:
            is_synced = _run_chroot_command(
                [
                    "sudo",
                    *chroot_arch_prefix(get_server_architecture()),
                    "arch-nspawn",
                    "-C",
                    str(staged_conf),
                    str(level_root),
                    "pacman",
                    "-Syuu",
                    "--noconfirm",
                ],
                log_output_func,
                timeout=3600,
            )
        finally:
            staged_conf.unlink(missing_ok=True)

        if not is_synced:
            # A partially prepared chroot would be reused as-is; start over on the next build
            subprocess.run(["sudo", "rm", "-rf", str(level_root)], capture_output=True, text=True)
            return None

        applied_conf.write_text(composed)
        log_output_func(f"{repo_level.value} chroot ready: {', '.join(sections_for_level(repo_level))} enabled")
        return level_buildroot


def create_custom_pacman_conf(
    buildroot_path: Path,
    build_dir: Path,
    extra_repos: List[Dict],
    log_output_func,
) -> Optional[Path]:
    """Write build_dir/pacman.conf: the buildroot's pacman.conf with custom repositories in front."""
    try:
        chroot_pacman_conf = buildroot_path / "root" / "etc" / "pacman.conf"

        if not chroot_pacman_conf.exists():
            log_output_func("Warning: pacman.conf not found in buildroot")
            return None

        composed = compose_pacman_conf(chroot_pacman_conf.read_text(), extra_repos, RepoLevel.BASE)
        custom_pacman_conf = build_dir / "pacman.conf"
        custom_pacman_conf.write_text(composed)

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


def srcdest_lock_path(srcdest_path: str, pkgname: str) -> str:
    """Path to the package-specific SRCDEST lock file."""
    pkgname_hash = hashlib.md5(pkgname.encode()).hexdigest()
    return os.path.join(srcdest_path, f".apb-{pkgname_hash}.lock")


def lock_srcdest(srcdest_path: str, pkgname: str) -> Optional[int]:
    """Lock SRCDEST for one package (exclusive per pkgname, shared across different packages)."""
    lock_file = srcdest_lock_path(srcdest_path, pkgname)
    try:
        fd = os.open(lock_file, os.O_CREAT | os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, IOError):
            os.close(fd)
            return None

        try:
            if os.fstat(fd).st_ino != os.stat(lock_file).st_ino:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
                return None
        except OSError:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
            return None

        return fd
    except (OSError, IOError) as exc:
        logger.error("Error accessing SRCDEST lock file %s: %s", lock_file, exc)
        return None


def cleanup_orphaned_srcdest_locks():
    """Remove SRCDEST lock files that are not held by any process."""
    try:
        makepkg_config = get_makepkg_config()
        if "SRCDEST" not in makepkg_config:
            return

        srcdest_path = makepkg_config["SRCDEST"]
        lock_pattern = os.path.join(srcdest_path, ".apb-*.lock")
        lock_files = glob.glob(lock_pattern)

        if not lock_files:
            return

        logger.info(
            "Found %s existing SRCDEST lock files: %s",
            len(lock_files),
            [os.path.basename(path) for path in lock_files],
        )

        cleaned_count = 0
        for lock_file in lock_files:
            try:
                fd = os.open(lock_file, os.O_RDWR)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    os.unlink(lock_file)
                    cleaned_count += 1
                    logger.info("Removed unheld SRCDEST lock %s", os.path.basename(lock_file))
                except (OSError, IOError):
                    logger.debug(
                        "SRCDEST lock %s is held by a running build, leaving in place",
                        os.path.basename(lock_file),
                    )
                finally:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    except OSError:
                        pass
                    os.close(fd)
            except OSError as lock_error:
                logger.error("Error processing lock file %s: %s", lock_file, lock_error)

        if cleaned_count > 0:
            logger.info("SRCDEST lock cleanup completed: removed %s unheld lock files", cleaned_count)

    except Exception as exc:
        logger.error("Error during SRCDEST lock cleanup: %s", exc)


def build_makechrootpkg_command(
    buildroot_path: Path,
    chroot_copy: str,
    makepkg_config: Dict[str, Any],
    custom_pacman_conf: Optional[str],
    server_arch: str,
) -> List[str]:
    """Assemble the makechrootpkg command for a build."""
    cmd = [
        "sudo",
        *chroot_arch_prefix(server_arch),
        "makechrootpkg",
        "-cuT",
        "-l",
        chroot_copy,
        "-r",
        str(buildroot_path),
    ]

    if "CCACHE_DIR" in makepkg_config:
        cmd.extend(["-d", makepkg_config["CCACHE_DIR"]])
    if "SRCDEST" in makepkg_config:
        cmd.extend(["-d", makepkg_config["SRCDEST"]])

    if custom_pacman_conf:
        cmd.extend(["-D", f"{custom_pacman_conf}:/etc/pacman.conf"])
        cmd.extend(["-D", "/etc/pacman.d/gnupg:/etc/pacman.d/gnupg"])

    return cmd


def _has_active_builds() -> bool:
    return any(
        build_info.get("status") == BuildStatus.BUILDING
        for build_info in active_builds.values()
    )


def cleanup_srcdest_sources(srcdest_path: Path, retention_days: int) -> Dict[str, int]:
    """Remove top-level SRCDEST entries older than the retention period."""
    cutoff = time.time() - retention_days * 86400
    stats = {"removed_files": 0, "removed_dirs": 0, "freed_bytes": 0}

    for entry in os.scandir(srcdest_path):
        if entry.name.startswith(".apb-") and entry.name.endswith(".lock"):
            continue

        try:
            entry_stat = entry.stat(follow_symlinks=False)
            if entry_stat.st_mtime >= cutoff:
                continue

            if entry.is_file(follow_symlinks=False):
                stats["freed_bytes"] += entry_stat.st_size
                os.unlink(entry.path)
                stats["removed_files"] += 1
            elif entry.is_dir(follow_symlinks=False):
                dir_size = 0
                for root, _dirs, files in os.walk(entry.path):
                    for filename in files:
                        try:
                            dir_size += os.stat(
                                os.path.join(root, filename),
                                follow_symlinks=False,
                            ).st_size
                        except OSError:
                            pass
                shutil.rmtree(entry.path)
                stats["removed_dirs"] += 1
                stats["freed_bytes"] += dir_size
        except OSError as exc:
            logger.warning("Failed to remove SRCDEST entry %s: %s", entry.path, exc)

    return stats


def cleanup_srcdest() -> None:
    """Clean orphaned SRCDEST locks and prune old cached source files."""
    config = get_makepkg_config()
    if "SRCDEST" not in config:
        return

    srcdest = Path(config["SRCDEST"])
    if not srcdest.is_dir():
        logger.warning("SRCDEST %s is not a directory, skipping cleanup", srcdest)
        return

    cleanup_orphaned_srcdest_locks()

    if _has_active_builds():
        logger.info("Skipping SRCDEST source cleanup while builds are active")
        return

    retention = server_config.get("srcdest_retention_days", DEFAULT_SRCDEST_RETENTION_DAYS)
    stats = cleanup_srcdest_sources(srcdest, retention)
    logger.info(
        "SRCDEST source cleanup: removed %s files, %s dirs, freed ~%s bytes",
        stats["removed_files"],
        stats["removed_dirs"],
        stats["freed_bytes"],
    )


def monitor_srcdest_cleanup() -> None:
    """Periodically clean SRCDEST when configured."""
    interval = server_config.get("srcdest_cleanup_interval", DEFAULT_SRCDEST_CLEANUP_INTERVAL)
    if interval <= 0:
        return

    while not shutdown_event.is_set():
        try:
            cleanup_srcdest()
        except Exception as exc:
            logger.error("SRCDEST cleanup failed: %s", exc)
        shutdown_event.wait(interval)


def unlock_srcdest(lock_fd: int):
    """Unlock SRCDEST directory"""
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
    except Exception as e:
        logger.error(f"Error unlocking SRCDEST: {e}")


def finalize_failed_build(build_id: str, build_dir: Path, reason: str, exit_code: int = 1):
    """Finalize a failed build with proper logging."""
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


def build_package(
    build_id: str,
    build_dir: Path,
    pkgbuild_info: Dict[str, Any],
    build_timeout: int = BUILD_TIMEOUT,
    extra_repos: List[Dict] = None,
    repo_level: RepoLevel = RepoLevel.BASE,
):
    """Build package using makechrootpkg"""
    logger.info(f"build_package called for build {build_id}")
    should_cleanup_failed_dir = False
    srcdest_lock = None
    chroot_copy = None

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

        buildroot_path = Path(server_config["buildroot"])

        # Get makepkg config
        makepkg_config = get_makepkg_config()

        # Lock SRCDEST if it exists with timeout
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
                    should_cleanup_failed_dir = True
                    return

            if repo_level != RepoLevel.BASE:
                log_output(
                    f"Enabling repository level '{repo_level.value}': "
                    f"{', '.join(sections_for_level(repo_level))}"
                )
            level_buildroot = ensure_level_buildroot(buildroot_path, repo_level, log_output)
            if level_buildroot is None:
                log_output(f"ERROR: Failed to prepare chroot for repository level '{repo_level.value}'")
                if srcdest_lock:
                    unlock_srcdest(srcdest_lock)
                finalize_failed_build(
                    build_id, build_dir, f"Failed to prepare chroot for repository level '{repo_level.value}'"
                )
                should_cleanup_failed_dir = True
                return

            if extra_repos:
                custom_pacman_conf = create_custom_pacman_conf(level_buildroot, build_dir, extra_repos, log_output)
                if custom_pacman_conf is None:
                    log_output("ERROR: Failed to create custom pacman.conf")
                    if srcdest_lock:
                        unlock_srcdest(srcdest_lock)
                    finalize_failed_build(build_id, build_dir, "Failed to create custom pacman.conf")
                    should_cleanup_failed_dir = True
                    return

            chroot_copy = chroot_slots.get()
            server_arch = get_server_architecture()
            if server_arch in ("powerpc", "espresso"):
                log_output(
                    f"Using ppc32 prefix for {server_arch} architecture to ensure 32-bit detection"
                )
            cmd = build_makechrootpkg_command(
                level_buildroot,
                chroot_copy,
                makepkg_config,
                custom_pacman_conf,
                server_arch,
            )
            log_output(f"Using chroot copy {chroot_copy}")
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
                        "download_url": build_download_path(build_id, pkg_file.name)
                    })

                active_builds[build_id]["packages"] = packages

            else:
                active_builds[build_id]["status"] = BuildStatus.FAILED
                active_builds[build_id]["exit_code"] = process.returncode
                log_output(f"Build failed with exit code {process.returncode}")

        finally:
            stop_tracked_build_process(build_id)
            if srcdest_lock:
                unlock_srcdest(srcdest_lock)
            if chroot_copy is not None:
                chroot_slots.put(chroot_copy)
                chroot_copy = None

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

        if active_builds[build_id]["status"] == BuildStatus.FAILED:
            should_cleanup_failed_dir = True

    except Exception as e:
        logger.error(f"Build error: {e}")
        if srcdest_lock:
            unlock_srcdest(srcdest_lock)
        if chroot_copy is not None:
            chroot_slots.put(chroot_copy)
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
        should_cleanup_failed_dir = True

    finally:
        close_build_log(build_id)
        if should_cleanup_failed_dir:
            cleanup_failed_build_dir(build_id, build_dir)
        register_finished_build()


def _wait_for_buildroot_drain() -> bool:
    """Wait until in-flight builds finish while draining. Returns False if shutting down."""
    while not shutdown_event.is_set():
        with buildroot_state_lock:
            if buildroot_state != BUILDROOT_STATE_DRAINING:
                return True
            if in_flight_builds == 0:
                return True
        time.sleep(1)
    return False


def _increment_in_flight_builds() -> None:
    global in_flight_builds
    with buildroot_state_lock:
        in_flight_builds += 1


def _decrement_in_flight_builds(_future) -> None:
    global in_flight_builds
    with buildroot_state_lock:
        in_flight_builds = max(0, in_flight_builds - 1)


def process_build_queue():
    """Process builds from queue"""
    logger.info("Build queue processor thread started")
    while not shutdown_event.is_set():
        try:
            with buildroot_state_lock:
                state = buildroot_state

            if state == BUILDROOT_STATE_DRAINING:
                if not _wait_for_buildroot_drain():
                    break
                with buildroot_state_lock:
                    should_recreate = (
                        buildroot_state == BUILDROOT_STATE_DRAINING
                        and in_flight_builds == 0
                    )
                if should_recreate:
                    recreate_buildroot(Path(server_config["buildroot"]))
                continue

            if state == BUILDROOT_STATE_RECREATING:
                time.sleep(1)
                continue

            if logger.level <= logging.DEBUG:
                logger.debug(f"Checking queue for builds (queue size: {build_queue.qsize()})")
            build_data = build_queue.get(timeout=1)

            build_id = build_data["build_id"]
            logger.info(f"Processing build {build_id} from queue")

            _increment_in_flight_builds()

            try:
                if logger.level <= logging.DEBUG:
                    logger.debug(f"Executor state - max_workers: {build_executor._max_workers}, active threads: {len(build_executor._threads)}")
                future = build_executor.submit(
                    build_package,
                    build_data["build_id"],
                    build_data["build_dir"],
                    build_data["pkgbuild_info"],
                    build_data.get("build_timeout", BUILD_TIMEOUT),
                    build_data.get("extra_repos", []),
                    build_data.get("repo_level", RepoLevel.BASE),
                )
                future.add_done_callback(_decrement_in_flight_builds)
            except Exception:
                _decrement_in_flight_builds(None)
                raise
            logger.info(f"Build {build_id} submitted to executor")

        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Error processing build queue: {e}")
            import traceback
            logger.error(f"Queue processor traceback: {traceback.format_exc()}")

    logger.info("Build queue processor thread stopped")


# Queue processor is now started in the lifespan manager


