#!/usr/bin/env python3
"""
APB Server - Arch Package Builder Server Component
Provides a complete package building service with buildroot management.
"""

import asyncio
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import argparse
import signal
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
import queue
import fcntl
import configparser
import gc
import resource
import select
from contextlib import asynccontextmanager
import tarfile

# Minimal dependencies - only FastAPI and uvicorn
try:
    from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request
    from fastapi.responses import JSONResponse, StreamingResponse, FileResponse, HTMLResponse
    from fastapi.middleware.cors import CORSMiddleware
    import uvicorn
    import psutil
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Install with: pip install fastapi uvicorn psutil")
    sys.exit(1)

# Version and constants
VERSION = "2025-09-04"
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 8000
DEFAULT_BUILDROOT = Path.home() / ".apb" / "buildroot"
DEFAULT_BUILDS_DIR = Path.home() / ".apb" / "builds"
DEFAULT_MAX_CONCURRENT = 3
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB per file
MAX_REQUEST_SIZE = 500 * 1024 * 1024  # 500MB total request
BUILD_TIMEOUT = 7200  # 2 hours max build time
MAX_BUILD_OUTPUTS = 10000  # Max lines to keep in memory

# Global state
build_queue = queue.Queue()
active_builds: Dict[str, Dict] = {}
build_history: Dict[str, Dict] = {}
build_executor = ThreadPoolExecutor(max_workers=DEFAULT_MAX_CONCURRENT)
build_outputs: Dict[str, List[str]] = {}
build_streams: Dict[str, List] = {}
server_config = {}
shutdown_event = threading.Event()
build_counter = 0  # Counter for buildroot recreation
running_processes: Dict[str, subprocess.Popen] = {}  # Track running build processes
buildroot_recreation_builds: Dict[str, bool] = {}  # Track builds doing buildroot recreation

# Resource monitoring
resource_monitor_thread = None
last_cleanup_time = time.time()

# Async context manager for app lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan"""
    global resource_monitor_thread, build_executor

    # Update executor with correct max_workers from server_config
    if "max_concurrent" in server_config:
        # Shutdown old executor
        build_executor.shutdown(wait=False)
        # Create new executor with correct worker count
        # IMPORTANT: This must be done here in the lifespan manager, not in main(),
        # because the process_build_queue thread (started below) captures the global
        # reference to build_executor. If we recreate it in main() after the app
        # starts, the queue processor will still use the old executor.
        build_executor = ThreadPoolExecutor(max_workers=server_config["max_concurrent"])
        logger.info(f"Build executor updated with {server_config['max_concurrent']} max workers")

    # Start resource monitoring
    resource_monitor_thread = threading.Thread(target=monitor_resources, daemon=True)
    resource_monitor_thread.start()

    # Start queue processor
    queue_thread = threading.Thread(target=process_build_queue, daemon=True)
    queue_thread.start()
    logger.info(f"Queue processor thread started: {queue_thread.is_alive()}")

    logger.info("APB Server background tasks started")

    yield

    # Cleanup on shutdown
    logger.info("APB Server shutting down...")
    shutdown_event.set()

    # Cancel running builds with appropriate timeouts
    for build_id, process in running_processes.items():
        try:
            is_buildroot_recreation = buildroot_recreation_builds.get(build_id, False)
            termination_timeout = 300 if is_buildroot_recreation else 10

            if is_buildroot_recreation:
                logger.info(f"Terminating build process {build_id} (buildroot recreation) - allowing {termination_timeout}s for graceful shutdown")
            else:
                logger.info(f"Terminating build process {build_id}")

            process.terminate()
            process.wait(timeout=termination_timeout)
        except subprocess.TimeoutExpired:
            if is_buildroot_recreation:
                logger.warning(f"Build {build_id} (buildroot recreation) did not terminate gracefully within {termination_timeout}s during shutdown, forcing kill")
            else:
                logger.warning(f"Build {build_id} did not terminate gracefully within {termination_timeout}s during shutdown, forcing kill")
            try:
                process.kill()
            except:
                pass
        except Exception as e:
            if "timed out" in str(e).lower() and is_buildroot_recreation:
                logger.warning(f"Expected timeout during shutdown for buildroot recreation build {build_id}: {e}")
            else:
                logger.error(f"Error terminating build {build_id} during shutdown: {e}")
            try:
                process.kill()
            except:
                pass

    # Cleanup executor
    build_executor.shutdown(wait=False)

    logger.info("APB Server shutdown complete")

# Create FastAPI app with lifespan
app = FastAPI(
    title="APB Server",
    version=VERSION,
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request timeout middleware
@app.middleware("http")
async def request_timeout_middleware(request: Request, call_next):
    """Add request timeout to prevent hanging requests"""
    try:
        # Set different timeouts based on endpoint
        if request.url.path.startswith("/build"):
            timeout = 300  # 5 minutes for build submissions
        elif request.url.path.startswith("/stream"):
            timeout = None  # No timeout for streaming endpoints
        else:
            timeout = 30  # 30 seconds for other endpoints

        if timeout:
            return await asyncio.wait_for(call_next(request), timeout=timeout)
        else:
            return await call_next(request)

    except asyncio.TimeoutError:
        logger.warning(f"Request timeout for {request.method} {request.url.path}")
        return JSONResponse(
            status_code=408,
            content={"error": "Request timeout", "detail": "Request took too long to process"}
        )
    except Exception as e:
        logger.error(f"Error in request timeout middleware: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error", "detail": str(e)}
        )

# Add global exception handler to prevent HTTP 502 errors
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler to prevent HTTP 502 errors"""
    logger.error(f"Unhandled exception in {request.method} {request.url}: {exc}")
    logger.error(f"Exception type: {type(exc).__name__}")

    # Force garbage collection
    gc.collect()

    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc), "type": type(exc).__name__}
    )

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class BuildStatus:
    QUEUED = "queued"
    BUILDING = "building"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


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

        # Limit output lines for active builds
        for build_id in list(build_outputs.keys()):
            if len(build_outputs[build_id]) > MAX_BUILD_OUTPUTS:
                # Keep only the last 5000 lines
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
    """Get the server's supported architecture for the farm"""
    try:
        # Check for command-line override first
        if server_config.get("architecture_override"):
            override_arch = server_config["architecture_override"]
            logger.info(f"Using command-line architecture override: {override_arch}")
            return override_arch

        # Read /etc/pacman.conf to get the Architecture setting
        pacman_conf_path = Path("/etc/pacman.conf")
        if pacman_conf_path.exists():
            with open(pacman_conf_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('Architecture') and '=' in line:
                        arch_value = line.split('=', 1)[1].strip()
                        if arch_value and arch_value != "auto":
                            logger.info(f"Found Architecture={arch_value} in /etc/pacman.conf")
                            return arch_value

        # If Architecture is "auto" or not set, map from machine architecture
        machine_arch = platform.machine()
        logger.info(f"Architecture not set in /etc/pacman.conf or is 'auto', mapping from machine architecture: {machine_arch}")

        # Map machine architecture to farm architecture names
        arch_mapping = {
            "ppc64le": "powerpc64le",
            "ppc64": "powerpc64",
            "ppc": "powerpc",
            "x86_64": "x86_64",
            "aarch64": "aarch64",
            "armv7h": "armv7h",
            "armv6h": "armv6h"
        }

        mapped_arch = arch_mapping.get(machine_arch, machine_arch)
        logger.info(f"Mapped machine architecture '{machine_arch}' to farm architecture '{mapped_arch}'")
        return mapped_arch

    except Exception as e:
        logger.error(f"Error determining server architecture: {e}")
        # Fallback to machine architecture
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
    """Parse PKGBUILD file to extract package information"""
    try:
        with open(pkgbuild_path, 'r') as f:
            content = f.read()

        # Simple parsing - in production, this would be more robust
        info = {"pkgname": "unknown", "arch": ["x86_64"], "validpgpkeys": [], "apb_output_timeout": None}
        pkgbase = None

        # Handle multi-line arrays
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
                    # Extract first package name from array
                    array_content = pkgname_value[1:-1].strip()
                    # Split by spaces and take first item, removing quotes
                    first_pkg = array_content.split()[0].strip('\'"') if array_content else "unknown"
                    info["pkgname"] = first_pkg
                else:
                    # Handle simple format: pkgname=package
                    info["pkgname"] = pkgname_value.strip('\'"')
            elif line.startswith('arch='):
                arch_str = line.split('=', 1)[1].strip()
                if arch_str.startswith('(') and arch_str.endswith(')'):
                    arch_str = arch_str[1:-1]
                info["arch"] = [a.strip('\'"') for a in arch_str.split()]
            elif line.startswith('validpgpkeys='):
                # Handle both single-line and multi-line arrays
                keys_content = line.split('=', 1)[1].strip()

                # If it's a single line array
                if keys_content.startswith('(') and keys_content.endswith(')'):
                    keys_content = keys_content[1:-1]
                    info["validpgpkeys"] = [key.strip('\'"') for key in keys_content.split() if key.strip('\'"')]
                # If it's a multi-line array
                elif keys_content.startswith('('):
                    keys_content = keys_content[1:]  # Remove opening parenthesis
                    keys = []

                    # Continue reading lines until we find the closing parenthesis
                    while i < len(lines) and not keys_content.endswith(')'):
                        if keys_content.strip():
                            keys.extend([key.strip('\'"') for key in keys_content.split() if key.strip('\'"')])
                        i += 1
                        if i < len(lines):
                            keys_content = lines[i].strip()

                    # Handle the last line with closing parenthesis
                    if keys_content.endswith(')'):
                        keys_content = keys_content[:-1]  # Remove closing parenthesis
                        if keys_content.strip():
                            keys.extend([key.strip('\'"') for key in keys_content.split() if key.strip('\'"')])

                    info["validpgpkeys"] = keys
            elif line.startswith('apb_output_timeout='):
                timeout_str = line.split('=', 1)[1].split('#')[0].strip().strip('\'"')
                try:
                    timeout_value = int(timeout_str)
                    # Validate timeout range (minimum 60 seconds, maximum 24 hours)
                    if timeout_value < 60:
                        logger.warning(f"apb_output_timeout value {timeout_value} too low, minimum is 60 seconds, ignoring")
                    elif timeout_value > 86400:  # 24 hours
                        logger.warning(f"apb_output_timeout value {timeout_value} too high, maximum is 86400 seconds (24 hours), ignoring")
                    else:
                        info["apb_output_timeout"] = timeout_value
                except ValueError:
                    logger.warning(f"Invalid apb_output_timeout value '{timeout_str}', ignoring")

            i += 1

        # If pkgbase is defined, use it as pkgname and ignore pkgname field completely
        if pkgbase:
            info["pkgname"] = pkgbase

        return info
    except Exception as e:
        logger.error(f"Error parsing PKGBUILD: {e}")
        return {"pkgname": "unknown", "arch": ["x86_64"], "validpgpkeys": [], "apb_output_timeout": None}


def download_gpg_keys(gpg_keys: List[str], log_output_func) -> bool:
    """Download GPG keys for package validation"""
    if not gpg_keys:
        return True

    try:
        log_output_func(f"Downloading {len(gpg_keys)} GPG keys for source validation")

        # Create GPG command to receive keys
        cmd = ["gpg", "--recv-keys"] + gpg_keys

        log_output_func(f"Running: {' '.join(cmd)}")

        # Execute GPG command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
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
            log_output_func(f"Warning: GPG key download failed with exit code {result.returncode}")
            log_output_func("This may cause source validation to fail during build")
            # Don't fail the build, just warn - some packages may have optional key validation
            return True

        log_output_func("GPG keys downloaded successfully")
        return True

    except subprocess.TimeoutExpired:
        log_output_func("Error: GPG key download timed out after 5 minutes")
        return False
    except Exception as e:
        log_output_func(f"Error downloading GPG keys: {e}")
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

        # Copy makepkg.conf
        host_makepkg_conf = Path("/etc/makepkg.conf")
        chroot_makepkg_conf = chroot_etc / "makepkg.conf"
        if host_makepkg_conf.exists():
            logger.info("Copying host /etc/makepkg.conf to chroot")
            try:
                cmd = ["sudo", "cp", str(host_makepkg_conf), str(chroot_makepkg_conf)]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    logger.error(f"Failed to copy makepkg.conf: {result.stderr}")
                    return False
            except Exception as e:
                logger.error(f"Failed to copy makepkg.conf: {e}")
                return False
        else:
            logger.warning("Host /etc/makepkg.conf not found")

        # Copy pacman.conf
        host_pacman_conf = Path("/etc/pacman.conf")
        chroot_pacman_conf = chroot_etc / "pacman.conf"
        if host_pacman_conf.exists():
            logger.info("Copying host /etc/pacman.conf to chroot")
            try:
                cmd = ["sudo", "cp", str(host_pacman_conf), str(chroot_pacman_conf)]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    logger.error(f"Failed to copy pacman.conf: {result.stderr}")
                    return False
            except Exception as e:
                logger.error(f"Failed to copy pacman.conf: {e}")
                return False
        else:
            logger.warning("Host /etc/pacman.conf not found")

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
                elif line.startswith('CCACHE_DIR=') and not line.startswith('#'):
                    config['CCACHE_DIR'] = line.split('=', 1)[1].strip('\'"')
    except Exception as e:
        logger.error(f"Error reading makepkg.conf: {e}")

    return config


def lock_srcdest(srcdest_path: str, pkgname: str) -> Optional[int]:
    """Lock SRCDEST directory with package-specific lock file"""
    try:
        lock_file = os.path.join(srcdest_path, f'.apb-{pkgname}.lock')

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
                    # If lock file is older than 30 minutes, consider it orphaned
                    if age_seconds > 600:
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
                        # If lock file is older than 30 minutes, consider it orphaned
                        if age_seconds > 1800:
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


def build_package(build_id: str, build_dir: Path, pkgbuild_info: Dict[str, Any], build_timeout: int = BUILD_TIMEOUT):
    """Build package using makechrootpkg"""
    global build_counter

    logger.info(f"build_package called for build {build_id}")

    try:
        # Update build status
        active_builds[build_id]["status"] = BuildStatus.BUILDING
        active_builds[build_id]["start_time"] = time.time()

        # Add to build outputs
        build_outputs[build_id] = []

        def log_output(message: str):
            build_outputs[build_id].append(message)
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
            # Download GPG keys if specified in PKGBUILD
            if pkgbuild_info.get("validpgpkeys"):
                log_output("Downloading GPG keys for source validation...")
                if not download_gpg_keys(pkgbuild_info["validpgpkeys"], log_output):
                    log_output("GPG key download failed, continuing build (may fail during source validation)")

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

            log_output(f"Running: {' '.join(cmd)}")

            # Execute build with timeout management
            process = subprocess.Popen(
                cmd,
                cwd=build_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                preexec_fn=os.setsid  # Create new process group for better cleanup
            )
            running_processes[build_id] = process  # Track the process

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

                    # Read output with timeout
                    try:
                        # Use poll() to check if process is still running
                        if process.poll() is not None:
                            # Process finished, read remaining output
                            remaining_output = process.stdout.read()
                            if remaining_output:
                                for line in remaining_output.split('\n'):
                                    if line.strip():
                                        log_output(line.rstrip())
                            break

                        # Read line with timeout simulation using select
                        if select.select([process.stdout], [], [], 1.0)[0]:
                            line = process.stdout.readline()
                            if line:
                                log_output(line.rstrip())
                                last_output_time = current_time

                    except Exception as e:
                        logger.error(f"Error reading process output: {e}")
                        break

                    # Small sleep to prevent busy waiting
                    time.sleep(0.1)

                except KeyboardInterrupt:
                    log_output("Build interrupted")
                    process.terminate()
                    break

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

        # Add logs
        log_file = build_dir / "build.log"
        with open(log_file, 'w') as f:
            f.write('\n'.join(build_outputs[build_id]))

        active_builds[build_id]["logs"] = [{
            "filename": "build.log",
            "size": log_file.stat().st_size,
            "download_url": f"/build/{build_id}/download/build.log"
        }]

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

        log_output(f"Build {build_id} finished")

    except Exception as e:
        logger.error(f"Build error: {e}")
        active_builds[build_id]["status"] = BuildStatus.FAILED
        active_builds[build_id]["end_time"] = time.time()
        active_builds[build_id]["duration"] = active_builds[build_id]["end_time"] - active_builds[build_id]["start_time"]
        active_builds[build_id]["exit_code"] = 1

        if build_id in build_outputs:
            build_outputs[build_id].append(f"Build failed: {str(e)}")

        # Move to history
        build_history[build_id] = active_builds[build_id].copy()


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
                build_data.get("build_timeout", BUILD_TIMEOUT)
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


@app.get("/")
async def get_server_info():
    """Get server information and status"""
    try:
        return {
            "status": "running",
            "version": VERSION,
            "supported_architecture": get_server_architecture(),
            "system_info": get_system_info(),
            "queue_status": get_queue_status()
        }
    except Exception as e:
        logger.error(f"Error getting server info: {e}")
        # Return minimal info to prevent HTTP 502
        return {
            "status": "running",
            "version": VERSION,
            "supported_architecture": get_server_architecture(),
            "system_info": {"architecture": platform.machine()},
            "queue_status": {"current_builds_count": 0, "queued_builds": 0}
        }


@app.get("/health")
async def health_check():
    """Enhanced health check endpoint that actually tests server responsiveness"""
    start_time = time.time()

    try:
        health_status = {
            "status": "healthy",
            "version": VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks": {}
        }

        # Test memory usage
        try:
            memory = psutil.virtual_memory()
            health_status["checks"]["memory"] = {
                "status": "ok" if memory.percent < 95 else "warning",
                "usage_percent": memory.percent,
                "available_mb": memory.available // (1024 * 1024)
            }
        except Exception as e:
            health_status["checks"]["memory"] = {"status": "error", "error": str(e)}

        # Test disk space
        try:
            disk = psutil.disk_usage(server_config.get("builds_dir", "/tmp"))
            disk_percent = (disk.used / disk.total) * 100
            health_status["checks"]["disk"] = {
                "status": "ok" if disk_percent < 95 else "warning",
                "usage_percent": disk_percent,
                "free_gb": disk.free // (1024 * 1024 * 1024)
            }
        except Exception as e:
            health_status["checks"]["disk"] = {"status": "error", "error": str(e)}

        # Test thread pool
        try:
            # Check if executor is responsive
            future = build_executor.submit(lambda: "test")
            try:
                result = future.result(timeout=1.0)
                health_status["checks"]["executor"] = {"status": "ok", "test_result": result}
            except Exception as e:
                health_status["checks"]["executor"] = {"status": "error", "error": str(e)}
        except Exception as e:
            health_status["checks"]["executor"] = {"status": "error", "error": str(e)}

        # Test build queue
        try:
            health_status["checks"]["build_queue"] = {
                "status": "ok",
                "queue_size": build_queue.qsize(),
                "active_builds": len(active_builds),
                "running_processes": len(running_processes)
            }
        except Exception as e:
            health_status["checks"]["build_queue"] = {"status": "error", "error": str(e)}

        # Test file system access
        try:
            test_file = Path(server_config.get("builds_dir", "/tmp")) / ".health_check"
            test_file.write_text("health_check")
            test_file.unlink()
            health_status["checks"]["filesystem"] = {"status": "ok"}
        except Exception as e:
            health_status["checks"]["filesystem"] = {"status": "error", "error": str(e)}

        # Calculate response time
        response_time = time.time() - start_time
        health_status["response_time_ms"] = round(response_time * 1000, 2)

        # Determine overall status
        check_statuses = [check.get("status", "error") for check in health_status["checks"].values()]
        if "error" in check_statuses:
            health_status["status"] = "degraded"
        elif "warning" in check_statuses:
            health_status["status"] = "warning"

        # If response time is too high, mark as degraded
        if response_time > 5.0:
            health_status["status"] = "degraded"
            health_status["warning"] = "High response time"

        return health_status

    except Exception as e:
        logger.error(f"Error in health check: {e}")
        # Return degraded status instead of always healthy
        return {
            "status": "degraded",
            "version": VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": str(e),
            "response_time_ms": round((time.time() - start_time) * 1000, 2)
        }


@app.post("/build")
async def submit_build(
    build_tarball: UploadFile = File(None),
    pkgbuild: UploadFile = File(None),
    build_id: str = Form(...),
    sources: List[UploadFile] = File(default=[]),
    build_timeout: Optional[int] = Form(None)
):
    """Submit a new build request (supports both tarball and individual file uploads)"""
    try:
        # Check if build_id already exists
        if build_id in active_builds or build_id in build_history:
            raise HTTPException(
                status_code=400,
                detail={"error": "Build ID already exists", "detail": f"Build with ID '{build_id}' already exists"}
            )

        # Validate and set build timeout
        timeout_seconds = BUILD_TIMEOUT  # Default timeout
        if build_timeout is not None:
            if build_timeout < 300 or build_timeout > 14400:  # 5 minutes to 4 hours
                raise HTTPException(
                    status_code=400,
                    detail={"error": "Invalid timeout", "detail": "Build timeout must be between 300 and 14400 seconds"}
                )
            timeout_seconds = build_timeout
            logger.info(f"Build {build_id} using custom timeout: {timeout_seconds} seconds")

        # Create build directory
        builds_dir = Path(server_config["builds_dir"])
        builds_dir.mkdir(parents=True, exist_ok=True)

        build_dir = builds_dir / build_id
        build_dir.mkdir(exist_ok=True)

        # Handle tarball upload (new method)
        if build_tarball and build_tarball.filename:
            # Check file size first
            if build_tarball.size and build_tarball.size > MAX_REQUEST_SIZE:
                raise HTTPException(
                    status_code=413,
                    detail={"error": "File too large", "detail": f"Tarball exceeds {MAX_REQUEST_SIZE} bytes"}
                )

            # Save tarball temporarily
            tarball_path = build_dir / "build.tar.gz"
            try:
                with open(tarball_path, 'wb') as f:
                    bytes_written = 0
                    while True:
                        chunk = await build_tarball.read(8192)  # 8KB chunks
                        if not chunk:
                            break

                        bytes_written += len(chunk)
                        if bytes_written > MAX_REQUEST_SIZE:
                            f.close()
                            tarball_path.unlink(missing_ok=True)  # Delete partial file
                            raise HTTPException(
                                status_code=413,
                                detail={"error": "File too large", "detail": f"Tarball exceeds {MAX_REQUEST_SIZE} bytes"}
                            )

                        f.write(chunk)

                # Extract tarball
                try:
                    with tarfile.open(tarball_path, 'r:gz') as tar:
                        # Extract all files to build directory
                        tar.extractall(path=build_dir, filter='data')

                    # Remove the tarball after extraction
                    tarball_path.unlink(missing_ok=True)

                    # Verify PKGBUILD exists
                    pkgbuild_path = build_dir / "PKGBUILD"
                    if not pkgbuild_path.exists():
                        raise HTTPException(
                            status_code=400,
                            detail={"error": "Invalid tarball", "detail": "Tarball must contain a PKGBUILD file"}
                        )

                except (tarfile.TarError, OSError) as e:
                    # Clean up on extraction error
                    tarball_path.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=400,
                        detail={"error": "Invalid tarball", "detail": f"Could not extract tarball: {str(e)}"}
                    )

            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(
                    status_code=400,
                    detail={"error": "Failed to save tarball", "detail": str(e)}
                )

        # Handle individual file uploads (legacy method for backward compatibility)
        elif pkgbuild and pkgbuild.filename:
            # Validate PKGBUILD file
            if pkgbuild.filename.lower() != "pkgbuild":
                raise HTTPException(
                    status_code=400,
                    detail={"error": "Invalid PKGBUILD file", "detail": "File must be named 'PKGBUILD'"}
                )

            # Save PKGBUILD with size limit and streaming
            pkgbuild_path = build_dir / "PKGBUILD"
            try:
                # Check file size first
                if pkgbuild.size and pkgbuild.size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail={"error": "File too large", "detail": f"PKGBUILD exceeds {MAX_FILE_SIZE} bytes"}
                    )

                # Stream file to disk to avoid memory issues
                with open(pkgbuild_path, 'wb') as f:
                    bytes_written = 0
                    while True:
                        # Read in chunks to avoid memory exhaustion
                        chunk = await pkgbuild.read(8192)  # 8KB chunks
                        if not chunk:
                            break

                        bytes_written += len(chunk)
                        if bytes_written > MAX_FILE_SIZE:
                            f.close()
                            pkgbuild_path.unlink(missing_ok=True)  # Delete partial file
                            raise HTTPException(
                                status_code=413,
                                detail={"error": "File too large", "detail": f"PKGBUILD exceeds {MAX_FILE_SIZE} bytes"}
                            )

                        f.write(chunk)

            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(
                    status_code=400,
                    detail={"error": "Failed to save PKGBUILD", "detail": str(e)}
                )

            # Save source files with size limits and streaming
            total_size = 0
            for source in sources:
                if source.filename:
                    source_path = build_dir / source.filename
                    try:
                        # Check individual file size
                        if source.size and source.size > MAX_FILE_SIZE:
                            logger.error(f"Source file {source.filename} too large: {source.size} bytes")
                            continue

                        # Stream file to disk
                        with open(source_path, 'wb') as f:
                            bytes_written = 0
                            while True:
                                chunk = await source.read(8192)  # 8KB chunks
                                if not chunk:
                                    break

                                bytes_written += len(chunk)
                                total_size += len(chunk)

                                # Check individual file size limit
                                if bytes_written > MAX_FILE_SIZE:
                                    f.close()
                                    source_path.unlink(missing_ok=True)
                                    logger.error(f"Source file {source.filename} exceeded size limit")
                                    break

                                # Check total request size limit
                                if total_size > MAX_REQUEST_SIZE:
                                    f.close()
                                    source_path.unlink(missing_ok=True)
                                    raise HTTPException(
                                        status_code=413,
                                        detail={"error": "Request too large", "detail": f"Total request size exceeds {MAX_REQUEST_SIZE} bytes"}
                                    )

                                f.write(chunk)

                    except HTTPException:
                        raise
                    except Exception as e:
                        logger.error(f"Error saving source file {source.filename}: {e}")
                        # Continue with other files
        else:
            raise HTTPException(
                status_code=400,
                detail={"error": "No build files provided", "detail": "Either build_tarball or pkgbuild must be provided"}
            )

        # Parse PKGBUILD (same path regardless of upload method)
        pkgbuild_path = build_dir / "PKGBUILD"
        pkgbuild_info = parse_pkgbuild(pkgbuild_path)

        if pkgbuild_info["pkgname"] == "unknown":
            raise HTTPException(
                status_code=400,
                detail={"error": "Invalid PKGBUILD file", "detail": "Missing required pkgname field"}
            )

        # Create build record
        active_builds[build_id] = {
            "build_id": build_id,
            "pkgname": pkgbuild_info["pkgname"],
            "status": BuildStatus.QUEUED,
            "created_at": time.time(),
            "arch": pkgbuild_info["arch"],
            "packages": [],
            "logs": [],
            "build_timeout": timeout_seconds
        }

        # Add to queue
        build_queue.put({
            "build_id": build_id,
            "build_dir": build_dir,
            "pkgbuild_info": pkgbuild_info,
            "build_timeout": timeout_seconds
        })

        logger.info(f"Build {build_id} added to queue (queue size now: {build_queue.qsize()})")

        return {
            "build_id": build_id,
            "status": "queued",
            "message": "Build queued successfully"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error submitting build: {e}")
        raise HTTPException(
            status_code=500,
            detail={"error": "Internal server error", "detail": str(e)}
        )


@app.get("/build/{build_id}/status-api")
async def get_build_status(build_id: str):
    """Get build status as JSON"""
    build_info = active_builds.get(build_id) or build_history.get(build_id)

    if not build_info:
        raise HTTPException(status_code=404, detail="Build not found")

    return build_info


@app.get("/build/{build_id}/output")
async def get_build_output(build_id: str, start_index: int = 0, limit: int = 50):
    """Get build output/logs"""
    if build_id not in build_outputs:
        raise HTTPException(status_code=404, detail="Build not found")

    output_lines = build_outputs[build_id]
    total_lines = len(output_lines)

    end_index = min(start_index + limit, total_lines)
    returned_lines = output_lines[start_index:end_index]

    return {
        "output": returned_lines,
        "total_lines": total_lines,
        "start_index": start_index,
        "returned_lines": len(returned_lines)
    }


@app.get("/build/{build_id}/stream")
async def stream_build_output(build_id: str):
    """Stream build output using Server-Sent Events"""

    async def event_generator():
        # Create queue for this stream
        stream_queue = queue.Queue()

        if build_id not in build_streams:
            build_streams[build_id] = []
        build_streams[build_id].append(stream_queue)

        try:
            # Send existing output
            if build_id in build_outputs:
                for line in build_outputs[build_id]:
                    yield f"event: output\ndata: {line}\n\n"

            # Send current status
            build_info = active_builds.get(build_id) or build_history.get(build_id)
            if build_info:
                yield f"event: status\ndata: {json.dumps({'status': build_info['status']})}\n\n"

            # Stream new events
            while True:
                try:
                    event_type, data = stream_queue.get(timeout=30)

                    if event_type == "output":
                        yield f"event: output\ndata: {data}\n\n"
                    elif event_type == "status":
                        yield f"event: status\ndata: {json.dumps(data)}\n\n"
                    elif event_type == "complete":
                        yield f"event: complete\ndata: {json.dumps(data)}\n\n"
                        break

                except queue.Empty:
                    # Send heartbeat
                    yield f"event: heartbeat\ndata: {time.time()}\n\n"

                    # Check if build is done
                    build_info = active_builds.get(build_id) or build_history.get(build_id)
                    if build_info and build_info["status"] in [BuildStatus.COMPLETED, BuildStatus.FAILED, BuildStatus.CANCELLED]:
                        break

        finally:
            # Remove from streams
            if build_id in build_streams:
                build_streams[build_id].remove(stream_queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/build/{build_id}/cancel")
async def cancel_build(build_id: str):
    """Cancel a build"""
    if build_id not in active_builds:
        raise HTTPException(status_code=404, detail="Build not found")

    build_info = active_builds[build_id]

    if build_info["status"] in [BuildStatus.COMPLETED, BuildStatus.FAILED, BuildStatus.CANCELLED]:
        return {"success": False, "message": "Build already finished"}

    # Mark as cancelled
    build_info["status"] = BuildStatus.CANCELLED
    build_info["end_time"] = time.time()

    if "start_time" in build_info:
        build_info["duration"] = build_info["end_time"] - build_info["start_time"]

    # Move to history
    build_history[build_id] = build_info.copy()

    return {"success": True, "message": "Build cancelled successfully"}


@app.get("/build/{build_id}/confirm-cancel")
async def confirm_cancel_build(build_id: str):
    """Get build cancellation confirmation page"""
    build_info = active_builds.get(build_id) or build_history.get(build_id)

    if not build_info:
        raise HTTPException(status_code=404, detail="Build not found")

    return HTMLResponse(f"""
    <html>
    <head><title>Cancel Build - {build_info['pkgname']}</title></head>
    <body>
        <h1>Cancel Build Confirmation</h1>
        <p>Are you sure you want to cancel the build for <strong>{build_info['pkgname']}</strong>?</p>
        <p>Build ID: {build_id}</p>
        <p>Status: {build_info['status']}</p>
        <form method="post" action="/build/{build_id}/cancel">
            <button type="submit" style="background-color: #ff4444; color: white; padding: 10px 20px; border: none; cursor: pointer;">Cancel Build</button>
            <a href="/build/{build_id}" style="margin-left: 10px; text-decoration: none; background-color: #ccc; color: black; padding: 10px 20px; display: inline-block;">Go Back</a>
        </form>
    </body>
    </html>
    """)


@app.get("/build/{build_id}/view/{filename}")
async def view_file(build_id: str, filename: str):
    """View a text file in the browser"""
    builds_dir = Path(server_config["builds_dir"])
    build_dir = builds_dir / build_id
    file_path = build_dir / filename

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        return HTMLResponse(f"""
        <html>
        <head><title>View File - {filename}</title></head>
        <body>
            <h1>File: {filename}</h1>
            <p>Build ID: {build_id}</p>
            <pre style="background-color: #f5f5f5; padding: 10px; border: 1px solid #ddd; overflow-x: auto;">{content}</pre>
            <a href="/build/{build_id}">Back to Build</a>
        </body>
        </html>
        """)
    except UnicodeDecodeError:
        # If file is not text, redirect to download
        return FileResponse(
            path=str(file_path),
            filename=filename,
            media_type='application/octet-stream'
        )


@app.get("/build/{build_id}/download/{filename}")
async def download_file(build_id: str, filename: str):
    """Download a build artifact"""
    builds_dir = Path(server_config["builds_dir"])
    build_dir = builds_dir / build_id
    file_path = build_dir / filename

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(
        path=str(file_path),
        filename=filename,
        media_type='application/octet-stream'
    )


@app.get("/builds/latest")
async def get_latest_builds(limit: int = 10, status: Optional[str] = None):
    """Get latest builds"""
    all_builds = list(build_history.values()) + list(active_builds.values())

    if status:
        all_builds = [b for b in all_builds if b["status"] == status]

    # Sort by creation time (newest first)
    all_builds.sort(key=lambda x: x.get("created_at", 0), reverse=True)

    builds = []
    for build in all_builds[:limit]:
        builds.append({
            "build_id": build["build_id"],
            "pkgname": build["pkgname"],
            "status": build["status"],
            "start_time": datetime.fromtimestamp(build.get("start_time", build.get("created_at", 0)), timezone.utc).isoformat(),
            "end_time": datetime.fromtimestamp(build["end_time"], timezone.utc).isoformat() if build.get("end_time") else None,
            "duration": build.get("duration", 0)
        })

    return {"builds": builds, "total": len(all_builds)}


@app.get("/builds/pkgname/{pkgname}")
async def get_builds_for_package(pkgname: str, limit: int = 5):
    """Get builds for a specific package"""
    all_builds = list(build_history.values()) + list(active_builds.values())
    pkg_builds = [b for b in all_builds if b["pkgname"] == pkgname]

    # Sort by creation time (newest first)
    pkg_builds.sort(key=lambda x: x.get("created_at", 0), reverse=True)

    builds = []
    for build in pkg_builds[:limit]:
        builds.append({
            "build_id": build["build_id"],
            "status": build["status"],
            "start_time": datetime.fromtimestamp(build.get("start_time", build.get("created_at", 0)), timezone.utc).isoformat(),
            "end_time": datetime.fromtimestamp(build["end_time"], timezone.utc).isoformat() if build.get("end_time") else None,
            "duration": build.get("duration", 0)
        })

    return {"pkgname": pkgname, "builds": builds, "total": len(pkg_builds)}


@app.get("/builds/pkgname/{pkgname}/latest")
async def get_latest_build_for_package(pkgname: str, successful_only: bool = True):
    """Get the latest build for a specific package"""
    all_builds = list(build_history.values()) + list(active_builds.values())
    pkg_builds = [b for b in all_builds if b["pkgname"] == pkgname]

    if successful_only:
        pkg_builds = [b for b in pkg_builds if b["status"] == BuildStatus.COMPLETED]

    if not pkg_builds:
        raise HTTPException(status_code=404, detail="No builds found for package")

    # Sort by creation time (newest first)
    pkg_builds.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    latest_build = pkg_builds[0]

    return {
        "build_id": latest_build["build_id"],
        "pkgname": latest_build["pkgname"],
        "status": latest_build["status"],
        "start_time": datetime.fromtimestamp(latest_build.get("start_time", latest_build.get("created_at", 0)), timezone.utc).isoformat(),
        "end_time": datetime.fromtimestamp(latest_build["end_time"], timezone.utc).isoformat() if latest_build.get("end_time") else None,
        "duration": latest_build.get("duration", 0),
        "packages": latest_build.get("packages", [])
    }


@app.get("/builds/pkgname/{pkgname}/latest/download/{file_type}")
async def download_latest_build_file(pkgname: str, file_type: str, successful_only: bool = True):
    """Download the latest build file for a package"""
    all_builds = list(build_history.values()) + list(active_builds.values())
    pkg_builds = [b for b in all_builds if b["pkgname"] == pkgname]

    if successful_only:
        pkg_builds = [b for b in pkg_builds if b["status"] == BuildStatus.COMPLETED]

    if not pkg_builds:
        raise HTTPException(status_code=404, detail="No builds found for package")

    # Sort by creation time (newest first)
    pkg_builds.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    latest_build = pkg_builds[0]

    builds_dir = Path(server_config["builds_dir"])
    build_dir = builds_dir / latest_build["build_id"]

    # Handle different file types
    if file_type == "package":
        # Find main package file
        for pkg_file in build_dir.glob("*.pkg.tar.*"):
            if not pkg_file.name.endswith("-debug.pkg.tar.xz"):
                return FileResponse(
                    path=str(pkg_file),
                    filename=pkg_file.name,
                    media_type='application/octet-stream'
                )
    elif file_type == "debug":
        # Find debug package file
        for pkg_file in build_dir.glob("*-debug.pkg.tar.*"):
            return FileResponse(
                path=str(pkg_file),
                filename=pkg_file.name,
                media_type='application/octet-stream'
            )
    elif file_type == "log":
        log_file = build_dir / "build.log"
        if log_file.exists():
            return FileResponse(
                path=str(log_file),
                filename="build.log",
                media_type='text/plain'
            )
    elif file_type == "pkgbuild":
        pkgbuild_file = build_dir / "PKGBUILD"
        if pkgbuild_file.exists():
            return FileResponse(
                path=str(pkgbuild_file),
                filename="PKGBUILD",
                media_type='text/plain'
            )

    raise HTTPException(status_code=404, detail=f"File type '{file_type}' not found")


@app.get("/build/{build_id}")
async def get_build_details(build_id: str, request: Request):
    """Get detailed build information (HTML or JSON based on Accept header)"""
    build_info = active_builds.get(build_id) or build_history.get(build_id)

    if not build_info:
        raise HTTPException(status_code=404, detail="Build not found")

    # Check Accept header for JSON vs HTML
    accept_header = request.headers.get("Accept", "")
    if "application/json" in accept_header:
        # Return JSON response
        sources = []
        builds_dir = Path(server_config["builds_dir"])
        build_dir = builds_dir / build_id

        # List source files
        for src_file in build_dir.iterdir():
            if src_file.is_file() and src_file.name not in ["build.log"] and not src_file.name.endswith(".pkg.tar.xz"):
                sources.append({
                    "filename": src_file.name,
                    "size": src_file.stat().st_size,
                    "download_url": f"/build/{build_id}/download/{src_file.name}"
                })

        return {
            "build_id": build_info["build_id"],
            "pkgname": build_info["pkgname"],
            "status": build_info["status"],
            "start_time": datetime.fromtimestamp(build_info.get("start_time", build_info.get("created_at", 0)), timezone.utc).isoformat(),
            "end_time": datetime.fromtimestamp(build_info["end_time"], timezone.utc).isoformat() if build_info.get("end_time") else None,
            "duration": build_info.get("duration", 0),
            "exit_code": build_info.get("exit_code", 0),
            "packages": build_info.get("packages", []),
            "logs": build_info.get("logs", []),
            "sources": sources
        }
    else:
        # Return HTML response
        packages_html = ""
        for pkg in build_info.get("packages", []):
            packages_html += f'<li><a href="{pkg["download_url"]}">{pkg["filename"]}</a> ({pkg["size"]} bytes)</li>'

        logs_html = ""
        for log in build_info.get("logs", []):
            logs_html += f'<li><a href="{log["download_url"]}">{log["filename"]}</a> ({log["size"]} bytes)</li>'

        return HTMLResponse(f"""
        <html>
        <head><title>Build Details - {build_info['pkgname']}</title></head>
        <body>
            <h1>Build Details: {build_info['pkgname']}</h1>
            <p><strong>Build ID:</strong> {build_id}</p>
            <p><strong>Status:</strong> {build_info['status']}</p>
            <p><strong>Start Time:</strong> {datetime.fromtimestamp(build_info.get("start_time", build_info.get("created_at", 0)), timezone.utc).isoformat()}</p>
            <p><strong>End Time:</strong> {datetime.fromtimestamp(build_info["end_time"], timezone.utc).isoformat() if build_info.get("end_time") else "N/A"}</p>
            <p><strong>Duration:</strong> {build_info.get("duration", 0):.2f} seconds</p>
            <p><strong>Exit Code:</strong> {build_info.get("exit_code", 0)}</p>

            <h2>Packages</h2>
            <ul>{packages_html}</ul>

            <h2>Logs</h2>
            <ul>{logs_html}</ul>

            <h2>Actions</h2>
            <a href="/build/{build_id}/stream">Stream Output</a> |
            <a href="/build/{build_id}/output">View Output</a> |
            <a href="/build/{build_id}/confirm-cancel">Cancel Build</a>
        </body>
        </html>
        """)


@app.get("/build/{build_id}/packages")
async def get_build_packages(build_id: str):
    """List packages produced by a build"""
    build_info = active_builds.get(build_id) or build_history.get(build_id)

    if not build_info:
        raise HTTPException(status_code=404, detail="Build not found")

    packages = []
    for pkg in build_info.get("packages", []):
        packages.append({
            "filename": pkg["filename"],
            "size": pkg["size"],
            "created_at": datetime.fromtimestamp(build_info.get("end_time", build_info.get("created_at", 0)), timezone.utc).isoformat(),
            "download_url": pkg["download_url"]
        })

    return {
        "build_id": build_id,
        "packages": packages
    }


@app.get("/admin/cleanup")
async def admin_cleanup_page():
    """Get cleanup administration page"""
    return HTMLResponse("""
    <html>
    <head><title>APB Server Admin - Cleanup</title></head>
    <body>
        <h1>APB Server Administration - Cleanup</h1>
        <p>Use this page to clean up old builds and temporary files.</p>
        <form method="post" action="/admin/cleanup">
            <button type="submit">Start Cleanup</button>
        </form>
    </body>
    </html>
    """)


@app.post("/admin/cleanup")
async def admin_cleanup():
    """Trigger server cleanup"""
    try:
        cleanup_id = f"cleanup_{int(time.time())}"

        # Clean up old builds (example: remove builds older than 7 days)
        builds_dir = Path(server_config["builds_dir"])
        current_time = time.time()
        week_ago = current_time - (7 * 24 * 60 * 60)

        cleaned_count = 0
        for build_dir in builds_dir.iterdir():
            if build_dir.is_dir():
                try:
                    # Check if build is old
                    if build_dir.stat().st_mtime < week_ago:
                        shutil.rmtree(build_dir)
                        cleaned_count += 1
                except Exception as e:
                    logger.error(f"Error cleaning up {build_dir}: {e}")

        logger.info(f"Cleanup completed: removed {cleaned_count} old builds")

        return {
            "success": True,
            "message": f"Cleanup completed: removed {cleaned_count} old builds",
            "cleanup_id": cleanup_id
        }

    except Exception as e:
        logger.error(f"Error during cleanup: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"Received signal {signum}, shutting down...")
    shutdown_event.set()
    sys.exit(0)


def main():
    """Main entry point"""
    global server_config

    parser = argparse.ArgumentParser(description="APB Server - Arch Package Builder")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host to bind to")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind to")
    parser.add_argument("--buildroot", type=Path, default=DEFAULT_BUILDROOT, help="Buildroot directory")
    parser.add_argument("--builds-dir", type=Path, default=DEFAULT_BUILDS_DIR, help="Builds directory")
    parser.add_argument("--max-concurrent", type=int, default=DEFAULT_MAX_CONCURRENT, help="Max concurrent builds")
    parser.add_argument("--buildroot-autorecreate", type=int, help="Recreate buildroot after N builds")
    parser.add_argument("--architecture", type=str, help="Override detected architecture (e.g., 'powerpc' for espresso server)")
    parser.add_argument("--max-file-size", type=int, default=100*1024*1024, help="Maximum file size in bytes")
    parser.add_argument("--max-request-size", type=int, default=500*1024*1024, help="Maximum total request size in bytes")
    parser.add_argument("--build-timeout", type=int, default=7200, help="Maximum build time in seconds")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    # Setup logging
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.info("Debug logging enabled")

    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Update global constants with command line arguments
    global MAX_FILE_SIZE, MAX_REQUEST_SIZE, BUILD_TIMEOUT
    MAX_FILE_SIZE = args.max_file_size
    MAX_REQUEST_SIZE = args.max_request_size
    BUILD_TIMEOUT = args.build_timeout

    # Store configuration
    server_config = {
        "host": args.host,
        "port": args.port,
        "buildroot": args.buildroot,
        "builds_dir": args.builds_dir,
        "max_concurrent": args.max_concurrent,
        "buildroot_autorecreate": args.buildroot_autorecreate,
        "architecture_override": args.architecture,
        "max_file_size": args.max_file_size,
        "max_request_size": args.max_request_size,
        "build_timeout": args.build_timeout
    }

    # Create directories
    args.buildroot.mkdir(parents=True, exist_ok=True)
    args.builds_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Starting APB Server v{VERSION}")
    logger.info(f"Buildroot: {args.buildroot}")
    logger.info(f"Builds directory: {args.builds_dir}")
    logger.info(f"Max concurrent builds: {args.max_concurrent}")
    logger.info(f"Max file size: {args.max_file_size // (1024*1024)} MB")
    logger.info(f"Max request size: {args.max_request_size // (1024*1024)} MB")
    logger.info(f"Build timeout: {args.build_timeout} seconds")

    # Set resource limits to unlimited
    try:
        limits_set = []

        # Set various ulimits to unlimited for build server operations
        ulimits_to_set = [
            ('RLIMIT_AS', 'address space'),
            ('RLIMIT_DATA', 'data segment size'),
            ('RLIMIT_STACK', 'stack size'),
            ('RLIMIT_CORE', 'core file size'),
            ('RLIMIT_FSIZE', 'file size'),
            ('RLIMIT_NOFILE', 'number of open files'),
            ('RLIMIT_NPROC', 'number of processes')
        ]

        for limit_name, description in ulimits_to_set:
            if hasattr(resource, limit_name):
                try:
                    current_soft, current_hard = resource.getrlimit(getattr(resource, limit_name))
                    # Set both soft and hard limits to unlimited (RLIM_INFINITY)
                    resource.setrlimit(getattr(resource, limit_name), (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
                    limits_set.append(f"{description} (was {current_soft}/{current_hard}, now unlimited)")
                except (OSError, ValueError) as e:
                    # Some limits might not be settable due to permissions
                    logger.warning(f"Could not set {description} to unlimited: {e}")

        if limits_set:
            logger.info(f"Resource limits set to unlimited: {', '.join(limits_set)}")
        else:
            logger.warning("No resource limits could be set to unlimited")

    except Exception as e:
        logger.warning(f"Error configuring resource limits: {e}")

    # Log the detected architecture
    detected_arch = get_server_architecture()
    logger.info(f"Detected server architecture: {detected_arch}")

    # Setup buildroot during startup
    logger.info("Setting up buildroot...")
    if not setup_buildroot(args.buildroot):
        logger.error("Failed to setup buildroot during startup")
        sys.exit(1)
    logger.info("Buildroot setup complete")

    # Clean up any orphaned SRCDEST locks from previous sessions
    logger.info("Checking for orphaned SRCDEST locks...")
    cleanup_orphaned_srcdest_locks()

    # Start server with improved configuration
    try:
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            log_level="info" if not args.debug else "debug",
            workers=1,  # Explicit single worker
            timeout_keep_alive=60,  # Keep connections alive longer
            access_log=True if args.debug else False,
            limit_concurrency=100  # Limit concurrent connections
        )
    except KeyboardInterrupt:
        logger.info("Server interrupted by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
