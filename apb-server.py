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
VERSION = "2025-07-11"
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 8000
DEFAULT_BUILDROOT = Path.home() / ".apb" / "buildroot"
DEFAULT_BUILDS_DIR = Path.home() / ".apb" / "builds"
DEFAULT_MAX_CONCURRENT = 3

# Global state
app = FastAPI(title="APB Server", version=VERSION)
build_queue = queue.Queue()
active_builds: Dict[str, Dict] = {}
build_history: Dict[str, Dict] = {}
build_executor = ThreadPoolExecutor(max_workers=DEFAULT_MAX_CONCURRENT)
build_outputs: Dict[str, List[str]] = {}
build_streams: Dict[str, List] = {}
server_config = {}
shutdown_event = threading.Event()
build_counter = 0  # Counter for buildroot recreation

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
            "uptime": f"{uptime_days} days, {uptime_hours} hours, {uptime_minutes} minutes"
        }
    except Exception as e:
        logger.error(f"Error getting system info: {e}")
        return {
            "architecture": platform.machine(),
            "cpu": {"model": "Unknown", "cores": 1, "load_average": [0.0, 0.0, 0.0]},
            "memory": {"total": 0, "available": 0, "used": 0, "percentage": 0.0},
            "disk": {"total": 0, "used": 0, "free": 0, "percentage": 0.0},
            "uptime": "Unknown"
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
    
    # Get current build info
    current_build = None
    for build_id, build_info in active_builds.items():
        if build_info["status"] == BuildStatus.BUILDING:
            current_build = {
                "build_id": build_id,
                "pkgname": build_info.get("pkgname", "unknown"),
                "status": "building",
                "start_time": build_info.get("start_time", time.time())
            }
            break
    
    return {
        "current_builds_count": current_builds,
        "queued_builds": queued_builds,
        "max_concurrent_builds": server_config.get("max_concurrent", DEFAULT_MAX_CONCURRENT),
        "current_build": current_build
    }


def parse_pkgbuild(pkgbuild_path: Path) -> Dict[str, Any]:
    """Parse PKGBUILD file to extract package information"""
    try:
        with open(pkgbuild_path, 'r') as f:
            content = f.read()
        
        # Simple parsing - in production, this would be more robust
        info = {"pkgname": "unknown", "arch": ["x86_64"], "validpgpkeys": []}
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
            
            i += 1
        
        # If pkgbase is defined, use it as pkgname and ignore pkgname field completely
        if pkgbase:
            info["pkgname"] = pkgbase
        
        return info
    except Exception as e:
        logger.error(f"Error parsing PKGBUILD: {e}")
        return {"pkgname": "unknown", "arch": ["x86_64"], "validpgpkeys": []}


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


def lock_srcdest(srcdest_path: str) -> Optional[int]:
    """Lock SRCDEST directory"""
    try:
        lock_file = os.path.join(srcdest_path, '.apb-lock')
        fd = os.open(lock_file, os.O_CREAT | os.O_WRONLY | os.O_TRUNC)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except (OSError, IOError):
        return None


def unlock_srcdest(lock_fd: int):
    """Unlock SRCDEST directory"""
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
    except Exception as e:
        logger.error(f"Error unlocking SRCDEST: {e}")


def build_package(build_id: str, build_dir: Path, pkgbuild_info: Dict[str, Any]):
    """Build package using makechrootpkg"""
    global build_counter
    
    try:
        # Update build status
        active_builds[build_id]["status"] = BuildStatus.BUILDING
        active_builds[build_id]["start_time"] = time.time()
        
        # Add to build outputs
        build_outputs[build_id] = []
        
        def log_output(message: str):
            build_outputs[build_id].append(message)
            # Send to streams
            for stream_queue in build_streams.get(build_id, []):
                try:
                    stream_queue.put(("output", message))
                except:
                    pass

        log_output(f"Starting build for {pkgbuild_info['pkgname']}")
        
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
            log_output("Removing existing buildroot for recreation")
            try:
                root_path = buildroot_path / "root"
                if root_path.exists():
                    shutil.rmtree(root_path)
                if not setup_buildroot(buildroot_path):
                    raise Exception("Failed to recreate buildroot")
            except Exception as e:
                log_output(f"Warning: Could not recreate buildroot: {e}")
                raise Exception("Failed to recreate buildroot")
        
        # Get makepkg config
        makepkg_config = get_makepkg_config()
        
        # Lock SRCDEST if it exists
        srcdest_lock = None
        if 'SRCDEST' in makepkg_config:
            srcdest_lock = lock_srcdest(makepkg_config['SRCDEST'])
            if srcdest_lock is None:
                log_output("Waiting for SRCDEST lock...")
                # Wait for lock
                while srcdest_lock is None and not shutdown_event.is_set():
                    time.sleep(1)
                    srcdest_lock = lock_srcdest(makepkg_config['SRCDEST'])
        
        try:
            # Download GPG keys if specified in PKGBUILD
            if pkgbuild_info.get("validpgpkeys"):
                log_output("Downloading GPG keys for source validation...")
                if not download_gpg_keys(pkgbuild_info["validpgpkeys"], log_output):
                    log_output("GPG key download failed, continuing build (may fail during source validation)")
            
            # Build makechrootpkg command with correct flags
            cmd = ["sudo", "makechrootpkg", "-cuT", "-r", str(buildroot_path)]
            
            # Add bind mounts
            if 'CCACHE_DIR' in makepkg_config:
                cmd.extend(["-d", makepkg_config['CCACHE_DIR']])
            if 'SRCDEST' in makepkg_config:
                cmd.extend(["-d", makepkg_config['SRCDEST']])
            
            log_output(f"Running: {' '.join(cmd)}")
            
            # Execute build
            process = subprocess.Popen(
                cmd,
                cwd=build_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            # Stream output
            for line in iter(process.stdout.readline, ''):
                if shutdown_event.is_set():
                    process.terminate()
                    break
                log_output(line.rstrip())
            
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
                stream_queue.put(("complete", {
                    "status": active_builds[build_id]["status"],
                    "exit_code": active_builds[build_id].get("exit_code", 1)
                }))
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
    while not shutdown_event.is_set():
        try:
            # Get build from queue
            build_data = build_queue.get(timeout=1)
            
            # Submit to executor
            build_executor.submit(
                build_package, 
                build_data["build_id"], 
                build_data["build_dir"], 
                build_data["pkgbuild_info"]
            )
            
        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Error processing build queue: {e}")


# Start queue processor
queue_thread = threading.Thread(target=process_build_queue, daemon=True)
queue_thread.start()


@app.get("/")
async def get_server_info():
    """Get server information and status"""
    return {
        "status": "running",
        "version": VERSION,
        "supported_architecture": get_server_architecture(),
        "system_info": get_system_info(),
        "queue_status": get_queue_status()
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": VERSION
    }


@app.post("/build")
async def submit_build(
    pkgbuild: UploadFile = File(...),
    build_id: str = Form(...),
    sources: List[UploadFile] = File(default=[])
):
    """Submit a new build request"""
    try:
        # Validate PKGBUILD file
        if not pkgbuild.filename or pkgbuild.filename.lower() != "pkgbuild":
            raise HTTPException(
                status_code=400, 
                detail={"error": "Invalid PKGBUILD file", "detail": "File must be named 'PKGBUILD'"}
            )
        
        # Check if build_id already exists
        if build_id in active_builds or build_id in build_history:
            raise HTTPException(
                status_code=400, 
                detail={"error": "Build ID already exists", "detail": f"Build with ID '{build_id}' already exists"}
            )
        
        # Create build directory
        builds_dir = Path(server_config["builds_dir"])
        builds_dir.mkdir(parents=True, exist_ok=True)
        
        build_dir = builds_dir / build_id
        build_dir.mkdir(exist_ok=True)
        
        # Save PKGBUILD
        pkgbuild_path = build_dir / "PKGBUILD"
        try:
            with open(pkgbuild_path, 'wb') as f:
                content = await pkgbuild.read()
                f.write(content)
        except Exception as e:
            raise HTTPException(
                status_code=400, 
                detail={"error": "Failed to save PKGBUILD", "detail": str(e)}
            )
        
        # Save source files
        for source in sources:
            if source.filename:
                source_path = build_dir / source.filename
                try:
                    with open(source_path, 'wb') as f:
                        content = await source.read()
                        f.write(content)
                except Exception as e:
                    logger.error(f"Error saving source file {source.filename}: {e}")
        
        # Parse PKGBUILD
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
            "logs": []
        }
        
        # Add to queue
        build_queue.put({
            "build_id": build_id,
            "build_dir": build_dir,
            "pkgbuild_info": pkgbuild_info
        })
        
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
    global server_config, build_executor
    
    parser = argparse.ArgumentParser(description="APB Server - Arch Package Builder")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host to bind to")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind to")
    parser.add_argument("--buildroot", type=Path, default=DEFAULT_BUILDROOT, help="Buildroot directory")
    parser.add_argument("--builds-dir", type=Path, default=DEFAULT_BUILDS_DIR, help="Builds directory")
    parser.add_argument("--max-concurrent", type=int, default=DEFAULT_MAX_CONCURRENT, help="Max concurrent builds")
    parser.add_argument("--buildroot-autorecreate", type=int, help="Recreate buildroot after N builds")
    parser.add_argument("--architecture", type=str, help="Override detected architecture (e.g., 'powerpc' for espresso server)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    # Setup logging
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Store configuration
    server_config = {
        "host": args.host,
        "port": args.port,
        "buildroot": args.buildroot,
        "builds_dir": args.builds_dir,
        "max_concurrent": args.max_concurrent,
        "buildroot_autorecreate": args.buildroot_autorecreate,
        "architecture_override": args.architecture
    }
    
    # Update executor with correct max_workers
    build_executor = ThreadPoolExecutor(max_workers=args.max_concurrent)
    
    # Create directories
    args.buildroot.mkdir(parents=True, exist_ok=True)
    args.builds_dir.mkdir(parents=True, exist_ok=True)
    
    logger.info(f"Starting APB Server v{VERSION}")
    logger.info(f"Buildroot: {args.buildroot}")
    logger.info(f"Builds directory: {args.builds_dir}")
    logger.info(f"Max concurrent builds: {args.max_concurrent}")
    
    # Log the detected architecture
    detected_arch = get_server_architecture()
    logger.info(f"Detected server architecture: {detected_arch}")
    
    # Setup buildroot during startup
    logger.info("Setting up buildroot...")
    if not setup_buildroot(args.buildroot):
        logger.error("Failed to setup buildroot during startup")
        sys.exit(1)
    logger.info("Buildroot setup complete")
    
    # Start server
    try:
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            log_level="info" if not args.debug else "debug"
        )
    except KeyboardInterrupt:
        logger.info("Server interrupted by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 