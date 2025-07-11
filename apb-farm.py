#!/usr/bin/env python3
"""
APB Farm - Arch Package Builder Farm Component
Manages multiple APB Servers, distributing builds based on architecture and load.
"""

import asyncio
import json
import logging
import os
import sqlite3
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import argparse
import signal
import tempfile
import re
from urllib.parse import urlparse
import aiohttp
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum

# FastAPI dependencies
try:
    from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request, Query
    from fastapi.responses import JSONResponse, StreamingResponse, FileResponse, HTMLResponse
    from fastapi.middleware.cors import CORSMiddleware
    import uvicorn
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Install with: pip install fastapi uvicorn aiohttp")
    sys.exit(1)

# Version and constants
VERSION = "2025-07-11"
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8080
DEFAULT_CONFIG_PATHS = [
    Path.cwd() / "apb.json",
    Path("/etc/apb/apb.json"),
    Path.home() / ".apb" / "apb.json",
    Path.home() / ".apb-farm" / "apb.json"
]

# Global state
config: Dict[str, Any] = {}
server_info_cache: Dict[str, Dict] = {}
build_queue: List[Dict] = []
build_database: sqlite3.Connection = None
http_session: aiohttp.ClientSession = None
shutdown_event = asyncio.Event()
background_tasks: List[asyncio.Task] = []

# Enhanced server tracking for resilient architecture detection
server_status_tracker: Dict[str, ServerStatus] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan events"""
    # Startup
    global build_database, background_tasks, config

    # Load configuration
    config = load_config()

    if not config.get("servers"):
        logger.error("No servers configured")
        yield
        return

    # Initialize database
    build_database = init_database()

    # Setup HTTP session
    await setup_http_session()

    # Start background tasks
    background_tasks.extend([
        asyncio.create_task(process_build_queue()),
        asyncio.create_task(update_build_status()),
        asyncio.create_task(discover_builds())
    ])

    logger.info(f"APB Farm started with {len(config.get('servers', {}))} architecture groups")

    yield

    # Shutdown
    # Signal shutdown
    shutdown_event.set()

    # Cancel background tasks
    for task in background_tasks:
        task.cancel()

    # Wait for tasks to complete
    await asyncio.gather(*background_tasks, return_exceptions=True)

    # Cleanup HTTP session
    await cleanup_http_session()

    # Close database
    if build_database:
        build_database.close()

    logger.info("APB Farm shutdown complete")


# Create FastAPI app with lifespan
app = FastAPI(title="APB Farm", version=VERSION, lifespan=lifespan)

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


class ServerHealth(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded" 
    UNAVAILABLE = "unavailable"
    MISCONFIGURED = "misconfigured"


@dataclass
class ServerStatus:
    url: str
    last_successful_contact: Optional[float] = None
    last_failed_contact: Optional[float] = None
    consecutive_failures: int = 0
    last_known_architecture: Optional[str] = None
    health: ServerHealth = ServerHealth.HEALTHY
    last_response: Optional[Dict] = None


def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load configuration from file"""
    if config_path:
        config_paths = [config_path]
    else:
        config_paths = DEFAULT_CONFIG_PATHS

    for path in config_paths:
        if path.exists():
            try:
                with open(path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading config from {path}: {e}")
                continue

    logger.error("No configuration file found")
    return {"servers": {}}


def init_database() -> sqlite3.Connection:
    """Initialize SQLite database for build tracking"""
    db_path = Path.home() / ".apb" / "farm.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS builds (
            id TEXT PRIMARY KEY,
            server_url TEXT,
            server_arch TEXT,
            pkgname TEXT,
            status TEXT,
            start_time REAL,
            end_time REAL,
            created_at REAL,
            queue_position INTEGER,
            submission_group TEXT
        )
    ''')

    # Add the submission_group column if it doesn't exist (for existing databases)
    try:
        conn.execute('ALTER TABLE builds ADD COLUMN submission_group TEXT')
        conn.commit()
    except sqlite3.OperationalError:
        # Column already exists
        pass

    conn.commit()
    return conn


def safe_timestamp_to_datetime(timestamp) -> Optional[str]:
    """Safely convert timestamp to datetime string"""
    if timestamp is None:
        return None
    try:
        # Convert to float if it's a string
        if isinstance(timestamp, str):
            timestamp = float(timestamp)
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError, OSError):
        return None


def obfuscate_server_url(url: str) -> str:
    """Obfuscate server URL for security"""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or "unknown"
        if len(hostname) >= 4:
            return f"{hostname[:3]}---{hostname[-1]}"
        else:
            return "ser---1"
    except Exception:
        return "ser---1"


def parse_pkgbuild_arch(pkgbuild_content: str) -> List[str]:
    """Parse PKGBUILD content to extract architecture"""
    try:
        for line in pkgbuild_content.split('\n'):
            line = line.strip()
            if line.startswith('arch='):
                arch_str = line.split('=', 1)[1].strip()
                if arch_str.startswith('(') and arch_str.endswith(')'):
                    arch_str = arch_str[1:-1]
                # Remove quotes and split
                archs = [a.strip('\'"') for a in arch_str.split()]
                return archs if archs else ["x86_64"]
        return ["x86_64"]
    except Exception as e:
        logger.error(f"Error parsing PKGBUILD architecture: {e}")
        return ["x86_64"]


def parse_pkgbuild_name(pkgbuild_content: str) -> str:
    """Parse PKGBUILD content to extract package name (use pkgbase if defined, ignore pkgname completely)"""
    try:
        pkgbase = None
        pkgname = None

        for line in pkgbuild_content.split('\n'):
            line = line.strip()
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
                    pkgname = first_pkg
                else:
                    # Handle simple format: pkgname=package
                    pkgname = pkgname_value.strip('\'"')

        # If pkgbase is defined, use it and ignore pkgname completely
        return pkgbase or pkgname or "unknown"
    except Exception as e:
        logger.error(f"Error parsing PKGBUILD name: {e}")
        return "unknown"


async def get_server_info(server_url: str) -> Optional[Dict]:
    """Get server information with enhanced resilient caching and health tracking"""
    global server_status_tracker

    # Get or create server status tracking
    if server_url not in server_status_tracker:
        server_status_tracker[server_url] = ServerStatus(url=server_url)

    status = server_status_tracker[server_url]
    current_time = time.time()

    # Check existing cache with different TTLs for success/failure
    cache_key = server_url
    cached_info = server_info_cache.get(cache_key)

    if cached_info:
        cache_age = current_time - cached_info.get('_cached_at', 0)

        # Use cached successful response if still valid (60 seconds)
        if cached_info.get('_success', False) and cache_age < 60:
            return cached_info

        # Use cached failure for shorter time (30 seconds) to reduce server load
        if not cached_info.get('_success', True) and cache_age < 30:
            return None

    # Attempt to contact server
    try:
        async with http_session.get(f"{server_url}/", timeout=10) as response:
            if response.status == 200:
                info = await response.json()

                # Successful contact - update health tracking
                status.last_successful_contact = current_time
                status.consecutive_failures = 0
                status.last_response = info

                # Track architecture if provided
                if 'supported_architecture' in info:
                    status.last_known_architecture = info['supported_architecture']

                # Update health status (recovery)
                if status.health in [ServerHealth.DEGRADED, ServerHealth.UNAVAILABLE]:
                    status.health = ServerHealth.HEALTHY
                    logger.info(f"Server {server_url} recovered to healthy state")

                # Cache successful response
                info['_cached_at'] = current_time
                info['_success'] = True
                server_info_cache[cache_key] = info

                return info
            else:
                raise Exception(f"HTTP {response.status}")

    except Exception as e:
        # Failed contact - update health tracking
        status.last_failed_contact = current_time
        status.consecutive_failures += 1

        # Update health status based on failure count
        if status.consecutive_failures >= 10:  # 10 failures = misconfigured
            if status.health != ServerHealth.MISCONFIGURED:
                status.health = ServerHealth.MISCONFIGURED
                logger.error(f"Server {server_url} marked as MISCONFIGURED after {status.consecutive_failures} consecutive failures")
        elif status.consecutive_failures >= 3:  # 3 failures = degraded
            if status.health != ServerHealth.DEGRADED:
                status.health = ServerHealth.DEGRADED
                logger.warning(f"Server {server_url} marked as DEGRADED after {status.consecutive_failures} consecutive failures")
        else:
            status.health = ServerHealth.UNAVAILABLE

        logger.error(f"Error fetching info from {server_url} (failure #{status.consecutive_failures}): {e}")

        # Cache failure with shorter TTL
        failure_info = {
            '_cached_at': current_time,
            '_success': False,
            '_error': str(e)
        }
        server_info_cache[cache_key] = failure_info

        return None


async def find_build_server(build_id: str) -> Optional[str]:
    """Find which server is handling a build"""
    # First check database
    cursor = build_database.cursor()
    cursor.execute("SELECT server_url FROM builds WHERE id = ?", (build_id,))
    result = cursor.fetchone()
    if result:
        return result[0]

    # Search all servers
    for arch_servers in config.get("servers", {}).values():
        for server_url in arch_servers:
            try:
                async with http_session.get(f"{server_url}/build/{build_id}/status-api", timeout=10) as response:
                    if response.status == 200:
                        return server_url
            except Exception:
                continue

    return None


async def get_available_architectures() -> Dict[str, List[str]]:
    """
    Get available architectures with resilient logic that uses last known
    good architecture information during temporary server failures.
    """
    global server_status_tracker

    available_archs = {}
    degraded_servers = []

    # Query all configured servers to get their actual supported architectures
    for config_arch, server_urls in config.get("servers", {}).items():
        for server_url in server_urls:
            try:
                # Get current server info (this updates health tracking)
                server_info = await get_server_info(server_url)

                # Get server status for health tracking
                status = server_status_tracker.get(server_url)
                if not status:
                    continue

                # Determine supported architecture
                supported_arch = None

                if server_info and 'supported_architecture' in server_info:
                    # Use current response
                    supported_arch = server_info['supported_architecture']
                elif status.last_known_architecture:
                    # Fall back to last known good architecture for temporarily unavailable servers
                    supported_arch = status.last_known_architecture
                    if status.health == ServerHealth.UNAVAILABLE:
                        logger.info(f"Using last known architecture {supported_arch} for temporarily unavailable server {server_url}")

                if supported_arch:
                    if supported_arch not in available_archs:
                        available_archs[supported_arch] = []

                    # Include server based on health status
                    if status.health == ServerHealth.HEALTHY:
                        available_archs[supported_arch].append(server_url)
                    elif status.health == ServerHealth.DEGRADED:
                        # Include degraded servers but track them
                        available_archs[supported_arch].append(server_url)
                        degraded_servers.append(server_url)
                    elif status.health == ServerHealth.UNAVAILABLE:
                        # Include temporarily unavailable servers with last known architecture
                        # This prevents them from being marked as misconfigured
                        available_archs[supported_arch].append(server_url)
                    # MISCONFIGURED servers are NOT included

                    # Log if there's a mismatch between config and actual
                    if config_arch != supported_arch:
                        logger.warning(f"Server {server_url} configured for {config_arch} but supports {supported_arch}")
                else:
                    # Only warn if we've never successfully contacted this server
                    if not status.last_known_architecture:
                        logger.warning(f"Server {server_url} did not report supported architecture and has no known architecture")

            except Exception as e:
                logger.error(f"Error checking server {server_url}: {e}")

    # Log degraded servers for monitoring
    if degraded_servers:
        logger.warning(f"Degraded servers (high failure rate): {degraded_servers}")

    return available_archs


async def get_best_server_for_arch(target_archs: List[str]) -> Optional[str]:
    """Find the best available server for the given architectures"""
    # Get actual available architectures from servers
    available_archs = await get_available_architectures()

    suitable_servers = []

    for arch in target_archs:
        if arch == "any":
            # Can use any architecture - add all available servers
            for server_list in available_archs.values():
                suitable_servers.extend(server_list)
        else:
            # Specific architecture - only add servers that actually support it
            if arch in available_archs:
                suitable_servers.extend(available_archs[arch])

    if not suitable_servers:
        return None

    # Remove duplicates
    suitable_servers = list(set(suitable_servers))

    # Check server availability, load, and health
    best_server = None
    best_score = float('inf')

    for server_url in suitable_servers:
        # Get server status for health information
        status = server_status_tracker.get(server_url)

        # Skip misconfigured servers entirely
        if status and status.health == ServerHealth.MISCONFIGURED:
            continue

        info = await get_server_info(server_url)
        if not info:
            continue

        queue_status = info.get("queue_status", {})
        current_builds = queue_status.get("current_builds_count", 0)
        queued_builds = queue_status.get("queued_builds", 0)
        max_concurrent = queue_status.get("max_concurrent_builds", 3)

        # Skip if server is at capacity
        if current_builds >= max_concurrent:
            continue

        # Calculate load score (lower is better)
        score = current_builds + queued_builds

        # Add penalty for degraded servers (prefer healthy servers)
        if status and status.health == ServerHealth.DEGRADED:
            score += 5  # Penalty to prefer healthy servers

        if score < best_score:
            best_score = score
            best_server = server_url

    return best_server


async def queue_build(build_id: str, pkgbuild_content: str, pkgname: str, target_archs: List[str], source_files: List[Dict] = None):
    """Queue a build for processing"""
    build_info = {
        "build_id": build_id,
        "pkgbuild_content": pkgbuild_content,
        "pkgname": pkgname,
        "target_architectures": target_archs,
        "source_files": source_files or [],
        "created_at": time.time(),
        "status": BuildStatus.QUEUED
    }

    build_queue.append(build_info)

    # Store in database
    cursor = build_database.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO builds 
        (id, server_url, server_arch, pkgname, status, start_time, end_time, created_at, queue_position, submission_group)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        build_id, None, None, pkgname, BuildStatus.QUEUED, 
        None, None, time.time(), len(build_queue), None
    ))
    build_database.commit()


async def queue_builds_for_architectures(pkgbuild_content: str, pkgname: str, target_archs: List[str], source_files: List[Dict] = None) -> List[Dict]:
    """
    Queue builds for each architecture that has available servers.
    Returns a list of build information dictionaries.
    """
    submission_group = str(uuid.uuid4())  # Group ID to track related builds
    queued_builds = []

    # Get actual available architectures from servers
    available_archs = await get_available_architectures()

    # Find architectures that have available servers
    buildable_archs = []
    skipped_archs = []

    for arch in target_archs:
        if arch == "any":
            # For "any" architecture, select the best available architecture (not all)
            if available_archs:
                # Pick the architecture with the least load
                best_arch = None
                best_load = float('inf')

                for avail_arch, server_urls in available_archs.items():
                    total_load = 0
                    available_servers = 0

                    for server_url in server_urls:
                        try:
                            server_info = await get_server_info(server_url)
                            if server_info:
                                queue_status = server_info.get("queue_status", {})
                                current_builds = queue_status.get("current_builds_count", 0)
                                queued_builds_count = queue_status.get("queued_builds", 0)
                                max_concurrent = queue_status.get("max_concurrent_builds", 3)

                                # Skip servers at capacity
                                if current_builds < max_concurrent:
                                    total_load += current_builds + queued_builds_count
                                    available_servers += 1
                        except Exception:
                            continue

                    # Calculate average load for this architecture
                    if available_servers > 0:
                        avg_load = total_load / available_servers
                        if avg_load < best_load:
                            best_load = avg_load
                            best_arch = avail_arch

                if best_arch:
                    buildable_archs.append(best_arch)
                    logger.info(f"Selected architecture '{best_arch}' for 'any' architecture package (lowest load: {best_load:.1f})")
                else:
                    skipped_archs.append(arch)
            else:
                skipped_archs.append(arch)
        else:
            # Check if this specific architecture has available servers
            if arch in available_archs and available_archs[arch]:
                buildable_archs.append(arch)
            else:
                skipped_archs.append(arch)

    # Remove duplicates while preserving order
    buildable_archs = list(dict.fromkeys(buildable_archs))

    # Log architecture scheduling decisions
    if buildable_archs:
        logger.info(f"Queuing builds for architectures: {buildable_archs}")
    if skipped_archs:
        logger.info(f"Skipping architectures (no available servers): {skipped_archs}")

    # Create a separate build for each available architecture
    for arch in buildable_archs:
        build_id = str(uuid.uuid4())

        build_info = {
            "build_id": build_id,
            "pkgbuild_content": pkgbuild_content,
            "pkgname": pkgname,
            "target_architectures": [arch],  # Single architecture per build
            "source_files": source_files or [],
            "created_at": time.time(),
            "status": BuildStatus.QUEUED,
            "submission_group": submission_group,
            "arch": arch
        }

        build_queue.append(build_info)

        # Store in database
        cursor = build_database.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO builds 
            (id, server_url, server_arch, pkgname, status, start_time, end_time, created_at, queue_position, submission_group)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            build_id, None, arch, pkgname, BuildStatus.QUEUED, 
            None, None, time.time(), len(build_queue), submission_group
        ))
        build_database.commit()

        queued_builds.append({
            "build_id": build_id,
            "arch": arch,
            "status": BuildStatus.QUEUED,
            "pkgname": pkgname,
            "submission_group": submission_group,
            "created_at": time.time()
        })

    return queued_builds


async def process_build_queue():
    """Background task to process build queue"""
    while not shutdown_event.is_set():
        try:
            if build_queue:
                build_info = build_queue.pop(0)
                build_id = build_info["build_id"]
                target_arch = build_info["target_architectures"][0]  # Now each build has exactly one architecture

                # Get actual available architectures from servers
                available_archs = await get_available_architectures()

                # Check if we have servers for this architecture
                if target_arch not in available_archs or not available_archs[target_arch]:
                    logger.error(f"No available servers for architecture {target_arch}")
                    # Mark build as failed
                    cursor = build_database.cursor()
                    cursor.execute('''
                        UPDATE builds SET status = ?, end_time = ?
                        WHERE id = ?
                    ''', (BuildStatus.FAILED, time.time(), build_id))
                    build_database.commit()
                    continue

                # Find the best server for this architecture
                server_url = await get_best_server_for_arch([target_arch])

                if server_url:
                    # Forward build to server
                    await forward_build_to_server(build_info, server_url)
                else:
                    # No suitable server available, requeue with delay
                    logger.warning(f"No available server for architecture {target_arch}, requeueing build {build_id}")
                    await asyncio.sleep(30)
                    build_queue.append(build_info)

            await asyncio.sleep(5)
        except Exception as e:
            logger.error(f"Error in build queue processing: {e}")
            await asyncio.sleep(10)


async def forward_build_to_server(build_info: Dict, server_url: str):
    """Forward a build to a specific server"""
    try:
        build_id = build_info["build_id"]

        # Create form data
        data = aiohttp.FormData()
        data.add_field('build_id', build_id)
        data.add_field('pkgbuild', build_info["pkgbuild_content"], 
                      filename='PKGBUILD', content_type='text/plain')

        # Add source files
        for source_file in build_info.get("source_files", []):
            data.add_field('sources', source_file["content"], 
                          filename=source_file["filename"], 
                          content_type=source_file["content_type"])

        async with http_session.post(f"{server_url}/build", data=data, timeout=30) as response:
            if response.status == 200:
                # Update database
                cursor = build_database.cursor()
                cursor.execute('''
                    UPDATE builds SET server_url = ?, status = ?, start_time = ?
                    WHERE id = ?
                ''', (server_url, BuildStatus.BUILDING, time.time(), build_id))
                build_database.commit()

                logger.info(f"Build {build_id} forwarded to {server_url}")
            else:
                logger.error(f"Failed to forward build {build_id} to {server_url}: {response.status}")
                # Requeue with delay
                await asyncio.sleep(30)
                build_queue.append(build_info)
    except Exception as e:
        logger.error(f"Error forwarding build {build_info['build_id']} to {server_url}: {e}")
        # Requeue with delay
        await asyncio.sleep(30)
        build_queue.append(build_info)


async def update_build_status():
    """Background task to update build status"""
    while not shutdown_event.is_set():
        try:
            cursor = build_database.cursor()
            cursor.execute('''
                SELECT id, server_url FROM builds 
                WHERE status IN (?, ?) AND server_url IS NOT NULL
            ''', (BuildStatus.QUEUED, BuildStatus.BUILDING))

            for build_id, server_url in cursor.fetchall():
                try:
                    async with http_session.get(f"{server_url}/build/{build_id}/status-api", timeout=10) as response:
                        if response.status == 200:
                            build_status = await response.json()
                            status = build_status.get("status", BuildStatus.QUEUED)

                            # Update database
                            cursor.execute('''
                                UPDATE builds SET status = ?, end_time = ?
                                WHERE id = ?
                            ''', (status, 
                                 time.time() if status in [BuildStatus.COMPLETED, BuildStatus.FAILED] else None,
                                 build_id))
                            build_database.commit()
                except Exception as e:
                    logger.error(f"Error updating status for build {build_id}: {e}")

            await asyncio.sleep(120)  # Check every 2 minutes
        except Exception as e:
            logger.error(f"Error in build status update: {e}")
            await asyncio.sleep(120)


async def discover_builds():
    """Background task to discover builds from all servers"""
    while not shutdown_event.is_set():
        try:
            # Get actual available architectures from servers
            available_archs = await get_available_architectures()

            for arch, server_urls in available_archs.items():
                for server_url in server_urls:
                    try:
                        async with http_session.get(f"{server_url}/builds/latest?limit=50", timeout=10) as response:
                            if response.status == 200:
                                builds_data = await response.json()
                                builds = builds_data.get("builds", [])

                                for build in builds:
                                    build_id = build.get("id")
                                    if build_id:
                                        cursor = build_database.cursor()
                                        cursor.execute("SELECT id FROM builds WHERE id = ?", (build_id,))
                                        if not cursor.fetchone():
                                            # New build discovered
                                            cursor.execute('''
                                                INSERT INTO builds 
                                                (id, server_url, server_arch, pkgname, status, start_time, end_time, created_at)
                                                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                                            ''', (
                                                build_id, server_url, arch, 
                                                build.get("pkgname", "unknown"),
                                                build.get("status", BuildStatus.QUEUED),
                                                build.get("start_time", time.time()),
                                                build.get("end_time"),
                                                build.get("created_at", time.time())
                                            ))
                                            build_database.commit()
                    except Exception as e:
                        logger.error(f"Error discovering builds from {server_url}: {e}")

            await asyncio.sleep(300)  # Check every 5 minutes
        except Exception as e:
            logger.error(f"Error in build discovery: {e}")
            await asyncio.sleep(300)


# API Endpoints

@app.get("/farm")
async def get_farm_info():
    """Get farm information and status of all managed servers"""
    servers = []
    available_archs = await get_available_architectures()

    # Group servers by their actual supported architecture
    for arch, server_urls in available_archs.items():
        for server_url in server_urls:
            server_info = await get_server_info(server_url)
            servers.append({
                "url": obfuscate_server_url(server_url),
                "arch": arch,  # Use actual supported architecture
                "status": "online" if server_info else "offline",
                "info": server_info
            })

    # Check for truly misconfigured servers (conservative approach)
    for config_arch, server_urls in config.get("servers", {}).items():
        for server_url in server_urls:
            # Check if this server is already properly listed
            already_listed = any(
                server["url"] == obfuscate_server_url(server_url) 
                for server in servers
            )

            if not already_listed:
                # Get server status for detailed health information
                status = server_status_tracker.get(server_url)

                # Only mark as misconfigured if we have strong evidence
                if status and status.health == ServerHealth.MISCONFIGURED:
                    servers.append({
                        "url": obfuscate_server_url(server_url),
                        "arch": f"{config_arch} (misconfigured)",
                        "status": "misconfigured",
                        "consecutive_failures": status.consecutive_failures,
                        "info": None
                    })
                elif status and status.health in [ServerHealth.DEGRADED, ServerHealth.UNAVAILABLE]:
                    # Don't mark degraded/unavailable servers as misconfigured
                    # They're already listed in their proper architecture group
                    pass
                else:
                    # Server not in tracking yet - get info to initialize
                    server_info = await get_server_info(server_url)
                    if not server_info:
                        # Initial failure - don't immediately mark as misconfigured
                        servers.append({
                            "url": obfuscate_server_url(server_url),
                            "arch": f"{config_arch} (checking...)",
                            "status": "initializing",
                            "info": None
                        })

    return {
        "status": "running",
        "version": VERSION,
        "servers": servers,
        "available_architectures": list(available_archs.keys()),
        "total_servers": len(servers)
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": VERSION
    }


@app.post("/build/{build_id}/cancel")
async def cancel_build(build_id: str):
    """Cancel a build by forwarding the request to the appropriate server"""
    server_url = await find_build_server(build_id)

    if not server_url:
        raise HTTPException(status_code=404, detail="Build not found")

    try:
        async with http_session.post(f"{server_url}/build/{build_id}/cancel", timeout=10) as response:
            if response.status == 200:
                result = await response.json()

                # Update local database
                cursor = build_database.cursor()
                cursor.execute('''
                    UPDATE builds SET status = ?, end_time = ?
                    WHERE id = ?
                ''', (BuildStatus.CANCELLED, time.time(), build_id))
                build_database.commit()

                return {
                    "success": True,
                    "message": f"Build {build_id} cancelled successfully",
                    "server_response": result
                }
            else:
                error_detail = await response.text()
                raise HTTPException(status_code=response.status, detail=f"Server error: {error_detail}")
    except Exception as e:
        logger.error(f"Error cancelling build {build_id} on server {server_url}: {e}")
        raise HTTPException(status_code=503, detail=f"Error contacting server: {e}")


@app.get("/dashboard")
async def get_dashboard(page: int = Query(1, ge=1)):
    """Get farm dashboard HTML"""
    # Get server status grouped by actual supported architecture
    available_archs = await get_available_architectures()
    servers_by_arch = {}

    for arch, server_urls in available_archs.items():
        servers_by_arch[arch] = []
        for server_url in server_urls:
            server_info = await get_server_info(server_url)
            servers_by_arch[arch].append({
                "url": obfuscate_server_url(server_url),
                "status": "online" if server_info else "offline",
                "info": server_info
            })

    # Check for truly misconfigured servers (conservative dashboard logic)
    for config_arch, server_urls in config.get("servers", {}).items():
        for server_url in server_urls:
            # Check if this server is already listed in available architectures
            already_listed = any(
                server_url in arch_servers 
                for arch_servers in available_archs.values()
            )
            if not already_listed:
                # Get server status for health information
                status = server_status_tracker.get(server_url)

                # Only show as misconfigured if we have strong evidence
                if status and status.health == ServerHealth.MISCONFIGURED:
                    if "misconfigured" not in servers_by_arch:
                        servers_by_arch["misconfigured"] = []
                    servers_by_arch["misconfigured"].append({
                        "url": obfuscate_server_url(server_url),
                        "status": f"misconfigured ({status.consecutive_failures} failures)",
                        "info": None
                    })
                elif not status or status.consecutive_failures < 3:
                    # Don't show servers that are just initializing or have few failures
                    pass

    # Get recent builds
    cursor = build_database.cursor()
    offset = (page - 1) * 20
    cursor.execute('''
        SELECT id, server_url, server_arch, pkgname, status, start_time, end_time, created_at
        FROM builds ORDER BY created_at DESC LIMIT 20 OFFSET ?
    ''', (offset,))

    builds = []
    for row in cursor.fetchall():
        builds.append({
            "id": row[0],
            "server_url": obfuscate_server_url(row[1]) if row[1] else "unknown",
            "server_arch": row[2],
            "pkgname": row[3],
            "status": row[4],
            "start_time": safe_timestamp_to_datetime(row[5]),
            "end_time": safe_timestamp_to_datetime(row[6]),
            "created_at": safe_timestamp_to_datetime(row[7]) or "unknown"
        })

    # Generate HTML
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>APB Farm Dashboard</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta http-equiv="refresh" content="10">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ text-align: center; margin-bottom: 30px; }}
            .servers {{ margin-bottom: 30px; }}
            .arch-group {{ margin-bottom: 20px; }}
            .arch-title {{ font-size: 18px; font-weight: bold; margin-bottom: 10px; }}
            .server {{ margin: 5px 0; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }}
            .online {{ background-color: #d4edda; }}
            .offline {{ background-color: #f8d7da; }}
            .misconfigured {{ background-color: #fff3cd; }}
            .builds {{ margin-top: 30px; }}
            .build {{ margin: 5px 0; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }}
            .completed {{ background-color: #d4edda; }}
            .failed {{ background-color: #f8d7da; }}
            .building {{ background-color: #fff3cd; }}
            .queued {{ background-color: #d1ecf1; }}
            .pagination {{ text-align: center; margin: 20px 0; }}
            .pagination a {{ margin: 0 5px; padding: 5px 10px; text-decoration: none; border: 1px solid #ddd; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>APB Farm Dashboard</h1>
            <p>Version: {VERSION}</p>
            <p>Available Architectures: {', '.join(available_archs.keys())}</p>
        </div>

        <div class="servers">
            <h2>Servers by Architecture</h2>
    """

    for arch, servers in servers_by_arch.items():
        html += f"""
            <div class="arch-group">
                <div class="arch-title">{arch}</div>
        """
        for server in servers:
            status_class = "online" if server["status"] == "online" else ("misconfigured" if arch == "misconfigured" else "offline")
            queue_info = ""
            if server["info"]:
                queue_status = server["info"].get("queue_status", {})
                queue_info = f" - Builds: {queue_status.get('current_builds_count', 0)}, Queued: {queue_status.get('queued_builds', 0)}"

            html += f"""
                <div class="server {status_class}">
                    <strong>{server['url']}</strong> ({server['status']}){queue_info}
                </div>
            """
        html += "</div>"

    html += """
        </div>

        <div class="builds">
            <h2>Recent Builds</h2>
    """

    for build in builds:
        html += f"""
            <div class="build {build['status']}">
                <strong>{build['pkgname']}</strong> 
                ({build['id'][:8]}...) - 
                {build['status']} on {build['server_url']} ({build['server_arch']})
                <br>
                <small>Created: {build['created_at']}</small>
            </div>
        """

    html += f"""
        </div>

        <div class="pagination">
            <a href="/dashboard?page={max(1, page-1)}">&laquo; Previous</a>
            <span>Page {page}</span>
            <a href="/dashboard?page={page+1}">Next &raquo;</a>
        </div>
    </body>
    </html>
    """

    return HTMLResponse(content=html)


@app.post("/build")
async def submit_build(
    pkgbuild: UploadFile = File(...),
    sources: List[UploadFile] = File(default=[]),
    architectures: str = Form(None)
):
    """Submit a build request"""
    try:
        # Read PKGBUILD content
        pkgbuild_content = (await pkgbuild.read()).decode('utf-8')

        # Parse PKGBUILD
        pkgname = parse_pkgbuild_name(pkgbuild_content)
        pkgbuild_archs = parse_pkgbuild_arch(pkgbuild_content)

        # Determine target architectures
        if architectures:
            # Use architectures provided by client (filtered list)
            target_archs = [arch.strip() for arch in architectures.split(',') if arch.strip()]
            logger.info(f"Using client-specified architectures: {target_archs}")
        else:
            # Fall back to all architectures from PKGBUILD
            target_archs = pkgbuild_archs
            logger.info(f"Using all PKGBUILD architectures: {target_archs}")

        # Validate that requested architectures are actually in the PKGBUILD
        invalid_archs = [arch for arch in target_archs if arch not in pkgbuild_archs and arch != "any"]
        if invalid_archs:
            logger.warning(f"Requested architectures {invalid_archs} not found in PKGBUILD arch={pkgbuild_archs}")
            # Filter out invalid architectures
            target_archs = [arch for arch in target_archs if arch in pkgbuild_archs or arch == "any"]

        if not target_archs:
            return {
                "error": "No valid architectures",
                "message": "No valid architectures specified or found in PKGBUILD",
                "pkgname": pkgname,
                "pkgbuild_architectures": pkgbuild_archs,
                "requested_architectures": architectures.split(',') if architectures else []
            }

        # Read source files
        source_files = []
        for source in sources:
            if source.filename:
                content = await source.read()
                source_files.append({
                    "filename": source.filename,
                    "content": content,
                    "content_type": source.content_type or "application/octet-stream"
                })

        # Queue builds for each architecture
        queued_builds = await queue_builds_for_architectures(pkgbuild_content, pkgname, target_archs, source_files)

        if not queued_builds:
            # Get available architectures for error message
            available_archs = await get_available_architectures()
            return {
                "error": "No builds queued",
                "message": "No servers available for any of the target architectures",
                "pkgname": pkgname,
                "target_architectures": target_archs,
                "available_architectures": list(available_archs.keys()),
                "pkgbuild_architectures": pkgbuild_archs
            }

        # Return the first build ID for backward compatibility, plus info about all builds
        primary_build = queued_builds[0]

        return {
            "build_id": primary_build["build_id"],  # Primary build ID for backward compatibility
            "status": BuildStatus.QUEUED,
            "message": f"Queued {len(queued_builds)} build(s) for processing",
            "pkgname": pkgname,
            "target_architectures": target_archs,
            "pkgbuild_architectures": pkgbuild_archs,  # Show all architectures from PKGBUILD
            "builds": queued_builds,  # Information about all queued builds
            "submission_group": primary_build["submission_group"],
            "queue_status": {
                "queue_size": len(build_queue),
                "builds_queued": len(queued_builds)
            },
            "created_at": time.time()
        }

    except Exception as e:
        logger.error(f"Error submitting build: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/build/{build_id}/status")
async def get_build_status(build_id: str, format: str = Query("html")):
    """Get build status"""
    server_url = await find_build_server(build_id)

    if not server_url:
        raise HTTPException(status_code=404, detail="Build not found")

    if format == "json":
        try:
            async with http_session.get(f"{server_url}/build/{build_id}/status-api", timeout=10) as response:
                if response.status == 200:
                    build_status = await response.json()
                    build_status["server_url"] = obfuscate_server_url(server_url)
                    return build_status
                else:
                    raise HTTPException(status_code=response.status, detail="Build not found")
        except Exception as e:
            raise HTTPException(status_code=503, detail=f"Error contacting server: {e}")
    else:
        # Forward to server's HTML page
        try:
            async with http_session.get(f"{server_url}/build/{build_id}", timeout=10) as response:
                if response.status == 200:
                    content = await response.text()
                    return HTMLResponse(content=content)
                else:
                    raise HTTPException(status_code=response.status, detail="Build not found")
        except Exception as e:
            raise HTTPException(status_code=503, detail=f"Error contacting server: {e}")


@app.get("/build/{build_id}/status-api")
async def get_build_status_api(build_id: str):
    """Get build status as JSON"""
    return await get_build_status(build_id, format="json")


@app.get("/build/{build_id}/output")
async def get_build_output(build_id: str, start_index: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=1000)):
    """Get build output/logs"""
    server_url = await find_build_server(build_id)

    if not server_url:
        raise HTTPException(status_code=404, detail="Build not found")

    try:
        params = {"start_index": start_index, "limit": limit}
        async with http_session.get(f"{server_url}/build/{build_id}/output", params=params, timeout=10) as response:
            if response.status == 200:
                return await response.json()
            else:
                raise HTTPException(status_code=response.status, detail="Build output not found")
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Error contacting server: {e}")


@app.get("/build/{build_id}/stream")
async def stream_build_output(build_id: str):
    """Stream build output in real-time"""
    server_url = await find_build_server(build_id)

    if not server_url:
        raise HTTPException(status_code=404, detail="Build not found")

    try:
        async def event_generator():
            async with http_session.get(f"{server_url}/build/{build_id}/stream", timeout=None) as response:
                if response.status == 200:
                    async for line in response.content:
                        yield line.decode('utf-8')
                else:
                    yield f"data: Error: {response.status}\n\n"

        return StreamingResponse(event_generator(), media_type="text/event-stream")
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Error contacting server: {e}")


@app.get("/build/{build_id}/download/{filename}")
async def download_file(build_id: str, filename: str):
    """Download build artifact"""
    server_url = await find_build_server(build_id)

    if not server_url:
        raise HTTPException(status_code=404, detail="Build not found")

    # Retry logic for file downloads
    max_retries = 3
    for attempt in range(max_retries):
        try:
            async with http_session.get(f"{server_url}/build/{build_id}/download/{filename}", timeout=30) as response:
                if response.status == 200:
                    content = await response.read()
                    return StreamingResponse(
                        iter([content]),
                        media_type="application/octet-stream",
                        headers={"Content-Disposition": f"attachment; filename={filename}"}
                    )
                elif response.status == 404:
                    raise HTTPException(status_code=404, detail="File not found")
                else:
                    if attempt < max_retries - 1:
                        await asyncio.sleep(1)
                        continue
                    raise HTTPException(status_code=response.status, detail="Download failed")
        except Exception as e:
            if attempt < max_retries - 1:
                await asyncio.sleep(1)
                continue
            raise HTTPException(status_code=503, detail=f"Error downloading file: {e}")


@app.get("/builds/latest")
async def get_latest_builds(limit: int = Query(20, ge=1, le=100), status: Optional[str] = Query(None)):
    """Get latest builds across all servers"""
    cursor = build_database.cursor()

    if status:
        cursor.execute('''
            SELECT id, server_url, server_arch, pkgname, status, start_time, end_time, created_at
            FROM builds WHERE status = ? ORDER BY created_at DESC LIMIT ?
        ''', (status, limit))
    else:
        cursor.execute('''
            SELECT id, server_url, server_arch, pkgname, status, start_time, end_time, created_at
            FROM builds ORDER BY created_at DESC LIMIT ?
        ''', (limit,))

    builds = []
    for row in cursor.fetchall():
        start_time_str = safe_timestamp_to_datetime(row[5])
        end_time_str = safe_timestamp_to_datetime(row[6])
        created_at_str = safe_timestamp_to_datetime(row[7])

        builds.append({
            "id": row[0],
            "server_url": obfuscate_server_url(row[1]) if row[1] else "unknown",
            "server_arch": row[2],
            "pkgname": row[3],
            "status": row[4],
            "start_time": f"{start_time_str} UTC" if start_time_str else None,
            "end_time": f"{end_time_str} UTC" if end_time_str else None,
            "created_at": f"{created_at_str} UTC" if created_at_str else "unknown"
        })

    return {"builds": builds}


async def setup_http_session():
    """Setup HTTP session for server communication"""
    global http_session
    timeout = aiohttp.ClientTimeout(total=30)
    http_session = aiohttp.ClientSession(timeout=timeout)


async def cleanup_http_session():
    """Cleanup HTTP session"""
    global http_session
    if http_session:
        await http_session.close()


def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"Received signal {signum}, shutting down...")
    sys.exit(0)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="APB Farm - Arch Package Builder Farm")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host to bind to")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind to")
    parser.add_argument("--log-level", default="INFO", 
                       choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                       help="Logging level")
    parser.add_argument("--config", type=Path, help="Configuration file path")

    args = parser.parse_args()

    # Set logging level
    logging.getLogger().setLevel(getattr(logging, args.log_level))

    # Load configuration
    global config
    config = load_config(args.config)

    if not config.get("servers"):
        logger.error("No servers configured. Please create an apb.json configuration file.")
        sys.exit(1)

    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Run server
    logger.info(f"Starting APB Farm on {args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, access_log=True)


if __name__ == "__main__":
    main()
