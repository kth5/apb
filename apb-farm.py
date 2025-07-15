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
VERSION = "2025-07-15"
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8080
DEFAULT_CONFIG_PATHS = [
    Path.cwd() / "apb.json",
    Path("/etc/apb/apb.json"),
    Path.home() / ".apb" / "apb.json",
    Path.home() / ".apb-farm" / "apb.json"
]

# Classes need to be defined before global state to avoid NameError
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
        asyncio.create_task(discover_builds()),
        asyncio.create_task(handle_unavailable_servers())
    ])

    logger.info(f"APB Farm started with {len(config.get('servers', {}))} architecture groups")

    yield

    # Shutdown
    logger.info("Starting APB Farm shutdown...")

    # Signal shutdown
    shutdown_event.set()

    # Cancel background tasks with timeout
    if background_tasks:
        logger.info(f"Cancelling {len(background_tasks)} background tasks...")
        for task in background_tasks:
            if not task.done():
                task.cancel()

        # Wait for tasks to complete with timeout
        try:
            await asyncio.wait_for(
                asyncio.gather(*background_tasks, return_exceptions=True),
                timeout=10  # Give tasks 10 seconds to clean up
            )
            logger.info("Background tasks cancelled successfully")
        except asyncio.TimeoutError:
            logger.warning("Some background tasks did not complete within timeout")

    # Cleanup HTTP session
    try:
        await cleanup_http_session()
        logger.info("HTTP session cleaned up")
    except Exception as e:
        logger.warning(f"Error cleaning up HTTP session: {e}")

    # Close database
    if build_database:
        try:
            build_database.close()
            logger.info("Database connection closed")
        except Exception as e:
            logger.warning(f"Error closing database: {e}")

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
            submission_group TEXT,
            last_known_status TEXT,
            last_status_update REAL,
            server_available BOOLEAN DEFAULT 1,
            cached_response TEXT
        )
    ''')

    # Add new columns if they don't exist (for existing databases)
    try:
        conn.execute('ALTER TABLE builds ADD COLUMN submission_group TEXT')
        conn.commit()
    except sqlite3.OperationalError:
        pass

    try:
        conn.execute('ALTER TABLE builds ADD COLUMN last_known_status TEXT')
        conn.commit()
    except sqlite3.OperationalError:
        pass

    try:
        conn.execute('ALTER TABLE builds ADD COLUMN last_status_update REAL')
        conn.commit()
    except sqlite3.OperationalError:
        pass

    try:
        conn.execute('ALTER TABLE builds ADD COLUMN server_available BOOLEAN DEFAULT 1')
        conn.commit()
    except sqlite3.OperationalError:
        pass

    try:
        conn.execute('ALTER TABLE builds ADD COLUMN cached_response TEXT')
        conn.commit()
    except sqlite3.OperationalError:
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

        # Use cached successful response if still valid (increased from 60 to 90 seconds)
        if cached_info.get('_success', False) and cache_age < 90:
            return cached_info

        # Use cached failure for longer time (increased from 30 to 45 seconds)
        if not cached_info.get('_success', True) and cache_age < 45:
            return None

    # Attempt to contact server with reduced retries and faster timeouts
    max_retries = 2  # Reduced from 3 to 2
    for attempt in range(max_retries):
        try:
            timeout = aiohttp.ClientTimeout(total=10, connect=3)

            async with http_session.get(f"{server_url}/", timeout=timeout) as response:
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

        except asyncio.TimeoutError:
            if attempt < max_retries - 1:
                # Shorter backoff: wait 0.5, 1 second
                await asyncio.sleep(0.5 * (2 ** attempt))
                continue
            else:
                raise Exception("Timeout after retries")
        except Exception as e:
            if attempt < max_retries - 1:
                # Shorter backoff for other errors too
                await asyncio.sleep(0.5 * (2 ** attempt))
                continue
            else:
                # Failed contact - update health tracking
                status.last_failed_contact = current_time
                status.consecutive_failures += 1

                # Be more conservative about marking servers as degraded
                # Only mark as degraded/unavailable if we have multiple consecutive failures
                # Special handling for HTTP 502 errors - these are often temporary
                if "502" in str(e) and status.consecutive_failures < 10:
                    # For HTTP 502 errors, don't mark as degraded immediately
                    status.health = ServerHealth.UNAVAILABLE
                    logger.debug(f"Server {server_url} returning HTTP 502 (failure #{status.consecutive_failures}), likely busy processing builds")
                elif status.consecutive_failures >= 15:  # Increased from 10 to 15
                    if status.health != ServerHealth.DEGRADED:
                        status.health = ServerHealth.DEGRADED
                        logger.error(f"Server {server_url} marked as SEVERELY DEGRADED after {status.consecutive_failures} consecutive failures")
                elif status.consecutive_failures >= 5:  # Increased from 3 to 5
                    if status.health != ServerHealth.DEGRADED:
                        status.health = ServerHealth.DEGRADED
                        logger.warning(f"Server {server_url} marked as DEGRADED after {status.consecutive_failures} consecutive failures")
                else:
                    status.health = ServerHealth.UNAVAILABLE

                # Use debug level for frequent timeout errors to reduce log noise
                if "Timeout" in str(e):
                    logger.debug(f"Timeout fetching info from {server_url} (failure #{status.consecutive_failures}): {e}")
                else:
                    logger.warning(f"Error fetching info from {server_url} (failure #{status.consecutive_failures}): {e}")

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
    # Check database for server assignment
    cursor = build_database.cursor()
    cursor.execute("SELECT server_url, server_available FROM builds WHERE id = ?", (build_id,))
    result = cursor.fetchone()

    if result:
        server_url, server_available = result
        if server_url:
            # We know which server should have this build
            if server_available is False:
                logger.warning(f"Build {build_id} is on server {server_url} but server is marked unavailable")
            return server_url

    # Build not found in our database - this means it was either:
    # 1. Never submitted through this farm
    # 2. Submitted but failed before server assignment
    # 3. Database was corrupted/reset
    logger.warning(f"Build {build_id} not found in farm database - may not have been submitted through this farm")
    return None


async def get_available_architectures() -> Dict[str, List[str]]:
    """
    Get available architectures with resilient logic that uses last known
    good architecture information during temporary server failures.
    Process servers concurrently to avoid blocking.
    """
    global server_status_tracker

    available_archs = {}
    degraded_servers = []

    # Collect all server URLs for concurrent processing
    all_servers = []
    for config_arch, server_urls in config.get("servers", {}).items():
        for server_url in server_urls:
            all_servers.append((config_arch, server_url))

    # Process all servers concurrently with timeout protection
    async def check_server(config_arch: str, server_url: str):
        try:
            # Get current server info (this updates health tracking)
            server_info = await get_server_info(server_url)

            # Get server status for health tracking
            status = server_status_tracker.get(server_url)
            if not status:
                return None

            # Determine supported architecture
            supported_arch = None

            if server_info and 'supported_architecture' in server_info:
                # Use current response
                supported_arch = server_info['supported_architecture']
            elif status.last_known_architecture:
                # Fall back to last known good architecture for temporarily unavailable servers
                supported_arch = status.last_known_architecture
                if status.health == ServerHealth.UNAVAILABLE:
                    logger.debug(f"Using last known architecture {supported_arch} for temporarily unavailable server {server_url}")

            if supported_arch:
                # Log if there's a mismatch between config and actual
                if config_arch != supported_arch:
                    logger.warning(f"Server {server_url} configured for {config_arch} but supports {supported_arch}")

                return {
                    'server_url': server_url,
                    'supported_arch': supported_arch,
                    'status': status,
                    'config_arch': config_arch
                }
            else:
                # Only warn if we've never successfully contacted this server
                if not status.last_known_architecture:
                    logger.warning(f"Server {server_url} did not report supported architecture and has no known architecture")
                return None

        except Exception as e:
            logger.debug(f"Error checking server {server_url}: {e}")
            return None

    # Process all servers concurrently
    if all_servers:
        # Create actual tasks from coroutines so we can properly cancel them on timeout
        tasks = [asyncio.create_task(check_server(config_arch, server_url)) for config_arch, server_url in all_servers]

        try:
            # Set a reasonable timeout for the entire architecture discovery process
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=15  # Maximum 15 seconds for all server checks
            )
        except asyncio.TimeoutError:
            logger.warning(f"Global timeout reached while checking {len(all_servers)} servers for available architectures")
            # Cancel any remaining tasks
            for task in tasks:
                if not task.done():
                    task.cancel()
            # Wait a bit for tasks to finish cancellation
            try:
                await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=1)
            except asyncio.TimeoutError:
                pass
            results = []

        # Process results
        for result in results:
            if isinstance(result, dict) and result:
                server_url = result['server_url']
                supported_arch = result['supported_arch']
                status = result['status']

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

    # Log degraded servers for monitoring (reduce log frequency)
    if degraded_servers:
        logger.debug(f"Degraded servers (high failure rate): {degraded_servers}")

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
        server_busy_with_buildroot = queue_status.get("server_busy_with_buildroot", False)
        buildroot_recreation_count = queue_status.get("buildroot_recreation_count", 0)

        # Skip if server is at capacity
        if current_builds >= max_concurrent:
            continue

        # Calculate load score (lower is better)
        score = current_builds + queued_builds

        # Add penalty for degraded servers (prefer healthy servers)
        if status and status.health == ServerHealth.DEGRADED:
            score += 5  # Penalty to prefer healthy servers

        # Add significant penalty for servers doing buildroot recreation
        # This encourages the farm to use other servers while buildroot recreation is happening
        if server_busy_with_buildroot:
            score += 20  # Large penalty to prefer servers not doing buildroot recreation
            logger.debug(f"Server {server_url} is busy with buildroot recreation ({buildroot_recreation_count} builds), adding penalty")

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

    logger.info(f"Starting build submission for package '{pkgname}' with target architectures: {target_archs}")

    # Get actual available architectures from servers
    available_archs = await get_available_architectures()
    logger.info(f"Available server architectures: {list(available_archs.keys())}")

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
                    logger.warning(f"No available servers for 'any' architecture")
            else:
                skipped_archs.append(arch)
                logger.warning(f"No server architectures available for 'any' architecture")
        else:
            # Check if this specific architecture has available servers
            if arch in available_archs and available_archs[arch]:
                buildable_archs.append(arch)
                logger.info(f"Architecture '{arch}' has {len(available_archs[arch])} available server(s)")
            else:
                skipped_archs.append(arch)
                logger.warning(f"No available servers for architecture '{arch}'")

    # Remove duplicates while preserving order
    buildable_archs = list(dict.fromkeys(buildable_archs))

    # Log architecture scheduling decisions
    if buildable_archs:
        logger.info(f"Queuing builds for architectures: {buildable_archs}")
    if skipped_archs:
        logger.warning(f"Skipping architectures (no available servers): {skipped_archs}")

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

        logger.info(f"Created build {build_id} for architecture '{arch}' (package: {pkgname})")

    logger.info(f"Submission complete: {len(queued_builds)} build(s) queued for package '{pkgname}' with submission group {submission_group}")
    return queued_builds


async def process_build_queue():
    """Background task to process build queue"""
    while not shutdown_event.is_set():
        try:
            if build_queue:
                build_info = build_queue.pop(0)
                build_id = build_info["build_id"]
                target_arch = build_info["target_architectures"][0]  # Now each build has exactly one architecture
                retry_count = build_info.get("retry_count", 0)
                max_retries = 3

                # Get actual available architectures from servers
                available_archs = await get_available_architectures()

                # Check if we have servers for this architecture
                if target_arch not in available_archs or not available_archs[target_arch]:
                    logger.error(f"No available servers for architecture {target_arch}, build {build_id} failed")
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
                    result = await forward_build_to_server(build_info, server_url)

                    if result is True:
                        # Successfully submitted
                        logger.info(f"Build {build_id} successfully queued on {server_url}")

                    elif result is False:
                        # Server rejected the build - don't retry, mark as failed
                        logger.error(f"Build {build_id} permanently rejected by {server_url}")

                    elif result is None:
                        # Temporary error (timeout, network) - retry with exponential backoff
                        if retry_count < max_retries:
                            retry_count += 1
                            build_info["retry_count"] = retry_count
                            delay = min(30 * (2 ** (retry_count - 1)), 300)  # Cap at 5 minutes

                            logger.warning(f"Build {build_id} submission failed (retry {retry_count}/{max_retries}), "
                                         f"requeueing with {delay}s delay")

                            # Wait and requeue
                            await asyncio.sleep(delay)
                            build_queue.append(build_info)
                        else:
                            # Max retries reached - mark as failed
                            logger.error(f"Build {build_id} failed after {max_retries} retry attempts")
                            cursor = build_database.cursor()
                            cursor.execute('''
                                UPDATE builds SET status = ?, end_time = ?
                                WHERE id = ?
                            ''', (BuildStatus.FAILED, time.time(), build_id))
                            build_database.commit()

                else:
                    # No suitable server available
                    if retry_count < max_retries:
                        retry_count += 1
                        build_info["retry_count"] = retry_count
                        delay = min(30 * retry_count, 180)  # Cap at 3 minutes for server availability

                        logger.warning(f"No available server for architecture {target_arch}, "
                                     f"requeueing build {build_id} (attempt {retry_count}/{max_retries + 1}) "
                                     f"with {delay}s delay")

                        await asyncio.sleep(delay)
                        build_queue.append(build_info)
                    else:
                        logger.error(f"No servers available for architecture {target_arch} after {max_retries + 1} attempts, "
                                   f"marking build {build_id} as failed")
                        cursor = build_database.cursor()
                        cursor.execute('''
                            UPDATE builds SET status = ?, end_time = ?
                            WHERE id = ?
                        ''', (BuildStatus.FAILED, time.time(), build_id))
                        build_database.commit()

            await asyncio.sleep(5)
        except Exception as e:
            logger.error(f"Error in build queue processing: {e}")
            await asyncio.sleep(10)


async def forward_build_to_server(build_info: Dict, server_url: str):
    """Forward a build to a specific server"""
    build_id = build_info["build_id"]

    try:
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

        # Use longer timeout for build submissions (increased from 30 to 60 seconds)
        timeout = aiohttp.ClientTimeout(total=60, connect=10)

        logger.info(f"Forwarding build {build_id} to {server_url}")

        async with http_session.post(f"{server_url}/build", data=data, timeout=timeout) as response:
            if response.status == 200:
                # Successful submission - update database
                cursor = build_database.cursor()
                cursor.execute('''
                    UPDATE builds SET server_url = ?, status = ?, start_time = ?
                    WHERE id = ?
                ''', (server_url, BuildStatus.BUILDING, time.time(), build_id))
                build_database.commit()

                logger.info(f"Build {build_id} successfully forwarded to {server_url}")
                return True

            else:
                # Server returned error - log details and mark as failed
                try:
                    error_text = await response.text()
                    logger.error(f"Server {server_url} rejected build {build_id} with HTTP {response.status}: {error_text}")
                except:
                    logger.error(f"Server {server_url} rejected build {build_id} with HTTP {response.status}")

                # Update database to mark build as failed
                cursor = build_database.cursor()
                cursor.execute('''
                    UPDATE builds SET status = ?, end_time = ?
                    WHERE id = ?
                ''', (BuildStatus.FAILED, time.time(), build_id))
                build_database.commit()

                return False

    except asyncio.TimeoutError:
        logger.error(f"Timeout forwarding build {build_id} to {server_url}")
        # Mark server as temporarily unavailable but don't fail the build immediately
        # Instead, requeue for retry with another server
        return None

    except Exception as e:
        logger.error(f"Error forwarding build {build_id} to {server_url}: {e}")
        # Network or other error - requeue for retry
        return None


async def update_single_build_status(build_id: str, server_url: str):
    """Update status for a single build with proper error isolation"""
    try:
        # Use shorter timeout specifically for status checks to avoid blocking
        timeout = aiohttp.ClientTimeout(total=10, connect=3)

        async with http_session.get(f"{server_url}/build/{build_id}/status-api", timeout=timeout) as response:
            if response.status == 200:
                build_status = await response.json()
                status = build_status.get("status", BuildStatus.QUEUED)
                current_time = time.time()

                # Update database with comprehensive status information
                cursor = build_database.cursor()
                cursor.execute('''
                    UPDATE builds SET
                        status = ?,
                        end_time = ?,
                        last_known_status = ?,
                        last_status_update = ?,
                        server_available = 1,
                        cached_response = ?
                    WHERE id = ?
                ''', (status,
                         current_time if status in [BuildStatus.COMPLETED, BuildStatus.FAILED] else None,
                         status,
                         current_time,
                         json.dumps(build_status),
                         build_id))
                build_database.commit()
                logger.debug(f"Updated status for build {build_id}: {status}")
            else:
                logger.warning(f"Server {server_url} returned HTTP {response.status} for build {build_id}")
                # Update last status check time
                cursor = build_database.cursor()
                cursor.execute('''
                    UPDATE builds SET
                        last_status_update = ?
                    WHERE id = ?
                ''', (time.time(), build_id))
                build_database.commit()
    except asyncio.TimeoutError:
        logger.warning(f"Timeout updating status for build {build_id} on {server_url}")
        cursor = build_database.cursor()
        cursor.execute('''
            UPDATE builds SET
                last_status_update = ?
            WHERE id = ?
        ''', (time.time(), build_id))
        build_database.commit()
    except Exception as e:
        logger.warning(f"Error updating status for build {build_id}: {e}")
        cursor = build_database.cursor()
        cursor.execute('''
            UPDATE builds SET
                last_status_update = ?
            WHERE id = ?
        ''', (time.time(), build_id))
        build_database.commit()


async def update_build_status():
    """Background task to update build status with concurrent processing"""
    while not shutdown_event.is_set():
        try:
            cursor = build_database.cursor()
            cursor.execute('''
                SELECT id, server_url FROM builds
                WHERE status IN (?, ?) AND server_url IS NOT NULL
            ''', (BuildStatus.QUEUED, BuildStatus.BUILDING))

            builds_to_update = cursor.fetchall()

            if builds_to_update:
                logger.debug(f"Updating status for {len(builds_to_update)} builds")

                # Process all builds concurrently with timeout protection
                # Create actual tasks from coroutines so we can properly cancel them on timeout
                tasks = [
                    asyncio.create_task(update_single_build_status(build_id, server_url))
                    for build_id, server_url in builds_to_update
                ]

                # Use asyncio.gather with return_exceptions to prevent one failure from blocking others
                # Also add a global timeout to prevent the entire batch from hanging
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*tasks, return_exceptions=True),
                        timeout=30  # Maximum 30 seconds for all status updates
                    )
                except asyncio.TimeoutError:
                    logger.warning(f"Global timeout reached while updating {len(builds_to_update)} build statuses")
                    # Cancel any remaining tasks
                    for task in tasks:
                        if not task.done():
                            task.cancel()
                    # Wait a bit for tasks to finish cancellation
                    try:
                        await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=1)
                    except asyncio.TimeoutError:
                        pass

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


async def handle_unavailable_servers():
    """Background task to monitor and handle builds on unavailable servers"""
    while not shutdown_event.is_set():
        try:
            current_time = time.time()

            # Check for builds on servers that have become unavailable
            cursor = build_database.cursor()
            cursor.execute('''
                SELECT id, server_url, server_arch, pkgname, status, start_time, last_status_update
                FROM builds
                WHERE status IN (?, ?) AND server_url IS NOT NULL
            ''', (BuildStatus.QUEUED, BuildStatus.BUILDING))

            active_builds_on_servers = cursor.fetchall()

            for build_id, server_url, server_arch, pkgname, status, start_time, last_status_update in active_builds_on_servers:
                # Check if this server is marked as unavailable
                server_status = server_status_tracker.get(server_url)

                if server_status and server_status.health in [ServerHealth.UNAVAILABLE, ServerHealth.MISCONFIGURED]:
                    # Server is unavailable - check how long the build has been without status update
                    time_since_last_update = current_time - (last_status_update or start_time or current_time)

                    # If no status update for more than 10 minutes, mark as potentially lost
                    if time_since_last_update > 600:  # 10 minutes
                        logger.warning(f"Build {build_id} on unavailable server {server_url} - no status update for {time_since_last_update:.0f} seconds")

                        # Try to get one more status update
                        try:
                            async with http_session.get(f"{server_url}/build/{build_id}/status-api", timeout=10) as response:
                                if response.status == 200:
                                    build_status = await response.json()
                                    # Update database with latest status
                                    cursor.execute('''
                                        UPDATE builds SET
                                            last_known_status = ?,
                                            last_status_update = ?,
                                            server_available = 1,
                                            cached_response = ?
                                        WHERE id = ?
                                    ''', (build_status.get('status', status), current_time,
                                         json.dumps(build_status), build_id))
                                    build_database.commit()
                                    logger.info(f"Successfully updated status for build {build_id} on server {server_url}")
                                    continue
                        except Exception as e:
                            logger.error(f"Failed to get status for build {build_id} on server {server_url}: {e}")

                        # Mark server as unavailable for this build
                        cursor.execute('''
                            UPDATE builds SET
                                server_available = 0,
                                last_status_update = ?
                            WHERE id = ?
                        ''', (current_time, build_id))
                        build_database.commit()

                        # If server has been unavailable for more than 30 minutes, consider the build lost
                        if time_since_last_update > 1800:  # 30 minutes
                            logger.error(f"Marking build {build_id} as failed - server {server_url} unavailable for {time_since_last_update:.0f} seconds")
                            cursor.execute('''
                                UPDATE builds SET
                                    status = ?,
                                    end_time = ?,
                                    last_known_status = 'failed_server_unavailable'
                                WHERE id = ?
                            ''', (BuildStatus.FAILED, current_time, build_id))
                            build_database.commit()

            await asyncio.sleep(120)  # Check every 2 minutes
        except Exception as e:
            logger.error(f"Error in handle_unavailable_servers: {e}")
            await asyncio.sleep(120)


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
                        current_builds = running_builds_by_server.get(server_url, [])
                        servers.append({
                            "url": obfuscate_server_url(server_url),
                            "arch": f"{config_arch} (checking...)",
                            "status": "initializing",
                            "info": None,
                            "current_builds": current_builds,
                            "real_server_url": server_url
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

    # Get currently running builds for all servers
    cursor = build_database.cursor()
    cursor.execute('''
        SELECT id, server_url, pkgname, start_time, created_at
        FROM builds
        WHERE status = ? AND server_url IS NOT NULL
        ORDER BY start_time DESC
    ''', (BuildStatus.BUILDING,))

    running_builds_by_server = {}
    for build_id, server_url, pkgname, start_time, created_at in cursor.fetchall():
        if server_url not in running_builds_by_server:
            running_builds_by_server[server_url] = []
        running_builds_by_server[server_url].append({
            "id": build_id,
            "pkgname": pkgname,
            "start_time": safe_timestamp_to_datetime(start_time),
            "created_at": safe_timestamp_to_datetime(created_at)
        })

    for arch, server_urls in available_archs.items():
        servers_by_arch[arch] = []
        for server_url in server_urls:
            server_info = await get_server_info(server_url)
            # Get running builds for this server
            current_builds = running_builds_by_server.get(server_url, [])
            servers_by_arch[arch].append({
                "url": obfuscate_server_url(server_url),
                "status": "online" if server_info else "offline",
                "info": server_info,
                "current_builds": current_builds,
                "real_server_url": server_url  # Keep for matching builds
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
                    # Get running builds for misconfigured server too
                    current_builds = running_builds_by_server.get(server_url, [])
                    servers_by_arch["misconfigured"].append({
                        "url": obfuscate_server_url(server_url),
                        "status": f"misconfigured ({status.consecutive_failures} failures)",
                        "info": None,
                        "current_builds": current_builds,
                        "real_server_url": server_url
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
            .build {{ margin: 5px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; word-break: break-all; }}
            .completed {{ background-color: #d4edda; }}
            .failed {{ background-color: #f8d7da; }}
            .building {{ background-color: #fff3cd; }}
            .queued {{ background-color: #d1ecf1; }}
            .cancelled {{ background-color: #e2e3e5; }}
            .build a {{ color: #007bff; text-decoration: none; margin-right: 10px; }}
            .build a:hover {{ text-decoration: underline; }}
            .build-id {{ font-family: 'Courier New', monospace; font-size: 0.9em; color: #666; }}
            .pagination {{ text-align: center; margin: 20px 0; }}
            .pagination a {{ margin: 0 5px; padding: 5px 10px; text-decoration: none; border: 1px solid #ddd; }}
            .running-builds {{ margin-top: 8px; padding: 8px; background-color: #f8f9fa; border-radius: 3px; border-left: 3px solid #007bff; }}
            .running-builds ul {{ margin: 5px 0 0 0; padding-left: 20px; }}
            .running-builds li {{ margin: 2px 0; font-size: 0.9em; }}
            .running-builds a {{ color: #007bff; text-decoration: none; }}
            .running-builds a:hover {{ text-decoration: underline; }}
            .running-builds small {{ color: #666; margin-left: 5px; }}
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
            buildroot_info = ""
            if server["info"]:
                queue_status = server["info"].get("queue_status", {})
                queue_info = f" - Builds: {queue_status.get('current_builds_count', 0)}, Queued: {queue_status.get('queued_builds', 0)}"

                # Add buildroot recreation information
                if queue_status.get("server_busy_with_buildroot", False):
                    buildroot_count = queue_status.get("buildroot_recreation_count", 0)
                    buildroot_info = f" - <span style='color: #ff8c00; font-weight: bold;'>🔨 Buildroot Recreation ({buildroot_count})</span>"

            # Show currently running builds
            current_builds_html = ""
            if server.get("current_builds"):
                current_builds_html = "<div class='running-builds'><strong>Currently Building:</strong><ul>"
                for build in server["current_builds"][:3]:  # Show max 3 builds to avoid clutter
                    start_time = build["start_time"] or "unknown"
                    current_builds_html += f"""
                        <li>
                            <a href="/build/{build['id']}/status" target="_blank">{build['pkgname']}</a>
                            <small>(started: {start_time})</small>
                        </li>
                    """
                if len(server["current_builds"]) > 3:
                    current_builds_html += f"<li><em>... and {len(server['current_builds']) - 3} more</em></li>"
                current_builds_html += "</ul></div>"

            html += f"""
                <div class="server {status_class}">
                    <strong>{server['url']}</strong> ({server['status']}){queue_info}{buildroot_info}
                    {current_builds_html}
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
                <strong>{build['pkgname']}</strong> - {build['status']} on {build['server_url']} ({build['server_arch']})
                <br>
                <span class="build-id">Build ID: {build['id']}</span>
                <br>
                <small>Created: {build['created_at']}</small>
                <br>
                <small>
                    <a href="/build/{build['id']}/status" target="_blank">📋 View Details & Logs</a>
                    {' | <a href="/build/{build["id"]}/output" target="_blank">📜 Raw Output</a>' if build['status'] in ['building', 'completed', 'failed'] else ''}
                </small>
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
    # First check our database for build information
    cursor = build_database.cursor()
    cursor.execute('''
        SELECT server_url, server_arch, pkgname, status, last_known_status,
               server_available, cached_response, last_status_update, created_at
        FROM builds WHERE id = ?
    ''', (build_id,))
    result = cursor.fetchone()

    if not result:
        # Build not found in our database
        error_detail = {
            "error": "Build not found",
            "detail": f"Build {build_id} was not found in the farm database. "
                     "This build may not have been submitted through this farm, "
                     "or the submission may have failed before being recorded.",
            "build_id": build_id
        }
        if format == "json":
            raise HTTPException(status_code=404, detail=error_detail)
        else:
            return HTMLResponse(f"""
            <html>
            <head><title>Build Not Found</title></head>
            <body>
                <h1>Build Not Found</h1>
                <p><strong>Build ID:</strong> {build_id}</p>
                <p>{error_detail['detail']}</p>
                <p>Please check that you're using the correct build ID and that the build was submitted to this farm.</p>
            </body>
            </html>
            """, status_code=404)

    server_url, server_arch, pkgname, status, last_known_status, server_available, cached_response, last_status_update, created_at = result

    # If we don't have a server_url, the build failed during submission
    if not server_url:
        error_detail = {
            "error": "Build submission failed",
            "detail": f"Build {build_id} failed during submission and was never assigned to a server. "
                     f"Current status: {status}",
            "build_id": build_id,
            "status": status,
            "created_at": created_at
        }
        if format == "json":
            raise HTTPException(status_code=404, detail=error_detail)
        else:
            return HTMLResponse(f"""
            <html>
            <head><title>Build Submission Failed - {pkgname}</title></head>
            <body>
                <h1>Build Submission Failed: {pkgname}</h1>
                <div style="background-color: #f8d7da; padding: 10px; border: 1px solid #f5c6cb; margin: 10px 0;">
                    <strong>❌ Build Submission Failed</strong><br>
                    This build failed during submission and was never assigned to a server.
                </div>
                <p><strong>Build ID:</strong> {build_id}</p>
                <p><strong>Status:</strong> {status}</p>
                <p><strong>Architecture:</strong> {server_arch or 'unknown'}</p>
                <p><strong>Created:</strong> {datetime.fromtimestamp(created_at).strftime('%Y-%m-%d %H:%M:%S') if created_at else 'unknown'}</p>
            </body>
            </html>
            """, status_code=404)

    # We have a server assignment - check if server is available
    if server_available is False:
        # Server is marked as unavailable, use cached data if available
        if cached_response:
            try:
                build_status = json.loads(cached_response)
                build_status["server_unavailable"] = True
                build_status["last_status_update"] = last_status_update
                build_status["server_url"] = obfuscate_server_url(server_url)
                build_status["server_arch"] = server_arch  # Add architecture from farm database

                if format == "json":
                    return build_status
                else:
                    return HTMLResponse(f"""
                    <html>
                    <head><title>Build Status (Server Unavailable) - {pkgname}</title></head>
                    <body>
                        <h1>Build Status: {pkgname}</h1>
                        <div style="background-color: #fff3cd; padding: 10px; border: 1px solid #ffeaa7; margin: 10px 0;">
                            <strong>⚠️ Server Currently Unavailable</strong><br>
                            The build server is currently unavailable. Showing last known status.
                        </div>
                        <p><strong>Build ID:</strong> {build_id}</p>
                        <p><strong>Status:</strong> {build_status.get('status', 'unknown')}</p>
                        <p><strong>Last Update:</strong> {datetime.fromtimestamp(last_status_update).strftime('%Y-%m-%d %H:%M:%S') if last_status_update else 'unknown'}</p>
                        <p><strong>Server:</strong> {obfuscate_server_url(server_url)}</p>
                        <p><em>This information may be outdated due to server unavailability.</em></p>
                    </body>
                    </html>
                    """)
            except json.JSONDecodeError:
                pass

        # No cached data and server unavailable
        error_detail = {
            "error": "Server unavailable",
            "detail": f"Build {build_id} is assigned to server {obfuscate_server_url(server_url)} "
                     "but the server is currently unavailable and no cached status is available.",
            "build_id": build_id,
            "server_url": obfuscate_server_url(server_url),
            "last_known_status": last_known_status or status
        }
        if format == "json":
            raise HTTPException(status_code=503, detail=error_detail)
        else:
            return HTMLResponse(f"""
            <html>
            <head><title>Server Unavailable - {pkgname}</title></head>
            <body>
                <h1>Server Unavailable: {pkgname}</h1>
                <div style="background-color: #f8d7da; padding: 10px; border: 1px solid #f5c6cb; margin: 10px 0;">
                    <strong>❌ Server Unavailable</strong><br>
                    The server handling this build is currently unavailable.
                </div>
                <p><strong>Build ID:</strong> {build_id}</p>
                <p><strong>Server:</strong> {obfuscate_server_url(server_url)}</p>
                <p><strong>Last Known Status:</strong> {last_known_status or status}</p>
                <p>Please try again later when the server recovers.</p>
            </body>
            </html>
            """, status_code=503)

    # Server should be available - try to contact it
    if format == "json":
        try:
            async with http_session.get(f"{server_url}/build/{build_id}/status-api", timeout=10) as response:
                if response.status == 200:
                    build_status = await response.json()
                    build_status["server_url"] = obfuscate_server_url(server_url)
                    if server_arch:
                        build_status["server_arch"] = server_arch  # Add architecture from farm database
                    else:
                        logger.warning(f"server_arch is None/empty for build {build_id}")

                    # Update our cache with the latest status
                    cursor = build_database.cursor()
                    cursor.execute('''
                        UPDATE builds SET
                            last_known_status = ?,
                            last_status_update = ?,
                            server_available = 1,
                            cached_response = ?
                        WHERE id = ?
                    ''', (build_status.get('status', 'unknown'), time.time(),
                         json.dumps(build_status), build_id))
                    build_database.commit()

                    return build_status
                else:
                    raise HTTPException(status_code=response.status, detail="Build not found")
        except Exception as e:
            # Server is unavailable, try to return cached response
            cursor = build_database.cursor()
            cursor.execute('''
                SELECT cached_response, last_status_update, server_arch, pkgname
                FROM builds WHERE id = ?
            ''', (build_id,))
            result = cursor.fetchone()

            if result and result[0]:  # cached_response exists
                try:
                    build_status = json.loads(result[0])
                    build_status["server_unavailable"] = True
                    build_status["last_status_update"] = result[1]
                    build_status["server_url"] = obfuscate_server_url(server_url)
                    build_status["server_arch"] = result[2]  # Add architecture from database result
                    build_status["error_message"] = f"Server unavailable: {str(e)}"
                    return build_status
                except json.JSONDecodeError:
                    pass

            raise HTTPException(status_code=503, detail=f"Server unavailable: {str(e)}")
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
            # Server is unavailable, try to return cached response as HTML
            cursor = build_database.cursor()
            cursor.execute('''
                SELECT cached_response, last_status_update, server_arch, pkgname
                FROM builds WHERE id = ?
            ''', (build_id,))
            result = cursor.fetchone()

            if result and result[0]:  # cached_response exists
                try:
                    build_status = json.loads(result[0])
                    pkgname = result[3] or 'unknown'
                    last_update = result[1]

                    return HTMLResponse(f"""
                    <html>
                    <head><title>Build Status (Server Unavailable) - {pkgname}</title></head>
                    <body>
                        <h1>Build Status: {pkgname}</h1>
                        <div style="background-color: #fff3cd; padding: 10px; border: 1px solid #ffeaa7; margin: 10px 0;">
                            <strong>⚠️ Server Currently Unavailable</strong><br>
                            The build server is currently unavailable. Showing last known status.
                        </div>
                        <p><strong>Build ID:</strong> {build_id}</p>
                        <p><strong>Status:</strong> {build_status.get('status', 'unknown')}</p>
                        <p><strong>Last Update:</strong> {datetime.fromtimestamp(last_update).strftime('%Y-%m-%d %H:%M:%S') if last_update else 'unknown'}</p>
                        <p><strong>Server:</strong> {obfuscate_server_url(server_url)}</p>
                        <p><em>This information may be outdated due to server unavailability.</em></p>
                        <p><strong>Error:</strong> {str(e)}</p>
                    </body>
                    </html>
                    """)
                except json.JSONDecodeError:
                    pass

            raise HTTPException(status_code=503, detail=f"Server unavailable: {str(e)}")


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
        # Check if we have build information in database
        cursor = build_database.cursor()
        cursor.execute('''
            SELECT server_url, server_available, pkgname
            FROM builds WHERE id = ?
        ''', (build_id,))
        result = cursor.fetchone()

        if result:
            server_url, server_available, pkgname = result
            if not server_available:
                raise HTTPException(
                    status_code=503,
                    detail={
                        "error": "Server unavailable",
                        "message": f"The server handling build {build_id} is currently unavailable",
                        "pkgname": pkgname,
                        "suggestion": "Please try again later when the server recovers"
                    }
                )

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
        if "503" in str(e) or "502" in str(e) or "Connection" in str(e):
            # Server unavailable
            cursor = build_database.cursor()
            cursor.execute('''
                SELECT pkgname FROM builds WHERE id = ?
            ''', (build_id,))
            result = cursor.fetchone()
            pkgname = result[0] if result else "unknown"

            raise HTTPException(
                status_code=503,
                detail={
                    "error": "Server unavailable",
                    "message": f"The server handling build {build_id} is currently unavailable",
                    "pkgname": pkgname,
                    "suggestion": "Please try again later when the server recovers"
                }
            )
        else:
            raise HTTPException(status_code=503, detail=f"Error contacting server: {e}")


@app.get("/build/{build_id}/download/{filename}")
async def download_file(build_id: str, filename: str):
    """Download build artifact"""
    server_url = await find_build_server(build_id)

    if not server_url:
        # Check if we have build information in database
        cursor = build_database.cursor()
        cursor.execute('''
            SELECT server_url, server_available, pkgname
            FROM builds WHERE id = ?
        ''', (build_id,))
        result = cursor.fetchone()

        if result:
            server_url, server_available, pkgname = result
            if not server_available:
                raise HTTPException(
                    status_code=503,
                    detail={
                        "error": "Server unavailable",
                        "message": f"The server handling build {build_id} is currently unavailable",
                        "pkgname": pkgname,
                        "suggestion": "Please try again later when the server recovers"
                    }
                )

        raise HTTPException(status_code=404, detail="Build not found")

    # Retry logic for file downloads
    max_retries = 3
    for attempt in range(max_retries):
        try:
            async with http_session.get(f"{server_url}/build/{build_id}/download/{filename}", timeout=300) as response:
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
            if "503" in str(e) or "502" in str(e) or "Connection" in str(e):
                # Server unavailable
                cursor = build_database.cursor()
                cursor.execute('''
                    SELECT pkgname FROM builds WHERE id = ?
                ''', (build_id,))
                result = cursor.fetchone()
                pkgname = result[0] if result else "unknown"

                raise HTTPException(
                    status_code=503,
                    detail={
                        "error": "Server unavailable",
                        "message": f"The server handling build {build_id} is currently unavailable",
                        "pkgname": pkgname,
                        "suggestion": "Please try again later when the server recovers"
                    }
                )
            elif attempt < max_retries - 1:
                await asyncio.sleep(1)
                continue
            else:
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
    """Setup HTTP session with optimized timeouts and connection pooling for farm responsiveness"""
    global http_session

    # Optimize connector for farm use case - many short requests to potentially slow servers
    connector = aiohttp.TCPConnector(
        limit=50,  # Reduced total connection pool size to prevent resource exhaustion
        limit_per_host=5,  # Reduced per-host limit to prevent single slow server from hogging connections
        ttl_dns_cache=300,  # DNS cache TTL
        use_dns_cache=True,
        keepalive_timeout=15,  # Reduced keepalive to free up connections faster
        enable_cleanup_closed=True
    )

    # Use conservative default timeout - individual operations will override as needed
    timeout = aiohttp.ClientTimeout(
        total=30,  # Reduced default timeout to prevent blocking
        connect=5,  # Faster connection timeout
        sock_read=15   # Faster socket read timeout
    )

    http_session = aiohttp.ClientSession(
        timeout=timeout,
        connector=connector,
        trust_env=True
    )


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
