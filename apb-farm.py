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
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
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
    from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request, Query, Depends
    from fastapi.responses import JSONResponse, StreamingResponse, FileResponse, HTMLResponse
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from pydantic import BaseModel, Field
    import uvicorn
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Install with: pip install fastapi uvicorn aiohttp")
    sys.exit(1)

# Version and constants
VERSION = "2025-07-16"
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8080
DEFAULT_CONFIG_PATHS = [
    Path.cwd() / "apb.json",
    Path("/etc/apb/apb.json"),
    Path.home() / ".apb" / "apb.json",
    Path.home() / ".apb-farm" / "apb.json"
]

# Authentication constants
TOKEN_EXPIRY_DAYS = 10
ADMIN_ROLE = "admin"
USER_ROLE = "user"
GUEST_ROLE = "guest"

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


class UserRole(Enum):
    ADMIN = "admin"
    USER = "user"
    GUEST = "guest"


@dataclass
class ServerStatus:
    url: str
    last_successful_contact: Optional[float] = None
    last_failed_contact: Optional[float] = None
    consecutive_failures: int = 0
    last_known_architecture: Optional[str] = None
    health: ServerHealth = ServerHealth.HEALTHY
    last_response: Optional[Dict] = None


@dataclass
class User:
    id: int
    username: str
    role: UserRole
    created_at: float
    last_login: Optional[float] = None
    email: Optional[str] = None


# Pydantic models for API requests/responses
class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=100)


class LoginResponse(BaseModel):
    token: str
    user: dict
    expires_in_days: int = 10


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=100)
    role: str = Field(default="user", pattern="^(user|admin)$")
    email: Optional[str] = Field(None, max_length=255)


class ChangeRoleRequest(BaseModel):
    role: str = Field(..., pattern="^(user|admin)$")


class UserResponse(BaseModel):
    id: int
    username: str
    role: str
    created_at: float
    last_login: Optional[float]
    email: Optional[str]


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=8, max_length=100)
    new_password: str = Field(..., min_length=8, max_length=100)
    confirm_password: str = Field(..., min_length=8, max_length=100)


class UpdateEmailRequest(BaseModel):
    email: Optional[str] = Field(None, max_length=255)


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

# Authentication manager instance
auth_manager = None


class AuthManager:
    """Manages authentication and authorization for APB Farm"""

    def __init__(self, db_connection: sqlite3.Connection):
        self.db = db_connection
        self.security = HTTPBearer(auto_error=False)
        self._init_auth_tables()
        self._create_default_admin()

    def _validate_email(self, email: str) -> bool:
        """Validate email format"""
        if not email:
            return True  # Email is optional

        # Simple email validation regex
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_pattern, email) is not None

    def _init_auth_tables(self):
        """Initialize authentication tables"""
        try:
            # Users table
            self.db.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',
                    created_at REAL NOT NULL,
                    last_login REAL,
                    is_active BOOLEAN DEFAULT 1,
                    email TEXT
                )
            ''')

            # Add email column if it doesn't exist (for existing databases)
            try:
                self.db.execute('ALTER TABLE users ADD COLUMN email TEXT')
                self.db.commit()
            except sqlite3.OperationalError:
                pass  # Column already exists

            # Tokens table
            self.db.execute('''
                CREATE TABLE IF NOT EXISTS tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_hash TEXT UNIQUE NOT NULL,
                    user_id INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    last_used_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')

            # Add user_id column to builds table if it doesn't exist
            try:
                self.db.execute('ALTER TABLE builds ADD COLUMN user_id INTEGER')
                self.db.commit()
            except sqlite3.OperationalError:
                pass  # Column already exists

            # Create indexes for performance
            self.db.execute('CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens(token_hash)')
            self.db.execute('CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens(user_id)')
            self.db.execute('CREATE INDEX IF NOT EXISTS idx_builds_user ON builds(user_id)')

            self.db.commit()
            logger.info("Authentication tables initialized")

        except Exception as e:
            logger.error(f"Failed to initialize auth tables: {e}")
            raise

    def _create_default_admin(self):
        """Create default admin user if none exists"""
        cursor = self.db.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = ?", (ADMIN_ROLE,))
        admin_count = cursor.fetchone()[0]

        if admin_count == 0:
            # Create default admin user
            default_password = "admin123"  # User should change this immediately
            admin_user = self.create_user("admin", default_password, UserRole.ADMIN)
            logger.warning(f"Created default admin user 'admin' with password '{default_password}' - CHANGE THIS IMMEDIATELY!")
            return admin_user
        return None

    def _hash_password(self, password: str) -> str:
        """Hash password using PBKDF2 with salt"""
        salt = secrets.token_hex(32)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}:{password_hash.hex()}"

    def _verify_password(self, password: str, stored_hash: str) -> bool:
        """Verify password against stored hash"""
        try:
            salt, hash_hex = stored_hash.split(':', 1)
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return secrets.compare_digest(password_hash.hex(), hash_hex)
        except Exception:
            return False

    def _generate_token(self) -> str:
        """Generate a secure random token"""
        return secrets.token_urlsafe(32)

    def _hash_token(self, token: str) -> str:
        """Hash token for storage"""
        return hashlib.sha256(token.encode()).hexdigest()

    def create_user(self, username: str, password: str, role: UserRole = UserRole.USER, email: Optional[str] = None) -> User:
        """Create a new user"""
        if len(username) < 3:
            raise ValueError("Username must be at least 3 characters")
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        if email and not self._validate_email(email):
            raise ValueError("Invalid email format")

        password_hash = self._hash_password(password)
        current_time = time.time()

        try:
            cursor = self.db.cursor()
            cursor.execute('''
                INSERT INTO users (username, password_hash, role, created_at, email)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, password_hash, role.value, current_time, email))

            user_id = cursor.lastrowid
            self.db.commit()

            logger.info(f"Created user '{username}' with role '{role.value}' and email '{email or 'none'}'")
            return User(
                id=user_id,
                username=username,
                role=role,
                created_at=current_time,
                email=email
            )

        except sqlite3.IntegrityError:
            raise ValueError(f"Username '{username}' already exists")
        except Exception as e:
            logger.error(f"Failed to create user: {e}")
            raise

    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user with username and password"""
        cursor = self.db.cursor()
        cursor.execute('''
            SELECT id, username, password_hash, role, created_at, last_login, email
            FROM users WHERE username = ? AND is_active = 1
        ''', (username,))

        row = cursor.fetchone()
        if not row:
            return None

        user_id, username, stored_hash, role, created_at, last_login, email = row

        if not self._verify_password(password, stored_hash):
            return None

        # Update last login
        current_time = time.time()
        cursor.execute('UPDATE users SET last_login = ? WHERE id = ?', (current_time, user_id))
        self.db.commit()

        return User(
            id=user_id,
            username=username,
            role=UserRole(role),
            created_at=created_at,
            last_login=current_time,
            email=email
        )

    def create_token(self, user: User) -> str:
        """Create a new authentication token for user"""
        token = self._generate_token()
        token_hash = self._hash_token(token)
        current_time = time.time()
        expires_at = current_time + (TOKEN_EXPIRY_DAYS * 24 * 3600)

        cursor = self.db.cursor()
        cursor.execute('''
            INSERT INTO tokens (token_hash, user_id, created_at, last_used_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (token_hash, user.id, current_time, current_time, expires_at))
        self.db.commit()

        logger.info(f"Created token for user '{user.username}'")
        return token

    def validate_token(self, token: str) -> Optional[User]:
        """Validate token and return associated user if valid"""
        if not token:
            return None

        token_hash = self._hash_token(token)
        current_time = time.time()

        cursor = self.db.cursor()
        cursor.execute('''
            SELECT t.user_id, t.expires_at, u.username, u.role, u.created_at, u.last_login
            FROM tokens t
            JOIN users u ON t.user_id = u.id
            WHERE t.token_hash = ? AND t.is_active = 1 AND u.is_active = 1
        ''', (token_hash,))

        row = cursor.fetchone()
        if not row:
            return None

        user_id, expires_at, username, role, created_at, last_login = row

        # Check if token has expired
        if current_time > expires_at:
            # Deactivate expired token
            cursor.execute('UPDATE tokens SET is_active = 0 WHERE token_hash = ?', (token_hash,))
            self.db.commit()
            return None

        # Update last used time and extend expiration
        new_expires_at = current_time + (TOKEN_EXPIRY_DAYS * 24 * 3600)
        cursor.execute('''
            UPDATE tokens SET last_used_at = ?, expires_at = ? WHERE token_hash = ?
        ''', (current_time, new_expires_at, token_hash))
        self.db.commit()

        return User(
            id=user_id,
            username=username,
            role=UserRole(role),
            created_at=created_at,
            last_login=last_login
        )

    def revoke_token(self, token: str) -> bool:
        """Revoke a specific token"""
        token_hash = self._hash_token(token)
        cursor = self.db.cursor()
        cursor.execute('UPDATE tokens SET is_active = 0 WHERE token_hash = ?', (token_hash,))
        self.db.commit()
        return cursor.rowcount > 0

    def revoke_user_tokens(self, user_id: int) -> int:
        """Revoke all tokens for a user"""
        cursor = self.db.cursor()
        cursor.execute('UPDATE tokens SET is_active = 0 WHERE user_id = ?', (user_id,))
        self.db.commit()
        return cursor.rowcount

    def cleanup_expired_tokens(self):
        """Remove expired tokens from database"""
        current_time = time.time()
        cursor = self.db.cursor()
        cursor.execute('DELETE FROM tokens WHERE expires_at < ?', (current_time,))
        deleted = cursor.rowcount
        self.db.commit()
        if deleted > 0:
            logger.info(f"Cleaned up {deleted} expired tokens")

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID"""
        cursor = self.db.cursor()
        cursor.execute('''
            SELECT id, username, role, created_at, last_login, email
            FROM users WHERE id = ? AND is_active = 1
        ''', (user_id,))

        row = cursor.fetchone()
        if row:
            return User(
                id=row[0],
                username=row[1],
                role=UserRole(row[2]),
                created_at=row[3],
                last_login=row[4],
                email=row[5]
            )
        return None

    def list_users(self, include_inactive: bool = False) -> List[User]:
        """List all users"""
        cursor = self.db.cursor()
        query = '''
            SELECT id, username, role, created_at, last_login, email
            FROM users
        '''
        if not include_inactive:
            query += ' WHERE is_active = 1'
        query += ' ORDER BY created_at'

        cursor.execute(query)
        users = []
        for row in cursor.fetchall():
            users.append(User(
                id=row[0],
                username=row[1],
                role=UserRole(row[2]),
                created_at=row[3],
                last_login=row[4],
                email=row[5]
            ))
        return users

    def delete_user(self, user_id: int) -> bool:
        """Soft delete a user (set inactive)"""
        cursor = self.db.cursor()
        cursor.execute('UPDATE users SET is_active = 0 WHERE id = ?', (user_id,))

        # Also revoke all user tokens
        self.revoke_user_tokens(user_id)
        self.db.commit()

        return cursor.rowcount > 0

    def change_user_role(self, user_id: int, new_role: UserRole) -> bool:
        """Change user role"""
        cursor = self.db.cursor()
        cursor.execute('UPDATE users SET role = ? WHERE id = ? AND is_active = 1',
                      (new_role.value, user_id))
        self.db.commit()
        return cursor.rowcount > 0

    def update_user_email(self, user_id: int, email: Optional[str]) -> bool:
        """Update user email address"""
        if email and not self._validate_email(email):
            raise ValueError("Invalid email format")

        cursor = self.db.cursor()
        cursor.execute('UPDATE users SET email = ? WHERE id = ? AND is_active = 1',
                      (email, user_id))
        self.db.commit()
        return cursor.rowcount > 0

    def get_user_builds(self, user_id: int, limit: int = 50) -> List[Dict]:
        """Get builds created by a specific user"""
        cursor = self.db.cursor()
        cursor.execute('''
            SELECT id, server_url, server_arch, pkgname, status, start_time, end_time, created_at
            FROM builds
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT ?
        ''', (user_id, limit))

        builds = []
        for row in cursor.fetchall():
            builds.append({
                "id": row[0],
                "server_url": row[1],
                "server_arch": row[2],
                "pkgname": row[3],
                "status": row[4],
                "start_time": row[5],
                "end_time": row[6],
                "created_at": row[7]
            })
        return builds

    def can_cancel_build(self, user: User, build_id: str) -> bool:
        """Check if user can cancel a specific build"""
        if user.role == UserRole.ADMIN:
            return True

        # Users can only cancel their own builds
        cursor = self.db.cursor()
        cursor.execute('SELECT user_id FROM builds WHERE id = ?', (build_id,))
        row = cursor.fetchone()

        return row and row[0] == user.id

    def change_password(self, user_id: int, current_password: str, new_password: str) -> bool:
        """Change user password after verifying current password"""
        cursor = self.db.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE id = ? AND is_active = 1', (user_id,))
        row = cursor.fetchone()

        if not row:
            return False

        stored_hash = row[0]

        # Verify current password
        if not self._verify_password(current_password, stored_hash):
            return False

        # Hash new password
        new_password_hash = self._hash_password(new_password)

        # Update password
        cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_password_hash, user_id))
        self.db.commit()

        logger.info(f"Password changed for user ID {user_id}")
        return True


# FastAPI Dependencies
async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
    request: Request = None
) -> Optional[User]:
    """Get current authenticated user from token (header or cookie)"""
    global auth_manager
    if not auth_manager:
        return None

    token = None

    # Try to get token from Authorization header first
    if credentials:
        token = credentials.credentials

    # If no header token, try to get from cookie
    if not token and request:
        token = request.cookies.get("authToken")

    if token:
        user = auth_manager.validate_token(token)
        return user

    return None


async def require_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
) -> User:
    """Require authentication - raise 401 if not authenticated"""
    current_user = await get_current_user(credentials, request)
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return current_user


async def require_admin(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
) -> User:
    """Require admin role - raise 403 if not admin"""
    current_user = await get_current_user(credentials, request)
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


async def get_current_user_optional(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
) -> Optional[User]:
    """Get current user but don't require authentication"""
    return await get_current_user(credentials, request)


async def cleanup_expired_tokens_task():
    """Background task to cleanup expired tokens"""
    global auth_manager
    while not shutdown_event.is_set():
        try:
            if auth_manager:
                auth_manager.cleanup_expired_tokens()
            await asyncio.sleep(3600)  # Run every hour
        except Exception as e:
            logger.error(f"Error in token cleanup: {e}")
            await asyncio.sleep(3600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan events"""
    # Startup
    global build_database, background_tasks, config, auth_manager

    # Load configuration
    config = load_config()

    if not config.get("servers"):
        logger.error("No servers configured")
        yield
        return

    # Initialize database
    build_database = init_database()

    # Initialize authentication
    auth_manager = AuthManager(build_database)

    # Setup HTTP session
    await setup_http_session()

    # Start background tasks
    background_tasks.extend([
        asyncio.create_task(process_build_queue()),
        asyncio.create_task(update_build_status()),
        asyncio.create_task(discover_builds()),
        asyncio.create_task(handle_unavailable_servers()),
        asyncio.create_task(cleanup_expired_tokens_task())
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


async def queue_build(build_id: str, pkgbuild_content: str, pkgname: str, target_archs: List[str], source_files: List[Dict] = None, user_id: Optional[int] = None):
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
        (id, server_url, server_arch, pkgname, status, start_time, end_time, created_at, queue_position, submission_group, user_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        build_id, None, None, pkgname, BuildStatus.QUEUED,
        None, None, time.time(), len(build_queue), None, user_id
    ))
    build_database.commit()


async def queue_builds_for_architectures(pkgbuild_content: str, pkgname: str, target_archs: List[str], source_files: List[Dict] = None, user_id: Optional[int] = None) -> List[Dict]:
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
            (id, server_url, server_arch, pkgname, status, start_time, end_time, created_at, queue_position, submission_group, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            build_id, None, arch, pkgname, BuildStatus.QUEUED,
            None, None, time.time(), len(build_queue), submission_group, user_id
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


# Authentication Routes

@app.post("/auth/login", response_model=LoginResponse)
async def login(login_data: LoginRequest):
    """Login with username and password"""
    global auth_manager
    user = auth_manager.authenticate_user(login_data.username, login_data.password)

    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = auth_manager.create_token(user)

    return LoginResponse(
        token=token,
        user={
            "id": user.id,
            "username": user.username,
            "role": user.role.value,
            "created_at": user.created_at,
            "last_login": user.last_login,
            "email": user.email
        }
    )


@app.post("/auth/logout")
async def logout(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
):
    """Logout current user (revoke current token)"""
    global auth_manager

    # Get token from header or cookie
    token = None
    if credentials:
        token = credentials.credentials
    else:
        token = request.cookies.get("authToken")

    if token and auth_manager:
        auth_manager.revoke_token(token)

    return {"message": "Logged out successfully"}


@app.get("/auth/logout")
async def logout_get(request: Request):
    """Browser-friendly logout endpoint"""
    # For GET requests, just return a message directing to POST
    # The JavaScript will handle the actual logout
    return {"message": "Use POST /auth/logout or JavaScript logout() function"}


@app.get("/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(require_auth)):
    """Get current user information"""
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        role=current_user.role.value,
        created_at=current_user.created_at,
        last_login=current_user.last_login,
        email=current_user.email
    )


@app.get("/auth/users", response_model=List[UserResponse])
async def list_users(current_user: User = Depends(require_admin)):
    """List all users (admin only)"""
    global auth_manager
    users = auth_manager.list_users()
    return [
        UserResponse(
            id=user.id,
            username=user.username,
            role=user.role.value,
            created_at=user.created_at,
            last_login=user.last_login,
            email=user.email
        )
        for user in users
    ]


@app.post("/auth/users", response_model=UserResponse)
async def create_user(
    user_data: CreateUserRequest,
    current_user: User = Depends(require_admin)
):
    """Create a new user (admin only)"""
    global auth_manager
    try:
        role = UserRole(user_data.role)
        new_user = auth_manager.create_user(user_data.username, user_data.password, role, user_data.email)

        return UserResponse(
            id=new_user.id,
            username=new_user.username,
            role=new_user.role.value,
            created_at=new_user.created_at,
            last_login=new_user.last_login,
            email=new_user.email
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/auth/users/{user_id}")
async def delete_user(
    user_id: int,
    current_user: User = Depends(require_admin)
):
    """Delete a user (admin only)"""
    global auth_manager
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    if auth_manager.delete_user(user_id):
        return {"message": f"User {user_id} deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail="User not found")


@app.put("/auth/users/{user_id}/role")
async def change_user_role(
    user_id: int,
    role_data: ChangeRoleRequest,
    current_user: User = Depends(require_admin)
):
    """Change user role (admin only)"""
    global auth_manager
    try:
        new_role = UserRole(role_data.role)

        if auth_manager.change_user_role(user_id, new_role):
            return {"message": f"User role changed to {new_role.value}"}
        else:
            raise HTTPException(status_code=404, detail="User not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/auth/users/{user_id}/revoke-tokens")
async def revoke_user_tokens(
    user_id: int,
    current_user: User = Depends(require_admin)
):
    """Revoke all tokens for a user (admin only)"""
    global auth_manager
    count = auth_manager.revoke_user_tokens(user_id)
    return {"message": f"Revoked {count} tokens for user {user_id}"}


@app.get("/auth/users/{user_id}/builds")
async def get_user_builds(
    user_id: int,
    current_user: User = Depends(require_admin),
    limit: int = 50
):
    """Get builds for a specific user (admin only)"""
    global auth_manager
    builds = auth_manager.get_user_builds(user_id, limit)
    return {"builds": builds}


@app.put("/auth/change-password")
async def change_password(
    password_data: ChangePasswordRequest,
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
):
    """Change current user's password"""
    global auth_manager

    # Get current user
    current_user = await get_current_user(credentials, request)
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Validate password confirmation
    if password_data.new_password != password_data.confirm_password:
        raise HTTPException(status_code=400, detail="New password and confirmation do not match")

    # Change password
    success = auth_manager.change_password(
        current_user.id,
        password_data.current_password,
        password_data.new_password
    )

    if not success:
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    # Revoke all existing tokens for this user (force re-login)
    auth_manager.revoke_user_tokens(current_user.id)

    return {"message": "Password changed successfully. Please log in again."}


@app.put("/auth/users/{user_id}/email")
async def update_user_email(
    user_id: int,
    email_data: UpdateEmailRequest,
    current_user: User = Depends(require_admin)
):
    """Update user email (admin only)"""
    global auth_manager
    try:
        if auth_manager.update_user_email(user_id, email_data.email):
            return {"message": f"Email updated for user {user_id}"}
        else:
            raise HTTPException(status_code=404, detail="User not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.put("/auth/my/email")
async def update_my_email(
    email_data: UpdateEmailRequest,
    current_user: User = Depends(require_auth)
):
    """Update current user's email"""
    global auth_manager
    try:
        if auth_manager.update_user_email(current_user.id, email_data.email):
            return {"message": "Email updated successfully"}
        else:
            raise HTTPException(status_code=404, detail="User not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# API Endpoints

@app.get("/farm")
async def get_farm_info(current_user: Optional[User] = Depends(get_current_user_optional)):
    """Get farm information and status of all managed servers"""
    servers = []
    available_archs = await get_available_architectures()

    # Group servers by their actual supported architecture
    for arch, server_urls in available_archs.items():
        for server_url in server_urls:
            server_info = await get_server_info(server_url)

            # Obfuscate URLs for non-admin users
            display_url = server_url if (current_user and current_user.role == UserRole.ADMIN) else obfuscate_server_url(server_url)

            servers.append({
                "url": display_url,
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
        "total_servers": len(servers),
        "authenticated": current_user is not None,
        "user_role": current_user.role.value if current_user else "guest"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": VERSION
    }


@app.post("/build/{build_id}/cancel")
async def cancel_build(
    build_id: str,
    current_user: User = Depends(require_auth)
):
    """Cancel a build (users can cancel own builds, admins can cancel any)"""
    global auth_manager

    # Check permissions
    if not auth_manager.can_cancel_build(current_user, build_id):
        raise HTTPException(status_code=403, detail="Not authorized to cancel this build")

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
async def get_dashboard(page: int = Query(1, ge=1), current_user: Optional[User] = Depends(get_current_user_optional)):
    """Get farm dashboard HTML"""
    # Get server status grouped by actual supported architecture
    available_archs = await get_available_architectures()
    servers_by_arch = {}

    # Get currently running builds for all servers
    cursor = build_database.cursor()
    cursor.execute('''
        SELECT b.id, b.server_url, b.pkgname, b.start_time, b.created_at, u.username
        FROM builds b
        LEFT JOIN users u ON b.user_id = u.id
        WHERE b.status = ? AND b.server_url IS NOT NULL
        ORDER BY b.start_time DESC
    ''', (BuildStatus.BUILDING,))

    running_builds_by_server = {}
    for build_id, server_url, pkgname, start_time, created_at, username in cursor.fetchall():
        if server_url not in running_builds_by_server:
            running_builds_by_server[server_url] = []
        running_builds_by_server[server_url].append({
            "id": build_id,
            "pkgname": pkgname,
            "start_time": safe_timestamp_to_datetime(start_time),
            "created_at": safe_timestamp_to_datetime(created_at),
            "username": username if username else "#anon#"
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

    # Get recent builds with user information
    cursor = build_database.cursor()
    offset = (page - 1) * 20
    cursor.execute('''
        SELECT b.id, b.server_url, b.server_arch, b.pkgname, b.status, b.start_time, b.end_time, b.created_at, u.username
        FROM builds b
        LEFT JOIN users u ON b.user_id = u.id
        ORDER BY b.created_at DESC LIMIT 20 OFFSET ?
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
            "created_at": safe_timestamp_to_datetime(row[7]) or "unknown",
            "username": row[8] if row[8] else "#anon#"
        })

    # Generate HTML with authentication UI
    auth_section = ""
    if current_user:
        admin_link = ""
        if current_user.role == UserRole.ADMIN:
            admin_link = '<a href="/admin" class="admin-link" title="User Administration">⚙️ Admin</a>'

        auth_section = f"""
        <div class="auth-section">
            {admin_link}
            <span class="auth-user clickable" onclick="showPasswordChangeForm()" title="Click to change password">👤 {current_user.username} ({current_user.role.value})</span>
            <button onclick="logout()" class="auth-button logout-button">Logout</button>
        </div>
        """
    else:
        auth_section = """
        <div class="auth-section">
            <button onclick="showLoginForm()" class="auth-button login-button">Login</button>
        </div>
        """

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>APB Farm Dashboard</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta http-equiv="refresh" content="10">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; position: relative; }}
            .header {{ text-align: center; margin-bottom: 30px; position: relative; }}
            .auth-section {{ position: absolute; top: 10px; right: 10px; display: flex; align-items: center; gap: 10px; }}
            .admin-link {{ color: #ffc107; font-weight: bold; text-decoration: none; padding: 5px 8px; border-radius: 3px; background-color: rgba(255, 193, 7, 0.1); }}
            .admin-link:hover {{ background-color: rgba(255, 193, 7, 0.2); text-decoration: underline; }}
            .auth-user {{ margin-right: 10px; font-weight: bold; color: #28a745; }}
            .auth-user.clickable {{ cursor: pointer; text-decoration: underline; }}
            .auth-user.clickable:hover {{ color: #1e7e34; }}
            .auth-button {{ padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; }}
            .login-button {{ background-color: #007bff; color: white; }}
            .login-button:hover {{ background-color: #0056b3; }}
            .logout-button {{ background-color: #dc3545; color: white; }}
            .logout-button:hover {{ background-color: #c82333; }}
            .login-form {{ position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: white; padding: 30px; border: 2px solid #ddd; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); z-index: 1000; display: none; }}
            .login-overlay {{ position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 999; display: none; }}
            .login-form input {{ display: block; width: 200px; margin: 10px 0; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }}
            .login-form button {{ margin: 5px; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; }}
            .login-submit {{ background-color: #28a745; color: white; }}
            .login-cancel {{ background-color: #6c757d; color: white; }}
            .error-message {{ color: #dc3545; margin: 10px 0; }}
            .success-message {{ color: #28a745; margin: 10px 0; font-weight: bold; }}
            .password-hint {{ color: #6c757d; font-size: 0.9em; margin: 5px 0; }}
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
        <div class="login-overlay" id="loginOverlay" onclick="hideLoginForm()"></div>
        <div class="login-form" id="loginForm">
            <h3>Login to APB Farm</h3>
            <form id="loginFormElement" onsubmit="submitLogin(event)">
                <input type="text" id="username" placeholder="Username" required>
                <input type="password" id="password" placeholder="Password" required>
                <div class="error-message" id="loginError"></div>
                <button type="submit" class="login-submit">Login</button>
                <button type="button" class="login-cancel" onclick="hideLoginForm()">Cancel</button>
            </form>
        </div>

        <div class="login-overlay" id="passwordChangeOverlay" onclick="hidePasswordChangeForm()"></div>
        <div class="login-form" id="passwordChangeForm">
            <h3>Change Password</h3>
            <form id="passwordChangeFormElement" onsubmit="submitPasswordChange(event)">
                <input type="password" id="currentPassword" placeholder="Current Password" required>
                <input type="password" id="newPassword" placeholder="New Password (min 8 characters)" required>
                <input type="password" id="confirmPassword" placeholder="Confirm New Password" required>
                <div class="password-hint">Password must be at least 8 characters long</div>
                <div class="error-message" id="passwordChangeError"></div>
                <div class="success-message" id="passwordChangeSuccess"></div>
                <button type="submit" class="login-submit">Change Password</button>
                <button type="button" class="login-cancel" onclick="hidePasswordChangeForm()">Cancel</button>
            </form>
        </div>

        <div class="header">
            {auth_section}
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
                    username = build.get("username", "#anon#")
                    current_builds_html += f"""
                        <li>
                            <a href="/build/{build['id']}/status">{build['pkgname']}</a> by <strong>{username}</strong>
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
                <small>Created: {build['created_at']} by <strong>{build['username']}</strong></small>
                <br>
                <small>
                    <a href="/build/{build['id']}/status">📋 View Details & Logs</a>
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

        <script>
            function showLoginForm() {{
                document.getElementById('loginOverlay').style.display = 'block';
                document.getElementById('loginForm').style.display = 'block';
                document.getElementById('username').focus();
            }}

            function hideLoginForm() {{
                document.getElementById('loginOverlay').style.display = 'none';
                document.getElementById('loginForm').style.display = 'none';
                document.getElementById('loginError').textContent = '';
                document.getElementById('loginFormElement').reset();
            }}

            function showPasswordChangeForm() {{
                document.getElementById('passwordChangeOverlay').style.display = 'block';
                document.getElementById('passwordChangeForm').style.display = 'block';
                document.getElementById('currentPassword').focus();
            }}

            function hidePasswordChangeForm() {{
                document.getElementById('passwordChangeOverlay').style.display = 'none';
                document.getElementById('passwordChangeForm').style.display = 'none';
                document.getElementById('passwordChangeError').textContent = '';
                document.getElementById('passwordChangeSuccess').textContent = '';
                document.getElementById('passwordChangeFormElement').reset();
            }}

            async function submitLogin(event) {{
                event.preventDefault();

                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                const errorDiv = document.getElementById('loginError');

                try {{
                    const response = await fetch('/auth/login', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                        }},
                        body: JSON.stringify({{ username, password }})
                    }});

                    if (response.ok) {{
                        const data = await response.json();
                        // Store token in localStorage and cookie
                        localStorage.setItem('authToken', data.token);
                        document.cookie = `authToken=${{data.token}}; path=/; max-age=${{data.expires_in_days * 24 * 3600}}; SameSite=Lax`;
                        // Reload page to show authenticated state
                        window.location.reload();
                    }} else {{
                        const errorData = await response.json();
                        errorDiv.textContent = errorData.detail || 'Login failed';
                    }}
                }} catch (error) {{
                    errorDiv.textContent = 'Network error. Please try again.';
                    console.error('Login error:', error);
                }}
            }}

            async function submitPasswordChange(event) {{
                event.preventDefault();

                const currentPassword = document.getElementById('currentPassword').value;
                const newPassword = document.getElementById('newPassword').value;
                const confirmPassword = document.getElementById('confirmPassword').value;
                const errorDiv = document.getElementById('passwordChangeError');
                const successDiv = document.getElementById('passwordChangeSuccess');

                // Clear previous messages
                errorDiv.textContent = '';
                successDiv.textContent = '';

                // Client-side validation
                if (newPassword !== confirmPassword) {{
                    errorDiv.textContent = 'New password and confirmation do not match';
                    return;
                }}

                if (newPassword.length < 8) {{
                    errorDiv.textContent = 'New password must be at least 8 characters long';
                    return;
                }}

                try {{
                    const token = getAuthToken();
                    const response = await fetch('/auth/change-password', {{
                        method: 'PUT',
                        headers: {{
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${{token}}`
                        }},
                        body: JSON.stringify({{
                            current_password: currentPassword,
                            new_password: newPassword,
                            confirm_password: confirmPassword
                        }})
                    }});

                    if (response.ok) {{
                        const data = await response.json();
                        successDiv.textContent = data.message;

                        // Auto-logout and redirect to login after 3 seconds
                        setTimeout(() => {{
                            localStorage.removeItem('authToken');
                            document.cookie = 'authToken=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
                            window.location.reload();
                        }}, 3000);
                    }} else {{
                        const errorData = await response.json();
                        errorDiv.textContent = errorData.detail || 'Password change failed';
                    }}
                }} catch (error) {{
                    errorDiv.textContent = 'Network error. Please try again.';
                    console.error('Password change error:', error);
                }}
            }}

            async function logout() {{
                try {{
                    const token = getAuthToken();
                    if (token) {{
                        await fetch('/auth/logout', {{
                            method: 'POST',
                            headers: {{
                                'Authorization': `Bearer ${{token}}`
                            }}
                        }});
                    }}
                }} catch (error) {{
                    console.error('Logout error:', error);
                }} finally {{
                    // Always remove token from localStorage and cookie
                    localStorage.removeItem('authToken');
                    document.cookie = 'authToken=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
                    window.location.reload();
                }}
            }}

            // Helper function to get auth token from localStorage or cookie
            function getAuthToken() {{
                // Try localStorage first
                let token = localStorage.getItem('authToken');
                if (token) return token;

                // Fall back to cookie
                const cookies = document.cookie.split(';');
                for (let cookie of cookies) {{
                    const [name, value] = cookie.trim().split('=');
                    if (name === 'authToken') {{
                        return value;
                    }}
                }}
                return null;
            }}

            // Sync token between localStorage and cookie on page load
            const token = getAuthToken();
            if (token) {{
                // Ensure token is in both localStorage and cookie
                localStorage.setItem('authToken', token);
                if (!document.cookie.includes('authToken=')) {{
                    document.cookie = `authToken=${{token}}; path=/; max-age=${{10 * 24 * 3600}}; SameSite=Lax`;
                }}

                // Add auth header to future requests
                const originalFetch = window.fetch;
                window.fetch = function(...args) {{
                    if (args[1]) {{
                        args[1].headers = args[1].headers || {{}};
                        args[1].headers['Authorization'] = `Bearer ${{token}}`;
                    }} else {{
                        args[1] = {{
                            headers: {{ 'Authorization': `Bearer ${{token}}` }}
                        }};
                    }}
                    return originalFetch.apply(this, args);
                }};
            }}
        </script>
    </body>
    </html>
    """

    return HTMLResponse(content=html)


@app.post("/build")
async def submit_build(
    pkgbuild: UploadFile = File(...),
    sources: List[UploadFile] = File(default=[]),
    architectures: str = Form(None),
    current_user: User = Depends(require_auth)  # Require authentication
):
    """Submit a build request (authenticated users only)"""
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
        queued_builds = await queue_builds_for_architectures(pkgbuild_content, pkgname, target_archs, source_files, current_user.id)

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
        SELECT b.server_url, b.server_arch, b.pkgname, b.status, b.last_known_status,
               b.server_available, b.cached_response, b.last_status_update, b.created_at, u.username
        FROM builds b
        LEFT JOIN users u ON b.user_id = u.id
        WHERE b.id = ?
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
            <!DOCTYPE html>
            <html>
            <head>
                <title>Build Not Found</title>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .header {{ text-align: center; margin-bottom: 30px; }}
                    .build {{ margin: 5px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; word-break: break-all; }}
                    .failed {{ background-color: #f8d7da; }}
                    .build-id {{ font-family: 'Courier New', monospace; font-size: 0.9em; color: #666; }}
                    .build a {{ color: #007bff; text-decoration: none; margin-right: 10px; }}
                    .build a:hover {{ text-decoration: underline; }}
                    .error-detail {{ background-color: #f8d7da; padding: 15px; border: 1px solid #f5c6cb; border-radius: 5px; margin: 15px 0; }}
                    .error-detail strong {{ color: #721c24; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>APB Farm - Build Status</h1>
                </div>

                <div class="build failed">
                    <h2>❌ Build Not Found</h2>
                    <div class="error-detail">
                        <strong>Error:</strong> The requested build could not be found in the farm database.
                    </div>

                    <p><strong>Build ID:</strong> <span class="build-id">{build_id}</span></p>

                    <h3>Details</h3>
                    <p>{error_detail['detail']}</p>

                    <h3>Next Steps</h3>
                    <ul>
                        <li>Verify that you're using the correct build ID</li>
                        <li>Ensure the build was submitted through this farm</li>
                        <li>Check if the build was submitted to a different farm instance</li>
                    </ul>

                    <p>
                        <a href="/dashboard">🏠 Back to Dashboard</a> |
                        <a href="/builds/latest">📋 View Recent Builds</a>
                    </p>
                </div>
            </body>
            </html>
            """, status_code=404)

    server_url, server_arch, pkgname, status, last_known_status, server_available, cached_response, last_status_update, created_at, username = result
    username = username if username else "#anon#"

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
            <!DOCTYPE html>
            <html>
            <head>
                <title>Build Submission Failed - {pkgname}</title>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .header {{ text-align: center; margin-bottom: 30px; }}
                    .build {{ margin: 5px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; word-break: break-all; }}
                    .failed {{ background-color: #f8d7da; }}
                    .build-id {{ font-family: 'Courier New', monospace; font-size: 0.9em; color: #666; }}
                    .build a {{ color: #007bff; text-decoration: none; margin-right: 10px; }}
                    .build a:hover {{ text-decoration: underline; }}
                    .error-detail {{ background-color: #f8d7da; padding: 15px; border: 1px solid #f5c6cb; border-radius: 5px; margin: 15px 0; }}
                    .error-detail strong {{ color: #721c24; }}
                    .metadata {{ background-color: #f8f9fa; padding: 10px; border: 1px solid #dee2e6; border-radius: 5px; margin: 15px 0; }}
                    .metadata p {{ margin: 5px 0; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>APB Farm - Build Status</h1>
                </div>

                <div class="build failed">
                    <h2>❌ Build Submission Failed: {pkgname}</h2>
                    <div class="error-detail">
                        <strong>Submission Error:</strong> This build failed during submission and was never assigned to a server.
                    </div>

                    <div class="metadata">
                        <p><strong>Build ID:</strong> <span class="build-id">{build_id}</span></p>
                        <p><strong>Package:</strong> {pkgname}</p>
                        <p><strong>Status:</strong> {status}</p>
                        <p><strong>Architecture:</strong> {server_arch or 'unknown'}</p>
                        <p><strong>Created:</strong> {datetime.fromtimestamp(created_at).strftime('%Y-%m-%d %H:%M:%S') if created_at else 'unknown'}</p>
                        <p><strong>Triggered by:</strong> {username}</p>
                    </div>

                    <h3>Possible Causes</h3>
                    <ul>
                        <li>No servers available for the target architecture</li>
                        <li>All servers at capacity during submission</li>
                        <li>Network connectivity issues</li>
                        <li>Invalid PKGBUILD or source files</li>
                    </ul>

                    <h3>Next Steps</h3>
                    <ul>
                        <li>Check server availability for your architecture</li>
                        <li>Verify your PKGBUILD is valid</li>
                        <li>Try submitting the build again</li>
                    </ul>

                    <p>
                        <a href="/dashboard">🏠 Back to Dashboard</a> |
                        <a href="/builds/latest">📋 View Recent Builds</a> |
                        <a href="/farm">🌾 View Farm Status</a>
                    </p>
                </div>
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
                    status_class = build_status.get('status', 'unknown')
                    # Get detailed status information if available
                    packages = build_status.get('packages', [])
                    logs = build_status.get('logs', [])
                    start_time = build_status.get('start_time')
                    end_time = build_status.get('end_time')
                    duration = build_status.get('duration', 0)

                    # Build packages HTML
                    packages_html = ""
                    if packages:
                        packages_html = "<h3>📦 Available Packages</h3><ul>"
                        for pkg in packages:
                            packages_html += f'<li><a href="{pkg.get("download_url", "#")}">{pkg.get("filename", "unknown")}</a> ({pkg.get("size", 0)} bytes)</li>'
                        packages_html += "</ul>"

                    # Build logs HTML
                    logs_html = ""
                    if logs:
                        logs_html = "<h3>📄 Build Logs</h3><ul>"
                        for log in logs:
                            logs_html += f'<li><a href="{log.get("download_url", "#")}">{log.get("filename", "unknown")}</a> ({log.get("size", 0)} bytes)</li>'
                        logs_html += "</ul>"

                    return HTMLResponse(f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Build Status (Server Unavailable) - {pkgname}</title>
                        <meta charset="utf-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1">
                        <meta http-equiv="refresh" content="30">
                        <style>
                            body {{ font-family: Arial, sans-serif; margin: 20px; }}
                            .header {{ text-align: center; margin-bottom: 30px; }}
                            .build {{ margin: 5px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; word-break: break-all; }}
                            .completed {{ background-color: #d4edda; }}
                            .failed {{ background-color: #f8d7da; }}
                            .building {{ background-color: #fff3cd; }}
                            .queued {{ background-color: #d1ecf1; }}
                            .cancelled {{ background-color: #e2e3e5; }}
                            .build-id {{ font-family: 'Courier New', monospace; font-size: 0.9em; color: #666; }}
                            .build a {{ color: #007bff; text-decoration: none; margin-right: 10px; }}
                            .build a:hover {{ text-decoration: underline; }}
                            .warning-detail {{ background-color: #fff3cd; padding: 15px; border: 1px solid #ffeaa7; border-radius: 5px; margin: 15px 0; }}
                            .warning-detail strong {{ color: #856404; }}
                            .metadata {{ background-color: #f8f9fa; padding: 10px; border: 1px solid #dee2e6; border-radius: 5px; margin: 15px 0; }}
                            .metadata p {{ margin: 5px 0; }}
                            .status-indicator {{ padding: 5px 10px; border-radius: 3px; font-weight: bold; display: inline-block; }}
                            .status-completed {{ background-color: #d4edda; color: #155724; }}
                            .status-failed {{ background-color: #f8d7da; color: #721c24; }}
                            .status-building {{ background-color: #fff3cd; color: #856404; }}
                            .status-queued {{ background-color: #d1ecf1; color: #0c5460; }}
                            .status-cancelled {{ background-color: #e2e3e5; color: #383d41; }}
                        </style>
                    </head>
                    <body>
                        <div class="header">
                            <h1>APB Farm - Build Status</h1>
                            <p>Package: <strong>{pkgname}</strong></p>
                        </div>

                        <div class="build {status_class}">
                            <h2>⚠️ Build Status (Server Unavailable)</h2>
                            <div class="warning-detail">
                                <strong>Server Status:</strong> The build server is currently unavailable. Showing last known status.<br>
                                <em>This page will auto-refresh every 30 seconds to check for server recovery.</em>
                            </div>

                            <div class="metadata">
                                <p><strong>Build ID:</strong> <span class="build-id">{build_id}</span></p>
                                <p><strong>Package:</strong> {pkgname}</p>
                                <p><strong>Status:</strong> <span class="status-indicator status-{status_class}">{build_status.get('status', 'unknown')}</span></p>
                                <p><strong>Server:</strong> {obfuscate_server_url(server_url)} (unavailable)</p>
                                <p><strong>Architecture:</strong> {server_arch or 'unknown'}</p>
                                <p><strong>Last Update:</strong> {datetime.fromtimestamp(last_status_update).strftime('%Y-%m-%d %H:%M:%S UTC') if last_status_update else 'unknown'}</p>
                                <p><strong>Triggered by:</strong> {username}</p>
                                {f'<p><strong>Start Time:</strong> {datetime.fromtimestamp(start_time).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>' if start_time else ''}
                                {f'<p><strong>End Time:</strong> {datetime.fromtimestamp(end_time).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>' if end_time else ''}
                                {f'<p><strong>Duration:</strong> {duration:.1f} seconds</p>' if duration > 0 else ''}
                            </div>

                            {packages_html}
                            {logs_html}

                            <h3>Actions</h3>
                            <p>
                                <a href="/build/{build_id}/status" onclick="location.reload()">🔄 Refresh Status</a> |
                                <a href="/dashboard">🏠 Back to Dashboard</a> |
                                <a href="/farm">🌾 View Farm Status</a>
                            </p>

                            <div style="margin-top: 20px; padding: 10px; background-color: #e9ecef; border-radius: 5px; font-size: 0.9em;">
                                <strong>Note:</strong> This information may be outdated due to server unavailability.
                                The server will automatically reconnect when available, and status will update.
                            </div>
                        </div>
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
            <!DOCTYPE html>
            <html>
            <head>
                <title>Server Unavailable - {pkgname}</title>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <meta http-equiv="refresh" content="60">
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .header {{ text-align: center; margin-bottom: 30px; }}
                    .build {{ margin: 5px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; word-break: break-all; }}
                    .failed {{ background-color: #f8d7da; }}
                    .build-id {{ font-family: 'Courier New', monospace; font-size: 0.9em; color: #666; }}
                    .build a {{ color: #007bff; text-decoration: none; margin-right: 10px; }}
                    .build a:hover {{ text-decoration: underline; }}
                    .error-detail {{ background-color: #f8d7da; padding: 15px; border: 1px solid #f5c6cb; border-radius: 5px; margin: 15px 0; }}
                    .error-detail strong {{ color: #721c24; }}
                    .metadata {{ background-color: #f8f9fa; padding: 10px; border: 1px solid #dee2e6; border-radius: 5px; margin: 15px 0; }}
                    .metadata p {{ margin: 5px 0; }}
                    .retry-info {{ background-color: #d1ecf1; padding: 15px; border: 1px solid #bee5eb; border-radius: 5px; margin: 15px 0; }}
                    .retry-info strong {{ color: #0c5460; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>APB Farm - Build Status</h1>
                    <p>Package: <strong>{pkgname}</strong></p>
                </div>

                <div class="build failed">
                    <h2>❌ Server Unavailable</h2>
                    <div class="error-detail">
                        <strong>Connection Error:</strong> The server handling this build is currently unavailable and no cached status is available.
                    </div>

                    <div class="metadata">
                        <p><strong>Build ID:</strong> <span class="build-id">{build_id}</span></p>
                        <p><strong>Package:</strong> {pkgname}</p>
                        <p><strong>Server:</strong> {obfuscate_server_url(server_url)} (unavailable)</p>
                        <p><strong>Architecture:</strong> {server_arch or 'unknown'}</p>
                        <p><strong>Last Known Status:</strong> {last_known_status or status}</p>
                        <p><strong>Triggered by:</strong> {username}</p>
                    </div>

                    <div class="retry-info">
                        <strong>Auto-Retry:</strong> This page will automatically refresh every 60 seconds to check for server recovery.<br>
                        <em>The farm will continue attempting to connect to the server in the background.</em>
                    </div>

                    <h3>Possible Causes</h3>
                    <ul>
                        <li>Server is temporarily down for maintenance</li>
                        <li>Network connectivity issues</li>
                        <li>Server overload or high resource usage</li>
                        <li>Server configuration problems</li>
                    </ul>

                    <h3>What to Do</h3>
                    <ul>
                        <li>Wait for the server to recover (auto-refresh will detect this)</li>
                        <li>Check the farm dashboard for other available servers</li>
                        <li>Contact the farm administrator if the issue persists</li>
                        <li>Consider submitting to a different architecture if available</li>
                    </ul>

                    <h3>Actions</h3>
                    <p>
                        <a href="/build/{build_id}/status" onclick="location.reload()">🔄 Refresh Status</a> |
                        <a href="/dashboard">🏠 Back to Dashboard</a> |
                        <a href="/farm">🌾 View Farm Status</a> |
                        <a href="/builds/latest">📋 View Recent Builds</a>
                    </p>

                    <div style="margin-top: 20px; padding: 10px; background-color: #e9ecef; border-radius: 5px; font-size: 0.9em;">
                        <strong>Status Monitoring:</strong> The farm is actively monitoring this server and will update the build status
                        as soon as connectivity is restored. Your build may still be running on the server.
                    </div>
                </div>
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
        # Generate farm's own HTML page instead of forwarding to server
        try:
            async with http_session.get(f"{server_url}/build/{build_id}/status-api", timeout=10) as response:
                if response.status == 200:
                    build_status = await response.json()
                    build_status["server_url"] = obfuscate_server_url(server_url)
                    if server_arch:
                        build_status["server_arch"] = server_arch

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

                    # Generate HTML response
                    status_class = build_status.get('status', 'unknown')
                    packages = build_status.get('packages', [])
                    logs = build_status.get('logs', [])
                    start_time = build_status.get('start_time')
                    end_time = build_status.get('end_time')
                    duration = build_status.get('duration', 0)

                    # Build packages HTML
                    packages_html = ""
                    if packages:
                        packages_html = "<h3>📦 Available Packages</h3><ul>"
                        for pkg in packages:
                            packages_html += f'<li><a href="{pkg.get("download_url", "#")}">{pkg.get("filename", "unknown")}</a> ({pkg.get("size", 0)} bytes)</li>'
                        packages_html += "</ul>"

                    # Build logs HTML
                    logs_html = ""
                    if logs:
                        logs_html = "<h3>📄 Build Logs</h3><ul>"
                        for log in logs:
                            logs_html += f'<li><a href="{log.get("download_url", "#")}">{log.get("filename", "unknown")}</a> ({log.get("size", 0)} bytes)</li>'
                        logs_html += "</ul>"

                    return HTMLResponse(f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Build Status - {pkgname}</title>
                        <meta charset="utf-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1">
                        <meta http-equiv="refresh" content="30">
                        <style>
                            body {{ font-family: Arial, sans-serif; margin: 20px; }}
                            .header {{ text-align: center; margin-bottom: 30px; }}
                            .build {{ margin: 5px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; word-break: break-all; }}
                            .completed {{ background-color: #d4edda; }}
                            .failed {{ background-color: #f8d7da; }}
                            .building {{ background-color: #fff3cd; }}
                            .queued {{ background-color: #d1ecf1; }}
                            .cancelled {{ background-color: #e2e3e5; }}
                            .build-id {{ font-family: 'Courier New', monospace; font-size: 0.9em; color: #666; }}
                            .build a {{ color: #007bff; text-decoration: none; margin-right: 10px; }}
                            .build a:hover {{ text-decoration: underline; }}
                            .metadata {{ background-color: #f8f9fa; padding: 10px; border: 1px solid #dee2e6; border-radius: 5px; margin: 15px 0; }}
                            .metadata p {{ margin: 5px 0; }}
                            .status-indicator {{ padding: 5px 10px; border-radius: 3px; font-weight: bold; display: inline-block; }}
                            .status-completed {{ background-color: #d4edda; color: #155724; }}
                            .status-failed {{ background-color: #f8d7da; color: #721c24; }}
                            .status-building {{ background-color: #fff3cd; color: #856404; }}
                            .status-queued {{ background-color: #d1ecf1; color: #0c5460; }}
                            .status-cancelled {{ background-color: #e2e3e5; color: #383d41; }}
                        </style>
                    </head>
                    <body>
                        <div class="header">
                            <h1>APB Farm - Build Status</h1>
                            <p>Package: <strong>{pkgname}</strong></p>
                        </div>

                        <div class="build {status_class}">
                            <h2>📋 Build Status</h2>

                            <div class="metadata">
                                <p><strong>Build ID:</strong> <span class="build-id">{build_id}</span></p>
                                <p><strong>Package:</strong> {pkgname}</p>
                                <p><strong>Status:</strong> <span class="status-indicator status-{status_class}">{build_status.get('status', 'unknown')}</span></p>
                                <p><strong>Server:</strong> {obfuscate_server_url(server_url)}</p>
                                <p><strong>Architecture:</strong> {server_arch or 'unknown'}</p>
                                <p><strong>Triggered by:</strong> {username}</p>
                                {f'<p><strong>Start Time:</strong> {datetime.fromtimestamp(start_time).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>' if start_time else ''}
                                {f'<p><strong>End Time:</strong> {datetime.fromtimestamp(end_time).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>' if end_time else ''}
                                {f'<p><strong>Duration:</strong> {duration:.1f} seconds</p>' if duration > 0 else ''}
                            </div>

                            {packages_html}
                            {logs_html}

                            <h3>Actions</h3>
                            <p>
                                <a href="/build/{build_id}/status" onclick="location.reload()">🔄 Refresh Status</a> |
                                <a href="/dashboard">🏠 Back to Dashboard</a> |
                                <a href="/farm">🌾 View Farm Status</a>
                            </p>
                        </div>
                    </body>
                    </html>
                    """)
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
                    status_class = build_status.get('status', 'unknown')

                    # Get detailed status information if available
                    packages = build_status.get('packages', [])
                    logs = build_status.get('logs', [])
                    start_time = build_status.get('start_time')
                    end_time = build_status.get('end_time')
                    duration = build_status.get('duration', 0)

                    # Build packages HTML
                    packages_html = ""
                    if packages:
                        packages_html = "<h3>📦 Available Packages</h3><ul>"
                        for pkg in packages:
                            packages_html += f'<li><a href="{pkg.get("download_url", "#")}">{pkg.get("filename", "unknown")}</a> ({pkg.get("size", 0)} bytes)</li>'
                        packages_html += "</ul>"

                    # Build logs HTML
                    logs_html = ""
                    if logs:
                        logs_html = "<h3>📄 Build Logs</h3><ul>"
                        for log in logs:
                            logs_html += f'<li><a href="{log.get("download_url", "#")}">{log.get("filename", "unknown")}</a> ({log.get("size", 0)} bytes)</li>'
                        logs_html += "</ul>"

                    return HTMLResponse(f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Build Status (Server Unavailable) - {pkgname}</title>
                        <meta charset="utf-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1">
                        <meta http-equiv="refresh" content="30">
                        <style>
                            body {{ font-family: Arial, sans-serif; margin: 20px; }}
                            .header {{ text-align: center; margin-bottom: 30px; }}
                            .build {{ margin: 5px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; word-break: break-all; }}
                            .completed {{ background-color: #d4edda; }}
                            .failed {{ background-color: #f8d7da; }}
                            .building {{ background-color: #fff3cd; }}
                            .queued {{ background-color: #d1ecf1; }}
                            .cancelled {{ background-color: #e2e3e5; }}
                            .build-id {{ font-family: 'Courier New', monospace; font-size: 0.9em; color: #666; }}
                            .build a {{ color: #007bff; text-decoration: none; margin-right: 10px; }}
                            .build a:hover {{ text-decoration: underline; }}
                            .warning-detail {{ background-color: #fff3cd; padding: 15px; border: 1px solid #ffeaa7; border-radius: 5px; margin: 15px 0; }}
                            .warning-detail strong {{ color: #856404; }}
                            .metadata {{ background-color: #f8f9fa; padding: 10px; border: 1px solid #dee2e6; border-radius: 5px; margin: 15px 0; }}
                            .metadata p {{ margin: 5px 0; }}
                            .status-indicator {{ padding: 5px 10px; border-radius: 3px; font-weight: bold; display: inline-block; }}
                            .status-completed {{ background-color: #d4edda; color: #155724; }}
                            .status-failed {{ background-color: #f8d7da; color: #721c24; }}
                            .status-building {{ background-color: #fff3cd; color: #856404; }}
                            .status-queued {{ background-color: #d1ecf1; color: #0c5460; }}
                            .status-cancelled {{ background-color: #e2e3e5; color: #383d41; }}
                            .error-info {{ background-color: #f8d7da; padding: 10px; border: 1px solid #f5c6cb; border-radius: 5px; margin: 15px 0; font-size: 0.9em; }}
                        </style>
                    </head>
                    <body>
                        <div class="header">
                            <h1>APB Farm - Build Status</h1>
                            <p>Package: <strong>{pkgname}</strong></p>
                        </div>

                        <div class="build {status_class}">
                            <h2>⚠️ Build Status (Server Connection Failed)</h2>
                            <div class="warning-detail">
                                <strong>Connection Issue:</strong> Unable to contact the build server. Showing last cached status.<br>
                                <em>This page will auto-refresh every 30 seconds to check for server recovery.</em>
                            </div>

                            <div class="metadata">
                                <p><strong>Build ID:</strong> <span class="build-id">{build_id}</span></p>
                                <p><strong>Package:</strong> {pkgname}</p>
                                <p><strong>Status:</strong> <span class="status-indicator status-{status_class}">{build_status.get('status', 'unknown')}</span></p>
                                <p><strong>Server:</strong> {obfuscate_server_url(server_url)} (connection failed)</p>
                                <p><strong>Architecture:</strong> {server_arch or 'unknown'}</p>
                                <p><strong>Last Update:</strong> {datetime.fromtimestamp(last_update).strftime('%Y-%m-%d %H:%M:%S UTC') if last_update else 'unknown'}</p>
                                <p><strong>Triggered by:</strong> {username}</p>
                                {f'<p><strong>Start Time:</strong> {datetime.fromtimestamp(start_time).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>' if start_time else ''}
                                {f'<p><strong>End Time:</strong> {datetime.fromtimestamp(end_time).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>' if end_time else ''}
                                {f'<p><strong>Duration:</strong> {duration:.1f} seconds</p>' if duration > 0 else ''}
                            </div>

                            <div class="error-info">
                                <strong>Connection Error:</strong> {str(e)}
                            </div>

                            {packages_html}
                            {logs_html}

                            <h3>Actions</h3>
                            <p>
                                <a href="/build/{build_id}/status" onclick="location.reload()">🔄 Refresh Status</a> |
                                <a href="/dashboard">🏠 Back to Dashboard</a> |
                                <a href="/farm">🌾 View Farm Status</a>
                            </p>

                            <div style="margin-top: 20px; padding: 10px; background-color: #e9ecef; border-radius: 5px; font-size: 0.9em;">
                                <strong>Note:</strong> This information may be outdated due to server connectivity issues.
                                The farm will automatically retry connection and update status when possible.
                            </div>
                        </div>
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
            SELECT b.id, b.server_url, b.server_arch, b.pkgname, b.status, b.start_time, b.end_time, b.created_at, u.username
            FROM builds b
            LEFT JOIN users u ON b.user_id = u.id
            WHERE b.status = ? ORDER BY b.created_at DESC LIMIT ?
        ''', (status, limit))
    else:
        cursor.execute('''
            SELECT b.id, b.server_url, b.server_arch, b.pkgname, b.status, b.start_time, b.end_time, b.created_at, u.username
            FROM builds b
            LEFT JOIN users u ON b.user_id = u.id
            ORDER BY b.created_at DESC LIMIT ?
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
            "created_at": f"{created_at_str} UTC" if created_at_str else "unknown",
            "username": row[8] if row[8] else "#anon#"
        })

    return {"builds": builds}


@app.get("/my/builds")
async def get_my_builds(
    current_user: User = Depends(require_auth),
    limit: int = Query(50, ge=1, le=200)
):
    """Get builds submitted by current user"""
    global auth_manager
    builds = auth_manager.get_user_builds(current_user.id, limit)

    # Add obfuscated server URLs for user display
    for build in builds:
        if build["server_url"]:
            build["server_url"] = obfuscate_server_url(build["server_url"])

    return {"builds": builds}


@app.get("/admin")
async def get_admin_panel(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
):
    """Admin panel for user management (admin only)"""
    current_user = await require_admin(request, credentials)

    # Get all users
    global auth_manager
    users = auth_manager.list_users()

    # Convert users to dict format for display
    users_data = []
    for user in users:
        users_data.append({
            "id": user.id,
            "username": user.username,
            "role": user.role.value,
            "created_at": datetime.fromtimestamp(user.created_at).strftime('%Y-%m-%d %H:%M:%S') if user.created_at else 'unknown',
            "last_login": datetime.fromtimestamp(user.last_login).strftime('%Y-%m-%d %H:%M:%S') if user.last_login else 'never',
            "email": user.email or 'none'
        })

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>APB Farm - Admin Panel</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ text-align: center; margin-bottom: 30px; }}
            .admin-section {{ margin: 20px 0; }}
            .admin-section h2 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 5px; }}
            .user-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            .user-table th, .user-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; word-wrap: break-word; }}
            .user-table th {{ background-color: #f8f9fa; font-weight: bold; }}
            .user-table tr:nth-child(even) {{ background-color: #f8f9fa; }}
            .user-table tr:hover {{ background-color: #e9ecef; }}
            .email-cell {{ max-width: 150px; overflow: hidden; text-overflow: ellipsis; }}
            .action-button {{ padding: 5px 10px; margin: 2px; border: none; border-radius: 3px; cursor: pointer; font-size: 12px; }}
            .edit-button {{ background-color: #ffc107; color: #000; }}
            .delete-button {{ background-color: #dc3545; color: white; }}
            .admin-badge {{ background-color: #28a745; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px; }}
            .user-badge {{ background-color: #007bff; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px; }}
            .add-user-form {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }}
            .add-user-form input, .add-user-form select {{ display: block; width: 200px; margin: 10px 0; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }}
            .add-user-form button {{ margin: 5px; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; }}
            .submit-button {{ background-color: #28a745; color: white; }}
            .cancel-button {{ background-color: #6c757d; color: white; }}
            .nav-links {{ margin: 20px 0; text-align: center; }}
            .nav-links a {{ margin: 0 10px; color: #007bff; text-decoration: none; }}
            .nav-links a:hover {{ text-decoration: underline; }}
            .error-message {{ color: #dc3545; margin: 10px 0; }}
            .success-message {{ color: #28a745; margin: 10px 0; font-weight: bold; }}
            .modal {{ position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: white; padding: 30px; border: 2px solid #ddd; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); z-index: 1000; display: none; max-width: 90%; max-height: 90%; overflow-y: auto; }}
            .modal-overlay {{ position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 999; display: none; }}
        </style>
    </head>
    <body>
        <div class="modal-overlay" id="modalOverlay" onclick="hideModal()"></div>
        <div class="modal" id="editUserModal">
            <h3>Edit User</h3>
            <form id="editUserForm" onsubmit="submitEditUser(event)">
                <input type="hidden" id="editUserId">
                <label>Username:</label>
                <input type="text" id="editUsername" readonly>
                <label>Role:</label>
                <select id="editRole" required>
                    <option value="user">User</option>
                    <option value="admin">Admin</option>
                </select>
                <label>Email:</label>
                <input type="email" id="editEmail" placeholder="user@example.com">
                <div class="error-message" id="editError"></div>
                <div class="success-message" id="editSuccess"></div>
                <button type="submit" class="submit-button">Update User</button>
                <button type="button" class="cancel-button" onclick="hideModal()">Cancel</button>
            </form>
        </div>

        <div class="header">
            <h1>APB Farm - Admin Panel</h1>
            <p>Logged in as: <strong>{current_user.username}</strong> (Admin)</p>
        </div>

        <div class="nav-links">
            <a href="/dashboard">🏠 Back to Dashboard</a>
            <a href="/farm">🌾 Farm Status</a>
            <a href="/builds/latest">📋 Recent Builds</a>
        </div>

        <div class="admin-section">
            <h2>👥 User Management</h2>

            <div class="add-user-form">
                <h3>Add New User</h3>
                <form id="addUserForm" onsubmit="submitAddUser(event)">
                    <label>Username:</label>
                    <input type="text" id="newUsername" placeholder="Username (min 3 characters)" required>
                    <label>Password:</label>
                    <input type="password" id="newPassword" placeholder="Password (min 8 characters)" required>
                    <label>Email:</label>
                    <input type="email" id="newEmail" placeholder="user@example.com (optional)">
                    <label>Role:</label>
                    <select id="newRole" required>
                        <option value="user">User</option>
                        <option value="admin">Admin</option>
                    </select>
                    <div class="error-message" id="addError"></div>
                    <div class="success-message" id="addSuccess"></div>
                    <button type="submit" class="submit-button">Add User</button>
                    <button type="button" class="cancel-button" onclick="clearAddForm()">Clear</button>
                </form>
            </div>

            <table class="user-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Created</th>
                        <th>Last Login</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
    """

    for user in users_data:
        role_badge = f'<span class="admin-badge">ADMIN</span>' if user["role"] == "admin" else f'<span class="user-badge">USER</span>'
        delete_disabled = 'disabled title="Cannot delete yourself"' if user["id"] == current_user.id else ''
        email_display = user["email"] if user["email"] != "none" else '<em>none</em>'

        html += f"""
                    <tr>
                        <td>{user["id"]}</td>
                        <td>{user["username"]}</td>
                        <td class="email-cell" title="{user['email']}">{email_display}</td>
                        <td>{role_badge}</td>
                        <td>{user["created_at"]}</td>
                        <td>{user["last_login"]}</td>
                        <td>
                            <button class="action-button edit-button" onclick="editUser({user['id']}, '{user['username']}', '{user['role']}', '{user['email'] if user['email'] != 'none' else ''}')">Edit</button>
                            <button class="action-button delete-button" onclick="deleteUser({user['id']}, '{user['username']}')" {delete_disabled}>Delete</button>
                        </td>
                    </tr>
        """

    html += f"""
                </tbody>
            </table>
        </div>

        <script>
            // Helper function to get auth token
            function getAuthToken() {{
                let token = localStorage.getItem('authToken');
                if (token) return token;

                const cookies = document.cookie.split(';');
                for (let cookie of cookies) {{
                    const [name, value] = cookie.trim().split('=');
                    if (name === 'authToken') {{
                        return value;
                    }}
                }}
                return null;
            }}

            function clearAddForm() {{
                document.getElementById('addUserForm').reset();
                document.getElementById('addError').textContent = '';
                document.getElementById('addSuccess').textContent = '';
            }}

            async function submitAddUser(event) {{
                event.preventDefault();

                const username = document.getElementById('newUsername').value;
                const password = document.getElementById('newPassword').value;
                const email = document.getElementById('newEmail').value || null;
                const role = document.getElementById('newRole').value;
                const errorDiv = document.getElementById('addError');
                const successDiv = document.getElementById('addSuccess');

                errorDiv.textContent = '';
                successDiv.textContent = '';

                try {{
                    const token = getAuthToken();
                    const response = await fetch('/auth/users', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${{token}}`
                        }},
                        body: JSON.stringify({{ username, password, email, role }})
                    }});

                    if (response.ok) {{
                        const data = await response.json();
                        successDiv.textContent = `User '${{username}}' created successfully!`;
                        clearAddForm();
                        setTimeout(() => window.location.reload(), 2000);
                    }} else {{
                        const errorData = await response.json();
                        errorDiv.textContent = errorData.detail || 'Failed to create user';
                    }}
                }} catch (error) {{
                    errorDiv.textContent = 'Network error. Please try again.';
                    console.error('Add user error:', error);
                }}
            }}

            function editUser(id, username, role, email) {{
                document.getElementById('editUserId').value = id;
                document.getElementById('editUsername').value = username;
                document.getElementById('editRole').value = role;
                document.getElementById('editEmail').value = email || '';
                document.getElementById('editError').textContent = '';
                document.getElementById('editSuccess').textContent = '';

                document.getElementById('modalOverlay').style.display = 'block';
                document.getElementById('editUserModal').style.display = 'block';
            }}

            function hideModal() {{
                document.getElementById('modalOverlay').style.display = 'none';
                document.getElementById('editUserModal').style.display = 'none';
            }}

            async function submitEditUser(event) {{
                event.preventDefault();

                const userId = document.getElementById('editUserId').value;
                const role = document.getElementById('editRole').value;
                const email = document.getElementById('editEmail').value || null;
                const errorDiv = document.getElementById('editError');
                const successDiv = document.getElementById('editSuccess');

                errorDiv.textContent = '';
                successDiv.textContent = '';

                try {{
                    const token = getAuthToken();

                    // Update role
                    const roleResponse = await fetch(`/auth/users/${{userId}}/role`, {{
                        method: 'PUT',
                        headers: {{
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${{token}}`
                        }},
                        body: JSON.stringify({{ role }})
                    }});

                    if (!roleResponse.ok) {{
                        const errorData = await roleResponse.json();
                        errorDiv.textContent = errorData.detail || 'Failed to update role';
                        return;
                    }}

                    // Update email
                    const emailResponse = await fetch(`/auth/users/${{userId}}/email`, {{
                        method: 'PUT',
                        headers: {{
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${{token}}`
                        }},
                        body: JSON.stringify({{ email }})
                    }});

                    if (emailResponse.ok) {{
                        successDiv.textContent = 'User updated successfully!';
                        setTimeout(() => {{
                            hideModal();
                            window.location.reload();
                        }}, 1500);
                    }} else {{
                        const errorData = await emailResponse.json();
                        errorDiv.textContent = errorData.detail || 'Failed to update email';
                    }}
                }} catch (error) {{
                    errorDiv.textContent = 'Network error. Please try again.';
                    console.error('Edit user error:', error);
                }}
            }}

            async function deleteUser(id, username) {{
                if (!confirm(`Are you sure you want to delete user '${{username}}'? This action cannot be undone.`)) {{
                    return;
                }}

                try {{
                    const token = getAuthToken();
                    const response = await fetch(`/auth/users/${{id}}`, {{
                        method: 'DELETE',
                        headers: {{
                            'Authorization': `Bearer ${{token}}`
                        }}
                    }});

                    if (response.ok) {{
                        alert(`User '${{username}}' deleted successfully!`);
                        window.location.reload();
                    }} else {{
                        const errorData = await response.json();
                        alert(`Failed to delete user: ${{errorData.detail || 'Unknown error'}}`);
                    }}
                }} catch (error) {{
                    alert('Network error. Please try again.');
                    console.error('Delete user error:', error);
                }}
            }}
        </script>
    </body>
    </html>
    """

    return HTMLResponse(content=html)


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
