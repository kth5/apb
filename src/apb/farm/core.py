"""APB farm core logic."""

import asyncio
import hashlib
import io
import json
import logging
import os
import re
import secrets
import signal
import smtplib
import sqlite3
import ssl
import sys
import tarfile
import tempfile
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from apb import VERSION
from apb.config import load_config
from apb.constants import ADMIN_ROLE, TOKEN_EXPIRY_DAYS, USER_ROLE, BuildStatus
from apb.pkgbuild import parse_pkgbuild

logger = logging.getLogger(__name__)

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8080


# Version and constants
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8080
DEFAULT_CONFIG_PATHS = [
    Path.cwd() / "apb.json",
    Path("/etc/apb/apb.json"),
    Path.home() / ".apb" / "apb.json",
    Path.home() / ".apb-farm" / "apb.json"
]

# Authentication constants
# Classes need to be defined before global state to avoid NameError
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
    email_notifications_enabled: bool = True


@dataclass
class SMTPConfig:
    id: int
    server: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    use_tls: bool = True
    from_email: Optional[str] = None
    from_name: Optional[str] = None
    created_at: float = 0
    updated_at: float = 0


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
    email_notifications_enabled: bool


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=8, max_length=100)
    new_password: str = Field(..., min_length=8, max_length=100)
    confirm_password: str = Field(..., min_length=8, max_length=100)


class UpdateEmailRequest(BaseModel):
    email: Optional[str] = Field(None, max_length=255)


class UpdateEmailNotificationsRequest(BaseModel):
    enabled: bool


class SMTPConfigRequest(BaseModel):
    server: str = Field(..., min_length=1, max_length=255)
    port: int = Field(..., ge=1, le=65535)
    username: Optional[str] = Field(None, max_length=255)
    password: Optional[str] = Field(None, max_length=255)
    use_tls: bool = Field(default=True)
    from_email: Optional[str] = Field(None, max_length=255)
    from_name: Optional[str] = Field(None, max_length=255)


class SMTPConfigResponse(BaseModel):
    id: int
    server: str
    port: int
    username: Optional[str]
    use_tls: bool
    from_email: Optional[str]
    from_name: Optional[str]
    created_at: float
    updated_at: float
    # Note: password is intentionally excluded from response for security


class SMTPTestRequest(BaseModel):
    test_email: str = Field(..., min_length=1, max_length=255)


# Global state
config: Dict[str, Any] = {}
server_info_cache: Dict[str, Dict] = {}
build_queue: List[Dict] = []
build_database: sqlite3.Connection = None
http_session: httpx.AsyncClient = None
shutdown_event = asyncio.Event()
background_tasks: List[asyncio.Task] = []
server_status_tracker: Dict[str, ServerStatus] = {}
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
                    email TEXT,
                    email_notifications_enabled BOOLEAN DEFAULT 1
                )
            ''')

            # Add email column if it doesn't exist (for existing databases)
            try:
                self.db.execute('ALTER TABLE users ADD COLUMN email TEXT')
                self.db.commit()
            except sqlite3.OperationalError:
                pass  # Column already exists

            # Add email_notifications_enabled column if it doesn't exist (for existing databases)
            try:
                self.db.execute('ALTER TABLE users ADD COLUMN email_notifications_enabled BOOLEAN DEFAULT 1')
                self.db.commit()
            except sqlite3.OperationalError:
                pass  # Column already exists

            # SMTP configuration table
            self.db.execute('''
                CREATE TABLE IF NOT EXISTS smtp_config (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    username TEXT,
                    password TEXT,
                    use_tls BOOLEAN DEFAULT 1,
                    from_email TEXT,
                    from_name TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
            ''')

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

            # Custom repositories table
            self.db.execute('''
                CREATE TABLE IF NOT EXISTS custom_repositories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    url TEXT NOT NULL,
                    gpg_key_id TEXT NOT NULL,
                    description TEXT,
                    is_active BOOLEAN DEFAULT 1,
                    created_at REAL NOT NULL,
                    created_by INTEGER NOT NULL,
                    FOREIGN KEY (created_by) REFERENCES users (id)
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
                INSERT INTO users (username, password_hash, role, created_at, email, email_notifications_enabled)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, password_hash, role.value, current_time, email, True))

            user_id = cursor.lastrowid
            self.db.commit()

            logger.info(f"Created user '{username}' with role '{role.value}' and email '{email or 'none'}'")
            return User(
                id=user_id,
                username=username,
                role=role,
                created_at=current_time,
                email=email,
                email_notifications_enabled=True
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
            SELECT id, username, password_hash, role, created_at, last_login, email, email_notifications_enabled
            FROM users WHERE username = ? AND is_active = 1
        ''', (username,))

        row = cursor.fetchone()
        if not row:
            return None

        user_id, username, stored_hash, role, created_at, last_login, email, email_notifications_enabled = row

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
            email=email,
            email_notifications_enabled=bool(email_notifications_enabled)
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
            SELECT id, username, role, created_at, last_login, email, email_notifications_enabled
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
                email=row[5],
                email_notifications_enabled=bool(row[6])
            )
        return None

    def list_users(self, include_inactive: bool = False) -> List[User]:
        """List all users"""
        cursor = self.db.cursor()
        query = '''
            SELECT id, username, role, created_at, last_login, email, email_notifications_enabled
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
                email=row[5],
                email_notifications_enabled=bool(row[6])
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

    def update_user_email_notifications(self, user_id: int, enabled: bool) -> bool:
        """Update user's email notification preference"""
        try:
            cursor = self.db.cursor()
            cursor.execute('''
                UPDATE users SET email_notifications_enabled = ? WHERE id = ? AND is_active = 1
            ''', (enabled, user_id))

            if cursor.rowcount > 0:
                self.db.commit()
                logger.info(f"Updated email notifications preference for user {user_id} to {enabled}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to update email notifications preference: {e}")
            return False

    def get_user_builds(self, user_id: int, limit: int = 50) -> List[Dict]:
        """Get builds created by a specific user"""
        cursor = self.db.cursor()
        cursor.execute('''
            SELECT id, server_url, server_arch, pkgname, status, start_time, end_time, created_at, epoch, pkgver, pkgrel
            FROM builds
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT ?
        ''', (user_id, limit))

        builds = []
        for row in cursor.fetchall():
            # Format package name with version
            pkgname = row[3]
            epoch = row[8]
            pkgver = row[9]
            pkgrel = row[10]
            display_name = format_package_name_with_version(pkgname, epoch, pkgver, pkgrel)

            builds.append({
                "id": row[0],
                "server_url": row[1],
                "server_arch": row[2],
                "pkgname": pkgname,
                "display_name": display_name,
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

    # SMTP Configuration Methods
    def get_smtp_config(self) -> Optional[SMTPConfig]:
        """Get current SMTP configuration"""
        cursor = self.db.cursor()
        cursor.execute('''
            SELECT id, server, port, username, password, use_tls, from_email, from_name, created_at, updated_at
            FROM smtp_config ORDER BY updated_at DESC LIMIT 1
        ''')
        row = cursor.fetchone()
        if row:
            return SMTPConfig(
                id=row[0],
                server=row[1],
                port=row[2],
                username=row[3],
                password=row[4],
                use_tls=bool(row[5]),
                from_email=row[6],
                from_name=row[7],
                created_at=row[8],
                updated_at=row[9]
            )
        return None

    def save_smtp_config(self, server: str, port: int, username: Optional[str] = None,
                        password: Optional[str] = None, use_tls: bool = True,
                        from_email: Optional[str] = None, from_name: Optional[str] = None) -> SMTPConfig:
        """Save SMTP configuration"""
        if from_email and not self._validate_email(from_email):
            raise ValueError("Invalid from_email format")

        current_time = time.time()
        cursor = self.db.cursor()

        # Delete existing config (we only keep one active config)
        cursor.execute('DELETE FROM smtp_config')

        # Insert new config
        cursor.execute('''
            INSERT INTO smtp_config (server, port, username, password, use_tls, from_email, from_name, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (server, port, username, password, use_tls, from_email, from_name, current_time, current_time))

        config_id = cursor.lastrowid
        self.db.commit()

        logger.info(f"SMTP configuration saved: {server}:{port}")
        return SMTPConfig(
            id=config_id,
            server=server,
            port=port,
            username=username,
            password=password,
            use_tls=use_tls,
            from_email=from_email,
            from_name=from_name,
            created_at=current_time,
            updated_at=current_time
        )

    def delete_smtp_config(self) -> bool:
        """Delete SMTP configuration"""
        cursor = self.db.cursor()
        cursor.execute('DELETE FROM smtp_config')
        self.db.commit()
        deleted_count = cursor.rowcount
        if deleted_count > 0:
            logger.info("SMTP configuration deleted")
        return deleted_count > 0

    def send_email(self, to_email: str, subject: str, body: str, html_body: Optional[str] = None) -> bool:
        """Send email using configured SMTP settings"""
        smtp_config = self.get_smtp_config()
        if not smtp_config:
            logger.warning("No SMTP configuration found, cannot send email")
            return False

        if not to_email or not self._validate_email(to_email):
            logger.warning(f"Invalid recipient email: {to_email}")
            return False

        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{smtp_config.from_name or 'APB Farm'} <{smtp_config.from_email or 'noreply@localhost'}>"
            msg['To'] = to_email

            # Add text part
            text_part = MIMEText(body, 'plain')
            msg.attach(text_part)

            # Add HTML part if provided
            if html_body:
                html_part = MIMEText(html_body, 'html')
                msg.attach(html_part)

            # Send email
            context = ssl.create_default_context() if smtp_config.use_tls else None

            if smtp_config.use_tls:
                with smtplib.SMTP(smtp_config.server, smtp_config.port) as server:
                    server.starttls(context=context)
                    if smtp_config.username and smtp_config.password:
                        server.login(smtp_config.username, smtp_config.password)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(smtp_config.server, smtp_config.port) as server:
                    if smtp_config.username and smtp_config.password:
                        server.login(smtp_config.username, smtp_config.password)
                    server.send_message(msg)

            logger.info(f"Email sent successfully to {to_email}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {e}")
            return False

    def send_user_notification(self, user_email: str, action: str, username: str, admin_user: str):
        """Send notification email for user account changes"""
        if not user_email:
            return False

        # Get dashboard URL from configuration
        global config
        farm_url = config.get('farm_url', 'http://localhost:8080')
        dashboard_url = f"{farm_url.rstrip('/')}/dashboard"

        subject_map = {
            'created': f'Your APB Farm account has been created',
            'updated': f'Your APB Farm account has been updated',
            'deleted': f'Your APB Farm account has been deleted'
        }

        body_map = {
            'created': f"""Hello {username},

Your APB Farm account has been created by administrator {admin_user}.

You can now log in to the APB Farm dashboard to submit build requests.

Dashboard URL: {dashboard_url}

Best regards,
APB Farm System""",
            'updated': f"""Hello {username},

Your APB Farm account has been updated by administrator {admin_user}.

If you have any questions about these changes, please contact your administrator.

Dashboard URL: {dashboard_url}

Best regards,
APB Farm System""",
            'deleted': f"""Hello {username},

Your APB Farm account has been deleted by administrator {admin_user}.

If you believe this was done in error, please contact your administrator.

Dashboard URL: {dashboard_url}

Best regards,
APB Farm System"""
        }

        subject = subject_map.get(action, f'APB Farm account {action}')
        body = body_map.get(action, f'Your APB Farm account has been {action} by administrator {admin_user}.')

        return self.send_email(user_email, subject, body)

    def send_build_notification(self, user_email: str, username: str, build_id: str, pkgname: str, status: str, arch: str, artifacts: List[Dict] = None):
        """Send notification email for build completion"""
        if not user_email:
            return False

        # Get farm URL from configuration
        global config
        farm_url = config.get('farm_url', 'http://localhost:8080')
        build_status_url = f"{farm_url.rstrip('/')}/build/{build_id}/status"
        dashboard_url = f"{farm_url.rstrip('/')}/dashboard"

        # Determine subject and status message
        status_display = {
            BuildStatus.COMPLETED: "Completed Successfully",
            BuildStatus.FAILED: "Failed",
            BuildStatus.CANCELLED: "Cancelled"
        }.get(status, status.title())

        subject = f"APB Build {status_display}: {pkgname} ({arch}) - {build_id[:8]}"

        # Build artifacts section
        artifacts_section = ""
        if artifacts and status == BuildStatus.COMPLETED:
            artifacts_section = "\n\nAvailable Artifacts:\n"
            for artifact in artifacts:
                download_url = f"{farm_url.rstrip('/')}/build/{build_id}/download/{artifact['filename']}"
                artifacts_section += f"  • {artifact['filename']} ({artifact.get('size', 'unknown')} bytes)\n"
                artifacts_section += f"    Download: {download_url}\n"

        # Build log section (always available)
        log_section = f"\n\nBuild Log:\n  • build.log\n    Download: {farm_url.rstrip('/')}/build/{build_id}/download/build.log"

        # Create email body
        body = f"""Hello {username},

Your build request has {status_display.lower()}.

Build Details:
  • Build ID: {build_id}
  • Package: {pkgname}
  • Architecture: {arch}
  • Status: {status_display}

View Build Status: {build_status_url}{artifacts_section}{log_section}

You can view all your builds on the dashboard: {dashboard_url}

Best regards,
APB Farm System"""

        return self.send_email(user_email, subject, body)


async def send_build_completion_email(build_id: str, status: str, build_status: Dict):
    """Send email notification when a build reaches a final status"""
    try:
        # Get build information from database
        global build_database, auth_manager
        cursor = build_database.cursor()
        cursor.execute('''
            SELECT user_id, pkgname, server_arch
            FROM builds
            WHERE id = ?
        ''', (build_id,))
        result = cursor.fetchone()

        if not result:
            logger.warning(f"Build {build_id} not found in database for email notification")
            return

        user_id, pkgname, arch = result

        if not user_id:
            logger.debug(f"No user_id for build {build_id}, skipping email notification")
            return

        # Get user information
        user = auth_manager.get_user_by_id(user_id)
        if not user or not user.email:
            logger.debug(f"No email address for user {user_id} (build {build_id}), skipping email notification")
            return

        # Check if user has email notifications enabled
        if not user.email_notifications_enabled:
            logger.debug(f"Email notifications disabled for user {user_id} (build {build_id}), skipping email notification")
            return

        # Extract artifacts from build status
        artifacts = []
        if status == BuildStatus.COMPLETED and 'packages' in build_status:
            artifacts = build_status['packages']

        # Send notification
        success = auth_manager.send_build_notification(
            user.email,
            user.username,
            build_id,
            pkgname or "unknown",
            status,
            arch or "unknown",
            artifacts
        )

        if success:
            logger.info(f"Build completion email sent to {user.email} for build {build_id}")
        else:
            logger.warning(f"Failed to send build completion email to {user.email} for build {build_id}")

    except Exception as e:
        logger.error(f"Error sending build completion email for build {build_id}: {e}")


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


async def cleanup_cache_task():
    """Background task to clean up expired cache artifacts"""
    while not shutdown_event.is_set():
        try:
            await asyncio.sleep(14400)  # Run every 4 hours
            if not shutdown_event.is_set():
                await cleanup_expired_cache()
        except Exception as e:
            logger.error(f"Error in cleanup_cache_task: {e}")
            await asyncio.sleep(300)  # Wait 5 minutes before retrying


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

    try:
        conn.execute('ALTER TABLE builds ADD COLUMN build_timeout INTEGER DEFAULT 7200')
        conn.commit()
    except sqlite3.OperationalError:
        pass

    try:
        conn.execute('ALTER TABLE builds ADD COLUMN epoch TEXT')
        conn.commit()
    except sqlite3.OperationalError:
        pass

    try:
        conn.execute('ALTER TABLE builds ADD COLUMN pkgver TEXT')
        conn.commit()
    except sqlite3.OperationalError:
        pass

    try:
        conn.execute('ALTER TABLE builds ADD COLUMN pkgrel TEXT')
        conn.commit()
    except sqlite3.OperationalError:
        pass

    # Create cache artifacts table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS cached_artifacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            build_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            cached_at REAL NOT NULL,
            last_accessed REAL NOT NULL,
            content_type TEXT DEFAULT 'application/octet-stream',
            UNIQUE(build_id, filename)
        )
    ''')

    conn.commit()

    try:
        conn.execute('ALTER TABLE builds ADD COLUMN first_missing_at REAL')
        conn.commit()
    except sqlite3.OperationalError:
        pass

    try:
        conn.execute('ALTER TABLE builds ADD COLUMN user_id INTEGER')
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
    return parse_pkgbuild(pkgbuild_content).arch


def parse_pkgbuild_name(pkgbuild_content: str) -> str:
    return parse_pkgbuild(pkgbuild_content).pkgname


def parse_pkgbuild_version(pkgbuild_content: str) -> Dict[str, str]:
    info = parse_pkgbuild(pkgbuild_content)
    result = {"pkgver": info.pkgver, "pkgrel": info.pkgrel}
    if info.epoch:
        result["epoch"] = info.epoch
    return result


def parse_pkgbuild_extra_repos(pkgbuild_content: str) -> List[str]:
    return parse_pkgbuild(pkgbuild_content).extra_repos


def validate_extra_repos(requested_repos: List[str]) -> Tuple[List[Dict], List[str]]:
    """Validate requested repositories against admin-configured list

    Returns:
        Tuple of (valid_repos, invalid_repos)
        valid_repos: List of dicts with name, url, gpg_key_id
        invalid_repos: List of repository names that are not configured
    """
    if not requested_repos:
        return [], []

    try:
        cursor = build_database.cursor()
        cursor.execute('''
            SELECT name, url, gpg_key_id FROM custom_repositories
            WHERE is_active = 1
        ''')
        configured_repos = {row[0]: {'url': row[1], 'gpg_key_id': row[2]} for row in cursor.fetchall()}

        valid_repos = []
        invalid_repos = []

        for repo_spec in requested_repos:
            # Parse repository specification: "reponame::https://repo.url"
            if '::' not in repo_spec:
                invalid_repos.append(repo_spec)
                continue

            repo_name, repo_url = repo_spec.split('::', 1)

            if repo_name in configured_repos:
                # Validate URL matches configured URL
                if configured_repos[repo_name]['url'] == repo_url:
                    valid_repos.append({
                        'name': repo_name,
                        'url': repo_url,
                        'gpg_key_id': configured_repos[repo_name]['gpg_key_id']
                    })
                else:
                    invalid_repos.append(repo_spec)
            else:
                invalid_repos.append(repo_spec)

        return valid_repos, invalid_repos

    except Exception as e:
        logger.error(f"Error validating extra repositories: {e}")
        return [], requested_repos


def get_cache_config() -> Dict[str, Any]:
    """Get cache configuration from the main config"""
    config = load_config()
    cache_config = config.get("cache", {})

    # Set defaults
    defaults = {
        "enabled": True,
        "retention_days": 30,
        "directory": "~/.apb/cache",
        "max_size_mb": 10240
    }

    for key, default_value in defaults.items():
        if key not in cache_config:
            cache_config[key] = default_value

    # Expand directory path
    cache_config["directory"] = Path(cache_config["directory"]).expanduser()

    return cache_config


def ensure_cache_directory() -> Path:
    """Ensure cache directory exists and return its path"""
    cache_config = get_cache_config()
    cache_dir = cache_config["directory"]
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


async def cache_artifact(build_id: str, filename: str, content: bytes) -> bool:
    """Cache an artifact to local storage"""
    cache_config = get_cache_config()

    if not cache_config["enabled"]:
        return False

    cache_dir = ensure_cache_directory()

    # Create build-specific directory
    build_cache_dir = cache_dir / build_id
    build_cache_dir.mkdir(exist_ok=True)

    file_path = build_cache_dir / filename
    current_time = time.time()

    try:
        # Write the file
        with open(file_path, 'wb') as f:
            f.write(content)

        # Determine content type
        content_type = "application/octet-stream"
        if filename.endswith('.log'):
            content_type = "text/plain"
        elif filename.endswith(('.pkg.tar.xz', '.pkg.tar.zst')):
            content_type = "application/x-xz" if filename.endswith('.xz') else "application/zstd"

        # Record in database
        cursor = build_database.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO cached_artifacts
            (build_id, filename, file_path, file_size, cached_at, last_accessed, content_type)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (build_id, filename, str(file_path), len(content), current_time, current_time, content_type))
        build_database.commit()

        logger.debug(f"Cached artifact {filename} for build {build_id} ({len(content)} bytes)")
        return True

    except Exception as e:
        logger.error(f"Failed to cache artifact {filename} for build {build_id}: {e}")
        # Clean up partial file
        if file_path.exists():
            file_path.unlink()
        return False


async def get_cached_artifact(build_id: str, filename: str) -> Optional[Dict[str, Any]]:
    """Get cached artifact info if available"""
    cache_config = get_cache_config()

    if not cache_config["enabled"]:
        return None

    cursor = build_database.cursor()
    cursor.execute('''
        SELECT file_path, file_size, cached_at, content_type
        FROM cached_artifacts
        WHERE build_id = ? AND filename = ?
    ''', (build_id, filename))

    result = cursor.fetchone()
    if not result:
        return None

    file_path, file_size, cached_at, content_type = result
    file_path = Path(file_path)

    # Check if file still exists
    if not file_path.exists():
        # File was deleted externally, remove from database
        cursor.execute('DELETE FROM cached_artifacts WHERE build_id = ? AND filename = ?', (build_id, filename))
        build_database.commit()
        return None

    # Update last accessed time
    current_time = time.time()
    cursor.execute('''
        UPDATE cached_artifacts
        SET last_accessed = ?
        WHERE build_id = ? AND filename = ?
    ''', (current_time, build_id, filename))
    build_database.commit()

    return {
        "file_path": file_path,
        "file_size": file_size,
        "cached_at": cached_at,
        "content_type": content_type
    }


async def proactively_cache_build_artifacts(build_id: str, server_url: str, build_status: Dict):
    """Proactively cache all artifacts for a completed build"""
    cache_config = get_cache_config()

    if not cache_config["enabled"]:
        return

    artifacts_to_cache = []

    # Add packages to cache list
    packages = build_status.get("packages", [])
    for package in packages:
        filename = package.get("filename")
        if filename:
            artifacts_to_cache.append(filename)

    # Add logs to cache list
    logs = build_status.get("logs", [])
    for log in logs:
        filename = log.get("filename")
        if filename:
            artifacts_to_cache.append(filename)

    if not artifacts_to_cache:
        logger.debug(f"No artifacts to cache for build {build_id}")
        return

    logger.info(f"Proactively caching {len(artifacts_to_cache)} artifacts for completed build {build_id}")

    cached_count = 0
    for filename in artifacts_to_cache:
        try:
            # Check if already cached
            existing_cache = await get_cached_artifact(build_id, filename)
            if existing_cache:
                logger.debug(f"Artifact {filename} for build {build_id} already cached")
                continue

            # Download and cache the artifact
            response = await http_session.get(f"{server_url}/build/{build_id}/download/{filename}", timeout=300)
            if response.status_code == 200:
                content = response.content
                if await cache_artifact(build_id, filename, content):
                    cached_count += 1
                    logger.debug(f"Proactively cached {filename} for build {build_id} ({len(content)} bytes)")
                else:
                    logger.warning(f"Failed to cache {filename} for build {build_id}")
            else:
                logger.warning(f"Failed to download {filename} for build {build_id} (HTTP {response.status_code})")

        except Exception as e:
            logger.error(f"Error proactively caching {filename} for build {build_id}: {e}")

    if cached_count > 0:
        logger.info(f"Successfully cached {cached_count}/{len(artifacts_to_cache)} artifacts for build {build_id}")


async def cleanup_expired_cache():
    """Clean up expired cache entries based on retention policy"""
    cache_config = get_cache_config()

    if not cache_config["enabled"]:
        return

    retention_seconds = cache_config["retention_days"] * 24 * 60 * 60
    current_time = time.time()
    cutoff_time = current_time - retention_seconds

    cursor = build_database.cursor()

    # Find expired artifacts
    cursor.execute('''
        SELECT build_id, filename, file_path
        FROM cached_artifacts
        WHERE cached_at < ?
    ''', (cutoff_time,))

    expired_artifacts = cursor.fetchall()

    for build_id, filename, file_path in expired_artifacts:
        try:
            # Delete the physical file
            file_path = Path(file_path)
            if file_path.exists():
                file_path.unlink()
                logger.debug(f"Deleted expired cache file: {file_path}")

            # Remove from database
            cursor.execute('DELETE FROM cached_artifacts WHERE build_id = ? AND filename = ?', (build_id, filename))

        except Exception as e:
            logger.error(f"Failed to clean up cached artifact {file_path}: {e}")

    # Clean up empty build directories
    cache_dir = ensure_cache_directory()
    try:
        for build_dir in cache_dir.iterdir():
            if build_dir.is_dir() and not any(build_dir.iterdir()):
                build_dir.rmdir()
                logger.debug(f"Removed empty cache directory: {build_dir}")
    except Exception as e:
        logger.error(f"Failed to clean up empty cache directories: {e}")

    build_database.commit()

    if expired_artifacts:
        logger.info(f"Cleaned up {len(expired_artifacts)} expired cached artifacts")


def determine_content_type_and_disposition(filename: str) -> Tuple[str, str]:
    """
    Determine content type and disposition based on filename.
    Returns tuple of (content_type, disposition)
    """
    content_type = "application/octet-stream"
    disposition = "attachment"  # Default to download

    # Text files - display inline in browser
    if filename.endswith('.log'):
        content_type = "text/plain"
        disposition = "inline"
    # Binary package files - force download
    elif filename.endswith(('.pkg.tar.xz', '.pkg.tar.zst')):
        content_type = "application/x-xz" if filename.endswith('.xz') else "application/zstd"
        disposition = "attachment"
    elif filename.endswith(('.tar', '.tar.gz', '.tar.bz2', '.tar.xz')):
        if filename.endswith('.gz'):
            content_type = "application/gzip"
        elif filename.endswith('.bz2'):
            content_type = "application/x-bzip2"
        elif filename.endswith('.xz'):
            content_type = "application/x-xz"
        else:
            content_type = "application/x-tar"
        disposition = "attachment"

    return content_type, disposition


def format_package_name_with_version(pkgname: str, epoch: str = None, pkgver: str = None, pkgrel: str = None) -> str:
    """Format package name with version in epoch:pkgver-pkgrel format"""
    if not pkgver or pkgver == "unknown":
        return pkgname

    version_str = ""
    if epoch:
        version_str += f"{epoch}:"
    version_str += f"{pkgver}-{pkgrel or '1'}"

    return f"{pkgname} ({version_str})"


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
            timeout = httpx.Timeout(10.0, connect=3.0)

            response = await http_session.get(f"{server_url}/", timeout=timeout)
            if response.status_code == 200:
                info = response.json()
                status.last_successful_contact = current_time
                status.consecutive_failures = 0
                status.last_response = info
                if 'supported_architecture' in info:
                    status.last_known_architecture = info['supported_architecture']
                if status.health in [ServerHealth.DEGRADED, ServerHealth.UNAVAILABLE]:
                    status.health = ServerHealth.HEALTHY
                    logger.info(f"Server {server_url} recovered to healthy state")
                info['_cached_at'] = current_time
                info['_success'] = True
                server_info_cache[cache_key] = info
                return info
            else:
                raise Exception(f"HTTP {response.status_code}")

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

    # Parse version information from PKGBUILD
    version_info = parse_pkgbuild_version(pkgbuild_content)
    epoch = version_info.get('epoch')
    pkgver = version_info.get('pkgver')
    pkgrel = version_info.get('pkgrel')

    # Store in database
    cursor = build_database.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO builds
        (id, server_url, server_arch, pkgname, status, start_time, end_time, created_at, queue_position, submission_group, user_id, epoch, pkgver, pkgrel)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        build_id, None, None, pkgname, BuildStatus.QUEUED,
        None, None, time.time(), len(build_queue), None, user_id, epoch, pkgver, pkgrel
    ))
    build_database.commit()


async def queue_builds_for_architectures(pkgbuild_content: str, pkgname: str, target_archs: List[str], source_files: List[Dict] = None, user_id: Optional[int] = None, build_timeout: int = 7200, original_tarball: Optional[bytes] = None, extra_repos: List[Dict] = None) -> List[Dict]:
    """
    Queue builds for each architecture that has available servers.

    Args:
        original_tarball: Contains original client tarball for direct forwarding (avoids recreation)

    Returns:
        List of build information dictionaries.
    """
    submission_group = str(uuid.uuid4())  # Group ID to track related builds
    queued_builds = []

    logger.info(f"Starting build submission for package '{pkgname}' with target architectures: {target_archs}")

    # Parse version information from PKGBUILD
    version_info = parse_pkgbuild_version(pkgbuild_content)
    epoch = version_info.get('epoch')
    pkgver = version_info.get('pkgver')
    pkgrel = version_info.get('pkgrel')

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
            "arch": arch,
            "build_timeout": build_timeout,
            "original_tarball": original_tarball,
            "extra_repos": extra_repos or []
        }

        build_queue.append(build_info)

        # Store in database
        cursor = build_database.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO builds
            (id, server_url, server_arch, pkgname, status, start_time, end_time, created_at, queue_position, submission_group, user_id, build_timeout, epoch, pkgver, pkgrel)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            build_id, None, arch, pkgname, BuildStatus.QUEUED,
            None, None, time.time(), len(build_queue), submission_group, user_id, build_timeout, epoch, pkgver, pkgrel
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
    """Forward a build to a specific server using tarball format"""
    build_id = build_info["build_id"]
    temp_tarball_path = None

    try:
        import tempfile

        # Use original tarball if available (optimal), otherwise recreate from source_files (legacy compatibility)
        if build_info.get("original_tarball"):
            # Write original tarball to temporary file
            with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as temp_tarball:
                temp_tarball.write(build_info["original_tarball"])
                temp_tarball.flush()
                temp_tarball_path = temp_tarball.name
        else:
            # Fallback: Create temporary tarball from source_files (only for legacy individual file submissions)
            import tarfile
            with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as temp_tarball:
                temp_tarball_path = temp_tarball.name
                # Create a temporary directory for build files
                with tempfile.TemporaryDirectory() as temp_build_dir:
                    temp_build_path = Path(temp_build_dir)

                    # Write PKGBUILD to real file
                    pkgbuild_path = temp_build_path / "PKGBUILD"
                    with open(pkgbuild_path, 'w', encoding='utf-8') as f:
                        f.write(build_info["pkgbuild_content"])

                    # Write source files to real files (legacy individual file submissions only)
                    for source_file in build_info.get("source_files", []):
                        source_path = temp_build_path / source_file["filename"]
                        file_content = source_file["content"]
                        if isinstance(file_content, str):
                            with open(source_path, 'w', encoding='utf-8') as f:
                                f.write(file_content)
                        else:
                            with open(source_path, 'wb') as f:
                                f.write(file_content)

                    # Create tarball from real files
                    with tarfile.open(temp_tarball.name, 'w:gz') as tar:
                        for item in temp_build_path.iterdir():
                            if item.is_file():
                                tar.add(item, arcname=item.name)

        form_data = {"build_id": build_id}
        if "build_timeout" in build_info:
            form_data["build_timeout"] = str(build_info["build_timeout"])
        if "extra_repos" in build_info and build_info["extra_repos"]:
            form_data["extra_repos"] = json.dumps(build_info["extra_repos"])

        timeout = httpx.Timeout(120.0, connect=15.0)
        logger.info(f"Forwarding build {build_id} to {server_url}")

        with open(temp_tarball_path, "rb") as tarball_file:
            files = {"build_tarball": ("build.tar.gz", tarball_file, "application/gzip")}
            response = await http_session.post(
                f"{server_url}/build",
                data=form_data,
                files=files,
                timeout=timeout,
            )

        if response.status_code == 200:
            cursor = build_database.cursor()
            cursor.execute('''
                UPDATE builds SET server_url = ?, status = ?, start_time = ?
                WHERE id = ?
            ''', (server_url, BuildStatus.BUILDING, time.time(), build_id))
            build_database.commit()
            logger.info(f"Build {build_id} successfully forwarded to {server_url}")
            return True

        try:
            error_text = response.text
            logger.error(f"Server {server_url} rejected build {build_id} with HTTP {response.status_code}: {error_text}")
        except Exception:
            logger.error(f"Server {server_url} rejected build {build_id} with HTTP {response.status_code}")

        cursor = build_database.cursor()
        cursor.execute('''
            UPDATE builds SET status = ?, end_time = ?
            WHERE id = ?
        ''', (BuildStatus.FAILED, time.time(), build_id))
        build_database.commit()
        return False

    except asyncio.TimeoutError:
        logger.error(f"Timeout forwarding build {build_id} to {server_url}")
        return None

    except Exception as e:
        logger.error(f"Error forwarding build {build_id} to {server_url}: {e}")
        return None

    finally:
        # Clean up temporary file
        if temp_tarball_path:
            try:
                os.unlink(temp_tarball_path)
            except OSError:
                pass


async def update_single_build_status(build_id: str, server_url: str):
    """Update status for a single build with proper error isolation"""
    try:
        # Use shorter timeout specifically for status checks to avoid blocking
        timeout = httpx.Timeout(10.0, connect=3.0)

        response = await http_session.get(f"{server_url}/build/{build_id}/status-api", timeout=timeout)
        if response.status_code == 200:
            build_status = response.json()
            status = build_status.get("status", BuildStatus.QUEUED)
            current_time = time.time()

            cursor = build_database.cursor()
            cursor.execute('''
                UPDATE builds SET
                    status = ?,
                    end_time = ?,
                    last_known_status = ?,
                    last_status_update = ?,
                    server_available = 1,
                    cached_response = ?,
                    first_missing_at = NULL
                WHERE id = ?
            ''', (status,
                     current_time if status in [BuildStatus.COMPLETED, BuildStatus.FAILED] else None,
                     status,
                     current_time,
                     json.dumps(build_status),
                     build_id))
            build_database.commit()
            logger.debug(f"Updated status for build {build_id}: {status}")

            if status in [BuildStatus.COMPLETED, BuildStatus.FAILED, BuildStatus.CANCELLED]:
                asyncio.create_task(send_build_completion_email(build_id, status, build_status))

            if status == BuildStatus.COMPLETED:
                asyncio.create_task(proactively_cache_build_artifacts(build_id, server_url, build_status))
        elif response.status_code == 404:
            current_time = time.time()
            cursor = build_database.cursor()

            cursor.execute('SELECT first_missing_at FROM builds WHERE id = ?', (build_id,))
            result = cursor.fetchone()
            first_missing_at = result[0] if result and result[0] else None

            if first_missing_at is None:
                logger.warning(f"Build {build_id} not found on server {server_url} - starting 15-minute timeout")
                cursor.execute('''
                    UPDATE builds SET
                        last_status_update = ?,
                        first_missing_at = ?
                    WHERE id = ?
                ''', (current_time, current_time, build_id))
            else:
                missing_duration = current_time - first_missing_at
                if missing_duration > 900:
                    logger.error(f"Build {build_id} missing from server {server_url} for {missing_duration:.0f} seconds - marking as failed")
                    cursor.execute('''
                        UPDATE builds SET
                            status = ?,
                            end_time = ?,
                            last_status_update = ?,
                            last_known_status = 'failed_missing_from_server'
                        WHERE id = ?
                    ''', (BuildStatus.FAILED, current_time, current_time, build_id))
                    asyncio.create_task(send_build_completion_email(build_id, BuildStatus.FAILED, {"status": BuildStatus.FAILED, "missing_from_server": True}))
                else:
                    cursor.execute('''
                        UPDATE builds SET
                            last_status_update = ?
                        WHERE id = ?
                    ''', (current_time, build_id))

            build_database.commit()
        else:
            logger.warning(f"Server {server_url} returned HTTP {response.status_code} for build {build_id}")
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
                        response = await http_session.get(f"{server_url}/builds/latest?limit=50", timeout=10)
                        if response.status_code == 200:
                            builds_data = response.json()
                            builds = builds_data.get("builds", [])

                            for build in builds:
                                build_id = build.get("build_id") or build.get("id")
                                if build_id:
                                    cursor = build_database.cursor()
                                    cursor.execute("SELECT id FROM builds WHERE id = ?", (build_id,))
                                    if not cursor.fetchone():
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
                            response = await http_session.get(f"{server_url}/build/{build_id}/status-api", timeout=10)
                            if response.status_code == 200:
                                build_status = response.json()
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


async def setup_http_session() -> None:
    """Setup HTTP client for upstream server communication."""
    global http_session
    http_session = httpx.AsyncClient(
        timeout=httpx.Timeout(30.0, connect=5.0),
        limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
        follow_redirects=True,
    )


async def cleanup_http_session() -> None:
    global http_session
    if http_session:
        await http_session.aclose()
        http_session = None


def signal_handler(signum, frame):
    logger.info("Received signal %s, shutting down...", signum)
    sys.exit(0)
