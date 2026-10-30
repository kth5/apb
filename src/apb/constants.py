"""Shared constants across APB components."""

from pathlib import Path

from apb import VERSION

FARM_DEFAULT_HOST = "0.0.0.0"
FARM_DEFAULT_PORT = 8080
DEFAULT_SERVER_URL = "http://localhost:8000"
DEFAULT_FARM_URL = f"http://localhost:{FARM_DEFAULT_PORT}"

BUILD_TIMEOUT_DEFAULT = 7200
BUILD_TIMEOUT_MIN = 300
BUILD_TIMEOUT_MAX = 14400
MAX_FILE_SIZE = 100 * 1024 * 1024
MAX_REQUEST_SIZE = 500 * 1024 * 1024
MAX_BUILD_OUTPUTS = 10000
GUEST_BUILD_LOG_TAIL_LINES = 100
TOKEN_EXPIRY_DAYS = 10

ADMIN_ROLE = "admin"
USER_ROLE = "user"
GUEST_ROLE = "guest"

MFA_METHOD_TOTP = "totp"
MFA_METHOD_WEBAUTHN = "webauthn"
MFA_METHOD_RECOVERY = "recovery"

DEFAULT_CONFIG_PATHS = [
    Path.cwd() / "apb.json",
    Path("/etc/apb/apb.json"),
    Path.home() / ".apb" / "apb.json",
    Path.home() / ".apb-farm" / "apb.json",
]


class BuildStatus:
    QUEUED = "queued"
    BUILDING = "building"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TERMINAL = (COMPLETED, FAILED, CANCELLED)


def user_agent(component: str) -> str:
    return f"APB-{component}/{VERSION}"
