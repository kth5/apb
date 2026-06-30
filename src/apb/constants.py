"""Shared constants across APB components."""

from apb import VERSION

BUILD_TIMEOUT_DEFAULT = 7200
BUILD_TIMEOUT_MIN = 300
BUILD_TIMEOUT_MAX = 14400
MAX_FILE_SIZE = 100 * 1024 * 1024
MAX_REQUEST_SIZE = 500 * 1024 * 1024
MAX_BUILD_OUTPUTS = 10000
TOKEN_EXPIRY_DAYS = 10

ADMIN_ROLE = "admin"
USER_ROLE = "user"
GUEST_ROLE = "guest"

DEFAULT_CONFIG_PATHS = [
    __import__("pathlib").Path.cwd() / "apb.json",
    __import__("pathlib").Path("/etc/apb/apb.json"),
    __import__("pathlib").Path.home() / ".apb" / "apb.json",
    __import__("pathlib").Path.home() / ".apb-farm" / "apb.json",
]


class BuildStatus:
    QUEUED = "queued"
    BUILDING = "building"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


def user_agent(component: str) -> str:
    return f"APB-{component}/{VERSION}"
