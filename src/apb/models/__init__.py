"""Shared Pydantic models."""

from datetime import datetime, timezone
from typing import Any, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utc_datetime(value: Any) -> Optional[datetime]:
    """Normalise an epoch timestamp, ISO string or datetime to an aware UTC datetime."""
    if value in (None, "", 0, "unknown"):
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc)
    if isinstance(value, str):
        value = datetime.fromisoformat(value.removesuffix(" UTC").replace("Z", "+00:00"))
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    raise ValueError(f"Unsupported timestamp: {value!r}")


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=100)


class UserResponse(BaseModel):
    id: int
    username: str
    role: str
    created_at: float
    last_login: Optional[float] = None
    email: Optional[str] = None
    email_notifications_enabled: bool = True


class LoginResponse(BaseModel):
    token: str
    user: UserResponse
    expires_in_days: int = 10


class BuildArtifact(BaseModel):
    filename: str
    size: int = 0
    download_url: Optional[str] = None


class BuildSummary(BaseModel):
    """Build list entry shared by server and farm; farm-only fields are optional."""

    model_config = ConfigDict(extra="ignore")

    build_id: str
    pkgname: str
    status: str
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    created_at: Optional[datetime] = None
    duration: Optional[float] = None
    server_arch: Optional[str] = None
    server_url: Optional[str] = None
    display_name: Optional[str] = None
    username: Optional[str] = None
    packages: Optional[List[BuildArtifact]] = None

    @field_validator("start_time", "end_time", "created_at", mode="before")
    @classmethod
    def _normalise_times(cls, value: Any) -> Optional[datetime]:
        return utc_datetime(value)


class BuildListResponse(BaseModel):
    pkgname: Optional[str] = None
    builds: List[BuildSummary]
    total: int


class BuildStatusResponse(BaseModel):
    """Payload of ``/build/{id}/status-api``; farm extras are optional.

    Times stay epoch seconds because the farm renders cached server status pages from them.
    """

    model_config = ConfigDict(extra="ignore")

    build_id: str
    pkgname: str
    status: str
    created_at: Optional[float] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    duration: Optional[float] = None
    exit_code: Optional[int] = None
    arch: Optional[List[str]] = None
    build_timeout: Optional[int] = None
    packages: List[BuildArtifact] = Field(default_factory=list)
    logs: List[BuildArtifact] = Field(default_factory=list)
    server_arch: Optional[str] = None
    server_url: Optional[str] = None
    artifacts_ready: Optional[bool] = None
    queue_state: Optional[str] = None
    queue_position: Optional[int] = None
    jobs_ahead: Optional[int] = None
    farm_queue_size: Optional[int] = None
    server_unavailable: Optional[bool] = None
    last_status_update: Optional[float] = None
    error_message: Optional[str] = None


class BuildSubmitResponse(BaseModel):
    build_id: str
    status: str
    message: Optional[str] = None


class QueuedBuildInfo(BaseModel):
    build_id: str
    arch: str
    status: str
    pkgname: str
    submission_group: str
    created_at: float
    queue_state: Optional[str] = None
    queue_position: Optional[int] = None
    jobs_ahead: Optional[int] = None
    farm_queue_size: Optional[int] = None


class FarmQueueStatus(BaseModel):
    queue_size: int
    builds_queued: int
    message: Optional[str] = None


class FarmBuildSubmitResponse(BuildSubmitResponse):
    pkgname: str
    target_architectures: List[str]
    pkgbuild_architectures: List[str]
    builds: List[QueuedBuildInfo]
    submission_group: str
    queue_status: Optional[FarmQueueStatus] = None
    created_at: float
    build_timeout: Optional[int] = None
    timeout_set_by: Optional[str] = None
