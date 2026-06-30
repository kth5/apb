"""Shared Pydantic models."""

from typing import List, Optional

from pydantic import BaseModel, Field


class BuildSubmitResponse(BaseModel):
    build_id: str
    status: str
    message: Optional[str] = None
