"""Base API response schemas."""

from typing import Any

from pydantic import BaseModel, Field


class BaseResponse(BaseModel):
    """Base response model for all API endpoints."""

    success: bool = Field(True, description="Whether the operation succeeded")
    message: str | None = Field(None, description="Human-readable message")
    metadata: dict[str, Any] | None = Field(None, description="Additional metadata")
