"""Base API response schemas."""

from typing import Any

from pydantic import BaseModel, Field


class BaseResponse(BaseModel):
    """Base response model for all API endpoints."""

    success: bool = Field(True, description="Whether the operation succeeded")
    message: str | None = Field(None, description="Human-readable message")
    metadata: dict[str, Any] | None = Field(None, description="Additional metadata")


class ErrorResponse(BaseModel):
    """Standardized error response for all API endpoints."""

    error: str = Field(..., description="Error type or code")
    detail: str | dict[str, Any] = Field(..., description="Error details")
    code: str | None = Field(None, description="Machine-readable error code")
    request_id: str | None = Field(None, description="Request ID for tracing")
