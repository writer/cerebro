"""Base API response schemas."""

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class BaseResponse(BaseModel):
    """Base response model for all API endpoints."""

    success: bool = Field(True, description="Whether the operation succeeded")
    message: Optional[str] = Field(None, description="Human-readable message")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")
