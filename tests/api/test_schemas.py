"""Tests for API schemas."""

import pytest
from pydantic import ValidationError

from cerebro.api.schemas.base import BaseResponse, ErrorResponse


class TestBaseResponse:
    """Tests for BaseResponse schema."""

    def test_default_values(self):
        """Test default values are set correctly."""
        response = BaseResponse()
        assert response.success is True
        assert response.message is None
        assert response.metadata is None

    def test_custom_values(self):
        """Test custom values are set correctly."""
        response = BaseResponse(
            success=False,
            message="Operation failed",
            metadata={"key": "value"},
        )
        assert response.success is False
        assert response.message == "Operation failed"
        assert response.metadata == {"key": "value"}


class TestErrorResponse:
    """Tests for ErrorResponse schema."""

    def test_required_fields(self):
        """Test that error and detail are required."""
        with pytest.raises(ValidationError):
            ErrorResponse()

    def test_minimal_response(self):
        """Test minimal error response."""
        response = ErrorResponse(error="NotFound", detail="Resource not found")
        assert response.error == "NotFound"
        assert response.detail == "Resource not found"
        assert response.code is None
        assert response.request_id is None

    def test_full_response(self):
        """Test full error response with all fields."""
        response = ErrorResponse(
            error="ValidationError",
            detail={"field": "email", "message": "Invalid format"},
            code="INVALID_EMAIL",
            request_id="req-123-456",
        )
        assert response.error == "ValidationError"
        assert response.detail == {"field": "email", "message": "Invalid format"}
        assert response.code == "INVALID_EMAIL"
        assert response.request_id == "req-123-456"

    def test_detail_can_be_string(self):
        """Test that detail can be a string."""
        response = ErrorResponse(error="Error", detail="Simple message")
        assert response.detail == "Simple message"

    def test_detail_can_be_dict(self):
        """Test that detail can be a dict."""
        response = ErrorResponse(error="Error", detail={"key": "value"})
        assert response.detail == {"key": "value"}

    def test_json_serialization(self):
        """Test JSON serialization."""
        response = ErrorResponse(
            error="HTTPException",
            detail="Not found",
            code="HTTP_404",
            request_id="abc-123",
        )
        json_data = response.model_dump()
        assert json_data == {
            "error": "HTTPException",
            "detail": "Not found",
            "code": "HTTP_404",
            "request_id": "abc-123",
        }
