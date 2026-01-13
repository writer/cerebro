"""RFC 7807 Problem Details error handling for Cerebro API.

This module provides standardized error responses following RFC 7807.
https://tools.ietf.org/html/rfc7807
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


class ErrorCode(str, Enum):
    """Standardized error codes for Cerebro API."""

    # Authentication errors (401)
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"  # noqa: S105
    TOKEN_INVALID = "TOKEN_INVALID"  # noqa: S105
    API_KEY_INVALID = "API_KEY_INVALID"
    API_KEY_EXPIRED = "API_KEY_EXPIRED"
    API_KEY_REVOKED = "API_KEY_REVOKED"

    # Authorization errors (403)
    INSUFFICIENT_PERMISSIONS = "INSUFFICIENT_PERMISSIONS"
    SCOPE_REQUIRED = "SCOPE_REQUIRED"
    ORG_ACCESS_DENIED = "ORG_ACCESS_DENIED"

    # Not found errors (404)
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    ORGANIZATION_NOT_FOUND = "ORGANIZATION_NOT_FOUND"
    FINDING_NOT_FOUND = "FINDING_NOT_FOUND"
    ACCOUNT_NOT_FOUND = "ACCOUNT_NOT_FOUND"
    RULE_NOT_FOUND = "RULE_NOT_FOUND"
    USER_NOT_FOUND = "USER_NOT_FOUND"
    API_KEY_NOT_FOUND = "API_KEY_NOT_FOUND"

    # Validation errors (400/422)
    VALIDATION_ERROR = "VALIDATION_ERROR"
    INVALID_REQUEST = "INVALID_REQUEST"
    INVALID_PARAMETER = "INVALID_PARAMETER"
    INVALID_SCOPE = "INVALID_SCOPE"
    INVALID_SEVERITY = "INVALID_SEVERITY"
    INVALID_STATUS = "INVALID_STATUS"

    # Conflict errors (409)
    RESOURCE_CONFLICT = "RESOURCE_CONFLICT"
    DUPLICATE_RESOURCE = "DUPLICATE_RESOURCE"

    # Rate limiting errors (429)
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"

    # Server errors (500)
    INTERNAL_ERROR = "INTERNAL_ERROR"
    DATABASE_ERROR = "DATABASE_ERROR"
    EXTERNAL_SERVICE_ERROR = "EXTERNAL_SERVICE_ERROR"

    # Service unavailable (503)
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"


class ProblemDetail(BaseModel):
    """
    RFC 7807 Problem Details response.

    See: https://tools.ietf.org/html/rfc7807
    """

    type: str = Field(
        default=...,
        description="A URI reference identifying the problem type",
        json_schema_extra={"example": "https://api.cerebro.io/errors/RESOURCE_NOT_FOUND"},
    )
    title: str = Field(
        default=...,
        description="A short, human-readable summary of the problem",
        json_schema_extra={"example": "Resource Not Found"},
    )
    status: int = Field(
        default=...,
        description="The HTTP status code",
        json_schema_extra={"example": 404},
    )
    detail: str = Field(
        default=...,
        description="A human-readable explanation specific to this occurrence",
        json_schema_extra={"example": "The finding with ID '123' was not found"},
    )
    instance: str | None = Field(
        default=None,
        description="A URI reference identifying the specific occurrence",
        json_schema_extra={"example": "/api/v1/findings/123"},
    )
    code: str = Field(
        default=...,
        description="Machine-readable error code",
        json_schema_extra={"example": "FINDING_NOT_FOUND"},
    )
    request_id: str | None = Field(
        default=None,
        description="Unique request identifier for support/debugging",
    )
    errors: list[dict[str, Any]] | None = Field(
        default=None,
        description="Detailed validation errors (for 422 responses)",
    )
    documentation_url: str | None = Field(
        default=None,
        description="URL to documentation about this error",
    )


# Error type base URL
ERROR_TYPE_BASE = "https://api.cerebro.io/errors"

# Error code to HTTP status mapping
ERROR_STATUS_MAP = {
    ErrorCode.INVALID_CREDENTIALS: 401,
    ErrorCode.TOKEN_EXPIRED: 401,
    ErrorCode.TOKEN_INVALID: 401,
    ErrorCode.API_KEY_INVALID: 401,
    ErrorCode.API_KEY_EXPIRED: 401,
    ErrorCode.API_KEY_REVOKED: 401,
    ErrorCode.INSUFFICIENT_PERMISSIONS: 403,
    ErrorCode.SCOPE_REQUIRED: 403,
    ErrorCode.ORG_ACCESS_DENIED: 403,
    ErrorCode.RESOURCE_NOT_FOUND: 404,
    ErrorCode.ORGANIZATION_NOT_FOUND: 404,
    ErrorCode.FINDING_NOT_FOUND: 404,
    ErrorCode.ACCOUNT_NOT_FOUND: 404,
    ErrorCode.RULE_NOT_FOUND: 404,
    ErrorCode.USER_NOT_FOUND: 404,
    ErrorCode.API_KEY_NOT_FOUND: 404,
    ErrorCode.VALIDATION_ERROR: 422,
    ErrorCode.INVALID_REQUEST: 400,
    ErrorCode.INVALID_PARAMETER: 400,
    ErrorCode.INVALID_SCOPE: 400,
    ErrorCode.INVALID_SEVERITY: 400,
    ErrorCode.INVALID_STATUS: 400,
    ErrorCode.RESOURCE_CONFLICT: 409,
    ErrorCode.DUPLICATE_RESOURCE: 409,
    ErrorCode.RATE_LIMIT_EXCEEDED: 429,
    ErrorCode.INTERNAL_ERROR: 500,
    ErrorCode.DATABASE_ERROR: 500,
    ErrorCode.EXTERNAL_SERVICE_ERROR: 502,
    ErrorCode.SERVICE_UNAVAILABLE: 503,
}

# Human-readable titles for error codes
ERROR_TITLES = {
    ErrorCode.INVALID_CREDENTIALS: "Invalid Credentials",
    ErrorCode.TOKEN_EXPIRED: "Token Expired",
    ErrorCode.TOKEN_INVALID: "Invalid Token",
    ErrorCode.API_KEY_INVALID: "Invalid API Key",
    ErrorCode.API_KEY_EXPIRED: "API Key Expired",
    ErrorCode.API_KEY_REVOKED: "API Key Revoked",
    ErrorCode.INSUFFICIENT_PERMISSIONS: "Insufficient Permissions",
    ErrorCode.SCOPE_REQUIRED: "Required Scope Missing",
    ErrorCode.ORG_ACCESS_DENIED: "Organization Access Denied",
    ErrorCode.RESOURCE_NOT_FOUND: "Resource Not Found",
    ErrorCode.ORGANIZATION_NOT_FOUND: "Organization Not Found",
    ErrorCode.FINDING_NOT_FOUND: "Finding Not Found",
    ErrorCode.ACCOUNT_NOT_FOUND: "Account Not Found",
    ErrorCode.RULE_NOT_FOUND: "Rule Not Found",
    ErrorCode.USER_NOT_FOUND: "User Not Found",
    ErrorCode.API_KEY_NOT_FOUND: "API Key Not Found",
    ErrorCode.VALIDATION_ERROR: "Validation Error",
    ErrorCode.INVALID_REQUEST: "Invalid Request",
    ErrorCode.INVALID_PARAMETER: "Invalid Parameter",
    ErrorCode.INVALID_SCOPE: "Invalid Scope",
    ErrorCode.INVALID_SEVERITY: "Invalid Severity",
    ErrorCode.INVALID_STATUS: "Invalid Status",
    ErrorCode.RESOURCE_CONFLICT: "Resource Conflict",
    ErrorCode.DUPLICATE_RESOURCE: "Duplicate Resource",
    ErrorCode.RATE_LIMIT_EXCEEDED: "Rate Limit Exceeded",
    ErrorCode.INTERNAL_ERROR: "Internal Server Error",
    ErrorCode.DATABASE_ERROR: "Database Error",
    ErrorCode.EXTERNAL_SERVICE_ERROR: "External Service Error",
    ErrorCode.SERVICE_UNAVAILABLE: "Service Unavailable",
}


class APIError(HTTPException):
    """
    Custom API exception that generates RFC 7807 Problem Details.
    """

    def __init__(
        self,
        code: ErrorCode,
        detail: str,
        errors: list[dict[str, Any]] | None = None,
        headers: dict[str, str] | None = None,
    ):
        self.code = code
        self.error_detail = detail
        self.errors = errors
        status_code = ERROR_STATUS_MAP.get(code, 500)
        super().__init__(status_code=status_code, detail=detail, headers=headers)


def create_problem_detail(
    code: ErrorCode,
    detail: str,
    request: Request | None = None,
    errors: list[dict[str, Any]] | None = None,
) -> ProblemDetail:
    """Create a ProblemDetail response."""
    status = ERROR_STATUS_MAP.get(code, 500)
    title = ERROR_TITLES.get(code, "Error")

    request_id = None
    instance = None
    if request:
        request_id = getattr(request.state, "request_id", None)
        instance = str(request.url.path)

    return ProblemDetail(
        type=f"{ERROR_TYPE_BASE}/{code.value}",
        title=title,
        status=status,
        detail=detail,
        instance=instance,
        code=code.value,
        request_id=request_id,
        errors=errors,
        documentation_url=f"https://docs.cerebro.io/errors/{code.value.lower()}",
    )


def problem_detail_response(
    code: ErrorCode,
    detail: str,
    request: Request | None = None,
    errors: list[dict[str, Any]] | None = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    """Create a JSONResponse with Problem Details."""
    problem = create_problem_detail(code, detail, request, errors)

    response_headers = {"Content-Type": "application/problem+json"}
    if headers:
        response_headers.update(headers)

    return JSONResponse(
        status_code=problem.status,
        content=problem.model_dump(exclude_none=True),
        headers=response_headers,
    )


# Exception handlers for FastAPI


async def api_error_handler(request: Request, exc: APIError) -> JSONResponse:
    """Handle APIError exceptions."""
    return problem_detail_response(
        code=exc.code,
        detail=exc.error_detail,
        request=request,
        errors=exc.errors,
        headers=exc.headers,
    )


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Handle standard HTTPException with Problem Details format."""
    # Map HTTP status codes to error codes
    code_map = {
        400: ErrorCode.INVALID_REQUEST,
        401: ErrorCode.INVALID_CREDENTIALS,
        403: ErrorCode.INSUFFICIENT_PERMISSIONS,
        404: ErrorCode.RESOURCE_NOT_FOUND,
        409: ErrorCode.RESOURCE_CONFLICT,
        422: ErrorCode.VALIDATION_ERROR,
        429: ErrorCode.RATE_LIMIT_EXCEEDED,
        500: ErrorCode.INTERNAL_ERROR,
        502: ErrorCode.EXTERNAL_SERVICE_ERROR,
        503: ErrorCode.SERVICE_UNAVAILABLE,
    }

    code = code_map.get(exc.status_code, ErrorCode.INTERNAL_ERROR)
    detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)

    return problem_detail_response(
        code=code,
        detail=detail,
        request=request,
        headers=exc.headers,
    )


async def validation_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    """Handle Pydantic validation errors."""
    from fastapi.exceptions import RequestValidationError

    if isinstance(exc, RequestValidationError):
        errors = []
        for error in exc.errors():
            loc = ".".join(str(part) for part in error["loc"])
            errors.append({
                "field": loc,
                "message": error["msg"],
                "type": error["type"],
            })

        return problem_detail_response(
            code=ErrorCode.VALIDATION_ERROR,
            detail="Request validation failed",
            request=request,
            errors=errors,
        )

    return problem_detail_response(
        code=ErrorCode.INTERNAL_ERROR,
        detail="An unexpected error occurred",
        request=request,
    )


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle unexpected exceptions."""
    import structlog

    logger = structlog.get_logger(__name__)
    request_id = getattr(request.state, "request_id", None)

    logger.exception(
        "unhandled_exception",
        request_id=request_id,
        error=str(exc),
        path=str(request.url.path),
    )

    return problem_detail_response(
        code=ErrorCode.INTERNAL_ERROR,
        detail="An unexpected error occurred",
        request=request,
    )


# Convenience functions for raising common errors


def raise_not_found(resource: str, resource_id: Any) -> None:
    """Raise a not found error."""
    code_map = {
        "organization": ErrorCode.ORGANIZATION_NOT_FOUND,
        "finding": ErrorCode.FINDING_NOT_FOUND,
        "account": ErrorCode.ACCOUNT_NOT_FOUND,
        "rule": ErrorCode.RULE_NOT_FOUND,
        "user": ErrorCode.USER_NOT_FOUND,
        "api_key": ErrorCode.API_KEY_NOT_FOUND,
    }
    code = code_map.get(resource.lower(), ErrorCode.RESOURCE_NOT_FOUND)
    raise APIError(
        code=code,
        detail=f"{resource.capitalize()} with ID '{resource_id}' not found",
    )


def raise_forbidden(message: str = "Access denied") -> None:
    """Raise a forbidden error."""
    raise APIError(
        code=ErrorCode.INSUFFICIENT_PERMISSIONS,
        detail=message,
    )


def raise_validation_error(message: str, errors: list[dict] | None = None) -> None:
    """Raise a validation error."""
    raise APIError(
        code=ErrorCode.VALIDATION_ERROR,
        detail=message,
        errors=errors,
    )
