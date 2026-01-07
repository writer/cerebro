"""API versioning and deprecation handling for Cerebro API.

This module provides:
- API version headers
- Deprecation warnings
- Sunset headers for deprecated endpoints
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import date, datetime

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = structlog.get_logger(__name__)

# Current API version
CURRENT_API_VERSION = "1.0.0"

# Standard headers
API_VERSION_HEADER = "X-API-Version"
DEPRECATION_HEADER = "Deprecation"
SUNSET_HEADER = "Sunset"
LINK_HEADER = "Link"


class DeprecatedEndpoint:
    """Configuration for a deprecated endpoint."""

    def __init__(
        self,
        path: str,
        deprecated_date: date,
        sunset_date: date | None = None,
        replacement: str | None = None,
        message: str | None = None,
    ):
        self.path = path
        self.deprecated_date = deprecated_date
        self.sunset_date = sunset_date
        self.replacement = replacement
        self.message = message


# Registry of deprecated endpoints
DEPRECATED_ENDPOINTS: dict[str, DeprecatedEndpoint] = {
    # Example: V1 endpoints being replaced by V2
    "/api/v1/organizations": DeprecatedEndpoint(
        path="/api/v1/organizations",
        deprecated_date=date(2025, 1, 1),
        sunset_date=date(2026, 7, 1),
        replacement="/api/v2/organizations",
        message="This endpoint is deprecated. Please migrate to /api/v2/organizations",
    ),
    "/api/v1/findings": DeprecatedEndpoint(
        path="/api/v1/findings",
        deprecated_date=date(2025, 1, 1),
        sunset_date=date(2026, 7, 1),
        replacement="/api/v2/findings",
        message="This endpoint is deprecated. Please migrate to /api/v2/findings",
    ),
}


class APIVersionMiddleware(BaseHTTPMiddleware):
    """
    Middleware that adds API version headers and deprecation warnings.
    """

    def __init__(
        self,
        app: ASGIApp,
        version: str = CURRENT_API_VERSION,
    ):
        super().__init__(app)
        self.version = version

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # Always add API version header
        response.headers[API_VERSION_HEADER] = self.version

        # Check for deprecation
        path = request.url.path
        deprecation = self._get_deprecation_info(path)

        if deprecation:
            self._add_deprecation_headers(response, deprecation)

            # Log deprecation usage
            logger.warning(
                "deprecated_endpoint_accessed",
                path=path,
                deprecated_date=deprecation.deprecated_date.isoformat(),
                sunset_date=deprecation.sunset_date.isoformat() if deprecation.sunset_date else None,
                replacement=deprecation.replacement,
            )

        return response

    def _get_deprecation_info(self, path: str) -> DeprecatedEndpoint | None:
        """Check if a path matches a deprecated endpoint."""
        # Exact match
        if path in DEPRECATED_ENDPOINTS:
            return DEPRECATED_ENDPOINTS[path]

        # Prefix match for parameterized paths
        for deprecated_path, info in DEPRECATED_ENDPOINTS.items():
            if path.startswith(deprecated_path):
                return info

        return None

    def _add_deprecation_headers(
        self,
        response: Response,
        deprecation: DeprecatedEndpoint,
    ) -> None:
        """Add deprecation headers to response."""
        # Deprecation header (RFC draft)
        response.headers[DEPRECATION_HEADER] = deprecation.deprecated_date.isoformat()

        # Sunset header (RFC 8594)
        if deprecation.sunset_date:
            # Format as HTTP-date (RFC 7231)
            sunset_dt = datetime.combine(deprecation.sunset_date, datetime.min.time())
            response.headers[SUNSET_HEADER] = sunset_dt.strftime("%a, %d %b %Y %H:%M:%S GMT")

        # Link header to replacement
        if deprecation.replacement:
            link_value = f'<{deprecation.replacement}>; rel="successor-version"'
            existing_link = response.headers.get(LINK_HEADER)
            if existing_link:
                response.headers[LINK_HEADER] = f"{existing_link}, {link_value}"
            else:
                response.headers[LINK_HEADER] = link_value

        # Custom deprecation message header
        if deprecation.message:
            response.headers["X-Deprecation-Notice"] = deprecation.message


def register_deprecated_endpoint(
    path: str,
    deprecated_date: date,
    sunset_date: date | None = None,
    replacement: str | None = None,
    message: str | None = None,
) -> None:
    """
    Register an endpoint as deprecated.

    Args:
        path: The endpoint path (can be a prefix)
        deprecated_date: Date when deprecation was announced
        sunset_date: Date when endpoint will be removed
        replacement: Path to the replacement endpoint
        message: Custom deprecation message
    """
    DEPRECATED_ENDPOINTS[path] = DeprecatedEndpoint(
        path=path,
        deprecated_date=deprecated_date,
        sunset_date=sunset_date,
        replacement=replacement,
        message=message,
    )


def mark_deprecated(
    deprecated_date: date,
    sunset_date: date | None = None,
    replacement: str | None = None,
    message: str | None = None,
):
    """
    Decorator to mark an endpoint as deprecated.

    Usage:
        @router.get("/old-endpoint")
        @mark_deprecated(
            deprecated_date=date(2025, 1, 1),
            sunset_date=date(2026, 1, 1),
            replacement="/api/v2/new-endpoint",
        )
        async def old_endpoint():
            ...
    """
    def decorator(func: Callable) -> Callable:
        # Store deprecation info on the function
        func._deprecation_info = {
            "deprecated_date": deprecated_date,
            "sunset_date": sunset_date,
            "replacement": replacement,
            "message": message,
        }
        return func
    return decorator


# Version negotiation support

SUPPORTED_VERSIONS = ["1.0", "2.0"]
DEFAULT_VERSION = "1.0"


def get_requested_version(request: Request) -> str:
    """
    Get the API version requested by the client.

    Checks in order:
    1. X-API-Version header
    2. Accept header (e.g., application/vnd.cerebro.v2+json)
    3. URL path (e.g., /api/v2/...)
    4. Default version
    """
    # Check header
    header_version = request.headers.get("X-API-Version")
    if header_version and header_version in SUPPORTED_VERSIONS:
        return header_version

    # Check Accept header
    accept = request.headers.get("Accept", "")
    if "vnd.cerebro.v" in accept:
        # Parse version from accept header
        import re
        match = re.search(r"vnd\.cerebro\.v(\d+)", accept)
        if match:
            version = f"{match.group(1)}.0"
            if version in SUPPORTED_VERSIONS:
                return version

    # Check URL path
    path = request.url.path
    if "/api/v2/" in path:
        return "2.0"
    elif "/api/v1/" in path:
        return "1.0"

    return DEFAULT_VERSION


# OpenAPI schema version info
def get_version_info() -> dict:
    """Get version information for OpenAPI schema."""
    return {
        "version": CURRENT_API_VERSION,
        "supported_versions": SUPPORTED_VERSIONS,
        "default_version": DEFAULT_VERSION,
        "deprecations": [
            {
                "path": dep.path,
                "deprecated_date": dep.deprecated_date.isoformat(),
                "sunset_date": dep.sunset_date.isoformat() if dep.sunset_date else None,
                "replacement": dep.replacement,
            }
            for dep in DEPRECATED_ENDPOINTS.values()
        ],
    }
