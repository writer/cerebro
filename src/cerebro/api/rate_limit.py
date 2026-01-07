"""Rate limiting with transparent headers for Cerebro API.

This module provides rate limiting with standard headers that communicate
limits to API consumers.
"""

from __future__ import annotations

import time
from collections.abc import Callable

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = structlog.get_logger(__name__)

# Standard rate limit headers
RATELIMIT_LIMIT = "X-RateLimit-Limit"
RATELIMIT_REMAINING = "X-RateLimit-Remaining"
RATELIMIT_RESET = "X-RateLimit-Reset"
RATELIMIT_POLICY = "X-RateLimit-Policy"
RETRY_AFTER = "Retry-After"


class RateLimitHeaders:
    """Container for rate limit header values."""

    def __init__(
        self,
        limit: int,
        remaining: int,
        reset: int,
        policy: str | None = None,
    ):
        self.limit = limit
        self.remaining = remaining
        self.reset = reset
        self.policy = policy

    def apply_to_response(self, response: Response) -> None:
        """Add rate limit headers to a response."""
        response.headers[RATELIMIT_LIMIT] = str(self.limit)
        response.headers[RATELIMIT_REMAINING] = str(self.remaining)
        response.headers[RATELIMIT_RESET] = str(self.reset)

        if self.policy:
            response.headers[RATELIMIT_POLICY] = self.policy


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware that adds rate limit headers to responses.

    Works with SlowAPI's rate limiting to provide transparency.
    """

    def __init__(
        self,
        app: ASGIApp,
        default_limit: int = 100,
        window_seconds: int = 60,
    ):
        super().__init__(app)
        self.default_limit = default_limit
        self.window_seconds = window_seconds

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # Check if SlowAPI already set rate limit info
        limiter = getattr(request.app.state, "limiter", None)
        if limiter:
            # Try to get rate limit state from request
            rate_limit_state = getattr(request.state, "_rate_limit_state", None)
            if rate_limit_state:
                headers = RateLimitHeaders(
                    limit=rate_limit_state.get("limit", self.default_limit),
                    remaining=rate_limit_state.get("remaining", self.default_limit),
                    reset=rate_limit_state.get("reset", int(time.time()) + self.window_seconds),
                    policy=f"{self.default_limit};w={self.window_seconds}",
                )
                headers.apply_to_response(response)
            else:
                # No rate limit state, add default headers
                reset_time = int(time.time()) + self.window_seconds
                headers = RateLimitHeaders(
                    limit=self.default_limit,
                    remaining=self.default_limit,
                    reset=reset_time,
                    policy=f"{self.default_limit};w={self.window_seconds}",
                )
                headers.apply_to_response(response)

        return response


def add_rate_limit_headers(
    response: Response,
    limit: int,
    remaining: int,
    reset_timestamp: int,
    policy: str | None = None,
) -> None:
    """
    Manually add rate limit headers to a response.

    Args:
        response: FastAPI/Starlette Response object
        limit: Maximum requests allowed in the window
        remaining: Requests remaining in current window
        reset_timestamp: Unix timestamp when the window resets
        policy: Optional policy string (e.g., "100;w=60")
    """
    headers = RateLimitHeaders(
        limit=limit,
        remaining=remaining,
        reset=reset_timestamp,
        policy=policy,
    )
    headers.apply_to_response(response)


def create_rate_limit_exceeded_response(
    limit: int,
    reset_timestamp: int,
    retry_after: int,
) -> dict:
    """
    Create a rate limit exceeded error response body.

    Returns a dict suitable for JSONResponse.
    """
    return {
        "type": "https://api.cerebro.io/errors/RATE_LIMIT_EXCEEDED",
        "title": "Rate Limit Exceeded",
        "status": 429,
        "detail": f"You have exceeded the rate limit of {limit} requests. Please retry after {retry_after} seconds.",
        "code": "RATE_LIMIT_EXCEEDED",
        "limit": limit,
        "reset": reset_timestamp,
        "retry_after": retry_after,
    }


# Tier-based rate limits
RATE_LIMIT_TIERS = {
    "free": {
        "requests_per_minute": 60,
        "requests_per_hour": 1000,
        "requests_per_day": 10000,
    },
    "starter": {
        "requests_per_minute": 100,
        "requests_per_hour": 5000,
        "requests_per_day": 50000,
    },
    "professional": {
        "requests_per_minute": 300,
        "requests_per_hour": 15000,
        "requests_per_day": 150000,
    },
    "enterprise": {
        "requests_per_minute": 1000,
        "requests_per_hour": 50000,
        "requests_per_day": 500000,
    },
}


def get_rate_limit_for_tier(tier: str, window: str = "minute") -> int:
    """
    Get rate limit for a pricing tier.

    Args:
        tier: Pricing tier (free, starter, professional, enterprise)
        window: Time window (minute, hour, day)

    Returns:
        Rate limit for the tier and window
    """
    tier_limits = RATE_LIMIT_TIERS.get(tier.lower(), RATE_LIMIT_TIERS["free"])
    key = f"requests_per_{window}"
    return tier_limits.get(key, 60)


# Endpoint-specific rate limits for expensive operations
ENDPOINT_RATE_LIMITS = {
    # Heavy computation endpoints
    "/api/v1/attack-path/analyze": {"limit": 10, "window": 60},
    "/api/v1/blast-radius": {"limit": 20, "window": 60},
    "/api/v1/what-if": {"limit": 20, "window": 60},

    # Bulk operations
    "/api/v1/findings/organizations/{org_id}/generate": {"limit": 5, "window": 300},
    "/api/v1/collectors/organizations/{org_id}/collect": {"limit": 10, "window": 300},

    # Export operations
    "/api/v1/compliance/export": {"limit": 10, "window": 60},
    "/api/v1/analytics/export": {"limit": 10, "window": 60},

    # Auth endpoints (stricter to prevent brute force)
    "/api/v1/auth/login": {"limit": 10, "window": 60},
    "/api/v1/auth/token": {"limit": 10, "window": 60},
}


def get_endpoint_rate_limit(path: str) -> dict | None:
    """
    Get specific rate limit for an endpoint.

    Args:
        path: Request path (may include path parameters)

    Returns:
        Dict with 'limit' and 'window' keys, or None for default limits
    """
    # Check exact match first
    if path in ENDPOINT_RATE_LIMITS:
        return ENDPOINT_RATE_LIMITS[path]

    # Check pattern matches (simple prefix matching)
    for pattern, limits in ENDPOINT_RATE_LIMITS.items():
        if "{" in pattern:
            # Convert pattern to prefix for matching
            prefix = pattern.split("{")[0]
            if path.startswith(prefix):
                return limits

    return None
