"""API Key usage tracking and metrics.

This module provides usage tracking for API keys with support for:
- In-memory metrics (default, suitable for development)
- Redis-backed metrics (production, distributed)
- CloudWatch metrics (optional, for AWS deployments)
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class EndpointStats:
    """Statistics for a single endpoint."""

    endpoint: str
    method: str
    total_requests: int = 0
    total_errors: int = 0
    total_latency_ms: float = 0.0

    @property
    def avg_latency_ms(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.total_latency_ms / self.total_requests

    @property
    def error_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.total_errors / self.total_requests


@dataclass
class UsageWindow:
    """Usage statistics for a time window."""

    start_time: datetime
    end_time: datetime
    total_requests: int = 0
    total_errors: int = 0
    total_latency_ms: float = 0.0
    endpoints: dict[str, EndpointStats] = field(default_factory=dict)

    def record_request(
        self,
        endpoint: str,
        method: str,
        latency_ms: float,
        is_error: bool = False,
    ) -> None:
        """Record a request in this window."""
        self.total_requests += 1
        self.total_latency_ms += latency_ms
        if is_error:
            self.total_errors += 1

        key = f"{method}:{endpoint}"
        if key not in self.endpoints:
            self.endpoints[key] = EndpointStats(endpoint=endpoint, method=method)

        stats = self.endpoints[key]
        stats.total_requests += 1
        stats.total_latency_ms += latency_ms
        if is_error:
            stats.total_errors += 1


@dataclass
class APIKeyUsageMetrics:
    """Complete usage metrics for an API key."""

    key_id: UUID
    total_requests: int = 0
    requests_last_hour: int = 0
    requests_last_24h: int = 0
    requests_last_7d: int = 0
    requests_last_30d: int = 0
    avg_latency_ms: float = 0.0
    error_rate: float = 0.0
    top_endpoints: list[dict[str, Any]] = field(default_factory=list)
    requests_by_hour: list[dict[str, Any]] = field(default_factory=list)
    rate_limit_hits: int = 0
    last_request_at: datetime | None = None


class UsageTracker(ABC):
    """Abstract base class for API key usage tracking."""

    @abstractmethod
    async def record_request(
        self,
        key_id: UUID,
        org_id: UUID,
        endpoint: str,
        method: str,
        latency_ms: float,
        status_code: int,
        ip_address: str | None = None,
    ) -> None:
        """Record an API request."""
        pass

    @abstractmethod
    async def get_metrics(self, key_id: UUID) -> APIKeyUsageMetrics:
        """Get usage metrics for an API key."""
        pass

    @abstractmethod
    async def get_rate_limit_remaining(
        self,
        key_id: UUID,
        rate_limit: int,
        window_seconds: int = 60,
    ) -> int:
        """Get remaining requests in current rate limit window."""
        pass

    @abstractmethod
    async def record_rate_limit_hit(self, key_id: UUID) -> None:
        """Record a rate limit hit."""
        pass


class InMemoryUsageTracker(UsageTracker):
    """In-memory usage tracker for development and testing."""

    def __init__(self, max_windows: int = 720) -> None:  # 720 hours = 30 days
        self._windows: dict[UUID, dict[datetime, UsageWindow]] = defaultdict(dict)
        self._rate_limit_counters: dict[UUID, dict[datetime, int]] = defaultdict(dict)
        self._rate_limit_hits: dict[UUID, int] = defaultdict(int)
        self._last_request: dict[UUID, datetime] = {}
        self._max_windows = max_windows
        self._lock = asyncio.Lock()

    def _get_hour_key(self, dt: datetime) -> datetime:
        """Get the hour key for a datetime."""
        return dt.replace(minute=0, second=0, microsecond=0)

    def _get_minute_key(self, dt: datetime) -> datetime:
        """Get the minute key for a datetime."""
        return dt.replace(second=0, microsecond=0)

    async def record_request(
        self,
        key_id: UUID,
        org_id: UUID,
        endpoint: str,
        method: str,
        latency_ms: float,
        status_code: int,
        ip_address: str | None = None,
    ) -> None:
        """Record an API request."""
        async with self._lock:
            now = datetime.now(UTC)
            hour_key = self._get_hour_key(now)

            # Get or create window
            windows = self._windows[key_id]
            if hour_key not in windows:
                windows[hour_key] = UsageWindow(
                    start_time=hour_key,
                    end_time=hour_key + timedelta(hours=1),
                )

            # Record the request
            is_error = status_code >= 400
            windows[hour_key].record_request(endpoint, method, latency_ms, is_error)

            # Update rate limit counter
            minute_key = self._get_minute_key(now)
            if minute_key not in self._rate_limit_counters[key_id]:
                self._rate_limit_counters[key_id][minute_key] = 0
            self._rate_limit_counters[key_id][minute_key] += 1

            # Update last request time
            self._last_request[key_id] = now

            # Cleanup old windows
            self._cleanup_old_data(key_id, now)

    def _cleanup_old_data(self, key_id: UUID, now: datetime) -> None:
        """Remove old data beyond retention period."""
        cutoff = now - timedelta(hours=self._max_windows)

        # Clean windows
        windows = self._windows[key_id]
        old_keys = [k for k in windows if k < cutoff]
        for key in old_keys:
            del windows[key]

        # Clean rate limit counters (keep only last hour)
        rate_cutoff = now - timedelta(hours=1)
        counters = self._rate_limit_counters[key_id]
        old_counters = [k for k in counters if k < rate_cutoff]
        for key in old_counters:
            del counters[key]

    async def get_metrics(self, key_id: UUID) -> APIKeyUsageMetrics:
        """Get usage metrics for an API key."""
        async with self._lock:
            now = datetime.now(UTC)
            windows = self._windows.get(key_id, {})

            # Calculate time boundaries
            hour_ago = now - timedelta(hours=1)
            day_ago = now - timedelta(days=1)
            week_ago = now - timedelta(days=7)
            month_ago = now - timedelta(days=30)

            # Aggregate metrics
            total_requests = 0
            requests_last_hour = 0
            requests_last_24h = 0
            requests_last_7d = 0
            requests_last_30d = 0
            total_latency = 0.0
            total_errors = 0
            endpoint_totals: dict[str, EndpointStats] = {}
            requests_by_hour: list[dict[str, Any]] = []

            for hour_key, window in sorted(windows.items()):
                total_requests += window.total_requests
                total_latency += window.total_latency_ms
                total_errors += window.total_errors

                if hour_key >= hour_ago:
                    requests_last_hour += window.total_requests
                if hour_key >= day_ago:
                    requests_last_24h += window.total_requests
                if hour_key >= week_ago:
                    requests_last_7d += window.total_requests
                if hour_key >= month_ago:
                    requests_last_30d += window.total_requests

                # Aggregate endpoint stats
                for key, stats in window.endpoints.items():
                    if key not in endpoint_totals:
                        endpoint_totals[key] = EndpointStats(
                            endpoint=stats.endpoint,
                            method=stats.method,
                        )
                    endpoint_totals[key].total_requests += stats.total_requests
                    endpoint_totals[key].total_errors += stats.total_errors
                    endpoint_totals[key].total_latency_ms += stats.total_latency_ms

                # Add to hourly breakdown (last 24 hours only)
                if hour_key >= day_ago:
                    requests_by_hour.append({
                        "hour": hour_key.isoformat(),
                        "requests": window.total_requests,
                        "errors": window.total_errors,
                    })

            # Calculate top endpoints
            top_endpoints = sorted(
                endpoint_totals.values(),
                key=lambda x: x.total_requests,
                reverse=True,
            )[:10]

            return APIKeyUsageMetrics(
                key_id=key_id,
                total_requests=total_requests,
                requests_last_hour=requests_last_hour,
                requests_last_24h=requests_last_24h,
                requests_last_7d=requests_last_7d,
                requests_last_30d=requests_last_30d,
                avg_latency_ms=total_latency / total_requests if total_requests > 0 else 0.0,
                error_rate=total_errors / total_requests if total_requests > 0 else 0.0,
                top_endpoints=[
                    {
                        "endpoint": e.endpoint,
                        "method": e.method,
                        "requests": e.total_requests,
                        "avg_latency_ms": e.avg_latency_ms,
                        "error_rate": e.error_rate,
                    }
                    for e in top_endpoints
                ],
                requests_by_hour=requests_by_hour,
                rate_limit_hits=self._rate_limit_hits.get(key_id, 0),
                last_request_at=self._last_request.get(key_id),
            )

    async def get_rate_limit_remaining(
        self,
        key_id: UUID,
        rate_limit: int,
        window_seconds: int = 60,
    ) -> int:
        """Get remaining requests in current rate limit window."""
        async with self._lock:
            now = datetime.now(UTC)
            minute_key = self._get_minute_key(now)
            current_count = self._rate_limit_counters[key_id].get(minute_key, 0)
            return max(0, rate_limit - current_count)

    async def record_rate_limit_hit(self, key_id: UUID) -> None:
        """Record a rate limit hit."""
        async with self._lock:
            self._rate_limit_hits[key_id] += 1


class RedisUsageTracker(UsageTracker):
    """Redis-backed usage tracker for production deployments."""

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        key_prefix: str = "cerebro:api_usage:",
        retention_days: int = 30,
    ) -> None:
        self._redis_url = redis_url
        self._key_prefix = key_prefix
        self._retention_days = retention_days
        self._redis: Any = None

    async def _get_redis(self) -> Any:
        """Get or create Redis connection."""
        if self._redis is None:
            try:
                import redis.asyncio as redis
                self._redis = redis.from_url(self._redis_url)
            except ImportError:
                logger.warning("redis package not installed, falling back to in-memory")
                raise
        return self._redis

    def _hour_key(self, key_id: UUID, dt: datetime) -> str:
        """Get Redis key for hourly metrics."""
        hour = dt.strftime("%Y%m%d%H")
        return f"{self._key_prefix}hour:{key_id}:{hour}"

    def _rate_key(self, key_id: UUID, dt: datetime) -> str:
        """Get Redis key for rate limiting."""
        minute = dt.strftime("%Y%m%d%H%M")
        return f"{self._key_prefix}rate:{key_id}:{minute}"

    async def record_request(
        self,
        key_id: UUID,
        org_id: UUID,
        endpoint: str,
        method: str,
        latency_ms: float,
        status_code: int,
        ip_address: str | None = None,
    ) -> None:
        """Record an API request."""
        try:
            redis_client = await self._get_redis()
            now = datetime.now(UTC)

            # Increment hourly counters
            hour_key = self._hour_key(key_id, now)
            is_error = 1 if status_code >= 400 else 0

            pipe = redis_client.pipeline()
            pipe.hincrby(hour_key, "requests", 1)
            pipe.hincrbyfloat(hour_key, "latency", latency_ms)
            pipe.hincrby(hour_key, "errors", is_error)
            pipe.hincrby(hour_key, f"endpoint:{method}:{endpoint}", 1)
            pipe.expire(hour_key, self._retention_days * 24 * 3600)

            # Increment rate limit counter
            rate_key = self._rate_key(key_id, now)
            pipe.incr(rate_key)
            pipe.expire(rate_key, 120)  # 2 minutes TTL

            # Update last request timestamp
            pipe.set(f"{self._key_prefix}last:{key_id}", now.isoformat())

            await pipe.execute()

        except Exception as e:
            logger.warning("Failed to record API usage", error=str(e))

    async def get_metrics(self, key_id: UUID) -> APIKeyUsageMetrics:
        """Get usage metrics for an API key."""
        try:
            redis_client = await self._get_redis()
            now = datetime.now(UTC)

            # Collect metrics from hourly buckets
            total_requests = 0
            requests_last_hour = 0
            requests_last_24h = 0
            requests_last_7d = 0
            requests_last_30d = 0
            total_latency = 0.0
            total_errors = 0
            endpoint_totals: dict[str, dict[str, Any]] = {}
            requests_by_hour: list[dict[str, Any]] = []

            for hours_ago in range(self._retention_days * 24):
                check_time = now - timedelta(hours=hours_ago)
                hour_key = self._hour_key(key_id, check_time)

                data = await redis_client.hgetall(hour_key)
                if not data:
                    continue

                requests = int(data.get(b"requests", 0))
                latency = float(data.get(b"latency", 0))
                errors = int(data.get(b"errors", 0))

                total_requests += requests
                total_latency += latency
                total_errors += errors

                if hours_ago < 1:
                    requests_last_hour += requests
                if hours_ago < 24:
                    requests_last_24h += requests
                    requests_by_hour.append({
                        "hour": check_time.replace(minute=0, second=0, microsecond=0).isoformat(),
                        "requests": requests,
                        "errors": errors,
                    })
                if hours_ago < 168:  # 7 days
                    requests_last_7d += requests
                requests_last_30d += requests

                # Aggregate endpoint stats
                for key, value in data.items():
                    key_str = key.decode() if isinstance(key, bytes) else key
                    if key_str.startswith("endpoint:"):
                        parts = key_str.split(":", 2)
                        if len(parts) == 3:
                            method, endpoint = parts[1], parts[2]
                            ep_key = f"{method}:{endpoint}"
                            if ep_key not in endpoint_totals:
                                endpoint_totals[ep_key] = {
                                    "method": method,
                                    "endpoint": endpoint,
                                    "requests": 0,
                                }
                            endpoint_totals[ep_key]["requests"] += int(value)

            # Get rate limit hits
            rate_limit_hits = int(
                await redis_client.get(f"{self._key_prefix}rate_hits:{key_id}") or 0
            )

            # Get last request time
            last_request_str = await redis_client.get(f"{self._key_prefix}last:{key_id}")
            last_request = (
                datetime.fromisoformat(last_request_str.decode())
                if last_request_str
                else None
            )

            # Sort endpoints by request count
            top_endpoints = sorted(
                endpoint_totals.values(),
                key=lambda x: x["requests"],
                reverse=True,
            )[:10]

            return APIKeyUsageMetrics(
                key_id=key_id,
                total_requests=total_requests,
                requests_last_hour=requests_last_hour,
                requests_last_24h=requests_last_24h,
                requests_last_7d=requests_last_7d,
                requests_last_30d=requests_last_30d,
                avg_latency_ms=total_latency / total_requests if total_requests > 0 else 0.0,
                error_rate=total_errors / total_requests if total_requests > 0 else 0.0,
                top_endpoints=top_endpoints,
                requests_by_hour=sorted(requests_by_hour, key=lambda x: x["hour"]),
                rate_limit_hits=rate_limit_hits,
                last_request_at=last_request,
            )

        except Exception as e:
            logger.warning("Failed to get API usage metrics", error=str(e))
            return APIKeyUsageMetrics(key_id=key_id)

    async def get_rate_limit_remaining(
        self,
        key_id: UUID,
        rate_limit: int,
        window_seconds: int = 60,
    ) -> int:
        """Get remaining requests in current rate limit window."""
        try:
            redis_client = await self._get_redis()
            now = datetime.now(UTC)
            rate_key = self._rate_key(key_id, now)
            current_count = int(await redis_client.get(rate_key) or 0)
            return max(0, rate_limit - current_count)
        except Exception as e:
            logger.warning("Failed to get rate limit", error=str(e))
            return rate_limit  # Allow request on error

    async def record_rate_limit_hit(self, key_id: UUID) -> None:
        """Record a rate limit hit."""
        try:
            redis_client = await self._get_redis()
            await redis_client.incr(f"{self._key_prefix}rate_hits:{key_id}")
        except Exception as e:
            logger.warning("Failed to record rate limit hit", error=str(e))


# Global usage tracker instance
_usage_tracker: UsageTracker | None = None


def get_usage_tracker() -> UsageTracker:
    """Get the global usage tracker instance."""
    global _usage_tracker
    if _usage_tracker is None:
        # Default to in-memory tracker
        # In production, configure RedisUsageTracker via environment
        _usage_tracker = InMemoryUsageTracker()
    return _usage_tracker


def set_usage_tracker(tracker: UsageTracker) -> None:
    """Set the global usage tracker instance."""
    global _usage_tracker
    _usage_tracker = tracker


async def record_api_request(
    key_id: UUID,
    org_id: UUID,
    endpoint: str,
    method: str,
    latency_ms: float,
    status_code: int,
    ip_address: str | None = None,
) -> None:
    """Convenience function to record an API request."""
    tracker = get_usage_tracker()
    await tracker.record_request(
        key_id, org_id, endpoint, method, latency_ms, status_code, ip_address
    )


async def get_api_key_metrics(key_id: UUID) -> APIKeyUsageMetrics:
    """Convenience function to get API key metrics."""
    tracker = get_usage_tracker()
    return await tracker.get_metrics(key_id)
