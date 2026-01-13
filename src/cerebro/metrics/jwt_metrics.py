"""Metrics for JWT operations."""

import time
from collections.abc import Generator
from contextlib import contextmanager

from prometheus_client import Counter, Gauge, Histogram

from .collection_metrics import cerebro_registry

# JWT token metrics
jwt_tokens_issued = Counter(
    "cerebro_jwt_tokens_issued_total",
    "Total number of JWT tokens issued",
    ["algorithm", "key_id"],
    registry=cerebro_registry,
)

jwt_tokens_verified = Counter(
    "cerebro_jwt_tokens_verified_total",
    "Total number of JWT token verifications",
    ["result", "algorithm", "key_id"],  # success, expired, invalid, revoked
    registry=cerebro_registry,
)

jwt_verification_duration = Histogram(
    "cerebro_jwt_verification_duration_seconds",
    "Time spent verifying JWT tokens",
    ["result"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25),
    registry=cerebro_registry,
)

# Key rotation metrics
jwt_key_rotations = Counter(
    "cerebro_jwt_key_rotations_total",
    "Total number of JWT key rotations",
    ["status"],  # success, failed
    registry=cerebro_registry,
)

jwt_active_keys = Gauge(
    "cerebro_jwt_active_keys",
    "Number of active JWT signing keys",
    registry=cerebro_registry,
)

jwks_cache_hits = Counter(
    "cerebro_jwks_cache_hits_total",
    "JWKS cache hits and misses",
    ["result"],  # hit, miss
    registry=cerebro_registry,
)

# Token revocation metrics
jwt_tokens_revoked = Counter(
    "cerebro_jwt_tokens_revoked_total",
    "Total number of revoked JWT tokens",
    ["reason"],  # logout, admin_action, security_incident
    registry=cerebro_registry,
)

jwt_revocation_list_size = Gauge(
    "cerebro_jwt_revocation_list_size",
    "Current size of JWT token revocation list",
    registry=cerebro_registry,
)

# JWKS endpoint metrics
jwks_requests = Counter(
    "cerebro_jwks_requests_total",
    "Total requests to JWKS endpoint",
    ["status_code"],
    registry=cerebro_registry,
)

jwks_response_time = Histogram(
    "cerebro_jwks_response_time_seconds",
    "JWKS endpoint response time",
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1),
    registry=cerebro_registry,
)

jwt_public_key_cache_hits = Counter(
    "cerebro_jwt_public_key_cache_total",
    "JWT public key cache hits and misses",
    ["result"],  # hit, miss, expired
    registry=cerebro_registry,
)


class JwtMetrics:
    """Helper class for JWT metrics."""

    @staticmethod
    def record_token_issued(algorithm: str, key_id: str) -> None:
        """Record JWT token issuance."""
        jwt_tokens_issued.labels(algorithm=algorithm, key_id=key_id).inc()

    @staticmethod
    @contextmanager
    def time_token_verification(algorithm: str = "unknown", key_id: str = "unknown") -> Generator[None, None, None]:
        """Context manager to time token verification."""
        start_time = time.time()
        result = "unknown"

        try:
            yield
            result = "success"
        except Exception as e:
            # Determine verification failure reason
            error_msg = str(e).lower()
            if "expired" in error_msg:
                result = "expired"
            elif "revoked" in error_msg:
                result = "revoked"
            else:
                result = "invalid"
            raise
        finally:
            duration = time.time() - start_time
            jwt_tokens_verified.labels(
                result=result, algorithm=algorithm, key_id=key_id
            ).inc()
            jwt_verification_duration.labels(result=result).observe(duration)

    @staticmethod
    def record_token_verified(result: str, algorithm: str, key_id: str) -> None:
        """Record token verification result."""
        jwt_tokens_verified.labels(
            result=result, algorithm=algorithm, key_id=key_id
        ).inc()

    @staticmethod
    def record_key_rotation(success: bool) -> None:
        """Record key rotation attempt."""
        status = "success" if success else "failed"
        jwt_key_rotations.labels(status=status).inc()

    @staticmethod
    def set_active_keys(count: int) -> None:
        """Set number of active signing keys."""
        jwt_active_keys.set(count)

    @staticmethod
    def record_jwks_cache(hit: bool) -> None:
        """Record JWKS cache hit or miss."""
        result = "hit" if hit else "miss"
        jwks_cache_hits.labels(result=result).inc()

    @staticmethod
    def record_token_revoked(reason: str) -> None:
        """Record token revocation."""
        jwt_tokens_revoked.labels(reason=reason).inc()
        jwt_revocation_list_size.inc()

    @staticmethod
    def record_revocation_cleanup(removed_count: int) -> None:
        """Record cleanup of expired revoked tokens."""
        jwt_revocation_list_size.dec(removed_count)

    @staticmethod
    def record_public_key_cache(result: str) -> None:
        """Record public key cache usage result (hit/miss/expired)."""
        jwt_public_key_cache_hits.labels(result=result).inc()

    @staticmethod
    @contextmanager
    def time_jwks_request() -> Generator[None, None, None]:
        """Context manager to time JWKS endpoint requests."""
        start_time = time.time()
        status_code = "unknown"

        try:
            yield
            status_code = "200"
        except Exception as e:
            # Try to extract status code
            if hasattr(e, "status_code"):
                status_code = str(e.status_code)
            else:
                status_code = "500"
            raise
        finally:
            duration = time.time() - start_time
            jwks_requests.labels(status_code=status_code).inc()
            jwks_response_time.observe(duration)


# Global instance
jwt_metrics = JwtMetrics()
