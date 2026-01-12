"""Metrics for data collection operations."""

import time
from collections.abc import Generator
from contextlib import contextmanager

import structlog
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

logger = structlog.get_logger(__name__)

# Create a custom registry for Cerebro metrics
cerebro_registry = CollectorRegistry()

# Collection performance metrics
config_snapshots_collected = Counter(
    "cerebro_config_snapshots_collected_total",
    "Total number of configuration snapshots collected",
    ["provider", "account_id", "resource_type"],
    registry=cerebro_registry,
)

iam_edges_collected = Counter(
    "cerebro_iam_edges_collected_total",
    "Total number of IAM edges collected",
    ["provider", "account_id"],
    registry=cerebro_registry,
)

collection_duration = Histogram(
    "cerebro_collection_duration_seconds",
    "Time spent collecting data from providers",
    ["provider", "account_id", "operation"],
    buckets=(0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 300.0),
    registry=cerebro_registry,
)

collection_errors = Counter(
    "cerebro_collection_errors_total",
    "Total number of collection errors",
    ["provider", "account_id", "error_type"],
    registry=cerebro_registry,
)

bulk_operation_duration = Histogram(
    "cerebro_bulk_operation_duration_seconds",
    "Time spent on bulk database operations",
    ["operation", "batch_size_range"],
    buckets=(0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0),
    registry=cerebro_registry,
)

bulk_operation_items = Counter(
    "cerebro_bulk_operation_items_total",
    "Total items processed in bulk operations",
    ["operation", "result"],
    registry=cerebro_registry,
)

# Provider API metrics
provider_api_calls = Counter(
    "cerebro_provider_api_calls_total",
    "Total number of provider API calls",
    ["provider", "endpoint", "status_code"],
    registry=cerebro_registry,
)

provider_api_duration = Histogram(
    "cerebro_provider_api_duration_seconds",
    "Duration of provider API calls",
    ["provider", "endpoint"],
    buckets=(0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    registry=cerebro_registry,
)

provider_rate_limit_hits = Counter(
    "cerebro_provider_rate_limit_hits_total",
    "Number of times provider rate limits were hit",
    ["provider"],
    registry=cerebro_registry,
)

# Concurrency metrics
concurrent_collections_active = Gauge(
    "cerebro_concurrent_collections_active",
    "Number of active concurrent collection operations",
    registry=cerebro_registry,
)

collection_queue_depth = Gauge(
    "cerebro_collection_queue_depth",
    "Number of items waiting in collection queues",
    ["queue_type"],
    registry=cerebro_registry,
)


class CollectionMetrics:
    """Helper class for collection metrics."""

    @staticmethod
    @contextmanager
    def time_collection(provider: str, account_id: str, operation: str) -> Generator[None, None, None]:
        """Context manager to time collection operations."""
        concurrent_collections_active.inc()
        start_time = time.time()

        try:
            yield
        except Exception as e:
            # Record error
            error_type = type(e).__name__
            collection_errors.labels(
                provider=provider, account_id=account_id, error_type=error_type
            ).inc()
            raise
        finally:
            duration = time.time() - start_time
            collection_duration.labels(
                provider=provider, account_id=account_id, operation=operation
            ).observe(duration)
            concurrent_collections_active.dec()

    @staticmethod
    @contextmanager
    def time_bulk_operation(operation: str, item_count: int) -> Generator[None, None, None]:
        """Context manager to time bulk database operations."""
        # Categorize batch size for better metrics
        if item_count < 100:
            batch_size_range = "small"
        elif item_count < 1000:
            batch_size_range = "medium"
        else:
            batch_size_range = "large"

        start_time = time.time()

        try:
            yield
            # Success
            bulk_operation_items.labels(operation=operation, result="success").inc(
                item_count
            )
        except Exception:
            # Failure
            bulk_operation_items.labels(operation=operation, result="error").inc(
                item_count
            )
            raise
        finally:
            duration = time.time() - start_time
            bulk_operation_duration.labels(
                operation=operation, batch_size_range=batch_size_range
            ).observe(duration)

    @staticmethod
    @contextmanager
    def time_provider_api(provider: str, endpoint: str) -> Generator[None, None, None]:
        """Context manager to time provider API calls."""
        start_time = time.time()
        status_code = "unknown"

        try:
            yield
            status_code = "success"
        except Exception as e:
            # Try to extract status code from exception
            if hasattr(e, "response") and hasattr(e.response, "status_code"):
                status_code = str(e.response.status_code)
            else:
                status_code = "error"

            # Check for rate limiting
            if "rate limit" in str(e).lower() or status_code in ["429", "503"]:
                provider_rate_limit_hits.labels(provider=provider).inc()

            raise
        finally:
            duration = time.time() - start_time

            provider_api_calls.labels(
                provider=provider, endpoint=endpoint, status_code=status_code
            ).inc()

            provider_api_duration.labels(provider=provider, endpoint=endpoint).observe(
                duration
            )

    @staticmethod
    def record_configs_collected(
        provider: str, account_id: str, resource_type: str, count: int
    ) -> None:
        """Record configuration snapshots collected."""
        config_snapshots_collected.labels(
            provider=provider, account_id=account_id, resource_type=resource_type
        ).inc(count)

    @staticmethod
    def record_iam_edges_collected(provider: str, account_id: str, count: int) -> None:
        """Record IAM edges collected."""
        iam_edges_collected.labels(provider=provider, account_id=account_id).inc(count)

    @staticmethod
    def set_queue_depth(queue_type: str, depth: int) -> None:
        """Set collection queue depth."""
        collection_queue_depth.labels(queue_type=queue_type).set(depth)


# Global instance
collection_metrics = CollectionMetrics()
