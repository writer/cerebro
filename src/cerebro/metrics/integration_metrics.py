"""Prometheus metrics tracking external integration synchronization."""

from __future__ import annotations

from prometheus_client import Gauge

from cerebro.metrics.collection_metrics import cerebro_registry

INTEGRATION_LAST_SYNC = Gauge(
    "cerebro_integration_last_sync_timestamp",
    "Unix timestamp for the last successful integration sync",
    labelnames=["integration", "scope"],
    registry=cerebro_registry,
)

INTEGRATION_EVENTS_INGESTED = Gauge(
    "cerebro_integration_events_ingested_total",
    "Number of events ingested during the latest integration sync run",
    labelnames=["integration", "scope"],
    registry=cerebro_registry,
)


def record_integration_sync(
    *,
    integration: str,
    scope: str,
    last_sync_unix: float,
    events_ingested: int,
) -> None:
    """Update gauges reflecting integration synchronization status."""

    INTEGRATION_LAST_SYNC.labels(integration=integration, scope=scope).set(
        last_sync_unix
    )
    INTEGRATION_EVENTS_INGESTED.labels(integration=integration, scope=scope).set(
        events_ingested
    )
