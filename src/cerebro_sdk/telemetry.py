"""Telemetry helpers for the Cerebro SDK."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager

from prometheus_client import CollectorRegistry, Counter, Histogram

from cerebro.core.config import Settings, settings
from cerebro.core.logging import configure_structlog


def configure_logging(
    level: str | None = None,
    *,
    json_output: bool | None = None,
    settings_obj: Settings | None = None,
) -> None:
    """Configure structlog according to settings or overrides."""

    config = settings_obj or settings
    if level:
        config.log_level = level
    if json_output is not None:
        config.log_format = "json" if json_output else "plain"

    configure_structlog()


def get_logger(name: str) -> logging.Logger:
    configure_structlog()
    return logging.getLogger(name)


def create_counter(
    name: str,
    documentation: str,
    *,
    registry: CollectorRegistry | None = None,
    labelnames: tuple[str, ...] | None = None,
) -> Counter:
    return Counter(name, documentation, labelnames=labelnames or (), registry=registry)


def create_histogram(
    name: str,
    documentation: str,
    *,
    registry: CollectorRegistry | None = None,
    buckets: tuple[float, ...] | None = None,
    labelnames: tuple[str, ...] | None = None,
) -> Histogram:
    return Histogram(
        name,
        documentation,
        buckets=buckets or Histogram.DEFAULT_BUCKETS,
        labelnames=labelnames or (),
        registry=registry,
    )


@contextmanager
def time_operation(histogram: Histogram, **labels) -> Iterator[None]:
    timer = histogram.labels(**labels) if histogram._labelnames else histogram
    with timer.time():
        yield
