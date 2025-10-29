"""Telemetry helpers for the Cerebro SDK."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Iterator, Optional

from prometheus_client import CollectorRegistry, Counter, Histogram

from cerebro.core.logging import configure_structlog
from cerebro.core.config import settings, Settings


def configure_logging(
    level: Optional[str] = None,
    *,
    json_output: Optional[bool] = None,
    settings_obj: Optional[Settings] = None,
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
    registry: Optional[CollectorRegistry] = None,
    labelnames: Optional[tuple[str, ...]] = None,
) -> Counter:
    return Counter(name, documentation, labelnames=labelnames or (), registry=registry)


def create_histogram(
    name: str,
    documentation: str,
    *,
    registry: Optional[CollectorRegistry] = None,
    buckets: Optional[tuple[float, ...]] = None,
    labelnames: Optional[tuple[str, ...]] = None,
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
