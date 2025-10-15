"""Prometheus metrics for Cerebro agent runtimes."""

from __future__ import annotations

import logging
from typing import Optional

from cerebro.core.config import settings

try:  # pragma: no cover - optional dependency guard
    from prometheus_client import CollectorRegistry, Counter, Histogram
except ImportError:  # pragma: no cover
    CollectorRegistry = None  # type: ignore
    Counter = None  # type: ignore
    Histogram = None  # type: ignore

logger = logging.getLogger(__name__)


_registry: Optional[CollectorRegistry]
if CollectorRegistry is not None:
    _registry = CollectorRegistry()
else:  # pragma: no cover - handled when prometheus not installed
    _registry = None


if _registry is not None:  # pragma: no branch
    runtime_duration = Histogram(
        "cerebro_agent_runtime_duration_seconds",
        "Time spent processing agent messages",
        ["backend", "agent_type", "outcome"],
        registry=_registry,
        buckets=(
            0.1,
            0.25,
            0.5,
            1.0,
            2.5,
            5.0,
            10.0,
            30.0,
        ),
    )
    runtime_tokens = Counter(
        "cerebro_agent_runtime_tokens_total",
        "Token usage by agent runtimes",
        ["backend", "agent_type", "direction"],
        registry=_registry,
    )
    runtime_tool_calls = Counter(
        "cerebro_agent_runtime_tool_calls_total",
        "Tool calls issued by agent runtimes",
        ["backend", "agent_type"],
        registry=_registry,
    )
    runtime_errors = Counter(
        "cerebro_agent_runtime_errors_total",
        "Errors encountered when executing agent messages",
        ["backend", "agent_type", "error_type"],
        registry=_registry,
    )
else:  # pragma: no cover - fallback no-op placeholders
    runtime_duration = None  # type: ignore
    runtime_tokens = None  # type: ignore
    runtime_tool_calls = None  # type: ignore
    runtime_errors = None  # type: ignore


def record_runtime_metrics(
    *,
    backend: str,
    agent_type: str,
    duration_seconds: float,
    success: bool,
    input_tokens: int,
    output_tokens: int,
    tool_calls: int,
    error_type: Optional[str] = None,
) -> None:
    """Record Prometheus metrics for a runtime call if enabled."""

    if not settings.enable_agent_metrics:
        return

    if runtime_duration is None:
        return

    outcome = "success" if success else "error"
    runtime_duration.labels(backend=backend, agent_type=agent_type, outcome=outcome).observe(
        duration_seconds
    )

    if input_tokens:
        runtime_tokens.labels(backend=backend, agent_type=agent_type, direction="input").inc(
            input_tokens
        )
    if output_tokens:
        runtime_tokens.labels(backend=backend, agent_type=agent_type, direction="output").inc(
            output_tokens
        )
    if tool_calls:
        runtime_tool_calls.labels(backend=backend, agent_type=agent_type).inc(tool_calls)

    if not success:
        runtime_errors.labels(
            backend=backend,
            agent_type=agent_type,
            error_type=error_type or "unknown",
        ).inc()


def get_registry() -> Optional[CollectorRegistry]:
    """Expose the agent metrics registry for exporters."""

    return _registry
