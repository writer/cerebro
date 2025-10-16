"""Observability helpers for metrics and telemetry configuration."""

from __future__ import annotations

import logging
from typing import Dict, Optional

from cerebro.core.config import settings

_logger = logging.getLogger(__name__)
_telemetry_configured = False


def configure_agent_observability() -> None:
    """Configure telemetry exporters if enabled in settings."""

    if not settings.enable_agent_telemetry:
        return

    if not settings.agent_otel_endpoint:
        _logger.info(
            "Agent telemetry enabled but no OTLP endpoint configured; spans will stay local",
        )
        return

    global _telemetry_configured
    if _telemetry_configured:
        return

    try:  # pragma: no cover - optional dependency wiring
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as exc:  # pragma: no cover
        _logger.warning(
            "OpenTelemetry exporter not available; install opentelemetry-sdk and opentelemetry-exporter-otlp-proto-http",
            error=str(exc),
        )
        return

    headers = _parse_otlp_headers(settings.agent_otel_headers)
    exporter = OTLPSpanExporter(
        endpoint=settings.agent_otel_endpoint,
        headers=headers,
        timeout=settings.agent_otel_timeout_seconds,
    )

    resource = Resource.create(
        {
            "service.name": "cerebro-agent-runtime",
            "service.namespace": "cerebro",
            "service.version": "0.1.0",
        }
    )

    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(tracer_provider)

    _telemetry_configured = True
    _logger.info(
        "Configured agent telemetry exporter",
        endpoint=settings.agent_otel_endpoint,
        timeout=settings.agent_otel_timeout_seconds,
    )


def _parse_otlp_headers(raw: Optional[str]) -> Optional[Dict[str, str]]:
    if not raw:
        return None

    headers: Dict[str, str] = {}
    for pair in raw.split(","):
        if "=" not in pair:
            continue
        key, value = pair.split("=", 1)
        key = key.strip()
        if not key:
            continue
        headers[key] = value.strip()
    return headers or None
