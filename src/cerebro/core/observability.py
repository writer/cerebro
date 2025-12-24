"""Observability helpers for metrics and telemetry configuration."""

from __future__ import annotations

import logging
from typing import Dict, Optional

from cerebro.core.config import settings
from cerebro.core.logging import configure_structlog

_logger = logging.getLogger(__name__)
_configured_service: Optional[str] = None


def configure_service_observability(
    service_name: str,
    *,
    service_namespace: str = "cerebro",
    service_version: Optional[str] = None,
) -> None:
    """Configure logging and telemetry exporters for a named service."""

    configure_structlog()

    if not settings.enable_agent_telemetry:
        return

    if not settings.agent_otel_endpoint:
        _logger.info(
            "Telemetry enabled but no OTLP endpoint configured; spans will stay local (service=%s)",
            service_name,
        )
        return

    global _configured_service
    if _configured_service:
        if _configured_service == service_name:
            return
        _logger.debug(
            "Telemetry already configured for %s; skipping reconfiguration for %s",
            _configured_service,
            service_name,
        )
        return

    try:  # pragma: no cover - optional dependency wiring
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as exc:  # pragma: no cover
        _logger.warning(
            "OpenTelemetry exporter not available; install opentelemetry-sdk and opentelemetry-exporter-otlp-proto-http: %s",
            str(exc),
        )
        return

    headers = _parse_otlp_headers(settings.agent_otel_headers)
    exporter = OTLPSpanExporter(
        endpoint=settings.agent_otel_endpoint,
        headers=headers,
        timeout=settings.agent_otel_timeout_seconds,
    )

    version_value = (
        service_version
        or getattr(settings, "runtime_release_version", None)
        or getattr(settings, "app_version", None)
        or "0.1.0"
    )

    resource = Resource.create(
        {
            "service.name": service_name,
            "service.namespace": service_namespace,
            "service.version": str(version_value),
            "deployment.environment": settings.environment,
        }
    )

    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(tracer_provider)

    _configured_service = service_name
    _logger.info(
        "Configured telemetry exporter: service=%s, endpoint=%s, timeout=%s",
        service_name,
        settings.agent_otel_endpoint,
        settings.agent_otel_timeout_seconds,
    )


def configure_agent_observability() -> None:
    """Backward-compatible wrapper for runtime observability configuration."""

    configure_service_observability(service_name="cerebro-agent-runtime")


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
