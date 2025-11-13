"""Metrics tracking for finding evidence payload characteristics."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Histogram

finding_registry = CollectorRegistry()

_EVIDENCE_PAYLOAD_BYTES = Histogram(
    "cerebro_finding_evidence_bytes",
    "Serialized size of finding evidence payloads in bytes",
    ["producer", "severity"],
    buckets=(
        64,
        128,
        256,
        512,
        1024,
        2048,
        4096,
        8192,
        16384,
        32768,
        65536,
        131072,
        262144,
        524288,
    ),
    registry=finding_registry,
)

_EVIDENCE_TOP_LEVEL_KEYS = Histogram(
    "cerebro_finding_evidence_fields",
    "Number of top-level keys present in finding evidence payloads",
    ["producer", "severity"],
    buckets=(
        0,
        1,
        2,
        4,
        6,
        8,
        12,
        16,
        24,
        32,
        48,
        64,
    ),
    registry=finding_registry,
)

_EVIDENCE_SERIALIZATION_FAILURES = Counter(
    "cerebro_finding_evidence_serialization_failures_total",
    "Count of evidence payloads that could not be serialized for metrics",
    ["producer"],
    registry=finding_registry,
)


def record_finding_evidence(
    *,
    producer_name: str,
    severity: str,
    payload_bytes: int,
    top_level_keys: int,
) -> None:
    """Record evidence payload size metrics for a finding."""

    _EVIDENCE_PAYLOAD_BYTES.labels(
        producer=producer_name,
        severity=severity,
    ).observe(payload_bytes)

    _EVIDENCE_TOP_LEVEL_KEYS.labels(
        producer=producer_name,
        severity=severity,
    ).observe(top_level_keys)


def record_serialization_failure(*, producer_name: str) -> None:
    """Record a serialization failure when evidence cannot be serialized."""

    _EVIDENCE_SERIALIZATION_FAILURES.labels(producer=producer_name).inc()


__all__ = [
    "finding_registry",
    "record_finding_evidence",
    "record_serialization_failure",
]
