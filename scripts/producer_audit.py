"""Audit helpers for finding producers.

Usage:
    uv run python scripts/producer_audit.py

Outputs a JSON summary listing each producer, whether it references the
standardized evidence builders, and whether it normalizes the context via
``ProducerRunContext.ensure``.
"""

from __future__ import annotations

import inspect
import json
from dataclasses import asdict, dataclass

from cerebro.findings.producers.registry import (
    auto_discover_producers,
    get_producer_registry,
)

BUILDER_TOKENS = (
    "build_identity_user_evidence",
    "build_ci_pipeline_exposure",
    "build_network_exposure_evidence",
    "build_storage_secret_evidence",
    "build_runner_group_exposure",
    "build_runner_host_exposure",
    "build_external_sharing_evidence",
    "build_sharepoint_anonymous_link_evidence",
    "build_security_group_exposure",
    "build_workflow_permission_evidence",
    "build_telemetry_incident_evidence",
)


@dataclass
class ProducerAuditRecord:
    name: str
    module: str
    builder_used: bool
    run_context_normalized: bool


def _detect_builder_usage(source: str) -> bool:
    return any(token in source for token in BUILDER_TOKENS)


def _detect_context_normalization(source: str) -> bool:
    return "ProducerRunContext.ensure" in source or "ProducerContext.ensure" in source


def audit_producers() -> list[ProducerAuditRecord]:
    auto_discover_producers()
    registry = get_producer_registry()
    records: list[ProducerAuditRecord] = []
    for producer_name, producer in sorted(registry._producers.items()):
        cls = producer.__class__
        try:
            source = inspect.getsource(cls.evaluate)
        except OSError:
            source = ""
        records.append(
            ProducerAuditRecord(
                name=producer_name,
                module=cls.__module__,
                builder_used=_detect_builder_usage(source),
                run_context_normalized=_detect_context_normalization(source),
            )
        )
    return records


def main() -> None:
    records = audit_producers()
    print(json.dumps([asdict(record) for record in records], indent=2))


if __name__ == "__main__":
    main()
