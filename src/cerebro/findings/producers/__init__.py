"""Finding producers organized by provider."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .base import BaseFindingProducer, ProducerContextInput, ProducerRegistry
from .registry import auto_discover_producers, producer_registry, register_producer


class ProducerBasedFindingService:
    """Finding service using the producer pattern."""

    def __init__(self, registry: ProducerRegistry) -> None:
        """Initialize with producer registry."""
        self.registry = registry

    def generate_findings_for_resources(
        self,
        resources: Sequence[Any],
        configs: Mapping[str, Any],
        context: ProducerContextInput | None = None,
    ) -> list[Any]:
        """Generate findings for multiple resources using producers."""

        all_findings: list[Any] = []

        for resource in resources:
            config = configs.get(resource.external_id)
            if not config:
                continue

            findings = self.registry.evaluate_resource(resource, config, context)
            all_findings.extend(findings)

        return all_findings


__all__ = [
    "BaseFindingProducer",
    "ProducerBasedFindingService",
    "ProducerRegistry",
    "auto_discover_producers",
    "producer_registry",
    "register_producer",
]
