"""Base producer class for finding generation."""

from __future__ import annotations

import abc
import hashlib
import json
import logging
from collections import defaultdict
from collections.abc import Mapping
from datetime import date, datetime, timezone
from typing import Any, Union
from uuid import UUID

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.utils import ProducerRunContext
from cerebro.metrics import (
    record_finding_evidence,
    record_serialization_failure,
)

logger = logging.getLogger(__name__)

ProducerContext = ProducerRunContext
ProducerContextInput = Union[ProducerRunContext, Mapping[str, Any]]
ProducerMetadata = dict[str, Any]


def _serialize_default(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, set):
        return sorted(str(item) for item in value)
    return str(value)


class BaseFindingProducer(abc.ABC):
    """Base class for all finding producers."""

    @property
    @abc.abstractmethod
    def desired_sources(self) -> set[str]:
        """The providers this producer cares about."""
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def resource_types(self) -> set[str]:
        """Resource types this producer evaluates."""
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def finding_name(self) -> str:
        """Name of the finding this producer creates."""
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def severity(self) -> Severity:
        """Severity level of findings this producer creates."""
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def rule_name(self) -> str:
        """Associated rule name for this producer."""
        raise NotImplementedError

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        """Framework mappings (CIS, NIST, etc.) - override in subclasses."""
        return {}

    @property
    def description(self) -> str:
        """Description of what this producer detects - override in subclasses."""
        return self.finding_name

    @property
    def remediation(self) -> str:
        """Remediation guidance - override in subclasses."""
        return "Review and remediate the identified misconfiguration"

    @abc.abstractmethod
    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate resource and config to produce findings."""
        raise NotImplementedError

    def create_finding(
        self,
        resource: ResourceEntity,
        rule_id: UUID,
        title: str | None = None,
        summary: str | None = None,
        evidence: Mapping[str, Any] | None = None,
        severity: Severity | None = None,
    ) -> FindingEntity:
        """Helper to create standardized findings."""
        evidence_dict = dict(evidence) if evidence is not None else {}
        top_level_keys = len(evidence_dict)

        payload_bytes: int | None
        if evidence_dict:
            try:
                serialized = json.dumps(
                    evidence_dict,
                    default=_serialize_default,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                payload_bytes = len(serialized.encode("utf-8"))
            except Exception:
                logger.debug(
                    "Failed to serialize finding evidence for metrics",
                    exc_info=True,
                    extra={
                        "producer": self.__class__.__name__,
                        "rule_name": self.rule_name,
                        "resource_id": resource.external_id,
                    },
                )
                record_serialization_failure(producer_name=self.__class__.__name__)
                payload_bytes = None
        else:
            payload_bytes = 0
        finding = FindingEntity(
            rule_id=rule_id,
            resource_external_id=resource.external_id,
            title=
            title
            or f"{self.finding_name}: {resource.name or resource.external_id}",
            summary=
            summary
            or (
                f"{self.description} detected on {resource.resource_type} "
                f"{resource.name or resource.external_id}"
            ),
            severity=severity or self.severity,
            evidence=evidence_dict,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )

        # Generate fingerprint based on rule and resource
        fingerprint_str = f"{rule_id}|{resource.external_id}|{self.finding_name}"
        finding.fingerprint = hashlib.sha256(fingerprint_str.encode()).hexdigest()

        logger.debug(
            "Finding evidence payload metrics",
            extra={
                "producer": self.__class__.__name__,
                "rule_name": self.rule_name,
                "resource_id": resource.external_id,
                "severity": finding.severity.value,
                "evidence_top_level_keys": top_level_keys,
                "evidence_bytes": payload_bytes,
            },
        )

        if payload_bytes is not None:
            record_finding_evidence(
                producer_name=self.__class__.__name__,
                severity=finding.severity.value,
                payload_bytes=payload_bytes,
                top_level_keys=top_level_keys,
            )

        return finding

    def should_evaluate(self, resource: ResourceEntity) -> bool:
        """Check if this producer should evaluate the given resource."""
        return (
            resource.provider in self.desired_sources
            and resource.resource_type in self.resource_types
        )

    def get_metadata(self) -> ProducerMetadata:
        """Get producer metadata."""
        return {
            "name": self.__class__.__name__,
            "finding_name": self.finding_name,
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity.value,
            "desired_sources": list(self.desired_sources),
            "resource_types": list(self.resource_types),
            "framework_mappings": self.framework_mappings,
            "remediation": self.remediation,
        }


class ProducerRegistry:
    """Registry for finding producers with auto-discovery."""

    def __init__(self) -> None:
        """Initialize producer registry."""
        self._producers: dict[str, BaseFindingProducer] = {}
        self._producers_by_source: defaultdict[
            str, list[BaseFindingProducer]
        ] = defaultdict(list)
        self._producers_by_resource_type: defaultdict[
            str, list[BaseFindingProducer]
        ] = defaultdict(list)

    def register(self, producer: BaseFindingProducer) -> None:
        """Register a producer instance."""
        producer_name = producer.__class__.__name__

        if producer_name in self._producers:
            logger.warning(f"Producer {producer_name} already registered, overriding")

        self._producers[producer_name] = producer

        for source in producer.desired_sources:
            self._producers_by_source[source].append(producer)

        for resource_type in producer.resource_types:
            self._producers_by_resource_type[resource_type].append(producer)

        logger.info("Registered producer: %s", producer_name)

    def get_producers_for_resource(
        self,
        provider: str,
        resource_type: str
    ) -> list[BaseFindingProducer]:
        """Get all producers that can evaluate a resource."""
        provider_producers = self._producers_by_source.get(provider, [])
        return [
            producer for producer in provider_producers
            if resource_type in producer.resource_types
        ]

    def evaluate_resource(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContextInput | None = None,
    ) -> list[FindingEntity]:
        """Evaluate resource using all applicable producers."""
        findings: list[FindingEntity] = []

        normalized_context = ProducerRunContext.ensure(context)

        producers = self.get_producers_for_resource(
            resource.provider, resource.resource_type
        )

        for producer in producers:
            try:
                producer_findings = producer.evaluate(
                    resource,
                    config,
                    normalized_context,
                )
                findings.extend(producer_findings)

                if producer_findings:
                    logger.info(
                        "Producer %s generated %s findings",
                        producer.__class__.__name__,
                        len(producer_findings),
                    )

            except Exception:
                logger.exception("Producer %s failed", producer.__class__.__name__)

        return findings

    def list_producers(self) -> list[str]:
        """List all registered producers."""
        return list(self._producers.keys())

    def get_producer_info(self, producer_name: str) -> ProducerMetadata | None:
        """Get producer metadata."""
        producer = self._producers.get(producer_name)
        return producer.get_metadata() if producer else None

    def get_all_producer_info(self) -> list[ProducerMetadata]:
        """Get metadata for all producers."""
        return [producer.get_metadata() for producer in self._producers.values()]
