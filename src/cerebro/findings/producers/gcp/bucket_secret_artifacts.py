"""Detect suspicious secret artifacts exposed in public GCS buckets."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.base import ProducerContext
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.utils import (
    clip_sequence,
    coerce_mapping,
    coerce_mapping_sequence,
    resolve_rule_id,
)

from .base import BaseGCPProducer

SUSPICIOUS_KEYWORDS = {
    "secret",
    "token",
    "apikey",
    "api_key",
    "credential",
    "password",
    "service_account",
    "pem",
    "p12",
    "ssh",
}

SUSPICIOUS_EXTENSIONS = {
    ".pem",
    ".key",
    ".p12",
    ".json",
    ".env",
    ".ini",
    ".tfvars",
}


def _is_public(normalized: Mapping[str, Any]) -> bool:
    if normalized.get("is_public"):
        return True
    public_prevention = normalized.get("public_access_prevention")
    if isinstance(public_prevention, str) and public_prevention.lower() == "enforced":
        return False
    upla = coerce_mapping(normalized.get("uniform_bucket_level_access")) or {}
    return upla.get("enabled") is False


def _iter_object_keys(normalized: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw_sample = normalized.get("objectsSample")
    if isinstance(raw_sample, Mapping):
        return [
            {
                "key": key,
                **(value if isinstance(value, Mapping) else {"size": value}),
            }
            for key, value in raw_sample.items()
        ]

    sequence = coerce_mapping_sequence(raw_sample)
    if sequence:
        return list(sequence)

    raw_objects = normalized.get("objects")
    if isinstance(raw_objects, Mapping):
        return [
            {
                "key": key,
                **(value if isinstance(value, Mapping) else {"size": value}),
            }
            for key, value in raw_objects.items()
        ]

    sequence = coerce_mapping_sequence(raw_objects)
    if sequence:
        return list(sequence)

    return []


def _is_suspicious(key: str | None) -> bool:
    if not key:
        return False
    lowered = key.lower()
    if any(keyword in lowered for keyword in SUSPICIOUS_KEYWORDS):
        return True
    return any(lowered.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)


@register_producer
class GCPBucketSecretArtifactProducer(BaseGCPProducer):
    """Flags suspicious credential artifacts within publicly exposed GCS buckets."""

    @property
    def resource_types(self) -> set[str]:
        return {"gcp.storage.bucket"}

    @property
    def finding_name(self) -> str:
        return "GCP: Public bucket exposes potential secrets"

    @property
    def rule_name(self) -> str:
        return "gcp_storage_bucket_secret_artifacts"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return (
            "Cloud Storage bucket contains files indicative of credentials while "
            "accessible publicly."
        )

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        normalized = config.normalized_config or {}

        if not _is_public(normalized):
            return []

        objects = _iter_object_keys(normalized)
        matches = [obj for obj in objects if _is_suspicious(obj.get("key"))]
        if not matches:
            return []

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        bucket_name = resource.name or resource.external_id
        location = normalized.get("location") or normalized.get("region")
        sample = [
            {
                "key": obj.get("key"),
                "content_type": obj.get("content_type"),
                "size_bytes": obj.get("size"),
            }
            for obj in clip_sequence(matches)
        ]

        upla = coerce_mapping(normalized.get("uniform_bucket_level_access")) or {}

        evidence = {
            "bucket": bucket_name,
            "region": location,
            "matched_objects": sample,
            "total_objects_sampled": len(objects),
            "public_access_prevention": normalized.get("public_access_prevention"),
            "uniform_bucket_level_access": upla.get("enabled"),
        }

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=f"Public bucket {bucket_name} exposes suspicious files",
            summary=(
                "GCS bucket "
                f"{bucket_name} is publicly accessible and contains objects that "
                "resemble credentials or API keys."
            ),
            evidence=evidence,
            severity=self.severity,
        )

        return [finding]
