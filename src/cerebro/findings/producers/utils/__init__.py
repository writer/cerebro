"""Utility helpers for findings producers."""

from __future__ import annotations

__all__ = [
    "ProducerRunContext",
    "RunnerGroupExposureEvidence",
    "RunnerHostExposureEvidence",
    "RunnerMetadata",
    "SecretArtifactSummary",
    "StorageSecretExposureEvidence",
    "analyze_instance_network_exposure",
    "build_runner_group_exposure",
    "build_runner_host_exposure",
    "build_storage_secret_evidence",
    "clip_sequence",
    "coerce_mapping",
    "coerce_mapping_sequence",
    "coerce_rule_id",
    "coerce_str_sequence",
    "compact_mapping",
    "has_public_interface",
    "resolve_rule_id",
    "security_group_rule_allows_public",
]

from .collections import coerce_mapping, coerce_mapping_sequence, coerce_str_sequence
from .context import ProducerRunContext
from .evidence import (
    RunnerGroupExposureEvidence,
    RunnerHostExposureEvidence,
    RunnerMetadata,
    SecretArtifactSummary,
    StorageSecretExposureEvidence,
    build_runner_group_exposure,
    build_runner_host_exposure,
    build_storage_secret_evidence,
    clip_sequence,
    compact_mapping,
)
from .exposure import (
    analyze_instance_network_exposure,
    has_public_interface,
    security_group_rule_allows_public,
)
from .rules import coerce_rule_id, resolve_rule_id
