"""Utility helpers for findings producers."""

from __future__ import annotations

__all__ = [
    "AnonymousLinkSummary",
    "CiPipelineExposureEvidence",
    "ExternalSharingEvidence",
    "ExternalUserAccess",
    "IdentityUserEvidence",
    "NetworkExposureDetail",
    "NetworkExposureEvidence",
    "ProducerRunContext",
    "RunnerGroupExposureEvidence",
    "RunnerHostExposureEvidence",
    "RunnerMetadata",
    "SecretArtifactSummary",
    "SharePointAnonymousLinkEvidence",
    "StorageSecretExposureEvidence",
    "analyze_instance_network_exposure",
    "build_ci_pipeline_exposure",
    "build_external_sharing_evidence",
    "build_identity_user_evidence",
    "build_network_exposure_evidence",
    "build_runner_group_exposure",
    "build_runner_host_exposure",
    "build_sharepoint_anonymous_link_evidence",
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
    AnonymousLinkSummary,
    CiPipelineExposureEvidence,
    ExternalSharingEvidence,
    ExternalUserAccess,
    IdentityUserEvidence,
    NetworkExposureDetail,
    NetworkExposureEvidence,
    RunnerGroupExposureEvidence,
    RunnerHostExposureEvidence,
    RunnerMetadata,
    SecretArtifactSummary,
    SharePointAnonymousLinkEvidence,
    StorageSecretExposureEvidence,
    build_ci_pipeline_exposure,
    build_external_sharing_evidence,
    build_identity_user_evidence,
    build_network_exposure_evidence,
    build_runner_group_exposure,
    build_runner_host_exposure,
    build_sharepoint_anonymous_link_evidence,
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
