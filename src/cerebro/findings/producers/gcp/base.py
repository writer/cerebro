"""Base class for GCP finding producers."""

from __future__ import annotations

from cerebro.findings.producers.base import BaseFindingProducer


class BaseGCPProducer(BaseFindingProducer):
    """Shared utilities for Google Cloud producers."""

    @property
    def desired_sources(self) -> set[str]:
        return {"gcp"}

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "cis": ["4.2"],
            "nist_800_53": ["AC-3", "SC-7"],
        }
