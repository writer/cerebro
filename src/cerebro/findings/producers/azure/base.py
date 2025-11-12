"""Base classes for Azure producers."""

from __future__ import annotations

from cerebro.findings.producers.base import BaseFindingProducer


class BaseAzureProducer(BaseFindingProducer):
    """Shared utilities for Azure findings."""

    @property
    def desired_sources(self) -> set[str]:
        return {"azure"}

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "cis": ["3.12"],
            "nist_800_53": ["AC-3", "SC-7"],
        }
