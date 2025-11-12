"""Base class for AWS finding producers."""

from __future__ import annotations

from cerebro.findings.producers.base import BaseFindingProducer


class BaseAWSProducer(BaseFindingProducer):
    """Base class for AWS finding producers."""

    @property
    def desired_sources(self) -> set[str]:
        return {"aws"}

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        """Default AWS framework mappings."""
        return {
            "cis": ["2.1.1"],  # Default AWS CIS control
            "nist_800_53": ["AC-3", "CM-6"],  # Access control and config management
        }
