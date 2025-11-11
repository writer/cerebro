"""Base classes for Azure producers."""

from typing import Dict, List, Set

from cerebro.findings.producers.base import BaseFindingProducer


class BaseAzureProducer(BaseFindingProducer):
    """Shared utilities for Azure findings."""

    @property
    def desired_sources(self) -> Set[str]:
        return {"azure"}

    @property
    def framework_mappings(self) -> Dict[str, List[str]]:
        return {
            "cis": ["3.12"],
            "nist_800_53": ["AC-3", "SC-7"],
        }
