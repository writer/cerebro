"""Base class for GitHub finding producers."""

from typing import Set
from cerebro.findings.producers.base import BaseFindingProducer


class BaseGitHubProducer(BaseFindingProducer):
    """Base class for GitHub finding producers."""
    
    @property
    def desired_sources(self) -> Set[str]:
        return {"github"}
    
    @property
    def framework_mappings(self) -> dict:
        """Default GitHub framework mappings."""
        return {
            "cis": ["5.1.4"],  # Default GitHub CIS control
            "nist_800_53": ["CM-3", "CM-6"],  # Configuration management
        }
