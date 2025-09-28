"""Base class for Okta finding producers."""

from typing import Set
from cerebro.findings.producers.base import BaseFindingProducer


class BaseOktaProducer(BaseFindingProducer):
    """Base class for Okta finding producers."""
    
    @property
    def desired_sources(self) -> Set[str]:
        return {"okta"}
    
    @property
    def framework_mappings(self) -> dict:
        """Default Okta framework mappings."""
        return {
            "nist_800_53": ["IA-2", "AC-2", "AC-6"],  # Identity and access controls
            "cwe": ["CWE-287"],  # Authentication weaknesses
        }
