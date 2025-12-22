"""Finding service interface and implementation."""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from uuid import UUID

from cerebro.findings.producers import (
    ProducerBasedFindingService as ProducerService,
    producer_registry,
)


class FindingService(ABC):
    """Abstract base class for finding services."""

    @abstractmethod
    async def generate_findings_for_resources(
        self, resources: List, configs: Dict, context: Optional[Dict] = None
    ) -> List:
        """Generate findings for multiple resources."""
        pass

    @abstractmethod
    async def generate_findings_for_organization(
        self, org_id: UUID, provider_type: Optional[str] = None
    ) -> List:
        """Generate findings for an entire organization."""
        pass


class DefaultFindingService(FindingService):
    """Default implementation using the producer-based service."""

    def __init__(self):
        """Initialize with default producer registry."""
        self.producer_service = ProducerService(producer_registry)

    async def generate_findings_for_resources(
        self, resources: List, configs: Dict, context: Optional[Dict] = None
    ) -> List:
        """Generate findings for multiple resources using producers."""
        return self.producer_service.generate_findings_for_resources(
            resources, configs, context
        )

    async def generate_findings_for_organization(
        self, org_id: UUID, provider_type: Optional[str] = None
    ) -> List:
        """Generate findings for an entire organization."""
        # This would typically fetch resources for the org and then call
        # generate_findings_for_resources, but that requires more integration
        # For now, return empty list to prevent import errors
        return []


# Export the concrete implementation as FindingService
FindingService = DefaultFindingService
