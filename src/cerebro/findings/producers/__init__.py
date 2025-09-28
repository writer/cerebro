"""Finding producers organized by provider."""

from typing import List, Dict, Optional

from .base import BaseFindingProducer, ProducerRegistry
from .registry import producer_registry, register_producer, auto_discover_producers


class ProducerBasedFindingService:
    """Finding service using the producer pattern."""
    
    def __init__(self, registry: ProducerRegistry):
        """Initialize with producer registry."""
        self.registry = registry
    
    def generate_findings_for_resources(
        self,
        resources: List,  # Import would be circular
        configs: Dict,
        context: Optional[Dict] = None
    ) -> List:
        """Generate findings for multiple resources using producers."""
        all_findings = []
        
        for resource in resources:
            config = configs.get(resource.external_id)
            if not config:
                continue
            
            findings = self.registry.evaluate_resource(resource, config, context)
            all_findings.extend(findings)
        
        return all_findings


__all__ = [
    "BaseFindingProducer",
    "ProducerRegistry", 
    "ProducerBasedFindingService",
    "producer_registry",
    "register_producer",
    "auto_discover_producers",
]
