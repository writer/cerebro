"""Base producer class for finding generation."""

import abc
import hashlib
from typing import List, Set, Dict, Any, Optional
from datetime import datetime
from uuid import UUID
import logging

from cerebro.domain.entities import ResourceEntity, ConfigEntity, FindingEntity, Severity

logger = logging.getLogger(__name__)


class BaseFindingProducer(abc.ABC):
    """Base class for all finding producers."""
    
    @property
    @abc.abstractmethod
    def desired_sources(self) -> Set[str]:
        """The providers this producer cares about."""
        pass
    
    @property
    @abc.abstractmethod
    def resource_types(self) -> Set[str]:
        """Resource types this producer evaluates."""
        pass
    
    @property
    @abc.abstractmethod
    def finding_name(self) -> str:
        """Name of the finding this producer creates."""
        pass
    
    @property
    @abc.abstractmethod
    def severity(self) -> Severity:
        """Severity level of findings this producer creates."""
        pass
    
    @property
    @abc.abstractmethod
    def rule_name(self) -> str:
        """Associated rule name for this producer."""
        pass
    
    @property
    def framework_mappings(self) -> Dict[str, List[str]]:
        """Framework mappings (CIS, NIST, etc.) - override in subclasses."""
        return {}
    
    @property
    def description(self) -> str:
        """Description of what this producer detects - override in subclasses."""
        return self.finding_name
    
    @property
    def remediation(self) -> str:
        """Remediation guidance - override in subclasses."""
        return "Review and remediate the identified misconfiguration"
    
    @abc.abstractmethod
    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, Any]] = None
    ) -> List[FindingEntity]:
        """Evaluate resource and config to produce findings."""
        pass
    
    def create_finding(
        self,
        resource: ResourceEntity,
        rule_id: UUID,
        title: Optional[str] = None,
        summary: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
        severity: Optional[Severity] = None
    ) -> FindingEntity:
        """Helper to create standardized findings."""
        finding = FindingEntity(
            rule_id=rule_id,
            resource_external_id=resource.external_id,
            title=title or f"{self.finding_name}: {resource.name or resource.external_id}",
            summary=summary or f"{self.description} detected on {resource.resource_type} {resource.name or resource.external_id}",
            severity=severity or self.severity,
            evidence=evidence or {},
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        
        # Generate fingerprint based on rule and resource
        fingerprint_str = f"{rule_id}|{resource.external_id}|{self.finding_name}"
        finding.fingerprint = hashlib.sha256(fingerprint_str.encode()).hexdigest()
        
        return finding
    
    def should_evaluate(self, resource: ResourceEntity) -> bool:
        """Check if this producer should evaluate the given resource."""
        return (resource.provider in self.desired_sources and 
                resource.resource_type in self.resource_types)
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get producer metadata."""
        return {
            "name": self.__class__.__name__,
            "finding_name": self.finding_name,
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity.value,
            "desired_sources": list(self.desired_sources),
            "resource_types": list(self.resource_types),
            "framework_mappings": self.framework_mappings,
            "remediation": self.remediation,
        }


class ProducerRegistry:
    """Registry for finding producers with auto-discovery."""
    
    def __init__(self):
        """Initialize producer registry."""
        self._producers: Dict[str, BaseFindingProducer] = {}
        self._producers_by_source: Dict[str, List[BaseFindingProducer]] = {}
        self._producers_by_resource_type: Dict[str, List[BaseFindingProducer]] = {}
    
    def register(self, producer: BaseFindingProducer) -> None:
        """Register a producer instance."""
        producer_name = producer.__class__.__name__
        
        if producer_name in self._producers:
            logger.warning(f"Producer {producer_name} already registered, overriding")
        
        self._producers[producer_name] = producer
        
        # Index by source
        for source in producer.desired_sources:
            if source not in self._producers_by_source:
                self._producers_by_source[source] = []
            self._producers_by_source[source].append(producer)
        
        # Index by resource type
        for resource_type in producer.resource_types:
            if resource_type not in self._producers_by_resource_type:
                self._producers_by_resource_type[resource_type] = []
            self._producers_by_resource_type[resource_type].append(producer)
        
        logger.info(f"Registered producer: {producer_name}")
    
    def get_producers_for_resource(
        self, 
        provider: str, 
        resource_type: str
    ) -> List[BaseFindingProducer]:
        """Get all producers that can evaluate a resource."""
        # Get by provider
        provider_producers = self._producers_by_source.get(provider, [])
        
        # Filter by resource type
        matching_producers = [
            p for p in provider_producers 
            if resource_type in p.resource_types
        ]
        
        return matching_producers
    
    def evaluate_resource(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, Any]] = None
    ) -> List[FindingEntity]:
        """Evaluate resource using all applicable producers."""
        findings = []
        
        producers = self.get_producers_for_resource(
            resource.provider, 
            resource.resource_type
        )
        
        for producer in producers:
            try:
                producer_findings = producer.evaluate(resource, config, context)
                findings.extend(producer_findings)
                
                if producer_findings:
                    logger.info(f"Producer {producer.__class__.__name__} generated {len(producer_findings)} findings")
                    
            except Exception as e:
                logger.error(f"Producer {producer.__class__.__name__} failed: {e}")
        
        return findings
    
    def list_producers(self) -> List[str]:
        """List all registered producers."""
        return list(self._producers.keys())
    
    def get_producer_info(self, producer_name: str) -> Optional[Dict[str, Any]]:
        """Get producer metadata."""
        producer = self._producers.get(producer_name)
        return producer.get_metadata() if producer else None
    
    def get_all_producer_info(self) -> List[Dict[str, Any]]:
        """Get metadata for all producers."""
        return [producer.get_metadata() for producer in self._producers.values()]
