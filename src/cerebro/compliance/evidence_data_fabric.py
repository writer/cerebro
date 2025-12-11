"""
Evidence Data Fabric - The foundation of Cerebro's Compliance Data Plane.

DEPRECATED: This module is being consolidated into the unified evidence system.
Use EvidenceService from evidence_service.py and the models from models.py for new implementations.

This module implements a normalized, queryable evidence model that serves as
the data substrate for rules, analytics, and AI - similar to Anecdotes.ai's approach.

Key principles:
- Evidence as structured, queryable tables (not just blobs)
- Lineage tracking from source to derived evidence
- Cross-evidence analysis and joins
- Requirement-level granularity (not just control-level)
- Temporal queries for point-in-time compliance state
"""

import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from uuid import uuid4
from sqlalchemy import (
    Column, String, DateTime, Text, Integer, Float, ForeignKey, Table, Index, UniqueConstraint
)
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.dialects.postgresql import UUID
from cerebro.core.database_types import JSONType

# Import unified enums from the consolidated models

Base = declarative_base()


class EvidenceEntityType(Enum):
    """Types of entities that evidence can be associated with."""
    IDENTITY = "identity"          # Users, service accounts, roles
    ASSET = "asset"               # Servers, databases, applications
    CONFIGURATION = "configuration"  # Settings, policies, rules
    ACTIVITY = "activity"         # Logs, events, actions
    DOCUMENT = "document"         # Policies, procedures, certificates
    VULNERABILITY = "vulnerability"  # Security findings, scan results
    ACCESS = "access"             # Permissions, group memberships
    CHANGE = "change"             # Modifications, deployments
    PROCESS = "process"           # Workflows, approvals, attestations
    VENDOR = "vendor"             # Third-party vendors, suppliers, partners
    CUSTOMER = "customer"         # Customer accounts, tenants, external clients


class EvidenceSourceType(Enum):
    """Types of evidence sources."""
    API = "api"                   # REST/GraphQL APIs
    DATABASE = "database"         # Direct DB queries
    LOG_FILE = "log_file"         # Log file parsing
    SCREENSHOT = "screenshot"     # UI screenshots
    DOCUMENT = "document"         # Uploaded files
    MANUAL_ENTRY = "manual"       # Human-entered data
    DERIVED = "derived"           # Computed from other evidence
    WEBHOOK = "webhook"           # Real-time notifications


class DataClassification(Enum):
    """Data sensitivity classification for evidence."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    PII = "pii"


# Association table for evidence relationships
evidence_relationships = Table(
    'evidence_relationships',
    Base.metadata,
    Column('parent_id', UUID(as_uuid=True), ForeignKey('evidence_records.id')),
    Column('child_id', UUID(as_uuid=True), ForeignKey('evidence_records.id')),
    Column('relationship_type', String(50)),
    Column('created_at', DateTime(timezone=True), default=datetime.now)
)


class EvidenceRecord(Base):
    """Core evidence record in the normalized data model."""
    __tablename__ = 'evidence_records'
    
    # Primary identification
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    source_id = Column(String(255), nullable=False)  # Original ID from source system
    content_hash = Column(String(64), nullable=False, index=True)  # SHA-256
    
    # Source and collection metadata
    source_system = Column(String(100), nullable=False)  # aws, github, okta, etc.
    source_type = Column(String(50), nullable=False)     # EvidenceSourceType
    collector_id = Column(String(100), nullable=False)   # Which collector gathered this
    collection_method = Column(String(100), nullable=False)
    
    # Entity being described
    entity_type = Column(String(50), nullable=False)     # EvidenceEntityType
    entity_id = Column(String(255), nullable=False)      # Canonical entity identifier
    entity_name = Column(String(500))                    # Human-readable name
    
    # Temporal information
    observed_at = Column(DateTime(timezone=True), nullable=False)  # When the state was observed
    collected_at = Column(DateTime(timezone=True), nullable=False, default=datetime.now)
    expires_at = Column(DateTime(timezone=True))         # When evidence becomes stale
    
    # Content and structure
    raw_data = Column(JSONType)                            # Original data from source
    normalized_data = Column(JSONType)                     # Standardized fields
    tags = Column(JSONType, default=dict)                  # Flexible tagging
    
    # Data governance
    data_classification = Column(String(50), default=DataClassification.INTERNAL.value)
    retention_class = Column(String(50), default="standard")
    pii_fields = Column(JSONType, default=list)            # List of fields containing PII
    
    # Quality and integrity
    quality_score = Column(Float, default=1.0)          # 0.0-1.0 confidence score
    lineage_depth = Column(Integer, default=0)          # How many derivation steps from source
    validation_status = Column(String(50), default="pending")  # pending, validated, failed
    
    # Framework and compliance context
    requirements = Column(JSONType, default=list)          # Requirement IDs this evidence supports
    controls = Column(JSONType, default=list)              # Control IDs (legacy compat)
    frameworks = Column(JSONType, default=list)            # Framework names
    
    # Relationships
    parent_records = relationship(
        "EvidenceRecord",
        secondary=evidence_relationships,
        primaryjoin=id==evidence_relationships.c.child_id,
        secondaryjoin=id==evidence_relationships.c.parent_id,
        back_populates="child_records"
    )
    child_records = relationship(
        "EvidenceRecord", 
        secondary=evidence_relationships,
        primaryjoin=id==evidence_relationships.c.parent_id,
        secondaryjoin=id==evidence_relationships.c.child_id,
        back_populates="parent_records"
    )
    
    # Indexes for common queries
    __table_args__ = (
        Index('idx_evidence_entity', 'entity_type', 'entity_id'),
        Index('idx_evidence_source', 'source_system', 'source_type'),
        Index('idx_evidence_temporal', 'observed_at', 'collected_at'),
        Index('idx_evidence_requirements', 'requirements'),
        UniqueConstraint('source_system', 'source_id', 'observed_at', name='uq_evidence_source_time')
    )


class EvidenceSchema(Base):
    """Schema definitions for different types of evidence."""
    __tablename__ = 'evidence_schemas'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    entity_type = Column(String(50), nullable=False)
    source_system = Column(String(100), nullable=False)
    version = Column(String(20), default="1.0")
    
    # Schema definition
    fields = Column(JSONType)                              # Field definitions with types
    required_fields = Column(JSONType, default=list)      # Required field names
    normalization_rules = Column(JSONType, default=dict)   # How to transform raw to normalized
    
    created_at = Column(DateTime(timezone=True), default=datetime.now)
    created_by = Column(String(255))
    
    __table_args__ = (
        UniqueConstraint('entity_type', 'source_system', 'version'),
    )


class EvidenceLineage(Base):
    """Tracks the lineage and derivation of evidence records."""
    __tablename__ = 'evidence_lineage'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    evidence_id = Column(UUID(as_uuid=True), ForeignKey('evidence_records.id'), nullable=False)
    
    # Derivation information
    derivation_type = Column(String(50))                # join, aggregate, transform, enrich
    derivation_logic = Column(Text)                     # How this was derived
    source_evidence_ids = Column(JSONType, default=list)   # Parent evidence IDs
    
    # Processing metadata  
    processor_id = Column(String(100))                  # What created this derivation
    processing_time = Column(Float)                     # Seconds to compute
    confidence_score = Column(Float, default=1.0)      # Confidence in derivation
    
    created_at = Column(DateTime(timezone=True), default=datetime.now)
    
    evidence = relationship("EvidenceRecord", backref="lineage_records")


class RequirementMapping(Base):
    """Maps framework requirements to evidence patterns."""
    __tablename__ = 'requirement_mappings'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Requirement identification
    framework_name = Column(String(100), nullable=False)
    requirement_id = Column(String(100), nullable=False)
    requirement_title = Column(String(500))
    requirement_description = Column(Text)
    
    # Evidence patterns
    evidence_patterns = Column(JSONType)                   # What evidence satisfies this req
    sufficiency_rules = Column(JSONType)                   # Rules for adequate evidence
    freshness_requirements = Column(JSONType)              # How fresh evidence must be
    
    # Cross-mapping
    equivalent_requirements = Column(JSONType, default=list)  # Other framework reqs that map
    parent_requirements = Column(JSONType, default=list)   # Higher-level requirements
    
    created_at = Column(DateTime(timezone=True), default=datetime.now)
    updated_at = Column(DateTime(timezone=True), default=datetime.now)
    
    __table_args__ = (
        UniqueConstraint('framework_name', 'requirement_id'),
        Index('idx_requirement_framework', 'framework_name')
    )


@dataclass
class EvidenceQuery:
    """Structured query for evidence data."""
    entity_types: List[EvidenceEntityType] = field(default_factory=list)
    entity_ids: List[str] = field(default_factory=list)
    source_systems: List[str] = field(default_factory=list)
    requirements: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    time_range: Optional[tuple[datetime, datetime]] = None
    tags: Dict[str, Any] = field(default_factory=dict)
    include_derived: bool = True
    min_quality_score: float = 0.0
    limit: Optional[int] = None


class EvidenceDataFabric:
    """Main interface to the evidence data fabric."""
    
    def __init__(self, session_factory: sessionmaker):
        self.session_factory = session_factory
        self._schemas: Dict[str, Dict] = {}
        
    def ingest_evidence(
        self,
        source_system: str,
        source_type: EvidenceSourceType,
        entity_type: EvidenceEntityType,
        entity_id: str,
        raw_data: Dict[str, Any],
        observed_at: Optional[datetime] = None,
        collector_id: str = "unknown",
        tags: Optional[Dict[str, Any]] = None
    ) -> str:
        """Ingest new evidence into the data fabric."""
        
        with self.session_factory() as session:
            # Calculate content hash
            content_str = json.dumps(raw_data, sort_keys=True)
            content_hash = hashlib.sha256(content_str.encode()).hexdigest()
            
            # Check for existing evidence with same hash and entity
            existing = session.query(EvidenceRecord).filter_by(
                entity_id=entity_id,
                content_hash=content_hash
            ).first()
            
            if existing:
                return str(existing.id)
            
            # Normalize the data using schema if available
            schema_key = f"{entity_type.value}:{source_system}"
            normalized_data = self._normalize_data(raw_data, schema_key)
            
            # Extract entity name from data
            entity_name = self._extract_entity_name(raw_data, entity_type)
            
            # Create evidence record
            record = EvidenceRecord(
                source_id=raw_data.get('id', str(uuid4())),
                content_hash=content_hash,
                source_system=source_system,
                source_type=source_type.value,
                collector_id=collector_id,
                collection_method="api",  # Default - should be parameterized
                entity_type=entity_type.value,
                entity_id=entity_id,
                entity_name=entity_name,
                observed_at=observed_at or datetime.now(timezone.utc),
                raw_data=raw_data,
                normalized_data=normalized_data,
                tags=tags or {}
            )
            
            session.add(record)
            session.commit()
            
            return str(record.id)
    
    def query_evidence(self, query: EvidenceQuery) -> List[EvidenceRecord]:
        """Query evidence using structured criteria."""
        
        with self.session_factory() as session:
            q = session.query(EvidenceRecord)
            
            # Apply filters
            if query.entity_types:
                entity_type_strs = [et.value for et in query.entity_types]
                q = q.filter(EvidenceRecord.entity_type.in_(entity_type_strs))
            
            if query.entity_ids:
                q = q.filter(EvidenceRecord.entity_id.in_(query.entity_ids))
            
            if query.source_systems:
                q = q.filter(EvidenceRecord.source_system.in_(query.source_systems))
            
            if query.requirements:
                # JSON containment
                for req in query.requirements:
                    q = q.filter(EvidenceRecord.requirements.contains([req]))
            
            if query.time_range:
                start, end = query.time_range
                q = q.filter(EvidenceRecord.observed_at.between(start, end))
            
            if query.min_quality_score > 0:
                q = q.filter(EvidenceRecord.quality_score >= query.min_quality_score)
            
            if not query.include_derived:
                q = q.filter(EvidenceRecord.lineage_depth == 0)
            
            # Apply tags filter
            for tag_key, tag_value in query.tags.items():
                q = q.filter(EvidenceRecord.tags[tag_key].astext == str(tag_value))
            
            # Order by recency
            q = q.order_by(EvidenceRecord.observed_at.desc())
            
            if query.limit:
                q = q.limit(query.limit)
            
            return q.all()
    
    def create_derived_evidence(
        self,
        derivation_type: str,
        derivation_logic: str,
        source_evidence_ids: List[str],
        processor_id: str,
        result_data: Dict[str, Any],
        entity_type: EvidenceEntityType,
        entity_id: str
    ) -> str:
        """Create evidence derived from other evidence records."""
        
        with self.session_factory() as session:
            # Create the derived evidence record
            evidence_id = self.ingest_evidence(
                source_system="cerebro_derived",
                source_type=EvidenceSourceType.DERIVED,
                entity_type=entity_type,
                entity_id=entity_id,
                raw_data=result_data,
                collector_id=processor_id,
                tags={"derived": True}
            )
            
            # Create lineage record
            lineage = EvidenceLineage(
                evidence_id=evidence_id,
                derivation_type=derivation_type,
                derivation_logic=derivation_logic,
                source_evidence_ids=source_evidence_ids,
                processor_id=processor_id
            )
            
            session.add(lineage)
            session.commit()
            
            return evidence_id
    
    def get_evidence_lineage(self, evidence_id: str) -> Dict[str, Any]:
        """Get complete lineage tree for an evidence record."""
        
        with self.session_factory() as session:
            evidence = session.query(EvidenceRecord).filter_by(id=evidence_id).first()
            if not evidence:
                return {}
            
            lineage_record = session.query(EvidenceLineage).filter_by(
                evidence_id=evidence_id
            ).first()
            
            lineage_tree = {
                "evidence_id": evidence_id,
                "entity_type": evidence.entity_type,
                "entity_id": evidence.entity_id,
                "source_system": evidence.source_system,
                "observed_at": evidence.observed_at.isoformat(),
                "is_derived": bool(lineage_record),
                "children": []
            }
            
            if lineage_record:
                lineage_tree["derivation"] = {
                    "type": lineage_record.derivation_type,
                    "logic": lineage_record.derivation_logic,
                    "processor": lineage_record.processor_id,
                    "confidence": lineage_record.confidence_score
                }
                
                # Recursively get parent lineages
                for parent_id in lineage_record.source_evidence_ids:
                    parent_lineage = self.get_evidence_lineage(parent_id)
                    if parent_lineage:
                        lineage_tree["children"].append(parent_lineage)
            
            return lineage_tree
    
    def register_schema(
        self,
        entity_type: EvidenceEntityType,
        source_system: str,
        fields: Dict[str, str],
        required_fields: List[str],
        normalization_rules: Dict[str, Any]
    ):
        """Register a schema for evidence normalization."""
        
        with self.session_factory() as session:
            schema = EvidenceSchema(
                entity_type=entity_type.value,
                source_system=source_system,
                fields=fields,
                required_fields=required_fields,
                normalization_rules=normalization_rules
            )
            
            session.merge(schema)  # Upsert
            session.commit()
            
        # Cache schema
        schema_key = f"{entity_type.value}:{source_system}"
        self._schemas[schema_key] = {
            "fields": fields,
            "required_fields": required_fields,
            "normalization_rules": normalization_rules
        }
    
    def cross_evidence_analysis(
        self, 
        analysis_type: str,
        entity_id: str,
        requirements: List[str]
    ) -> Dict[str, Any]:
        """Perform cross-evidence analysis for compliance requirements."""
        
        # Query all evidence for the entity and requirements
        query = EvidenceQuery(
            entity_ids=[entity_id],
            requirements=requirements,
            include_derived=True
        )
        
        evidence_records = self.query_evidence(query)
        
        if analysis_type == "mfa_compliance":
            return self._analyze_mfa_compliance(evidence_records)
        elif analysis_type == "access_review":
            return self._analyze_access_patterns(evidence_records) 
        elif analysis_type == "configuration_drift":
            return self._analyze_config_drift(evidence_records)
        else:
            return {"error": f"Unknown analysis type: {analysis_type}"}
    
    def _normalize_data(self, raw_data: Dict[str, Any], schema_key: str) -> Dict[str, Any]:
        """Normalize raw data using registered schema."""
        
        if schema_key not in self._schemas:
            return raw_data  # No normalization available
        
        schema = self._schemas[schema_key]
        normalization_rules = schema.get("normalization_rules", {})
        normalized = {}
        
        for field, rule in normalization_rules.items():
            if rule["type"] == "direct":
                # Direct field mapping
                source_field = rule["source_field"]
                if source_field in raw_data:
                    normalized[field] = raw_data[source_field]
            elif rule["type"] == "computed":
                # Computed field
                if rule["compute"] == "timestamp":
                    # Convert timestamp formats
                    source_field = rule["source_field"]
                    if source_field in raw_data:
                        # Add timestamp parsing logic here
                        normalized[field] = raw_data[source_field]
        
        return normalized
    
    def _extract_entity_name(self, raw_data: Dict[str, Any], entity_type: EvidenceEntityType) -> Optional[str]:
        """Extract human-readable name from raw data."""
        
        # Common name fields by entity type
        name_fields = {
            EvidenceEntityType.IDENTITY: ["name", "displayName", "username", "email"],
            EvidenceEntityType.ASSET: ["name", "hostname", "instanceId", "resourceName"],
            EvidenceEntityType.CONFIGURATION: ["name", "policyName", "ruleName"],
            EvidenceEntityType.VENDOR: ["name", "vendorName", "display_name", "companyName"],
            EvidenceEntityType.CUSTOMER: ["name", "customerName", "companyName", "accountName"],
        }
        
        fields = name_fields.get(entity_type, ["name", "title", "id"])
        
        for field in fields:
            if field in raw_data and raw_data[field]:
                return str(raw_data[field])
        
        return None
    
    def _analyze_mfa_compliance(self, evidence_records: List[EvidenceRecord]) -> Dict[str, Any]:
        """Analyze MFA compliance across identity systems."""
        
        mfa_data = []
        for record in evidence_records:
            if record.entity_type == EvidenceEntityType.IDENTITY.value:
                normalized = record.normalized_data or {}
                mfa_enabled = normalized.get("mfa_enabled", False)
                mfa_data.append({
                    "entity_id": record.entity_id,
                    "entity_name": record.entity_name,
                    "source_system": record.source_system,
                    "mfa_enabled": mfa_enabled,
                    "observed_at": record.observed_at
                })
        
        # Cross-system analysis
        entities_by_id = {}
        for item in mfa_data:
            entity_id = item["entity_id"]
            if entity_id not in entities_by_id:
                entities_by_id[entity_id] = []
            entities_by_id[entity_id].append(item)
        
        compliance_summary = {
            "total_identities": len(entities_by_id),
            "mfa_compliant": 0,
            "mfa_non_compliant": 0,
            "inconsistent_mfa": 0,
            "details": []
        }
        
        for entity_id, systems in entities_by_id.items():
            mfa_states = [s["mfa_enabled"] for s in systems]
            
            if all(mfa_states):
                compliance_summary["mfa_compliant"] += 1
                status = "compliant"
            elif not any(mfa_states):
                compliance_summary["mfa_non_compliant"] += 1
                status = "non_compliant"
            else:
                compliance_summary["inconsistent_mfa"] += 1
                status = "inconsistent"
            
            compliance_summary["details"].append({
                "entity_id": entity_id,
                "entity_name": systems[0]["entity_name"],
                "status": status,
                "systems": systems
            })
        
        return compliance_summary
    
    def _analyze_access_patterns(self, evidence_records: List[EvidenceRecord]) -> Dict[str, Any]:
        """Analyze access patterns for access review requirements."""
        # Placeholder implementation
        return {"analysis": "access_patterns", "records_analyzed": len(evidence_records)}
    
    def _analyze_config_drift(self, evidence_records: List[EvidenceRecord]) -> Dict[str, Any]:
        """Analyze configuration drift over time."""
        # Placeholder implementation  
        return {"analysis": "config_drift", "records_analyzed": len(evidence_records)}


# Factory function
def create_evidence_data_fabric(database_url: str) -> EvidenceDataFabric:
    """Create and initialize evidence data fabric."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    
    session_factory = sessionmaker(bind=engine)
    return EvidenceDataFabric(session_factory)
