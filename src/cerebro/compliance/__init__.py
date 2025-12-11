"""
Unified compliance module for Cerebro Security System.

Provides comprehensive compliance functionality with:
- Pluggable framework system
- Unified evidence collection and storage
- Proper dependency injection
- Consolidated APIs

This replaces the previous fragmented compliance modules with a
clean, well-architected system.
"""

# Core models and interfaces
from .models import (
    BaseEvidenceMetadata,
    ComplianceEvidenceMetadata,
    ForensicEvidenceMetadata,
    VendorEvidenceMetadata,
    CustomerEvidenceMetadata,
    EvidenceBundle,
    EvidenceRepository,
    EvidenceStatus,
    EvidenceCategory,
    create_compliance_evidence,
    create_forensic_evidence,
    create_audit_evidence,
    create_vendor_evidence,
    create_customer_evidence,
    metadata_to_dict,
)

# Framework system
from .framework_registry import (
    FrameworkRegistry, FrameworkProvider, FrameworkDefinition,
    ControlDefinition, get_framework_registry, get_framework,
    list_frameworks, register_framework_provider
)

# Evidence services
from .evidence_service import EvidenceService, EvidenceQueryService
from .storage import FileBasedEvidenceRepository, InMemoryEvidenceRepository
from .evidence import EvidenceCollector, EvidenceItem
from .generator import ComplianceEvidenceGenerator

# Import framework providers to trigger registration
from . import frameworks as _frameworks  # noqa: F401

__all__ = [
    # New unified system
    "BaseEvidenceMetadata",
    "ComplianceEvidenceMetadata",
    "ForensicEvidenceMetadata",
    "VendorEvidenceMetadata",
    "CustomerEvidenceMetadata",
    "EvidenceBundle",
    "EvidenceRepository",
    "EvidenceStatus",
    "EvidenceCategory",
    "create_compliance_evidence",
    "create_forensic_evidence",
    "create_audit_evidence",
    "create_vendor_evidence",
    "create_customer_evidence",
    "metadata_to_dict",
    "FrameworkRegistry",
    "FrameworkProvider",
    "FrameworkDefinition",
    "ControlDefinition",
    "get_framework_registry",
    "get_framework",
    "list_frameworks",
    "register_framework_provider",
    "EvidenceService",
    "EvidenceQueryService",
    "FileBasedEvidenceRepository",
    "InMemoryEvidenceRepository",
    "EvidenceCollector",
    "EvidenceItem",
    "ComplianceEvidenceGenerator",
]
