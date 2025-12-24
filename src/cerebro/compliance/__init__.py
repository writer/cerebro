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
# Import framework providers to trigger registration
from . import frameworks as _frameworks  # noqa: F401
from .evidence import EvidenceCollector, EvidenceItem

# Evidence services
from .evidence_service import EvidenceQueryService, EvidenceService

# Framework system
from .framework_registry import (
    ControlDefinition,
    FrameworkDefinition,
    FrameworkProvider,
    FrameworkRegistry,
    get_framework,
    get_framework_registry,
    list_frameworks,
    register_framework_provider,
)
from .generator import ComplianceEvidenceGenerator
from .models import (
    BaseEvidenceMetadata,
    ComplianceEvidenceMetadata,
    CustomerEvidenceMetadata,
    EvidenceBundle,
    EvidenceCategory,
    EvidenceRepository,
    EvidenceStatus,
    ForensicEvidenceMetadata,
    VendorEvidenceMetadata,
    create_audit_evidence,
    create_compliance_evidence,
    create_customer_evidence,
    create_forensic_evidence,
    create_vendor_evidence,
    metadata_to_dict,
)
from .storage import FileBasedEvidenceRepository, InMemoryEvidenceRepository

__all__ = [
    # New unified system
    "BaseEvidenceMetadata",
    "ComplianceEvidenceGenerator",
    "ComplianceEvidenceMetadata",
    "ControlDefinition",
    "CustomerEvidenceMetadata",
    "EvidenceBundle",
    "EvidenceCategory",
    "EvidenceCollector",
    "EvidenceItem",
    "EvidenceQueryService",
    "EvidenceRepository",
    "EvidenceService",
    "EvidenceStatus",
    "FileBasedEvidenceRepository",
    "ForensicEvidenceMetadata",
    "FrameworkDefinition",
    "FrameworkProvider",
    "FrameworkRegistry",
    "InMemoryEvidenceRepository",
    "VendorEvidenceMetadata",
    "create_audit_evidence",
    "create_compliance_evidence",
    "create_customer_evidence",
    "create_forensic_evidence",
    "create_vendor_evidence",
    "get_framework",
    "get_framework_registry",
    "list_frameworks",
    "metadata_to_dict",
    "register_framework_provider",
]
