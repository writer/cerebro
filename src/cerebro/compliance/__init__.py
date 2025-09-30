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
    BaseEvidenceMetadata, ComplianceEvidenceMetadata, ForensicEvidenceMetadata,
    EvidenceBundle, EvidenceRepository, EvidenceStatus, EvidenceCategory,
    create_compliance_evidence, create_forensic_evidence, create_audit_evidence
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

# Import framework providers to trigger registration
from . import frameworks

__all__ = [
    # New unified system
    "BaseEvidenceMetadata",
    "ComplianceEvidenceMetadata",
    "ForensicEvidenceMetadata",
    "EvidenceBundle",
    "EvidenceRepository",
    "EvidenceStatus",
    "EvidenceCategory",
    "create_compliance_evidence",
    "create_forensic_evidence",
    "create_audit_evidence",
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
]
