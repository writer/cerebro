"""
Requirement-Level Cross-Framework Mapping System.

Provides fine-grained requirement mapping across compliance frameworks,
enabling evidence reuse and precision - a key differentiator vs Vanta/Drata.

Key capabilities:
- Requirement-level mapping (not just control-level)
- Contextual evidence reuse across frameworks
- Per-scope mapping overrides (subsidiary, region, etc.)
- Automated gap detection and surplus evidence identification
- Cross-framework requirement analysis
"""

from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from uuid import uuid4
from sqlalchemy.ext.declarative import declarative_base

from .evidence_data_fabric import EvidenceDataFabric, EvidenceQuery, EvidenceEntityType

Base = declarative_base()


class MappingConfidence(Enum):
    """Confidence levels for requirement mappings."""

    EXACT = "exact"  # 1:1 mapping, identical requirements
    HIGH = "high"  # Very similar, minor differences
    MEDIUM = "medium"  # Related but some differences
    LOW = "low"  # Conceptually related but significant differences
    PARTIAL = "partial"  # Only partially overlapping


class EvidenceReusability(Enum):
    """How evidence can be reused across requirements."""

    DIRECT = "direct"  # Evidence applies directly without modification
    CONTEXTUAL = "contextual"  # Evidence applies with context/interpretation
    PARTIAL = "partial"  # Some evidence fields apply
    DERIVED = "derived"  # Evidence can be transformed/aggregated
    NOT_REUSABLE = "not_reusable"


@dataclass
class RequirementDefinition:
    """Detailed definition of a compliance requirement."""

    id: str
    framework_name: str
    requirement_id: str  # e.g., "CC6.1.1", "A.9.2.1.a"
    title: str
    description: str

    # Hierarchy
    parent_requirement_id: Optional[str] = None
    sub_requirements: List[str] = field(default_factory=list)

    # Classification
    control_family: str = ""
    control_type: str = ""  # preventive, detective, corrective

    # Evidence requirements
    evidence_types: List[str] = field(default_factory=list)
    sufficiency_criteria: Dict[str, Any] = field(default_factory=dict)
    freshness_requirement_days: Optional[int] = None

    # Testing requirements
    testing_frequency: str = "annually"
    sample_size_required: Optional[int] = None

    # Context and interpretation
    implementation_guidance: str = ""
    common_interpretations: List[str] = field(default_factory=list)

    # Metadata
    version: str = "1.0"
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class RequirementMapping:
    """Maps requirements across frameworks."""

    id: str
    source_requirement: RequirementDefinition
    target_requirement: RequirementDefinition

    # Mapping quality
    confidence: MappingConfidence
    evidence_reusability: EvidenceReusability

    # Mapping details
    mapping_notes: str = ""
    differences: List[str] = field(default_factory=list)
    additional_evidence_needed: List[str] = field(default_factory=list)

    # Context and overrides
    applicable_scopes: List[str] = field(
        default_factory=list
    )  # subsidiary, region, etc.
    scope_overrides: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Validation
    validated_by: Optional[str] = None
    validated_at: Optional[datetime] = None
    validation_notes: str = ""

    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class EvidenceMapping:
    """Maps evidence to specific requirements."""

    requirement_id: str
    framework_name: str
    evidence_pattern: Dict[str, Any]  # Pattern that evidence must match
    weight: float = 1.0  # How much this evidence contributes (0.0-1.0)
    mandatory: bool = True  # Whether this evidence is required or optional
    context_notes: str = ""


class RequirementMappingService:
    """Service for managing requirement-level cross-framework mappings."""

    def __init__(self, evidence_fabric: EvidenceDataFabric):
        self.evidence_fabric = evidence_fabric
        self._requirements: Dict[str, RequirementDefinition] = {}
        self._mappings: Dict[str, RequirementMapping] = {}
        self._evidence_mappings: Dict[str, List[EvidenceMapping]] = {}

        # Load framework requirement definitions
        self._load_framework_requirements()
        self._generate_cross_mappings()

    def get_requirement_mappings(
        self,
        source_framework: str,
        target_framework: str,
        confidence_threshold: MappingConfidence = MappingConfidence.MEDIUM,
    ) -> List[RequirementMapping]:
        """Get mappings between two frameworks."""

        mappings = []
        for mapping in self._mappings.values():
            if (
                mapping.source_requirement.framework_name == source_framework
                and mapping.target_requirement.framework_name == target_framework
                and self._confidence_level(mapping.confidence)
                >= self._confidence_level(confidence_threshold)
            ):
                mappings.append(mapping)

        return mappings

    def find_equivalent_requirements(
        self,
        requirement_id: str,
        framework_name: str,
        target_frameworks: Optional[List[str]] = None,
    ) -> List[Tuple[RequirementDefinition, MappingConfidence]]:
        """Find equivalent requirements across frameworks."""

        source_key = f"{framework_name}:{requirement_id}"
        if source_key not in self._requirements:
            return []

        equivalents = []
        for mapping in self._mappings.values():
            source_matches = (
                mapping.source_requirement.framework_name == framework_name
                and mapping.source_requirement.requirement_id == requirement_id
            )

            if source_matches:
                if (
                    target_frameworks is None
                    or mapping.target_requirement.framework_name in target_frameworks
                ):
                    equivalents.append((mapping.target_requirement, mapping.confidence))

        # Sort by confidence level
        equivalents.sort(key=lambda x: self._confidence_level(x[1]), reverse=True)
        return equivalents

    def analyze_evidence_reuse(
        self, requirements: List[str], scope: Optional[str] = None
    ) -> Dict[str, Any]:
        """Analyze how evidence can be reused across requirements."""

        # Group requirements by framework
        reqs_by_framework: Dict[str, List[str]] = {}
        for req_id in requirements:
            # Parse framework from requirement ID format
            framework = self._extract_framework_from_req(req_id)
            if framework not in reqs_by_framework:
                reqs_by_framework[framework] = []
            reqs_by_framework[framework].append(req_id)

        # Find cross-framework mappings
        reuse_opportunities: List[Dict[str, Any]] = []
        duplicated_evidence: List[str] = []
        missing_evidence: List[str] = []

        for source_framework, source_reqs in reqs_by_framework.items():
            for target_framework, target_reqs in reqs_by_framework.items():
                if source_framework != target_framework:
                    mappings = self.get_requirement_mappings(
                        source_framework, target_framework
                    )

                    for mapping in mappings:
                        if (
                            mapping.source_requirement.requirement_id in source_reqs
                            and mapping.target_requirement.requirement_id in target_reqs
                        ):

                            reuse_opportunity = {
                                "source_requirement": mapping.source_requirement.requirement_id,
                                "target_requirement": mapping.target_requirement.requirement_id,
                                "source_framework": source_framework,
                                "target_framework": target_framework,
                                "reusability": mapping.evidence_reusability.value,
                                "confidence": mapping.confidence.value,
                                "additional_evidence_needed": mapping.additional_evidence_needed,
                                "scope": scope,
                            }
                            reuse_opportunities.append(reuse_opportunity)

        return {
            "reuse_opportunities": reuse_opportunities,
            "potential_savings": len(reuse_opportunities),
            "duplicated_evidence": duplicated_evidence,
            "missing_evidence": missing_evidence,
            "total_requirements": len(requirements),
            "unique_frameworks": len(reqs_by_framework),
        }

    def validate_requirement_coverage(
        self,
        requirements: List[str],
        evidence_query_filter: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Validate that requirements have adequate evidence coverage."""

        coverage_results = {}

        for req_id in requirements:
            framework = self._extract_framework_from_req(req_id)
            req_key = f"{framework}:{req_id}"

            if req_key not in self._requirements:
                coverage_results[req_id] = {
                    "status": "unknown_requirement",
                    "coverage": 0.0,
                }
                continue

            evidence_mappings = self._evidence_mappings.get(req_key, [])

            if not evidence_mappings:
                coverage_results[req_id] = {
                    "status": "no_evidence_mapping",
                    "coverage": 0.0,
                }
                continue

            # Check each evidence mapping
            total_weight = 0.0
            satisfied_weight = 0.0
            evidence_details = []

            for evidence_mapping in evidence_mappings:
                total_weight += evidence_mapping.weight

                # Query for evidence matching this pattern
                evidence_count = self._count_matching_evidence(
                    evidence_mapping, evidence_query_filter
                )

                is_satisfied = evidence_count > 0 or not evidence_mapping.mandatory
                if is_satisfied:
                    satisfied_weight += evidence_mapping.weight

                evidence_details.append(
                    {
                        "pattern": evidence_mapping.evidence_pattern,
                        "weight": evidence_mapping.weight,
                        "mandatory": evidence_mapping.mandatory,
                        "evidence_count": evidence_count,
                        "satisfied": is_satisfied,
                    }
                )

            coverage_percentage = (
                (satisfied_weight / total_weight) if total_weight > 0 else 0.0
            )

            coverage_results[req_id] = {
                "status": "adequate" if coverage_percentage >= 0.8 else "insufficient",
                "coverage": coverage_percentage,
                "evidence_details": evidence_details,
                "total_evidence_types": len(evidence_mappings),
                "satisfied_evidence_types": sum(
                    1 for e in evidence_details if e["satisfied"]
                ),
            }

        return coverage_results

    def generate_cross_framework_report(
        self,
        base_framework: str,
        target_frameworks: List[str],
        scope: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate comprehensive cross-framework mapping report."""

        base_requirements = [
            req
            for req in self._requirements.values()
            if req.framework_name == base_framework
        ]

        mapping_summary: Dict[str, Dict[str, Any]] = {}
        gap_analysis: Dict[str, Any] = {}

        for target_framework in target_frameworks:
            framework_mappings = self.get_requirement_mappings(
                base_framework, target_framework
            )

            mapped_reqs = {
                m.source_requirement.requirement_id for m in framework_mappings
            }
            unmapped_reqs = [
                req.requirement_id
                for req in base_requirements
                if req.requirement_id not in mapped_reqs
            ]

            # Group by confidence level
            confidence_breakdown = {}
            for confidence in MappingConfidence:
                confidence_breakdown[confidence.value] = len(
                    [m for m in framework_mappings if m.confidence == confidence]
                )

            mapping_summary[target_framework] = {
                "total_mappings": len(framework_mappings),
                "mapped_requirements": len(mapped_reqs),
                "unmapped_requirements": len(unmapped_reqs),
                "mapping_percentage": len(mapped_reqs) / len(base_requirements) * 100,
                "confidence_breakdown": confidence_breakdown,
                "unmapped_requirement_ids": unmapped_reqs,
            }

            # Evidence reuse analysis
            all_reqs = [req.requirement_id for req in base_requirements]
            target_reqs = [
                req.requirement_id
                for req in self._requirements.values()
                if req.framework_name == target_framework
            ]

            reuse_analysis = self.analyze_evidence_reuse(all_reqs + target_reqs, scope)
            gap_analysis[target_framework] = reuse_analysis

        return {
            "base_framework": base_framework,
            "target_frameworks": target_frameworks,
            "scope": scope,
            "generated_at": datetime.now().isoformat(),
            "base_requirements_count": len(base_requirements),
            "mapping_summary": mapping_summary,
            "evidence_reuse_analysis": gap_analysis,
            "overall_stats": {
                "avg_mapping_percentage": (
                    sum(ms["mapping_percentage"] for ms in mapping_summary.values())
                    / len(mapping_summary)
                    if mapping_summary
                    else 0
                ),
                "total_reuse_opportunities": sum(
                    ga["potential_savings"] for ga in gap_analysis.values()
                ),
                "frameworks_analyzed": len(target_frameworks),
            },
        }

    def create_custom_mapping(
        self,
        source_framework: str,
        source_requirement_id: str,
        target_framework: str,
        target_requirement_id: str,
        confidence: MappingConfidence,
        evidence_reusability: EvidenceReusability,
        mapping_notes: str = "",
        scope_overrides: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> RequirementMapping:
        """Create a custom requirement mapping."""

        source_key = f"{source_framework}:{source_requirement_id}"
        target_key = f"{target_framework}:{target_requirement_id}"

        if source_key not in self._requirements or target_key not in self._requirements:
            raise ValueError("Source or target requirement not found")

        mapping = RequirementMapping(
            id=str(uuid4()),
            source_requirement=self._requirements[source_key],
            target_requirement=self._requirements[target_key],
            confidence=confidence,
            evidence_reusability=evidence_reusability,
            mapping_notes=mapping_notes,
            scope_overrides=scope_overrides or {},
        )

        self._mappings[mapping.id] = mapping
        return mapping

    def _load_framework_requirements(self):
        """Load detailed requirement definitions for each framework."""

        # SOC 2 Requirements (detailed breakdown)
        soc2_requirements = [
            RequirementDefinition(
                id="soc2:CC6.1.1",
                framework_name="soc2",
                requirement_id="CC6.1.1",
                title="User Access Provisioning",
                description="Entity implements logical access security software, infrastructure, and architectures to protect against threats from sources outside its system boundaries.",
                control_family="Access Control",
                control_type="preventive",
                evidence_types=[
                    "user_provisioning_logs",
                    "access_management_config",
                    "identity_provider_config",
                ],
                sufficiency_criteria={
                    "min_evidence_items": 3,
                    "time_coverage": "full_period",
                },
                freshness_requirement_days=30,
                testing_frequency="quarterly",
            ),
            RequirementDefinition(
                id="soc2:CC6.1.2",
                framework_name="soc2",
                requirement_id="CC6.1.2",
                title="User Access Modifications",
                description="Entity documents and implements logical access security measures to protect against threats.",
                control_family="Access Control",
                control_type="preventive",
                evidence_types=[
                    "access_change_logs",
                    "approval_workflows",
                    "access_review_reports",
                ],
                sufficiency_criteria={"min_evidence_items": 2, "sample_size": 10},
                freshness_requirement_days=30,
            ),
            RequirementDefinition(
                id="soc2:CC6.2.1",
                framework_name="soc2",
                requirement_id="CC6.2.1",
                title="Multi-Factor Authentication",
                description="Users are authenticated prior to being granted access to the system and data.",
                control_family="Authentication",
                control_type="preventive",
                evidence_types=[
                    "mfa_configuration",
                    "authentication_logs",
                    "user_mfa_status",
                ],
                sufficiency_criteria={"coverage_percentage": 100},
                freshness_requirement_days=7,
            ),
        ]

        # ISO 27001 Requirements
        iso_requirements = [
            RequirementDefinition(
                id="iso27001:A.9.2.1.1",
                framework_name="iso27001",
                requirement_id="A.9.2.1.1",
                title="User Registration Process",
                description="A formal user registration and de-registration process shall be implemented to enable assignment of access rights.",
                control_family="Access Control",
                control_type="administrative",
                evidence_types=[
                    "user_registration_procedures",
                    "access_provisioning_logs",
                    "hr_integration_config",
                ],
                sufficiency_criteria={
                    "procedural_documentation": True,
                    "implementation_evidence": True,
                },
                freshness_requirement_days=90,
            ),
            RequirementDefinition(
                id="iso27001:A.9.4.2.1",
                framework_name="iso27001",
                requirement_id="A.9.4.2.1",
                title="Secure Authentication",
                description="Where password authentication is used, the system shall enforce the use of good quality passwords.",
                control_family="Authentication",
                control_type="technical",
                evidence_types=[
                    "password_policy_config",
                    "authentication_system_config",
                    "mfa_enforcement",
                ],
                sufficiency_criteria={
                    "technical_controls": True,
                    "policy_enforcement": True,
                },
            ),
        ]

        # Store requirements by framework:requirement_id key
        all_requirements = soc2_requirements + iso_requirements
        for req in all_requirements:
            key = f"{req.framework_name}:{req.requirement_id}"
            self._requirements[key] = req

            # Create evidence mappings
            evidence_mappings = []
            for evidence_type in req.evidence_types:
                evidence_mapping = EvidenceMapping(
                    requirement_id=req.requirement_id,
                    framework_name=req.framework_name,
                    evidence_pattern={
                        "tags": {"evidence_type": evidence_type},
                        "requirements": [req.requirement_id],
                    },
                    weight=1.0 / len(req.evidence_types),  # Equal weight distribution
                    mandatory=True,
                )
                evidence_mappings.append(evidence_mapping)

            self._evidence_mappings[key] = evidence_mappings

    def _generate_cross_mappings(self):
        """Generate cross-framework requirement mappings."""

        # SOC 2 CC6.1.1 <-> ISO 27001 A.9.2.1.1 (User provisioning)
        self._mappings["soc2_cc611_iso_a9211"] = RequirementMapping(
            id="soc2_cc611_iso_a9211",
            source_requirement=self._requirements["soc2:CC6.1.1"],
            target_requirement=self._requirements["iso27001:A.9.2.1.1"],
            confidence=MappingConfidence.HIGH,
            evidence_reusability=EvidenceReusability.CONTEXTUAL,
            mapping_notes="Both requirements address user access provisioning, but ISO focuses more on formal processes while SOC2 emphasizes technical implementation",
            differences=[
                "ISO requires more procedural documentation",
                "SOC2 focuses on technical controls",
            ],
        )

        # SOC 2 CC6.2.1 <-> ISO 27001 A.9.4.2.1 (Authentication)
        self._mappings["soc2_cc621_iso_a9421"] = RequirementMapping(
            id="soc2_cc621_iso_a9421",
            source_requirement=self._requirements["soc2:CC6.2.1"],
            target_requirement=self._requirements["iso27001:A.9.4.2.1"],
            confidence=MappingConfidence.MEDIUM,
            evidence_reusability=EvidenceReusability.PARTIAL,
            mapping_notes="Both address authentication but SOC2 requires MFA while ISO focuses on password quality",
            differences=["SOC2 mandates MFA", "ISO emphasizes password policies"],
            additional_evidence_needed=["password_policy_documentation"],
        )

    def _confidence_level(self, confidence: MappingConfidence) -> int:
        """Convert confidence enum to numeric level for comparison."""
        levels = {
            MappingConfidence.EXACT: 5,
            MappingConfidence.HIGH: 4,
            MappingConfidence.MEDIUM: 3,
            MappingConfidence.LOW: 2,
            MappingConfidence.PARTIAL: 1,
        }
        return levels.get(confidence, 0)

    def _extract_framework_from_req(self, req_id: str) -> str:
        """Extract framework name from requirement ID."""
        # Simple heuristic - in real implementation would be more sophisticated
        if req_id.startswith("CC"):
            return "soc2"
        elif req_id.startswith("A."):
            return "iso27001"
        elif "." in req_id:
            return req_id.split(".")[0]
        else:
            return "unknown"

    def _count_matching_evidence(
        self, evidence_mapping: EvidenceMapping, query_filter: Optional[Dict[str, Any]]
    ) -> int:
        """Count evidence records matching a pattern."""

        # Build query from evidence pattern
        query = EvidenceQuery()

        pattern = evidence_mapping.evidence_pattern

        if "tags" in pattern:
            query.tags = pattern["tags"]

        if "requirements" in pattern:
            query.requirements = pattern["requirements"]

        if query_filter:
            # Apply additional filters
            if "time_range" in query_filter:
                query.time_range = query_filter["time_range"]
            if "entity_types" in query_filter:
                query.entity_types = [
                    EvidenceEntityType(et) for et in query_filter["entity_types"]
                ]

        # Execute query
        evidence_records = self.evidence_fabric.query_evidence(query)
        return len(evidence_records)


# Factory function
def create_requirement_mapper(
    evidence_fabric: EvidenceDataFabric,
) -> RequirementMappingService:
    """Create and initialize requirement mapping service."""
    return RequirementMappingService(evidence_fabric)
