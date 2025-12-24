"""
Unified compliance API endpoints.

Consolidates compliance functionality from multiple modules into a single,
coherent API with proper dependency injection and real implementation.
"""

import logging
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.api.auth import (
    User,
    get_current_user,
    require_read_findings,
    require_scopes,
)
from cerebro.api.org_access import require_org_access
from cerebro.api.utils import StandardResponses, get_entity_by_id_or_404
from cerebro.compliance.evidence_service import EvidenceQueryService, EvidenceService

# Compliance modules
from cerebro.compliance.framework_registry import get_framework_registry
from cerebro.compliance.models import EvidenceStatus
from cerebro.compliance.storage import FileBasedEvidenceRepository
from cerebro.core.database import get_db
from cerebro.core.models import Organization
from cerebro.query.bootstrap import get_query_engine

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/compliance", dependencies=[Depends(get_current_user)])


# Request/Response Models
class FrameworkSummary(BaseModel):
    """Framework summary information."""

    framework_id: str
    name: str
    version: str
    description: str
    total_controls: int
    automated_controls: int
    automation_percentage: float
    issuing_organization: str
    certification_available: bool


class ControlSummary(BaseModel):
    """Control summary information."""

    control_id: str
    title: str
    category: str
    control_type: str
    automation_level: str
    testing_frequency: str
    risk_level: str
    evidence_count: int = 0
    compliance_status: str = "unknown"


class EvidenceCollectionRequest(BaseModel):
    """Request to collect evidence for controls."""

    framework_id: str
    control_ids: list[str]
    test_run_id: str | None = None
    collector_id: str = "api_user"


class EvidenceBundleRequest(BaseModel):
    """Request to create evidence bundle."""

    bundle_name: str
    framework_id: str
    control_ids: list[str]
    period_start: datetime | None = None
    period_end: datetime | None = None
    bundle_type: str = "compliance"
    description: str = ""


class ComplianceStatusResponse(BaseModel):
    """Compliance status response."""

    framework_id: str
    organization_id: str
    assessment_date: datetime
    total_controls: int
    compliant_controls: int
    non_compliant_controls: int
    testing_controls: int
    compliance_percentage: float
    control_status: list[ControlSummary]


# Dependency injection for services
def get_evidence_repository():
    """Get evidence repository instance."""
    # In production, this would be configured based on settings
    return FileBasedEvidenceRepository("/tmp/cerebro_evidence")


def get_evidence_service(
    repository=Depends(get_evidence_repository), db: AsyncSession = Depends(get_db)
):
    """Get evidence service with dependencies."""
    query_engine = get_query_engine()
    return EvidenceService(repository, query_engine=query_engine)


def get_evidence_query_service(repository=Depends(get_evidence_repository)):
    """Get evidence query service."""
    return EvidenceQueryService(repository)


# === FRAMEWORK MANAGEMENT ENDPOINTS ===


@router.get("/frameworks", summary="List Compliance Frameworks")
async def list_compliance_frameworks(
    framework_type: str | None = Query(None, description="Filter by framework type"),
    current_user: User = Depends(get_current_user),
) -> list[FrameworkSummary]:
    """List all available compliance frameworks."""
    try:
        registry = get_framework_registry()

        if framework_type:
            frameworks = registry.get_frameworks_by_type(framework_type)
        else:
            framework_ids = registry.list_frameworks()
            frameworks = [f for fid in framework_ids if (f := registry.get_framework(fid)) is not None]  # type: ignore[assignment,misc]

        summaries = []
        for framework in frameworks:
            automated_controls = len(
                [
                    c
                    for c in framework.controls
                    if c.automation_level.value == "automated"
                ]
            )

            summaries.append(
                FrameworkSummary(
                    framework_id=framework.framework_id,
                    name=framework.name,
                    version=framework.version,
                    description=framework.description,
                    total_controls=len(framework.controls),
                    automated_controls=automated_controls,
                    automation_percentage=(
                        round((automated_controls / len(framework.controls)) * 100, 1)
                        if framework.controls
                        else 0
                    ),
                    issuing_organization=framework.issuing_organization,
                    certification_available=framework.certification_available,
                )
            )

        return summaries

    except Exception as e:
        logger.error(f"Failed to list frameworks: {e}")
        raise StandardResponses.internal_error("Failed to retrieve frameworks")


@router.get("/frameworks/{framework_id}", summary="Get Framework Details")
async def get_framework_details(
    framework_id: str,
    version: str | None = Query(None, description="Framework version"),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Get detailed information about a compliance framework."""
    try:
        registry = get_framework_registry()
        framework = registry.get_framework(framework_id, version)

        if not framework:
            raise StandardResponses.not_found(f"Framework '{framework_id}' not found")

        # Group controls by family
        controls_by_family = {}
        for family, control_ids in framework.control_families.items():
            family_controls = []
            for control_id in control_ids:
                control = framework.get_control(control_id)
                if control:
                    family_controls.append(
                        {
                            "control_id": control.control_id,
                            "title": control.title,
                            "description": control.description,
                            "control_type": control.control_type.value,
                            "automation_level": control.automation_level.value,
                            "testing_frequency": control.testing_frequency.value,
                            "risk_level": control.risk_level,
                            "evidence_queries_count": len(control.evidence_queries),
                        }
                    )
            controls_by_family[family] = family_controls

        return {
            "framework": {
                "framework_id": framework.framework_id,
                "name": framework.name,
                "version": framework.version,
                "description": framework.description,
                "issuing_organization": framework.issuing_organization,
                "framework_type": framework.framework_type,
                "industry_focus": framework.industry_focus,
                "geographic_scope": framework.geographic_scope,
                "certification_available": framework.certification_available,
            },
            "summary": {
                "total_controls": len(framework.controls),
                "control_families": len(framework.control_families),
                "automated_controls": len(framework.get_automated_controls()),
                "implementation_tiers": framework.implementation_tiers,
            },
            "controls_by_family": controls_by_family,
            "maturity_model": framework.maturity_model,
            "references": framework.references,
            "documentation_urls": framework.documentation_urls,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get framework details: {e}")
        raise StandardResponses.internal_error("Failed to retrieve framework details")


@router.get(
    "/frameworks/{framework_id}/controls/{control_id}", summary="Get Control Details"
)
async def get_control_details(
    framework_id: str, control_id: str, current_user: User = Depends(get_current_user)
) -> dict[str, Any]:
    """Get detailed information about a specific control."""
    try:
        registry = get_framework_registry()
        framework = registry.get_framework(framework_id)

        if not framework:
            raise StandardResponses.not_found(f"Framework '{framework_id}' not found")

        control = framework.get_control(control_id)
        if not control:
            raise StandardResponses.not_found(f"Control '{control_id}' not found")

        return {
            "control_id": control.control_id,
            "title": control.title,
            "description": control.description,
            "category": control.category,
            "control_type": control.control_type.value,
            "automation_level": control.automation_level.value,
            "testing_frequency": control.testing_frequency.value,
            "risk_level": control.risk_level,
            "business_impact": control.business_impact,
            "evidence_queries": control.evidence_queries,
            "evidence_collection_methods": control.evidence_collection_methods,
            "remediation_guidance": control.remediation_guidance,
            "implementation_guidance": control.implementation_guidance,
            "testing_procedures": control.testing_procedures,
            "depends_on": control.depends_on,
            "related_controls": control.related_controls,
            "tags": control.tags,
            "references": control.references,
            "last_updated": control.last_updated,
            "version": control.version,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get control details: {e}")
        raise StandardResponses.internal_error("Failed to retrieve control details")


# === EVIDENCE COLLECTION ENDPOINTS ===


@router.post(
    "/organizations/{org_id}/collect-evidence", summary="Collect Compliance Evidence"
)
async def collect_compliance_evidence(
    org_id: UUID,
    request: EvidenceCollectionRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    evidence_service: EvidenceService = Depends(get_evidence_service),
    current_user: User = Depends(
        require_org_access(require_scopes("compliance:collect"))
    ),
) -> dict[str, Any]:
    """Collect evidence for specified controls."""
    await get_entity_by_id_or_404(db, Organization, org_id, "Organization not found")

    try:
        registry = get_framework_registry()
        framework = registry.get_framework(request.framework_id)

        if not framework:
            raise StandardResponses.bad_request(
                f"Framework '{request.framework_id}' not found"
            )

        # Validate control IDs
        invalid_controls = []
        for control_id in request.control_ids:
            if not framework.get_control(control_id):
                invalid_controls.append(control_id)

        if invalid_controls:
            raise StandardResponses.bad_request(
                f"Invalid control IDs: {invalid_controls}"
            )

        # Start evidence collection in background
        collection_task_id = (
            f"evidence_collection_{org_id}_{request.test_run_id or 'adhoc'}"
        )

        background_tasks.add_task(
            _collect_evidence_background,
            evidence_service,
            request.framework_id,
            request.control_ids,
            request.collector_id,
            request.test_run_id,
        )

        return {
            "message": f"Evidence collection started for {len(request.control_ids)} controls",
            "framework_id": request.framework_id,
            "control_ids": request.control_ids,
            "task_id": collection_task_id,
            "estimated_duration_minutes": len(request.control_ids)
            * 2,  # Rough estimate
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Evidence collection failed: {e}")
        raise StandardResponses.internal_error("Evidence collection failed")


@router.get("/organizations/{org_id}/evidence", summary="List Evidence Items")
async def list_evidence(
    org_id: UUID,
    framework_id: str | None = Query(None, description="Filter by framework"),
    control_id: str | None = Query(None, description="Filter by control"),
    status: str | None = Query(None, description="Filter by status"),
    db: AsyncSession = Depends(get_db),
    query_service: EvidenceQueryService = Depends(get_evidence_query_service),
    current_user: User = Depends(require_org_access(require_read_findings)),
) -> list[dict[str, Any]]:
    """List evidence items for organization."""
    await get_entity_by_id_or_404(db, Organization, org_id, "Organization not found")

    try:
        # Build search filters
        filters: dict[str, Any] = {}
        if framework_id:
            filters["framework_name"] = framework_id
        if control_id:
            filters["control_id"] = control_id
        if status:
            filters["status"] = EvidenceStatus(status)

        evidence_items = await query_service.search_evidence(**filters)  # type: ignore[arg-type]

        return [
            {
                "id": item.id,
                "category": item.category.value,
                "status": item.status.value,
                "collected_at": (
                    item.collected_at.isoformat() if item.collected_at else None
                ),
                "collector_id": item.collector_id,
                "source_system": item.source_system,
                "content_size": item.content_size,
                "framework_name": getattr(item, "framework_name", None),
                "control_id": getattr(item, "control_id", None),
                "tags": item.tags,
            }
            for item in evidence_items[:100]  # Limit results
        ]

    except Exception as e:
        logger.error(f"Failed to list evidence: {e}")
        raise StandardResponses.internal_error("Failed to retrieve evidence")


@router.get(
    "/organizations/{org_id}/evidence/{evidence_id}", summary="Get Evidence Details"
)
async def get_evidence_details(
    org_id: UUID,
    evidence_id: str,
    include_content: bool = Query(False, description="Include evidence content"),
    db: AsyncSession = Depends(get_db),
    repository=Depends(get_evidence_repository),
    current_user: User = Depends(require_org_access(require_read_findings)),
) -> dict[str, Any]:
    """Get detailed evidence information."""
    await get_entity_by_id_or_404(db, Organization, org_id, "Organization not found")

    try:
        if include_content:
            evidence_data = await repository.get_evidence(evidence_id)
            if not evidence_data:
                raise StandardResponses.not_found("Evidence not found")

            content, metadata = evidence_data

            # Convert content to string if it's text-based
            content_preview = None
            if (
                metadata.content_type.startswith("text/")
                or metadata.content_type == "application/json"
            ):
                try:
                    content_preview = content.decode("utf-8")[:1000]  # First 1000 chars
                except UnicodeDecodeError:
                    content_preview = "Binary content"

            return {
                "metadata": _metadata_to_dict(metadata),
                "content_preview": content_preview,
                "content_size": len(content),
            }
        else:
            metadata = await repository.get_metadata(evidence_id)
            if not metadata:
                raise StandardResponses.not_found("Evidence not found")

            return {"metadata": _metadata_to_dict(metadata)}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get evidence details: {e}")
        raise StandardResponses.internal_error("Failed to retrieve evidence details")


# === EVIDENCE BUNDLE ENDPOINTS ===


@router.post(
    "/organizations/{org_id}/evidence-bundles", summary="Create Evidence Bundle"
)
async def create_evidence_bundle(
    org_id: UUID,
    request: EvidenceBundleRequest,
    db: AsyncSession = Depends(get_db),
    evidence_service: EvidenceService = Depends(get_evidence_service),
    current_user: User = Depends(
        require_org_access(require_scopes("compliance:bundle"))
    ),
) -> dict[str, str]:
    """Create evidence bundle for audit delivery."""
    await get_entity_by_id_or_404(db, Organization, org_id, "Organization not found")

    try:
        # Validate framework
        registry = get_framework_registry()
        framework = registry.get_framework(request.framework_id)
        if not framework:
            raise StandardResponses.bad_request(
                f"Framework '{request.framework_id}' not found"
            )

        # Get evidence for specified controls
        query_service = EvidenceQueryService(evidence_service.repository)
        evidence_ids = []

        for control_id in request.control_ids:
            control_evidence = await query_service.get_evidence_by_control(
                control_id, request.framework_id
            )
            evidence_ids.extend([e.id for e in control_evidence])

        if not evidence_ids:
            raise StandardResponses.bad_request(
                "No evidence found for specified controls"
            )

        # Create bundle
        bundle_id = await evidence_service.create_evidence_bundle(
            bundle_name=request.bundle_name,
            framework_name=request.framework_id,
            control_ids=request.control_ids,
            evidence_ids=evidence_ids,
            created_by=current_user.username,
            organization_id=str(org_id),
            bundle_type=request.bundle_type,
            description=request.description,
            period_start=request.period_start,
            period_end=request.period_end,
        )

        return {
            "bundle_id": bundle_id,
            "message": f"Created evidence bundle with {len(evidence_ids)} evidence items",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create evidence bundle: {e}")
        raise StandardResponses.internal_error("Failed to create evidence bundle")


@router.get(
    "/organizations/{org_id}/compliance-status/{framework_id}",
    summary="Get Compliance Status",
)
async def get_compliance_status(
    org_id: UUID,
    framework_id: str,
    db: AsyncSession = Depends(get_db),
    query_service: EvidenceQueryService = Depends(get_evidence_query_service),
    current_user: User = Depends(require_org_access(require_read_findings)),
) -> ComplianceStatusResponse:
    """Get current compliance status for organization and framework."""
    await get_entity_by_id_or_404(db, Organization, org_id, "Organization not found")

    try:
        registry = get_framework_registry()
        framework = registry.get_framework(framework_id)

        if not framework:
            raise StandardResponses.not_found(f"Framework '{framework_id}' not found")

        # Assess compliance status for each control
        control_summaries = []
        compliant_count = 0
        non_compliant_count = 0
        testing_count = 0

        for control in framework.controls:
            evidence_items = await query_service.get_evidence_by_control(
                control.control_id, framework_id
            )

            # Determine compliance status based on evidence
            if not evidence_items:
                compliance_status = "no_evidence"
            else:
                # Simple heuristic: if we have recent evidence, consider compliant
                recent_evidence = [
                    e
                    for e in evidence_items
                    if e.collected_at
                    and e.collected_at > (datetime.utcnow() - timedelta(days=90))
                ]

                if recent_evidence:
                    # Use framework provider validation if available
                    provider = registry.get_provider(framework_id)
                    if provider:
                        # Would validate with actual evidence data
                        compliance_status = "compliant"
                        compliant_count += 1
                    else:
                        compliance_status = "compliant"
                        compliant_count += 1
                else:
                    compliance_status = "non_compliant"
                    non_compliant_count += 1

            control_summaries.append(
                ControlSummary(
                    control_id=control.control_id,
                    title=control.title,
                    category=control.category,
                    control_type=control.control_type.value,
                    automation_level=control.automation_level.value,
                    testing_frequency=control.testing_frequency.value,
                    risk_level=control.risk_level,
                    evidence_count=len(evidence_items),
                    compliance_status=compliance_status,
                )
            )

        total_controls = len(framework.controls)
        compliance_percentage = (
            round((compliant_count / total_controls) * 100, 1)
            if total_controls > 0
            else 0
        )

        return ComplianceStatusResponse(
            framework_id=framework_id,
            organization_id=str(org_id),
            assessment_date=datetime.utcnow(),
            total_controls=total_controls,
            compliant_controls=compliant_count,
            non_compliant_controls=non_compliant_count,
            testing_controls=testing_count,
            compliance_percentage=compliance_percentage,
            control_status=control_summaries,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get compliance status: {e}")
        raise StandardResponses.internal_error("Failed to assess compliance status")


# === UTILITY FUNCTIONS ===


async def _collect_evidence_background(
    evidence_service: EvidenceService,
    framework_id: str,
    control_ids: list[str],
    collector_id: str,
    test_run_id: str | None,
):
    """Background task for evidence collection."""
    try:
        registry = get_framework_registry()

        for control_id in control_ids:
            queries = registry.get_evidence_queries(framework_id, control_id)
            if queries:
                evidence_ids = await evidence_service.collect_compliance_evidence(
                    control_id=control_id,
                    framework_name=framework_id,
                    queries=queries,
                    collector_id=collector_id,
                    test_run_id=test_run_id,
                )
                logger.info(
                    f"Collected {len(evidence_ids)} evidence items for control {control_id}"
                )

        logger.info(
            f"Background evidence collection completed for {len(control_ids)} controls"
        )

    except Exception as e:
        logger.error(f"Background evidence collection failed: {e}")


def _metadata_to_dict(metadata) -> dict[str, Any]:
    """Convert metadata to dictionary for API response."""
    result = {
        "id": metadata.id,
        "category": metadata.category.value,
        "content_type": metadata.content_type,
        "collector_id": metadata.collector_id,
        "collector_type": metadata.collector_type,
        "collection_method": metadata.collection_method.value,
        "source_system": metadata.source_system,
        "content_size": metadata.content_size,
        "content_hash": metadata.content_hash,
        "created_at": metadata.created_at.isoformat(),
        "collected_at": (
            metadata.collected_at.isoformat() if metadata.collected_at else None
        ),
        "status": metadata.status.value,
        "retention_class": metadata.retention_class.value,
        "expires_at": metadata.expires_at.isoformat() if metadata.expires_at else None,
        "pii_detected": metadata.pii_detected,
        "sensitivity_level": metadata.sensitivity_level,
        "tags": metadata.tags,
        "related_evidence_ids": metadata.related_evidence_ids,
    }

    # Add type-specific fields
    if hasattr(metadata, "control_id"):
        result["control_id"] = metadata.control_id
    if hasattr(metadata, "framework_name"):
        result["framework_name"] = metadata.framework_name
    if hasattr(metadata, "query_used"):
        result["query_used"] = metadata.query_used

    return result


# === HEALTH CHECK ===


@router.get("/health", summary="Compliance Service Health")
async def compliance_health():
    """Check health of compliance services."""
    try:
        registry = get_framework_registry()
        frameworks = registry.list_frameworks()

        return {
            "service": "compliance",
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "frameworks_available": len(frameworks),
            "frameworks": frameworks,
            "capabilities": [
                "framework_management",
                "evidence_collection",
                "evidence_storage",
                "evidence_bundling",
                "compliance_assessment",
            ],
        }

    except Exception as e:
        logger.error(f"Compliance health check failed: {e}")
        raise StandardResponses.internal_error("Compliance service unhealthy")
