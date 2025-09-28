"""
Identity governance API endpoints.

Provides REST API for JML campaigns, access reviews, peer group analysis,
and exception management.
"""

from typing import List, Optional
from uuid import UUID
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
import logging

from ...core.database import get_db
from ...core.models import Organization
from ...api.auth import require_read_findings
from ...identity_governance.jml_campaigns import get_jml_manager, JMLEventType
from ...identity_governance.access_reviews import get_access_review_manager, ReviewDecision
from ...identity_governance.peer_groups import get_peer_group_analyzer
from ...identity_governance.exceptions import get_exception_manager, ExceptionType

router = APIRouter()
logger = logging.getLogger(__name__)


class JMLCampaignRequest(BaseModel):
    """Request to create JML campaign."""
    campaign_name: str = Field(..., description="Name for the JML campaign")
    lookback_days: int = Field(30, description="Days to look back for changes", ge=1, le=90)


class AccessReviewRequest(BaseModel):
    """Request to create access review."""
    quarter: str = Field(..., description="Quarter identifier (e.g., 'Q1 2024')")
    scope: Optional[Dict[str, Any]] = Field(None, description="Review scope filters")


class ReviewDecisionRequest(BaseModel):
    """Request to record review decision."""
    item_id: str = Field(..., description="Review item ID")
    decision: str = Field(..., description="Review decision")
    justification: str = Field(..., description="Decision justification")
    exception_days: Optional[int] = Field(None, description="Exception duration in days")


class ExceptionRequest(BaseModel):
    """Request for access exception."""
    principal_id: str
    resource_id: str
    permission: str
    provider: str
    justification: str
    business_need: str
    exception_type: str
    duration_days: int = Field(..., ge=1, le=365)
    project_reference: Optional[str] = None


# JML Campaign Endpoints
@router.post("/organizations/{org_id}/jml/campaigns")
async def create_jml_campaign(
    org_id: UUID,
    request: JMLCampaignRequest,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Create Joiner/Mover/Leaver campaign."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        jml_manager = get_jml_manager()
        campaign = await jml_manager.create_jml_campaign(
            str(org_id),
            request.campaign_name,
            current_user.username,
            request.lookback_days
        )
        
        return {
            "success": True,
            "message": f"JML campaign created with {campaign['summary']['jml_events_detected']} events",
            "data": campaign
        }
        
    except Exception as e:
        logger.error(f"JML campaign creation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Campaign creation failed: {str(e)}")


@router.get("/organizations/{org_id}/jml/events")
async def get_jml_events(
    org_id: UUID,
    lookback_days: int = Query(7, description="Days to look back", ge=1, le=90),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Get recent JML events for organization."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        jml_manager = get_jml_manager()
        events = await jml_manager.detect_jml_events(str(org_id), lookback_days)
        
        # Filter by event type if specified
        if event_type:
            events = [e for e in events if e.event_type.value == event_type]
        
        return {
            "organization_id": str(org_id),
            "lookback_days": lookback_days,
            "total_events": len(events),
            "events": [
                {
                    "event_id": event.event_id,
                    "principal_id": event.principal_id,
                    "event_type": event.event_type.value,
                    "event_date": event.event_date.isoformat(),
                    "requires_review": event.requires_review,
                    "review_deadline": event.review_deadline.isoformat(),
                    "affected_access_count": len(event.affected_access),
                    "metadata": event.metadata
                }
                for event in events
            ]
        }
        
    except Exception as e:
        logger.error(f"JML events retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"JML events failed: {str(e)}")


# Access Review Endpoints
@router.post("/organizations/{org_id}/access-reviews")
async def create_access_review(
    org_id: UUID,
    request: AccessReviewRequest,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Create quarterly access review campaign."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        review_manager = get_access_review_manager()
        review = await review_manager.create_quarterly_review(
            str(org_id),
            request.quarter,
            current_user.username,
            request.scope
        )
        
        return {
            "success": True,
            "message": f"Access review created with {len(review.review_items)} items",
            "data": {
                "review_id": review.review_id,
                "quarter": review.review_period,
                "due_date": review.due_date.isoformat(),
                "total_items": len(review.review_items),
                "status": review.status.value
            }
        }
        
    except Exception as e:
        logger.error(f"Access review creation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Review creation failed: {str(e)}")


@router.get("/organizations/{org_id}/access-reviews")
async def list_access_reviews(
    org_id: UUID,
    status: Optional[str] = Query(None, description="Filter by status"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """List access reviews for organization."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        review_manager = get_access_review_manager()
        
        # Get pending and overdue reviews
        pending_reviews = await review_manager.get_pending_reviews(str(org_id))
        overdue_reviews = await review_manager.get_overdue_reviews(str(org_id))
        
        all_reviews = pending_reviews + overdue_reviews
        
        # Filter by status if specified
        if status:
            all_reviews = [r for r in all_reviews if r.get("status") == status]
        
        return {
            "organization_id": str(org_id),
            "total_reviews": len(all_reviews),
            "pending_count": len(pending_reviews),
            "overdue_count": len(overdue_reviews),
            "reviews": all_reviews
        }
        
    except Exception as e:
        logger.error(f"Access review listing failed: {e}")
        raise HTTPException(status_code=500, detail=f"Review listing failed: {str(e)}")


@router.post("/organizations/{org_id}/access-reviews/{review_id}/decisions")
async def record_review_decision(
    org_id: UUID,
    review_id: str,
    request: ReviewDecisionRequest,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Record access review decision."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        review_manager = get_access_review_manager()
        
        # Convert string decision to enum
        decision_enum = ReviewDecision(request.decision.lower())
        
        decision_record = await review_manager.record_review_decision(
            review_id,
            request.item_id,
            current_user.username,
            decision_enum,
            request.justification,
            request.exception_days
        )
        
        return {
            "success": True,
            "message": f"Review decision recorded: {request.decision}",
            "data": decision_record
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid decision: {str(e)}")
    except Exception as e:
        logger.error(f"Review decision failed: {e}")
        raise HTTPException(status_code=500, detail=f"Decision recording failed: {str(e)}")


# Peer Group Analysis Endpoints
@router.get("/organizations/{org_id}/peer-groups/analysis")
async def get_peer_group_analysis(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Get peer group analysis and outlier detection."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        analyzer = get_peer_group_analyzer()
        report = await analyzer.generate_peer_group_report(str(org_id))
        
        return {
            "success": True,
            "message": f"Analyzed {report['summary']['departments_analyzed']} departments",
            "data": report
        }
        
    except Exception as e:
        logger.error(f"Peer group analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Peer group analysis failed: {str(e)}")


@router.get("/organizations/{org_id}/peer-groups/outliers")
async def get_access_outliers(
    org_id: UUID,
    min_risk_score: float = Query(0.6, description="Minimum risk score for outliers", ge=0.0, le=1.0),
    department: Optional[str] = Query(None, description="Filter by department"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Get access outliers compared to peer groups."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        analyzer = get_peer_group_analyzer()
        outliers = await analyzer.analyze_outliers(str(org_id))
        
        # Filter by risk score
        filtered_outliers = [o for o in outliers if o.risk_score >= min_risk_score]
        
        # Filter by department if specified
        if department:
            filtered_outliers = [o for o in filtered_outliers if o.department == department]
        
        return {
            "organization_id": str(org_id),
            "min_risk_score": min_risk_score,
            "total_outliers": len(filtered_outliers),
            "outliers": [
                {
                    "principal_id": outlier.principal_id,
                    "department": outlier.department,
                    "role": outlier.role,
                    "risk_score": outlier.risk_score,
                    "outlier_permission_count": len(outlier.outlier_permissions),
                    "peer_group_size": outlier.peer_group_size,
                    "recommendations": outlier.recommendations
                }
                for outlier in filtered_outliers
            ]
        }
        
    except Exception as e:
        logger.error(f"Outlier analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Outlier analysis failed: {str(e)}")


# Exception Management Endpoints
@router.post("/organizations/{org_id}/exceptions")
async def request_access_exception(
    org_id: UUID,
    request: ExceptionRequest,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Request time-boxed access exception."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        exception_manager = get_exception_manager()
        
        # Convert string to enum
        exception_type_enum = ExceptionType(request.exception_type.lower())
        
        exception = await exception_manager.request_access_exception(
            request.principal_id,
            request.resource_id,
            request.permission,
            request.provider,
            current_user.username,
            request.justification,
            request.business_need,
            exception_type_enum,
            request.duration_days,
            request.project_reference
        )
        
        return {
            "success": True,
            "message": "Access exception requested",
            "data": {
                "exception_id": exception.exception_id,
                "status": exception.status.value,
                "expiry_date": exception.expiry_date.isoformat(),
                "requires_approval": exception.metadata.get("approval_required", False)
            }
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Exception request failed: {e}")
        raise HTTPException(status_code=500, detail=f"Exception request failed: {str(e)}")


@router.post("/organizations/{org_id}/exceptions/{exception_id}/approve")
async def approve_access_exception(
    org_id: UUID,
    exception_id: str,
    approval_justification: str = Field(..., description="Justification for approval"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Approve access exception."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        exception_manager = get_exception_manager()
        
        approved_exception = await exception_manager.approve_exception(
            exception_id,
            current_user.username,
            approval_justification
        )
        
        return {
            "success": True,
            "message": "Access exception approved",
            "data": {
                "exception_id": exception_id,
                "approved_at": approved_exception.approved_at.isoformat(),
                "expiry_date": approved_exception.expiry_date.isoformat(),
                "attestation_id": approved_exception.attestation_id
            }
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Exception approval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Exception approval failed: {str(e)}")


@router.post("/organizations/{org_id}/exceptions/process-expired")
async def process_expired_exceptions(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Process expired exceptions and auto-revoke access."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        exception_manager = get_exception_manager()
        results = await exception_manager.process_expired_exceptions(str(org_id))
        
        return {
            "success": True,
            "message": f"Processed {results['expired_count']} expired exceptions",
            "data": results
        }
        
    except Exception as e:
        logger.error(f"Exception processing failed: {e}")
        raise HTTPException(status_code=500, detail=f"Exception processing failed: {str(e)}")


# Combined Identity Governance Dashboard
@router.get("/organizations/{org_id}/identity-governance/dashboard")
async def get_identity_governance_dashboard(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_read_findings)
):
    """Get comprehensive identity governance dashboard."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        jml_manager = get_jml_manager()
        review_manager = get_access_review_manager()
        analyzer = get_peer_group_analyzer()
        exception_manager = get_exception_manager()
        
        # Get recent JML events
        jml_events = await jml_manager.detect_jml_events(str(org_id), 30)
        
        # Get pending reviews
        pending_reviews = await review_manager.get_pending_reviews(str(org_id))
        overdue_reviews = await review_manager.get_overdue_reviews(str(org_id))
        
        # Get peer group outliers
        outliers = await analyzer.analyze_outliers(str(org_id))
        high_risk_outliers = [o for o in outliers if o.risk_score >= 0.8]
        
        # Process expired exceptions
        expired_results = await exception_manager.process_expired_exceptions(str(org_id))
        
        return {
            "organization_id": str(org_id),
            "dashboard_generated_at": datetime.now().isoformat(),
            "summary": {
                "jml_events_30_days": len(jml_events),
                "pending_reviews": len(pending_reviews),
                "overdue_reviews": len(overdue_reviews),
                "high_risk_outliers": len(high_risk_outliers),
                "expired_exceptions": expired_results["expired_count"]
            },
            "urgent_actions": [
                {
                    "type": "overdue_review",
                    "count": len(overdue_reviews),
                    "message": f"{len(overdue_reviews)} access reviews are overdue"
                },
                {
                    "type": "high_risk_outliers",
                    "count": len(high_risk_outliers),
                    "message": f"{len(high_risk_outliers)} users have unusual access patterns"
                },
                {
                    "type": "jml_reviews_required",
                    "count": len([e for e in jml_events if e.requires_review]),
                    "message": f"{len([e for e in jml_events if e.requires_review])} lifecycle events require access review"
                }
            ],
            "recent_jml_events": [
                {
                    "event_id": event.event_id,
                    "principal_id": event.principal_id,
                    "event_type": event.event_type.value,
                    "requires_review": event.requires_review,
                    "review_deadline": event.review_deadline.isoformat()
                }
                for event in jml_events[:10]  # Latest 10
            ],
            "top_outliers": [
                {
                    "principal_id": outlier.principal_id,
                    "department": outlier.department,
                    "risk_score": outlier.risk_score,
                    "outlier_permission_count": len(outlier.outlier_permissions)
                }
                for outlier in high_risk_outliers[:5]  # Top 5
            ]
        }
        
    except Exception as e:
        logger.error(f"Identity governance dashboard failed: {e}")
        raise HTTPException(status_code=500, detail=f"Dashboard generation failed: {str(e)}")
