"""
Security review management for vendor assessments.

Implements comprehensive security review workflows, tracking, and reporting
for vendor risk management and compliance requirements.
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Column, String, DateTime, Boolean, Text, Integer
from sqlalchemy.sql import func

from cerebro.core.database import Base

logger = logging.getLogger(__name__)


class ReviewStatus(Enum):
    """Status of security review."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    APPROVED = "approved"
    REJECTED = "rejected"
    REQUIRES_REMEDIATION = "requires_remediation"
    EXPIRED = "expired"


class ReviewType(Enum):
    """Type of security review."""
    INITIAL_ASSESSMENT = "initial_assessment"
    ANNUAL_REVIEW = "annual_review"
    CHANGE_ASSESSMENT = "change_assessment"
    INCIDENT_REVIEW = "incident_review"
    COMPLIANCE_AUDIT = "compliance_audit"
    PENETRATION_TEST = "penetration_test"


class SecurityFramework(Enum):
    """Security frameworks for assessment."""
    SOC2_TYPE_I = "soc2_type_i"
    SOC2_TYPE_II = "soc2_type_ii"
    ISO27001 = "iso27001"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    FedRAMP = "fedramp"


@dataclass
class SecurityControlResult:
    """Result of a security control assessment."""
    control_id: str
    control_name: str
    description: str
    status: str  # "compliant", "non_compliant", "partial", "not_applicable"
    evidence: List[str]
    remediation_required: bool
    remediation_deadline: Optional[datetime] = None
    notes: Optional[str] = None


@dataclass 
class ReviewMetrics:
    """Metrics for security review performance."""
    total_controls: int
    compliant_controls: int
    non_compliant_controls: int
    partial_compliance: int
    not_applicable: int
    remediation_items: int
    overall_score: float
    risk_rating: str


class SecurityReview(Base):
    """Database model for security reviews."""
    __tablename__ = "security_reviews"
    
    review_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    vendor_id: Mapped[str] = mapped_column(String(100), nullable=False)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    
    # Review metadata
    review_type: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default=ReviewStatus.PENDING.value)
    framework: Mapped[str] = mapped_column(String(50), nullable=False)
    
    # Timeline
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    due_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    
    # Review details
    scope: Mapped[Optional[str]] = mapped_column(Text)
    objectives: Mapped[Optional[str]] = mapped_column(Text)
    methodology: Mapped[Optional[str]] = mapped_column(Text)
    
    # Results
    overall_score: Mapped[Optional[float]] = mapped_column()
    risk_rating: Mapped[Optional[str]] = mapped_column(String(20))
    findings_summary: Mapped[Optional[str]] = mapped_column(Text)
    remediation_plan: Mapped[Optional[str]] = mapped_column(Text)
    
    # Tracking
    reviewer_id: Mapped[Optional[str]] = mapped_column(String(100))
    approved_by: Mapped[Optional[str]] = mapped_column(String(100))
    next_review_due: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    
    # Metadata
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class SecurityReviewControl(Base):
    """Database model for individual security controls within reviews."""
    __tablename__ = "security_review_controls"
    
    control_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    review_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    
    # Control details
    control_reference: Mapped[str] = mapped_column(String(50), nullable=False)
    control_name: Mapped[str] = mapped_column(String(200), nullable=False)
    control_description: Mapped[Optional[str]] = mapped_column(Text)
    control_category: Mapped[Optional[str]] = mapped_column(String(100))
    
    # Assessment
    assessment_status: Mapped[str] = mapped_column(String(50), nullable=False)  # compliant, non_compliant, etc.
    assessment_notes: Mapped[Optional[str]] = mapped_column(Text)
    evidence_links: Mapped[Optional[str]] = mapped_column(Text)  # JSON array of URLs/references
    
    # Remediation
    remediation_required: Mapped[bool] = mapped_column(Boolean, default=False)
    remediation_priority: Mapped[Optional[str]] = mapped_column(String(20))
    remediation_deadline: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    remediation_status: Mapped[Optional[str]] = mapped_column(String(50))
    
    # Tracking
    assessed_by: Mapped[Optional[str]] = mapped_column(String(100))
    assessed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), onupdate=func.now())


class SecurityReviewManager:
    """Manager for security review operations and workflows."""
    
    def __init__(self, db_session: AsyncSession):
        """Initialize security review manager."""
        self.db = db_session
    
    async def create_security_review(
        self,
        vendor_id: str,
        org_id: UUID,
        review_type: ReviewType,
        framework: SecurityFramework,
        scope: Optional[str] = None,
        due_date: Optional[datetime] = None,
        reviewer_id: Optional[str] = None
    ) -> SecurityReview:
        """Create a new security review."""
        
        # Calculate default due date if not provided
        if not due_date:
            if review_type == ReviewType.INITIAL_ASSESSMENT:
                due_date = datetime.utcnow() + timedelta(days=30)
            elif review_type == ReviewType.ANNUAL_REVIEW:
                due_date = datetime.utcnow() + timedelta(days=45)
            else:
                due_date = datetime.utcnow() + timedelta(days=14)
        
        review = SecurityReview(
            vendor_id=vendor_id,
            org_id=org_id,
            review_type=review_type.value,
            framework=framework.value,
            scope=scope,
            due_date=due_date,
            reviewer_id=reviewer_id
        )
        
        self.db.add(review)
        await self.db.commit()
        await self.db.refresh(review)
        
        logger.info(f"Created security review {review.review_id} for vendor {vendor_id}")
        return review
    
    async def get_review(self, review_id: UUID) -> Optional[SecurityReview]:
        """Get security review by ID."""
        return await self.db.get(SecurityReview, review_id)
    
    async def list_reviews(
        self,
        org_id: UUID,
        vendor_id: Optional[str] = None,
        status: Optional[ReviewStatus] = None,
        framework: Optional[SecurityFramework] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[SecurityReview]:
        """List security reviews with filtering."""
        stmt = select(SecurityReview).where(SecurityReview.org_id == org_id)
        
        if vendor_id:
            stmt = stmt.where(SecurityReview.vendor_id == vendor_id)
        if status:
            stmt = stmt.where(SecurityReview.status == status.value)
        if framework:
            stmt = stmt.where(SecurityReview.framework == framework.value)
        
        stmt = stmt.order_by(desc(SecurityReview.created_at)).offset(offset).limit(limit)
        
        return list(await self.db.scalars(stmt))
    
    async def start_review(self, review_id: UUID, reviewer_id: str) -> bool:
        """Start a security review."""
        review = await self.get_review(review_id)
        if not review:
            return False
        
        review.status = ReviewStatus.IN_PROGRESS.value
        review.started_at = datetime.utcnow()
        review.reviewer_id = reviewer_id
        
        await self.db.commit()
        
        logger.info(f"Started security review {review_id} by {reviewer_id}")
        return True
    
    async def complete_review(
        self,
        review_id: UUID,
        overall_score: float,
        risk_rating: str,
        findings_summary: str,
        remediation_plan: Optional[str] = None
    ) -> bool:
        """Complete a security review with results."""
        review = await self.get_review(review_id)
        if not review:
            return False
        
        review.status = ReviewStatus.COMPLETED.value
        review.completed_at = datetime.utcnow()
        review.overall_score = overall_score
        review.risk_rating = risk_rating
        review.findings_summary = findings_summary
        review.remediation_plan = remediation_plan
        
        # Calculate next review due date
        if review.review_type == ReviewType.ANNUAL_REVIEW.value:
            review.next_review_due = datetime.utcnow() + timedelta(days=365)
        else:
            review.next_review_due = datetime.utcnow() + timedelta(days=180)
        
        await self.db.commit()
        
        logger.info(f"Completed security review {review_id} with score {overall_score}")
        return True
    
    async def approve_review(self, review_id: UUID, approver_id: str) -> bool:
        """Approve a completed security review."""
        review = await self.get_review(review_id)
        if not review or review.status != ReviewStatus.COMPLETED.value:
            return False
        
        review.status = ReviewStatus.APPROVED.value
        review.approved_by = approver_id
        
        await self.db.commit()
        
        logger.info(f"Approved security review {review_id} by {approver_id}")
        return True
    
    async def reject_review(
        self,
        review_id: UUID,
        reason: str,
        approver_id: str
    ) -> bool:
        """Reject a security review."""
        review = await self.get_review(review_id)
        if not review:
            return False
        
        review.status = ReviewStatus.REJECTED.value
        review.approved_by = approver_id
        review.findings_summary = f"REJECTED: {reason}"
        
        await self.db.commit()
        
        logger.info(f"Rejected security review {review_id} by {approver_id}")
        return True
    
    async def add_control_assessment(
        self,
        review_id: UUID,
        control_ref: str,
        control_name: str,
        assessment_status: str,
        evidence_links: Optional[List[str]] = None,
        notes: Optional[str] = None,
        remediation_required: bool = False,
        assessor_id: Optional[str] = None
    ) -> SecurityReviewControl:
        """Add a control assessment to a security review."""
        
        control = SecurityReviewControl(
            review_id=review_id,
            control_reference=control_ref,
            control_name=control_name,
            assessment_status=assessment_status,
            assessment_notes=notes,
            evidence_links=str(evidence_links) if evidence_links else None,
            remediation_required=remediation_required,
            assessed_by=assessor_id,
            assessed_at=datetime.utcnow() if assessor_id else None
        )
        
        self.db.add(control)
        await self.db.commit()
        await self.db.refresh(control)
        
        logger.debug(f"Added control assessment {control_ref} to review {review_id}")
        return control
    
    async def get_review_controls(self, review_id: UUID) -> List[SecurityReviewControl]:
        """Get all control assessments for a review."""
        stmt = select(SecurityReviewControl).where(
            SecurityReviewControl.review_id == review_id
        ).order_by(SecurityReviewControl.control_reference)
        
        return list(await self.db.scalars(stmt))
    
    async def calculate_review_metrics(self, review_id: UUID) -> ReviewMetrics:
        """Calculate metrics for a security review."""
        controls = await self.get_review_controls(review_id)
        
        if not controls:
            return ReviewMetrics(
                total_controls=0,
                compliant_controls=0,
                non_compliant_controls=0,
                partial_compliance=0,
                not_applicable=0,
                remediation_items=0,
                overall_score=0.0,
                risk_rating="unknown"
            )
        
        # Count control statuses
        status_counts = {}
        remediation_count = 0
        
        for control in controls:
            status = control.assessment_status
            status_counts[status] = status_counts.get(status, 0) + 1
            
            if control.remediation_required:
                remediation_count += 1
        
        total = len(controls)
        compliant = status_counts.get("compliant", 0)
        non_compliant = status_counts.get("non_compliant", 0)
        partial = status_counts.get("partial", 0)
        not_applicable = status_counts.get("not_applicable", 0)
        
        # Calculate overall score
        scored_controls = total - not_applicable
        if scored_controls > 0:
            weighted_score = (compliant * 1.0 + partial * 0.5) / scored_controls
            overall_score = weighted_score * 100
        else:
            overall_score = 0.0
        
        # Determine risk rating
        if overall_score >= 90:
            risk_rating = "low"
        elif overall_score >= 75:
            risk_rating = "medium"
        elif overall_score >= 60:
            risk_rating = "high"
        else:
            risk_rating = "critical"
        
        return ReviewMetrics(
            total_controls=total,
            compliant_controls=compliant,
            non_compliant_controls=non_compliant,
            partial_compliance=partial,
            not_applicable=not_applicable,
            remediation_items=remediation_count,
            overall_score=overall_score,
            risk_rating=risk_rating
        )
    
    async def get_overdue_reviews(self, org_id: UUID) -> List[SecurityReview]:
        """Get security reviews that are overdue."""
        now = datetime.utcnow()
        
        stmt = select(SecurityReview).where(
            and_(
                SecurityReview.org_id == org_id,
                SecurityReview.due_date < now,
                SecurityReview.status.in_([
                    ReviewStatus.PENDING.value,
                    ReviewStatus.IN_PROGRESS.value
                ])
            )
        ).order_by(SecurityReview.due_date)
        
        return list(await self.db.scalars(stmt))
    
    async def get_upcoming_reviews(
        self,
        org_id: UUID,
        days_ahead: int = 30
    ) -> List[SecurityReview]:
        """Get security reviews due in the next N days."""
        now = datetime.utcnow()
        future_date = now + timedelta(days=days_ahead)
        
        stmt = select(SecurityReview).where(
            and_(
                SecurityReview.org_id == org_id,
                SecurityReview.due_date >= now,
                SecurityReview.due_date <= future_date,
                SecurityReview.status.in_([
                    ReviewStatus.PENDING.value,
                    ReviewStatus.IN_PROGRESS.value
                ])
            )
        ).order_by(SecurityReview.due_date)
        
        return list(await self.db.scalars(stmt))
    
    async def generate_review_report(self, review_id: UUID) -> Dict[str, Any]:
        """Generate comprehensive review report."""
        review = await self.get_review(review_id)
        if not review:
            raise ValueError(f"Review {review_id} not found")
        
        controls = await self.get_review_controls(review_id)
        metrics = await self.calculate_review_metrics(review_id)
        
        # Group controls by category
        controls_by_category = {}
        for control in controls:
            category = control.control_category or "General"
            if category not in controls_by_category:
                controls_by_category[category] = []
            controls_by_category[category].append({
                "control_reference": control.control_reference,
                "control_name": control.control_name,
                "status": control.assessment_status,
                "remediation_required": control.remediation_required,
                "notes": control.assessment_notes
            })
        
        return {
            "review": {
                "review_id": str(review.review_id),
                "vendor_id": review.vendor_id,
                "review_type": review.review_type,
                "framework": review.framework,
                "status": review.status,
                "started_at": review.started_at.isoformat() if review.started_at else None,
                "completed_at": review.completed_at.isoformat() if review.completed_at else None,
                "due_date": review.due_date.isoformat() if review.due_date else None,
                "overall_score": review.overall_score,
                "risk_rating": review.risk_rating
            },
            "metrics": {
                "total_controls": metrics.total_controls,
                "compliant_controls": metrics.compliant_controls,
                "non_compliant_controls": metrics.non_compliant_controls,
                "partial_compliance": metrics.partial_compliance,
                "not_applicable": metrics.not_applicable,
                "remediation_items": metrics.remediation_items,
                "overall_score": metrics.overall_score,
                "risk_rating": metrics.risk_rating
            },
            "controls_by_category": controls_by_category,
            "remediation_items": [
                {
                    "control_reference": control.control_reference,
                    "control_name": control.control_name,
                    "priority": control.remediation_priority,
                    "deadline": control.remediation_deadline.isoformat() if control.remediation_deadline else None,
                    "status": control.remediation_status
                }
                for control in controls if control.remediation_required
            ]
        }
    
    async def update_review_status(
        self,
        review_id: UUID,
        status: ReviewStatus,
        notes: Optional[str] = None
    ) -> bool:
        """Update security review status."""
        review = await self.get_review(review_id)
        if not review:
            return False
        
        old_status = review.status
        review.status = status.value
        
        if notes:
            review.findings_summary = (review.findings_summary or "") + f"\n{notes}"
        
        await self.db.commit()
        
        logger.info(f"Updated review {review_id} status from {old_status} to {status.value}")
        return True
    
    async def schedule_next_review(
        self,
        vendor_id: str,
        org_id: UUID,
        base_review_id: UUID
    ) -> Optional[SecurityReview]:
        """Schedule the next periodic review for a vendor."""
        base_review = await self.get_review(base_review_id)
        if not base_review:
            return None
        
        # Determine next review type and timing
        if base_review.review_type == ReviewType.INITIAL_ASSESSMENT.value:
            next_type = ReviewType.ANNUAL_REVIEW
            due_date = datetime.utcnow() + timedelta(days=365)
        else:
            next_type = ReviewType.ANNUAL_REVIEW
            due_date = datetime.utcnow() + timedelta(days=365)
        
        next_review = await self.create_security_review(
            vendor_id=vendor_id,
            org_id=org_id,
            review_type=next_type,
            framework=SecurityFramework(base_review.framework),
            due_date=due_date
        )
        
        logger.info(f"Scheduled next review {next_review.review_id} for vendor {vendor_id}")
        return next_review
    
    async def get_review_dashboard(self, org_id: UUID) -> Dict[str, Any]:
        """Get dashboard data for security reviews.
        
        Uses SQL aggregation for efficient counting on large datasets.
        """
        # Get total count
        total_stmt = select(func.count()).select_from(SecurityReview).where(
            SecurityReview.org_id == org_id
        )
        total_reviews = await self.db.scalar(total_stmt) or 0
        
        # Get counts by status using SQL GROUP BY
        status_stmt = select(
            SecurityReview.status,
            func.count().label('count')
        ).where(SecurityReview.org_id == org_id).group_by(SecurityReview.status)
        status_results = await self.db.execute(status_stmt)
        status_counts = {row.status: row.count for row in status_results}
        
        # Get overdue and upcoming reviews
        overdue = await self.get_overdue_reviews(org_id)
        upcoming = await self.get_upcoming_reviews(org_id, days_ahead=30)
        
        return {
            "summary": {
                "total_reviews": total_reviews,
                "pending_reviews": status_counts.get(ReviewStatus.PENDING.value, 0),
                "in_progress_reviews": status_counts.get(ReviewStatus.IN_PROGRESS.value, 0),
                "completed_reviews": status_counts.get(ReviewStatus.COMPLETED.value, 0),
                "approved_reviews": status_counts.get(ReviewStatus.APPROVED.value, 0),
                "overdue_reviews": len(overdue),
                "upcoming_reviews": len(upcoming)
            },
            "overdue_reviews": [
                {
                    "review_id": str(review.review_id),
                    "vendor_id": review.vendor_id,
                    "due_date": review.due_date.isoformat() if review.due_date else None,
                    "days_overdue": (datetime.utcnow() - review.due_date).days if review.due_date else 0
                }
                for review in overdue
            ],
            "upcoming_reviews": [
                {
                    "review_id": str(review.review_id),
                    "vendor_id": review.vendor_id,
                    "due_date": review.due_date.isoformat() if review.due_date else None,
                    "days_until_due": (review.due_date - datetime.utcnow()).days if review.due_date else 0
                }
                for review in upcoming
            ]
        }
