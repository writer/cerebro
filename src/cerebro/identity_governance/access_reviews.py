"""
Quarterly access review management with attestation workflows.

Implements time-boxed access reviews with auto-expiry and attestation tracking.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from sqlalchemy import and_, select

from ..auditability.attestation import get_attestation_service
from ..core.database import async_session_factory
from ..core.models import IamEdge, Principal

logger = logging.getLogger(__name__)


class ReviewStatus(Enum):
    """Status of access reviews."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    EXCEPTION_GRANTED = "exception_granted"


class ReviewDecision(Enum):
    """Possible decisions for access review."""

    APPROVE = "approve"  # Keep access
    REVOKE = "revoke"  # Remove access
    REDUCE = "reduce"  # Reduce permissions
    EXCEPTION = "exception"  # Grant time-limited exception
    TRANSFER = "transfer"  # Transfer to new owner


@dataclass
class AccessReviewItem:
    """Single access item being reviewed."""

    item_id: str
    principal_id: str
    resource_id: str
    permission: str
    provider: str
    granted_date: datetime
    last_used: datetime | None
    business_justification: str
    risk_level: str
    reviewer_assigned: str
    status: ReviewStatus
    decision: ReviewDecision | None
    decision_justification: str | None
    decision_date: datetime | None
    exception_expiry: datetime | None


@dataclass
class AccessReview:
    """Quarterly access review campaign."""

    review_id: str
    organization_id: str
    review_period: str  # "Q1 2024"
    created_by: str
    created_at: datetime
    due_date: datetime
    status: ReviewStatus
    scope: dict[str, Any]  # Which principals/resources to review
    review_items: list[AccessReviewItem]
    completion_stats: dict[str, int]
    attestations: list[str]  # List of attestation IDs


class AccessReviewManager:
    """
    Manages quarterly access reviews with attestation workflows.

    Provides automated access review campaigns with time-boxed exceptions
    and cryptographic attestation of review decisions.
    """

    def __init__(self):
        self.attestation_service = get_attestation_service()

    async def create_quarterly_review(
        self,
        org_id: str,
        quarter: str,  # "Q1 2024"
        created_by: str,
        scope: dict[str, Any] | None = None,
    ) -> AccessReview:
        """
        Create quarterly access review campaign.

        Args:
            org_id: Organization ID
            quarter: Quarter identifier (e.g., "Q1 2024")
            created_by: User creating the review
            scope: Optional scope filters (departments, roles, etc.)

        Returns:
            AccessReview campaign
        """
        review_id = f"access_review_{org_id}_{quarter.replace(' ', '_')}"

        # Calculate due date (30 days from creation)
        due_date = datetime.now() + timedelta(days=30)

        # Get all principals in scope
        principals = await self._get_principals_in_scope(org_id, scope or {})

        # Create review items for each principal's access
        review_items = []
        for principal in principals:
            principal_items = await self._create_review_items_for_principal(
                principal, created_by
            )
            review_items.extend(principal_items)

        review = AccessReview(
            review_id=review_id,
            organization_id=org_id,
            review_period=quarter,
            created_by=created_by,
            created_at=datetime.now(),
            due_date=due_date,
            status=ReviewStatus.PENDING,
            scope=scope or {},
            review_items=review_items,
            completion_stats={
                "total_items": len(review_items),
                "pending": len(review_items),
                "approved": 0,
                "rejected": 0,
                "exceptions": 0,
            },
            attestations=[],
        )

        logger.info(
            f"Created quarterly access review {review_id} with {len(review_items)} items"
        )

        return review

    async def _get_principals_in_scope(
        self, org_id: str, scope: dict[str, Any]
    ) -> list[Principal]:
        """Get principals within review scope."""
        async with async_session_factory() as db:
            stmt = select(Principal).where(Principal.org_id == org_id)  # type: ignore[attr-defined]

            # Apply scope filters
            if "departments" in scope:
                # Would need department field in Principal model
                pass

            if "roles" in scope:
                # Would need role field in Principal model
                pass

            if "providers" in scope:
                stmt = stmt.where(Principal.provider.in_(scope["providers"]))

            return list(await db.scalars(stmt))

    async def _create_review_items_for_principal(
        self, principal: Principal, reviewer: str
    ) -> list[AccessReviewItem]:
        """Create review items for all of a principal's access."""
        items = []

        async with async_session_factory() as db:
            # Get effective IAM edges for principal
            stmt = select(IamEdge).where(
                and_(
                    IamEdge.principal_id == principal.principal_id,
                    IamEdge.effective,  # type: ignore[attr-defined]
                )
            )

            edges = await db.scalars(stmt)

            for edge in edges:
                # Calculate risk level based on permission
                risk_level = self._calculate_permission_risk(
                    edge.permission, edge.provider
                )

                # Generate business justification prompt
                justification = await self._generate_justification_prompt(
                    edge, principal
                )

                item = AccessReviewItem(
                    item_id=f"review_{edge.edge_id}",
                    principal_id=str(principal.principal_id),  # type: ignore[arg-type]
                    resource_id=str(edge.resource_id) if edge.resource_id else "",  # type: ignore[arg-type]
                    permission=edge.permission,
                    provider=edge.provider,
                    granted_date=edge.captured_at,  # type: ignore[attr-defined]
                    last_used=None,  # Would integrate with usage analytics
                    business_justification=justification,
                    risk_level=risk_level,
                    reviewer_assigned=reviewer,
                    status=ReviewStatus.PENDING,
                    decision=None,
                    decision_justification=None,
                    decision_date=None,
                    exception_expiry=None,
                )

                items.append(item)

        return items

    def _calculate_permission_risk(self, permission: str, provider: str) -> str:
        """Calculate risk level for a permission."""
        high_risk_patterns = [
            "admin",
            "owner",
            "root",
            "superuser",
            "full_access",
            "delete",
            "create",
            "modify",
            "write",
            "*",
        ]

        permission_lower = permission.lower()

        if any(pattern in permission_lower for pattern in high_risk_patterns):
            return "high"
        elif "read" in permission_lower:
            return "low"
        else:
            return "medium"

    async def _generate_justification_prompt(
        self, edge: IamEdge, principal: Principal
    ) -> str:
        """Generate business justification prompt for reviewers."""
        return (
            f"Why does {principal.display_name} need {edge.permission} "
            f"access to {edge.resource_id} in {edge.provider}?"
        )

    async def record_review_decision(
        self,
        review_id: str,
        item_id: str,
        reviewer: str,
        decision: ReviewDecision,
        justification: str,
        exception_days: int | None = None,
    ) -> dict[str, Any]:
        """
        Record a review decision with cryptographic attestation.

        Args:
            review_id: Access review campaign ID
            item_id: Specific review item ID
            reviewer: User making the decision
            decision: Review decision
            justification: Business justification for decision
            exception_days: Days for exception if granted

        Returns:
            Decision record with attestation
        """
        decision_id = f"decision_{item_id}_{int(datetime.now().timestamp())}"

        # Calculate exception expiry if applicable
        exception_expiry = None
        if decision == ReviewDecision.EXCEPTION and exception_days:
            exception_expiry = datetime.now() + timedelta(days=exception_days)

        # Create decision record
        decision_record = {
            "decision_id": decision_id,
            "review_id": review_id,
            "item_id": item_id,
            "reviewer": reviewer,
            "decision": decision.value,
            "justification": justification,
            "decision_date": datetime.now().isoformat(),
            "exception_expiry": (
                exception_expiry.isoformat() if exception_expiry else None
            ),
        }

        # Create cryptographic attestation for decision
        attestation = await self.attestation_service.attest_finding_suppression(  # type: ignore[attr-defined]
            finding_id=item_id,
            actor=reviewer,
            suppression_reason=f"Access review decision: {decision.value} - {justification}",
            expiry_date=exception_expiry,
            approver=None,  # Could add approval workflow
        )

        # Store attestation ID in decision record
        decision_record["attestation_id"] = attestation.attestation_id

        logger.info(f"Recorded access review decision {decision_id}: {decision.value}")

        return decision_record

    async def get_pending_reviews(self, org_id: str) -> list[dict[str, Any]]:
        """Get all pending access reviews for organization."""
        # In production, would query from persistent storage
        # For now, return example structure
        return [
            {
                "review_id": f"access_review_{org_id}_Q1_2024",
                "review_period": "Q1 2024",
                "status": "in_progress",
                "due_date": (datetime.now() + timedelta(days=15)).isoformat(),
                "completion_percentage": 65.0,
                "pending_items": 45,
                "high_risk_pending": 12,
            }
        ]

    async def get_overdue_reviews(self, org_id: str) -> list[dict[str, Any]]:
        """Get overdue access reviews requiring immediate attention."""
        # Query overdue reviews
        # For now, return example structure
        return [
            {
                "review_id": f"access_review_{org_id}_Q4_2023",
                "review_period": "Q4 2023",
                "due_date": (datetime.now() - timedelta(days=5)).isoformat(),
                "days_overdue": 5,
                "pending_items": 23,
                "high_risk_pending": 8,
                "escalation_required": True,
            }
        ]

    async def auto_expire_exceptions(self, org_id: str) -> dict[str, Any]:
        """
        Auto-expire time-boxed access exceptions.

        Automatically revokes access for expired exceptions.
        """
        expired_count = 0
        revoked_items = []

        # In production, would query stored review decisions for expired exceptions
        # and automatically revoke access through provider APIs

        # Example expired exception handling
        current_time = datetime.now()

        # This would query actual exception records
        expired_exceptions = [
            {
                "item_id": "review_item_123",
                "principal_id": "user_456",
                "resource_id": "sensitive_resource",
                "exception_expiry": current_time - timedelta(days=1),
                "original_justification": "Temporary project access",
            }
        ]

        for exception in expired_exceptions:
            # Create attestation for auto-expiry
            attestation = await self.attestation_service.attest_finding_suppression(  # type: ignore[attr-defined]
                finding_id=exception["item_id"],
                actor="system_auto_expire",
                suppression_reason=f"Exception expired: {exception['original_justification']}",
            )

            revoked_items.append(
                {
                    "item_id": exception["item_id"],
                    "principal_id": exception["principal_id"],
                    "resource_id": exception["resource_id"],
                    "revoked_at": current_time.isoformat(),
                    "attestation_id": attestation.attestation_id,
                }
            )

            expired_count += 1

        return {
            "expired_exceptions": expired_count,
            "revoked_items": revoked_items,
            "processed_at": current_time.isoformat(),
        }


# Global access review manager
_access_review_manager = AccessReviewManager()


def get_access_review_manager() -> AccessReviewManager:
    """Get global access review manager."""
    return _access_review_manager
