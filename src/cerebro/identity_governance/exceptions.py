"""
Time-boxed exception management for access reviews.

Implements exception workflows with SLAs, auto-expiry, and revalidation.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

import structlog

from ..auditability.attestation import get_attestation_service
from ..auditability.transparency_log import LogEntryType, get_transparency_log

logger = structlog.get_logger(__name__)


class ExceptionStatus(Enum):
    """Status of access exceptions."""

    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    REVALIDATION_REQUIRED = "revalidation_required"


class ExceptionType(Enum):
    """Types of access exceptions."""

    TEMPORARY_PROJECT = "temporary_project"
    EMERGENCY_ACCESS = "emergency_access"
    CONTRACTOR_ACCESS = "contractor_access"
    CROSS_TRAINING = "cross_training"
    COMPLIANCE_EXCEPTION = "compliance_exception"
    TECHNICAL_LIMITATION = "technical_limitation"


@dataclass
class AccessException:
    """Time-boxed access exception with SLA tracking."""

    exception_id: str
    principal_id: str
    resource_id: str
    permission: str
    provider: str
    exception_type: ExceptionType
    status: ExceptionStatus

    # Request details
    requested_by: str
    requested_at: datetime
    justification: str
    business_need: str
    project_reference: str | None

    # Approval workflow
    approver: str | None
    approved_at: datetime | None
    approval_justification: str | None

    # Time limits
    start_date: datetime
    expiry_date: datetime
    max_duration_days: int

    # Monitoring
    last_used: datetime | None
    usage_count: int
    revalidation_due: datetime | None

    # Attestation
    attestation_id: str | None

    # Metadata
    metadata: dict[str, Any]


class ExceptionManager:
    """
    Manages time-boxed access exceptions with SLA enforcement.

    Provides workflow for requesting, approving, and monitoring
    temporary access with automatic expiry.
    """

    def __init__(self):
        self.attestation_service = get_attestation_service()
        self.transparency_log = get_transparency_log()

    async def request_access_exception(
        self,
        principal_id: str,
        resource_id: str,
        permission: str,
        provider: str,
        requested_by: str,
        justification: str,
        business_need: str,
        exception_type: ExceptionType,
        duration_days: int,
        project_reference: str | None = None,
    ) -> AccessException:
        """
        Request a time-boxed access exception.

        Creates exception request with approval workflow.
        """
        exception_id = f"exc_{principal_id}_{int(datetime.now().timestamp())}"

        # Validate duration against policy limits
        max_duration = self._get_max_duration_for_type(exception_type)
        if duration_days > max_duration:
            raise ValueError(
                f"Requested duration {duration_days} days exceeds maximum "
                f"{max_duration} days for {exception_type.value}"
            )

        # Create exception request
        exception = AccessException(
            exception_id=exception_id,
            principal_id=principal_id,
            resource_id=resource_id,
            permission=permission,
            provider=provider,
            exception_type=exception_type,
            status=ExceptionStatus.PENDING_APPROVAL,
            # Request details
            requested_by=requested_by,
            requested_at=datetime.now(),
            justification=justification,
            business_need=business_need,
            project_reference=project_reference,
            # Approval workflow (to be filled)
            approver=None,
            approved_at=None,
            approval_justification=None,
            # Time limits
            start_date=datetime.now(),
            expiry_date=datetime.now() + timedelta(days=duration_days),
            max_duration_days=duration_days,
            # Monitoring
            last_used=None,
            usage_count=0,
            revalidation_due=None,
            # Attestation
            attestation_id=None,
            # Metadata
            metadata={
                "creation_source": "manual_request",
                "risk_assessment": self._assess_exception_risk(
                    exception_type, permission, provider
                ),
                "approval_required": self._requires_approval(
                    exception_type, permission
                ),
            },
        )

        # Log exception request
        await self.transparency_log.append_entry(
            LogEntryType.ACCESS_GRANTED,
            requested_by,
            exception_id,
            "access_exception_requested",
            {
                "exception_id": exception_id,
                "principal_id": principal_id,
                "resource_id": resource_id,
                "exception_type": exception_type.value,
                "duration_days": duration_days,
                "justification": justification,
            },
        )

        logger.info(f"Access exception requested: {exception_id}")

        return exception

    async def approve_exception(
        self, exception_id: str, approver: str, approval_justification: str
    ) -> AccessException:
        """
        Approve an access exception request.

        Creates cryptographic attestation and activates the exception.
        """
        # Load exception (would be from database in production)
        exception = await self._load_exception(exception_id)

        if exception.status != ExceptionStatus.PENDING_APPROVAL:
            raise ValueError(f"Exception {exception_id} not pending approval")

        # Update exception with approval
        exception.approver = approver
        exception.approved_at = datetime.now()
        exception.approval_justification = approval_justification
        exception.status = ExceptionStatus.ACTIVE

        # Set revalidation date (halfway through exception period)
        exception_duration = exception.expiry_date - exception.start_date
        exception.revalidation_due = exception.start_date + (exception_duration / 2)

        # Create cryptographic attestation
        attestation = await self.attestation_service.attest_finding_suppression(  # type: ignore[attr-defined]
            finding_id=exception_id,
            actor=approver,
            suppression_reason=f"Access exception approved: {approval_justification}",
            expiry_date=exception.expiry_date,
            approver=approver,
        )

        exception.attestation_id = attestation.attestation_id

        # Log approval
        await self.transparency_log.append_entry(
            LogEntryType.ACCESS_GRANTED,
            approver,
            exception_id,
            "access_exception_approved",
            {
                "exception_id": exception_id,
                "approver": approver,
                "expiry_date": exception.expiry_date.isoformat(),
                "attestation_id": attestation.attestation_id,
            },
        )

        logger.info(f"Access exception approved: {exception_id} by {approver}")

        return exception

    async def revoke_exception(
        self, exception_id: str, revoked_by: str, revocation_reason: str
    ) -> AccessException:
        """
        Revoke an active access exception.

        Immediately terminates the exception with attestation.
        """
        exception = await self._load_exception(exception_id)

        if exception.status not in [ExceptionStatus.ACTIVE, ExceptionStatus.APPROVED]:
            raise ValueError(
                f"Exception {exception_id} cannot be revoked (status: {exception.status})"
            )

        # Update exception status
        exception.status = ExceptionStatus.REVOKED

        # Create revocation attestation
        attestation = await self.attestation_service.attest_finding_suppression(  # type: ignore[attr-defined]
            finding_id=exception_id,
            actor=revoked_by,
            suppression_reason=f"Exception revoked: {revocation_reason}",
        )

        # Log revocation
        await self.transparency_log.append_entry(
            LogEntryType.ACCESS_REVOKED,
            revoked_by,
            exception_id,
            "access_exception_revoked",
            {
                "exception_id": exception_id,
                "revoked_by": revoked_by,
                "revocation_reason": revocation_reason,
                "attestation_id": attestation.attestation_id,
            },
        )

        logger.info(f"Access exception revoked: {exception_id} by {revoked_by}")

        return exception

    async def process_expired_exceptions(self, org_id: str) -> dict[str, Any]:
        """
        Process expired exceptions and auto-revoke access.

        Automatically revokes expired exceptions and creates attestations.
        """
        current_time = datetime.now()

        # Find expired exceptions (would query from database)
        expired_exceptions = await self._get_expired_exceptions(org_id, current_time)

        auto_revoked: list[dict[str, str]] = []
        revalidation_required: list[dict[str, str]] = []
        errors: list[dict[str, str]] = []
        processed_results: dict[str, Any] = {
            "processed_at": current_time.isoformat(),
            "expired_count": len(expired_exceptions),
            "auto_revoked": auto_revoked,
            "revalidation_required": revalidation_required,
            "errors": errors,
        }

        for exception in expired_exceptions:
            try:
                if exception.status == ExceptionStatus.ACTIVE:
                    # Auto-revoke expired exception
                    revoked_exception = await self.revoke_exception(
                        exception.exception_id,
                        "system_auto_expire",
                        f"Exception expired on {exception.expiry_date.isoformat()}",
                    )

                    auto_revoked.append(
                        {
                            "exception_id": exception.exception_id,
                            "principal_id": exception.principal_id,
                            "resource_id": exception.resource_id,
                            "expired_date": exception.expiry_date.isoformat(),
                            "attestation_id": revoked_exception.attestation_id or "",
                        }
                    )

                elif (
                    exception.revalidation_due
                    and exception.revalidation_due <= current_time
                ):
                    # Mark for revalidation
                    exception.status = ExceptionStatus.REVALIDATION_REQUIRED

                    revalidation_required.append(
                        {
                            "exception_id": exception.exception_id,
                            "principal_id": exception.principal_id,
                            "revalidation_due": exception.revalidation_due.isoformat(),
                        }
                    )

            except Exception as e:
                logger.error(
                    f"Failed to process expired exception {exception.exception_id}: {e}"
                )
                errors.append(
                    {"exception_id": exception.exception_id, "error": str(e)}
                )

        return processed_results

    def _get_max_duration_for_type(self, exception_type: ExceptionType) -> int:
        """Get maximum allowed duration for exception type."""
        max_durations = {
            ExceptionType.EMERGENCY_ACCESS: 3,  # 3 days max
            ExceptionType.TEMPORARY_PROJECT: 90,  # 90 days max
            ExceptionType.CONTRACTOR_ACCESS: 180,  # 6 months max
            ExceptionType.CROSS_TRAINING: 30,  # 30 days max
            ExceptionType.COMPLIANCE_EXCEPTION: 365,  # 1 year max
            ExceptionType.TECHNICAL_LIMITATION: 180,  # 6 months max
        }

        return max_durations.get(exception_type, 30)  # Default 30 days

    def _assess_exception_risk(
        self, exception_type: ExceptionType, permission: str, provider: str
    ) -> str:
        """Assess risk level of exception request."""
        # High-risk permissions
        if any(
            term in permission.lower() for term in ["admin", "owner", "delete", "full"]
        ):
            return "high"

        # Emergency access is always high risk
        if exception_type == ExceptionType.EMERGENCY_ACCESS:
            return "high"

        # Cross-training and temporary projects are medium risk
        if exception_type in [
            ExceptionType.CROSS_TRAINING,
            ExceptionType.TEMPORARY_PROJECT,
        ]:
            return "medium"

        return "low"

    def _requires_approval(
        self, exception_type: ExceptionType, permission: str
    ) -> bool:
        """Determine if exception requires approval."""
        # Emergency access requires post-facto approval
        if exception_type == ExceptionType.EMERGENCY_ACCESS:
            return True

        # Admin permissions always require approval
        if any(term in permission.lower() for term in ["admin", "owner", "full"]):
            return True

        # Long-duration exceptions require approval
        if exception_type in [
            ExceptionType.CONTRACTOR_ACCESS,
            ExceptionType.COMPLIANCE_EXCEPTION,
        ]:
            return True

        return False

    async def _load_exception(self, exception_id: str) -> AccessException:
        """Load exception from storage (mock implementation)."""
        # In production, would load from database
        # For now, return mock exception
        return AccessException(
            exception_id=exception_id,
            principal_id="mock_user",
            resource_id="mock_resource",
            permission="mock_permission",
            provider="mock_provider",
            exception_type=ExceptionType.TEMPORARY_PROJECT,
            status=ExceptionStatus.PENDING_APPROVAL,
            requested_by="mock_requester",
            requested_at=datetime.now(),
            justification="Mock justification",
            business_need="Mock business need",
            project_reference=None,
            approver=None,
            approved_at=None,
            approval_justification=None,
            start_date=datetime.now(),
            expiry_date=datetime.now() + timedelta(days=30),
            max_duration_days=30,
            last_used=None,
            usage_count=0,
            revalidation_due=None,
            attestation_id=None,
            metadata={},
        )

    async def _get_expired_exceptions(
        self, org_id: str, current_time: datetime
    ) -> list[AccessException]:
        """Get expired exceptions for organization."""
        # In production, would query database for expired exceptions
        # For now, return empty list
        return []


# Global exception manager
_exception_manager = ExceptionManager()


def get_exception_manager() -> ExceptionManager:
    """Get global exception manager."""
    return _exception_manager
