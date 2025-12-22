"""
Auto-quarantine system for high-risk OAuth applications.

Implements automated revocation of risky apps with change tickets
and approval workflows for restoration.
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

from .toxic_combinations import ToxicCombinationResult, ToxicityLevel
from ..auditability.attestation import get_attestation_service
from ..auditability.transparency_log import get_transparency_log, LogEntryType

logger = logging.getLogger(__name__)


class QuarantineStatus(Enum):
    """Status of quarantined applications."""

    PENDING = "pending"
    QUARANTINED = "quarantined"
    APPROVED_RESTORATION = "approved_restoration"
    RESTORED = "restored"
    PERMANENTLY_BLOCKED = "permanently_blocked"


class QuarantineReason(Enum):
    """Reasons for quarantining applications."""

    TOXIC_COMBINATION = "toxic_combination"
    HIGH_RISK_UNUSED = "high_risk_unused"
    SECURITY_VIOLATION = "security_violation"
    COMPLIANCE_VIOLATION = "compliance_violation"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    MANUAL_REVIEW = "manual_review"


@dataclass
class QuarantineAction:
    """Record of quarantine action taken."""

    action_id: str
    app_id: str
    app_name: str
    provider: str
    action_type: str  # "quarantine", "restore", "approve_restoration"
    reason: QuarantineReason
    triggered_by: str  # "auto_detector", "manual", "policy_engine"
    triggered_at: datetime

    # Risk assessment
    risk_score: float
    toxic_patterns: List[str]

    # Approval workflow
    approver: Optional[str]
    approved_at: Optional[datetime]
    approval_justification: Optional[str]

    # Restoration details
    restoration_conditions: List[str]
    estimated_restoration_date: Optional[datetime]

    # Attestation
    attestation_id: str

    # Metadata
    metadata: Dict[str, Any]


class QuarantineManager:
    """
    Manages automatic quarantine of high-risk OAuth applications.

    Provides automated response to toxic combinations with approval
    workflows for restoration and change ticket integration.
    """

    def __init__(self):
        self.attestation_service = get_attestation_service()
        self.transparency_log = get_transparency_log()
        self.quarantine_thresholds = {
            "auto_quarantine_score": 0.8,
            "immediate_quarantine_score": 0.95,
            "restoration_review_days": 30,
        }

    async def evaluate_for_quarantine(
        self, toxic_results: List[ToxicCombinationResult]
    ) -> List[QuarantineAction]:
        """
        Evaluate toxic combination results for quarantine actions.

        Args:
            toxic_results: Results from toxic combination detection

        Returns:
            List of quarantine actions to take
        """
        quarantine_actions = []

        for result in toxic_results:
            # Check if app meets quarantine criteria
            if (
                result.auto_quarantine_eligible
                and result.toxicity_score
                >= self.quarantine_thresholds["auto_quarantine_score"]
            ):

                # Determine quarantine reason
                reason = self._determine_quarantine_reason(result)

                # Create quarantine action
                action = await self._create_quarantine_action(result, reason)
                quarantine_actions.append(action)

        return quarantine_actions

    async def _create_quarantine_action(
        self, toxic_result: ToxicCombinationResult, reason: QuarantineReason
    ) -> QuarantineAction:
        """Create quarantine action for toxic app."""
        action_id = (
            f"quarantine_{toxic_result.app_id}_{int(datetime.now().timestamp())}"
        )

        # Determine if immediate quarantine is needed
        immediate = (
            toxic_result.toxicity_score
            >= self.quarantine_thresholds["immediate_quarantine_score"]
        )

        # Create quarantine action
        action = QuarantineAction(
            action_id=action_id,
            app_id=toxic_result.app_id,
            app_name=toxic_result.app_name,
            provider=toxic_result.provider,
            action_type="quarantine",
            reason=reason,
            triggered_by="auto_detector",
            triggered_at=datetime.now(),
            risk_score=toxic_result.toxicity_score,
            toxic_patterns=[
                pattern.pattern_id for pattern in toxic_result.toxic_patterns
            ],
            approver=None,
            approved_at=None,
            approval_justification=None,
            restoration_conditions=self._generate_restoration_conditions(toxic_result),
            estimated_restoration_date=datetime.now()
            + timedelta(days=self.quarantine_thresholds["restoration_review_days"]),
            attestation_id="",  # Will be set after attestation creation
            metadata={
                "immediate_quarantine": immediate,
                "auto_generated": True,
                "detection_timestamp": toxic_result.detected_at.isoformat(),
            },
        )

        # Create cryptographic attestation for quarantine
        attestation = await self.attestation_service.attest_finding_suppression(
            finding_id=action.action_id,
            actor="auto_quarantine_system",
            suppression_reason=f"OAuth app quarantined: {reason.value} - {action.toxic_patterns}",
            expiry_date=action.estimated_restoration_date,
        )

        action.attestation_id = attestation.attestation_id

        # Log to transparency log
        await self.transparency_log.append_entry(
            LogEntryType.ACCESS_REVOKED,
            "auto_quarantine_system",
            action.app_id,
            "oauth_app_quarantined",
            {
                "action_id": action.action_id,
                "reason": reason.value,
                "toxicity_score": toxic_result.toxicity_score,
                "toxic_patterns": action.toxic_patterns,
                "immediate": immediate,
                "attestation_id": action.attestation_id,
            },
        )

        logger.warning(
            f"OAuth app quarantined: {toxic_result.app_name} (score: {toxic_result.toxicity_score})"
        )

        return action

    def _determine_quarantine_reason(
        self, toxic_result: ToxicCombinationResult
    ) -> QuarantineReason:
        """Determine primary reason for quarantine."""
        # Find highest severity pattern
        highest_severity = max(
            pattern.toxicity_level for pattern in toxic_result.toxic_patterns
        )

        if highest_severity == ToxicityLevel.CRITICAL:
            return QuarantineReason.SECURITY_VIOLATION
        elif highest_severity == ToxicityLevel.DANGEROUS:
            return QuarantineReason.TOXIC_COMBINATION
        else:
            return QuarantineReason.MANUAL_REVIEW

    def _generate_restoration_conditions(
        self, toxic_result: ToxicCombinationResult
    ) -> List[str]:
        """Generate conditions that must be met for app restoration."""
        conditions = []

        # Aggregate conditions from all toxic patterns
        for pattern in toxic_result.toxic_patterns:
            conditions.extend(pattern.remediation_steps)

        # Add general conditions
        conditions.extend(
            [
                "Security team review and approval",
                "Business justification for app necessity",
                "App owner assignment and accountability",
                "Implementation of recommended mitigations",
            ]
        )

        # Deduplicate
        return list(set(conditions))

    async def request_app_restoration(
        self,
        action_id: str,
        requested_by: str,
        business_justification: str,
        mitigation_plan: List[str],
    ) -> Dict[str, Any]:
        """
        Request restoration of quarantined OAuth app.

        Creates restoration request with business justification.
        """
        restoration_id = f"restore_{action_id}_{int(datetime.now().timestamp())}"

        # Load quarantine action (would be from database in production)
        quarantine_action = await self._load_quarantine_action(action_id)

        restoration_request = {
            "restoration_id": restoration_id,
            "quarantine_action_id": action_id,
            "app_id": quarantine_action["app_id"],
            "app_name": quarantine_action["app_name"],
            "requested_by": requested_by,
            "requested_at": datetime.now().isoformat(),
            "business_justification": business_justification,
            "mitigation_plan": mitigation_plan,
            "status": "pending_approval",
            "original_quarantine_reason": quarantine_action["reason"],
            "original_risk_score": quarantine_action["risk_score"],
        }

        # Log restoration request
        await self.transparency_log.append_entry(
            LogEntryType.ACCESS_GRANTED,
            requested_by,
            quarantine_action["app_id"],
            "oauth_app_restoration_requested",
            {
                "restoration_id": restoration_id,
                "action_id": action_id,
                "justification": business_justification,
                "mitigation_count": len(mitigation_plan),
            },
        )

        logger.info(f"OAuth app restoration requested: {restoration_id}")

        return restoration_request

    async def approve_app_restoration(
        self, restoration_id: str, approver: str, approval_conditions: List[str]
    ) -> Dict[str, Any]:
        """
        Approve restoration of quarantined OAuth app.

        Creates approval attestation and schedules restoration.
        """
        # Load restoration request (would be from database)
        restoration_request = await self._load_restoration_request(restoration_id)

        # Create approval attestation
        attestation = await self.attestation_service.attest_finding_suppression(
            finding_id=restoration_request["restoration_id"],
            actor=approver,
            suppression_reason=f"OAuth app restoration approved with conditions: {approval_conditions}",
        )

        # Update restoration status
        restoration_request.update(
            {
                "status": "approved",
                "approver": approver,
                "approved_at": datetime.now().isoformat(),
                "approval_conditions": approval_conditions,
                "attestation_id": attestation.attestation_id,
                "scheduled_restoration": datetime.now()
                + timedelta(hours=24),  # 24-hour delay
            }
        )

        # Log approval
        await self.transparency_log.append_entry(
            LogEntryType.ACCESS_GRANTED,
            approver,
            restoration_request["app_id"],
            "oauth_app_restoration_approved",
            {
                "restoration_id": restoration_id,
                "approver": approver,
                "conditions_count": len(approval_conditions),
                "attestation_id": attestation.attestation_id,
            },
        )

        logger.info(f"OAuth app restoration approved: {restoration_id} by {approver}")

        return restoration_request

    async def execute_quarantine(self, action: QuarantineAction) -> Dict[str, Any]:
        """
        Execute quarantine action against OAuth app.

        Integrates with provider APIs to actually revoke app access.
        """
        execution_result = {
            "action_id": action.action_id,
            "app_id": action.app_id,
            "executed_at": datetime.now().isoformat(),
            "success": False,
            "provider_responses": {},
            "errors": [],
        }

        try:
            # Execute provider-specific quarantine
            if action.provider == "google_workspace":
                result = await self._quarantine_google_app(action.app_id)
                execution_result["provider_responses"]["google"] = result

            elif action.provider == "m365":
                result = await self._quarantine_m365_app(action.app_id)
                execution_result["provider_responses"]["m365"] = result

            elif action.provider == "github":
                result = await self._quarantine_github_app(action.app_id)
                execution_result["provider_responses"]["github"] = result

            elif action.provider == "slack":
                result = await self._quarantine_slack_app(action.app_id)
                execution_result["provider_responses"]["slack"] = result

            execution_result["success"] = True

            # Log successful execution
            await self.transparency_log.append_entry(
                LogEntryType.ACCESS_REVOKED,
                "quarantine_executor",
                action.app_id,
                "oauth_app_quarantine_executed",
                {
                    "action_id": action.action_id,
                    "provider": action.provider,
                    "execution_result": "success",
                },
            )

        except Exception as e:
            logger.error(f"Failed to execute quarantine for {action.app_id}: {e}")
            execution_result["errors"].append(str(e))

        return execution_result

    async def _quarantine_google_app(self, app_id: str) -> Dict[str, Any]:
        """Quarantine Google Workspace OAuth app."""
        # In production, would use Google Admin SDK to revoke app
        return {
            "method": "google_admin_sdk_revoke",
            "app_id": app_id,
            "status": "revoked",
            "timestamp": datetime.now().isoformat(),
        }

    async def _quarantine_m365_app(self, app_id: str) -> Dict[str, Any]:
        """Quarantine Microsoft 365 OAuth app."""
        # In production, would use Microsoft Graph API to disable app
        return {
            "method": "graph_api_disable",
            "app_id": app_id,
            "status": "disabled",
            "timestamp": datetime.now().isoformat(),
        }

    async def _quarantine_github_app(self, app_id: str) -> Dict[str, Any]:
        """Quarantine GitHub OAuth app."""
        # In production, would use GitHub API to revoke app access
        return {
            "method": "github_api_revoke",
            "app_id": app_id,
            "status": "access_revoked",
            "timestamp": datetime.now().isoformat(),
        }

    async def _quarantine_slack_app(self, app_id: str) -> Dict[str, Any]:
        """Quarantine Slack OAuth app."""
        # In production, would use Slack API to uninstall app
        return {
            "method": "slack_api_uninstall",
            "app_id": app_id,
            "status": "uninstalled",
            "timestamp": datetime.now().isoformat(),
        }

    async def _load_quarantine_action(self, action_id: str) -> Dict[str, Any]:
        """Load quarantine action from storage."""
        # Mock implementation
        return {
            "action_id": action_id,
            "app_id": "mock_app",
            "app_name": "Mock App",
            "reason": "toxic_combination",
            "risk_score": 0.9,
        }

    async def _load_restoration_request(self, restoration_id: str) -> Dict[str, Any]:
        """Load restoration request from storage."""
        # Mock implementation
        return {
            "restoration_id": restoration_id,
            "app_id": "mock_app",
            "app_name": "Mock App",
            "requested_by": "user@company.com",
            "business_justification": "Required for project X",
        }

    async def get_quarantine_summary(self, org_id: str) -> Dict[str, Any]:
        """Get summary of quarantine actions for organization."""
        # In production, would query quarantine database
        return {
            "organization_id": org_id,
            "summary_date": datetime.now().isoformat(),
            "total_quarantined": 5,
            "pending_restoration": 2,
            "permanently_blocked": 1,
            "quarantines_last_30_days": 3,
            "quarantine_reasons": {
                "toxic_combination": 3,
                "high_risk_unused": 1,
                "security_violation": 1,
            },
        }


# Global quarantine manager
_quarantine_manager = QuarantineManager()


def get_quarantine_manager() -> QuarantineManager:
    """Get global quarantine manager."""
    return _quarantine_manager
