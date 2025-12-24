"""
Joiner/Mover/Leaver (JML) campaign management.

Detects stale access after manager/role changes by integrating with
HR systems (Okta/AD/Workday) and tracking identity lifecycle events.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from sqlalchemy import and_, select

from ..auditability.transparency_log import LogEntryType, get_transparency_log
from ..core.database import async_session_factory
from ..core.models import IamEdge
from ..query.bootstrap import get_query_engine

logger = logging.getLogger(__name__)


class LifecycleStage(Enum):
    """Employee lifecycle stages."""

    JOINER = "joiner"  # New employee
    MOVER = "mover"  # Role/department change
    LEAVER = "leaver"  # Employee departure
    ACTIVE = "active"  # Current employee
    CONTRACTOR = "contractor"  # External contractor
    INACTIVE = "inactive"  # Temporarily inactive


class JMLEventType(Enum):
    """Types of JML events that trigger access reviews."""

    HIRE = "hire"
    ROLE_CHANGE = "role_change"
    DEPARTMENT_CHANGE = "department_change"
    MANAGER_CHANGE = "manager_change"
    TERMINATION = "termination"
    PROMOTION = "promotion"
    TRANSFER = "transfer"
    CONTRACTOR_START = "contractor_start"
    CONTRACTOR_END = "contractor_end"


@dataclass
class JMLEvent:
    """Identity lifecycle event requiring access review."""

    event_id: str
    principal_id: str
    event_type: JMLEventType
    event_date: datetime
    previous_attributes: dict[str, Any]
    new_attributes: dict[str, Any]
    triggered_by: str  # System or user that detected the change
    requires_review: bool
    review_deadline: datetime
    affected_access: list[str]  # List of access that may need review
    metadata: dict[str, Any]


@dataclass
class StaleAccessItem:
    """Access that may be stale after lifecycle event."""

    principal_id: str
    resource_id: str
    permission: str
    provider: str
    granted_date: datetime
    last_used: datetime | None
    risk_score: float
    reason_stale: str
    recommended_action: str


class JMLCampaignManager:
    """
    Manages Joiner/Mover/Leaver campaigns for identity governance.

    Integrates with HR systems to detect lifecycle events and triggers
    access reviews for potentially stale permissions.
    """

    def __init__(self):
        self.query_engine = get_query_engine()
        self.transparency_log = get_transparency_log()

    async def detect_jml_events(
        self, org_id: str, lookback_days: int = 7
    ) -> list[JMLEvent]:
        """
        Detect JML events by analyzing identity attribute changes.

        Compares current identity attributes with historical data to
        identify role changes, department moves, and other lifecycle events.
        """
        events = []
        end_date = datetime.now()
        start_date = end_date - timedelta(days=lookback_days)

        # Query recent identity changes across providers
        identity_changes = await self._detect_identity_changes(
            org_id, start_date, end_date
        )

        for change in identity_changes:
            # Analyze change to determine event type
            event_type = self._classify_change(change)

            if event_type:
                # Get affected access for this principal
                affected_access = await self._get_affected_access(
                    change["principal_id"]
                )

                # Calculate review deadline based on event type
                review_deadline = self._calculate_review_deadline(
                    event_type, change["change_date"]
                )

                event = JMLEvent(
                    event_id=f"jml_{change['principal_id']}_{int(change['change_date'].timestamp())}",
                    principal_id=change["principal_id"],
                    event_type=event_type,
                    event_date=change["change_date"],
                    previous_attributes=change["previous_attributes"],
                    new_attributes=change["new_attributes"],
                    triggered_by="jml_detector",
                    requires_review=self._requires_access_review(event_type),
                    review_deadline=review_deadline,
                    affected_access=affected_access,
                    metadata={
                        "detection_confidence": change.get("confidence", 1.0),
                        "change_source": change.get("source", "unknown"),
                        "change_magnitude": change.get("magnitude", "minor"),
                    },
                )

                events.append(event)

                # Log to transparency log
                await self.transparency_log.append_entry(
                    LogEntryType.USER_ACTION,
                    "jml_detector",
                    change["principal_id"],
                    f"jml_event_detected_{event_type.value}",
                    {
                        "event_id": event.event_id,
                        "event_type": event_type.value,
                        "requires_review": event.requires_review,
                        "review_deadline": review_deadline.isoformat(),
                        "affected_access_count": len(affected_access),
                    },
                )

        logger.info(f"Detected {len(events)} JML events for org {org_id}")
        return events

    async def _detect_identity_changes(
        self, org_id: str, start_date: datetime, end_date: datetime
    ) -> list[dict[str, Any]]:
        """Detect identity attribute changes across providers."""
        changes = []

        # Query Okta user changes
        okta_changes = await self._detect_okta_changes(start_date, end_date)
        changes.extend(okta_changes)

        # Query M365 user changes
        m365_changes = await self._detect_m365_changes(start_date, end_date)
        changes.extend(m365_changes)

        # Query AWS IAM changes (limited without CloudTrail integration)
        aws_changes = await self._detect_aws_changes(start_date, end_date)
        changes.extend(aws_changes)

        return changes

    async def _detect_okta_changes(
        self, start_date: datetime, end_date: datetime
    ) -> list[dict[str, Any]]:
        """Detect Okta user attribute changes."""
        changes = []

        try:
            # Query current Okta users
            result = await self.query_engine.execute_query(
                f"""
                SELECT user_id, username, display_name, status,
                       job_title, department, attributes, updated_at
                FROM okta_user
                WHERE updated_at >= '{start_date.isoformat()}'
            """
            )

            for user in result.rows:
                # Simulate change detection (in production, would compare with historical snapshots)
                changes.append(
                    {
                        "principal_id": user["user_id"],
                        "provider": "okta",
                        "change_date": datetime.fromisoformat(user["updated_at"]),
                        "previous_attributes": {},  # Would load from historical data
                        "new_attributes": {
                            "job_title": user.get("job_title"),
                            "department": user.get("department"),
                            "status": user["status"],
                        },
                        "source": "okta_api",
                        "confidence": 0.9,
                    }
                )

        except Exception as e:
            logger.error(f"Failed to detect Okta changes: {e}")

        return changes

    async def _detect_m365_changes(
        self, start_date: datetime, end_date: datetime
    ) -> list[dict[str, Any]]:
        """Detect M365 user attribute changes."""
        changes = []

        try:
            # Query M365 users with recent updates
            result = await self.query_engine.execute_query(
                f"""
                SELECT user_id, user_principal_name, display_name,
                       job_title, department, account_enabled, updated_at
                FROM m365_user
                WHERE updated_at >= '{start_date.isoformat()}'
            """
            )

            for user in result.rows:
                changes.append(
                    {
                        "principal_id": user["user_id"],
                        "provider": "m365",
                        "change_date": datetime.fromisoformat(user["updated_at"]),
                        "previous_attributes": {},
                        "new_attributes": {
                            "job_title": user.get("job_title"),
                            "department": user.get("department"),
                            "account_enabled": user["account_enabled"],
                        },
                        "source": "graph_api",
                        "confidence": 0.85,
                    }
                )

        except Exception as e:
            logger.error(f"Failed to detect M365 changes: {e}")

        return changes

    async def _detect_aws_changes(
        self, start_date: datetime, end_date: datetime
    ) -> list[dict[str, Any]]:
        """Detect AWS IAM user changes."""
        changes = []

        try:
            # Query AWS IAM users (limited change detection without CloudTrail)
            result = await self.query_engine.execute_query(
                """
                SELECT user_id, user_name, arn, password_last_used, updated_at
                FROM aws_iam_user
            """
            )

            # Simple heuristic: users with recent password usage changes
            for user in result.rows:
                if user.get("password_last_used"):
                    last_used = datetime.fromisoformat(user["password_last_used"])
                    if last_used >= start_date:
                        changes.append(
                            {
                                "principal_id": user["user_id"],
                                "provider": "aws",
                                "change_date": last_used,
                                "previous_attributes": {},
                                "new_attributes": {
                                    "password_last_used": user["password_last_used"]
                                },
                                "source": "iam_api",
                                "confidence": 0.6,  # Lower confidence without proper change tracking
                            }
                        )

        except Exception as e:
            logger.error(f"Failed to detect AWS changes: {e}")

        return changes

    def _classify_change(self, change: dict[str, Any]) -> JMLEventType | None:
        """Classify identity change into JML event type."""
        previous = change["previous_attributes"]
        new = change["new_attributes"]

        # Check for status changes
        if previous.get("status") != new.get("status"):
            if new.get("status") == "inactive":
                return JMLEventType.TERMINATION
            elif previous.get("status") == "inactive" and new.get("status") == "active":
                return JMLEventType.HIRE

        # Check for role/department changes
        if previous.get("job_title") != new.get("job_title"):
            return JMLEventType.ROLE_CHANGE

        if previous.get("department") != new.get("department"):
            return JMLEventType.DEPARTMENT_CHANGE

        # Check for manager changes (if available in attributes)
        if previous.get("manager") != new.get("manager"):
            return JMLEventType.MANAGER_CHANGE

        return None

    async def _get_affected_access(self, principal_id: str) -> list[str]:
        """Get all access that might be affected by lifecycle event."""
        affected_access = []

        async with async_session_factory() as db:
            # Query current IAM edges for principal
            stmt = select(IamEdge).where(
                and_(IamEdge.principal_id == principal_id, IamEdge.effective)  # type: ignore[attr-defined]
            )

            edges = await db.scalars(stmt)

            for edge in edges:
                access_description = (
                    f"{edge.provider}:{edge.permission}@{edge.resource_id}"
                )
                affected_access.append(access_description)

        return affected_access

    def _requires_access_review(self, event_type: JMLEventType) -> bool:
        """Determine if event type requires access review."""
        review_required = {
            JMLEventType.TERMINATION: True,
            JMLEventType.DEPARTMENT_CHANGE: True,
            JMLEventType.ROLE_CHANGE: True,
            JMLEventType.MANAGER_CHANGE: True,
            JMLEventType.CONTRACTOR_END: True,
            JMLEventType.HIRE: False,  # New hires get provisioning, not review
            JMLEventType.PROMOTION: False,  # Usually adds access, doesn't remove
            JMLEventType.CONTRACTOR_START: False,
        }

        return review_required.get(event_type, True)  # Default to requiring review

    def _calculate_review_deadline(
        self, event_type: JMLEventType, event_date: datetime
    ) -> datetime:
        """Calculate deadline for access review based on event type."""
        deadlines = {
            JMLEventType.TERMINATION: 1,  # 1 day - immediate
            JMLEventType.CONTRACTOR_END: 1,  # 1 day - immediate
            JMLEventType.DEPARTMENT_CHANGE: 7,  # 1 week
            JMLEventType.ROLE_CHANGE: 7,  # 1 week
            JMLEventType.MANAGER_CHANGE: 14,  # 2 weeks
            JMLEventType.TRANSFER: 14,  # 2 weeks
        }

        days_to_deadline = deadlines.get(event_type, 30)  # Default 30 days
        return event_date + timedelta(days=days_to_deadline)

    async def identify_stale_access(
        self, org_id: str, jml_events: list[JMLEvent]
    ) -> list[StaleAccessItem]:
        """
        Identify access that has become stale due to JML events.

        Returns list of access items that should be reviewed or revoked.
        """
        stale_access = []

        for event in jml_events:
            if not event.requires_review:
                continue

            # Get current access for principal
            current_access = await self._get_current_access(event.principal_id)

            # Analyze each access item for staleness
            for access in current_access:
                stale_item = await self._analyze_access_staleness(event, access)
                if stale_item:
                    stale_access.append(stale_item)

        return stale_access

    async def _get_current_access(self, principal_id: str) -> list[dict[str, Any]]:
        """Get current access for a principal across all providers."""
        access_items = []

        async with async_session_factory() as db:
            stmt = select(IamEdge).where(
                and_(IamEdge.principal_id == principal_id, IamEdge.effective)  # type: ignore[attr-defined]
            )

            edges = await db.scalars(stmt)

            for edge in edges:
                access_items.append(
                    {
                        "resource_id": edge.resource_id,
                        "permission": edge.permission,
                        "provider": edge.provider,
                        "granted_date": edge.captured_at,  # type: ignore[attr-defined]
                        "edge_type": edge.edge_type,  # type: ignore[attr-defined]
                        "metadata": edge.metadata,
                    }
                )

        return access_items

    async def _analyze_access_staleness(
        self, jml_event: JMLEvent, access: dict[str, Any]
    ) -> StaleAccessItem | None:
        """Analyze if access item is stale due to JML event."""

        # Risk scoring based on event type and access type
        risk_score = 0.0
        reason_stale = ""
        recommended_action = ""

        # Termination events make all access stale
        if jml_event.event_type == JMLEventType.TERMINATION:
            risk_score = 1.0
            reason_stale = "User terminated"
            recommended_action = "Revoke immediately"

        # Department changes may make cross-department access stale
        elif jml_event.event_type == JMLEventType.DEPARTMENT_CHANGE:
            old_dept = jml_event.previous_attributes.get("department", "")
            new_dept = jml_event.new_attributes.get("department", "")

            # Check if access is department-specific
            if old_dept and old_dept != new_dept:
                if old_dept.lower() in access["resource_id"].lower():
                    risk_score = 0.8
                    reason_stale = f"Department change: {old_dept} -> {new_dept}"
                    recommended_action = "Review access necessity for new department"

        # Role changes may make role-specific access stale
        elif jml_event.event_type == JMLEventType.ROLE_CHANGE:
            old_role = jml_event.previous_attributes.get("job_title", "")
            new_role = jml_event.new_attributes.get("job_title", "")

            if old_role and old_role != new_role:
                # Check if access contains old role keywords
                role_keywords = old_role.lower().split()
                if any(
                    keyword in access["permission"].lower() for keyword in role_keywords
                ):
                    risk_score = 0.7
                    reason_stale = f"Role change: {old_role} -> {new_role}"
                    recommended_action = "Verify access aligns with new role"

        # Manager changes may affect approval-based access
        elif jml_event.event_type == JMLEventType.MANAGER_CHANGE:
            risk_score = 0.5
            reason_stale = "Manager change - review reporting structure access"
            recommended_action = "Review manager-delegated permissions"

        # Return stale access item if risk threshold met
        if risk_score >= 0.5:
            return StaleAccessItem(
                principal_id=jml_event.principal_id,
                resource_id=access["resource_id"],
                permission=access["permission"],
                provider=access["provider"],
                granted_date=access["granted_date"],
                last_used=None,  # Would need usage analytics
                risk_score=risk_score,
                reason_stale=reason_stale,
                recommended_action=recommended_action,
            )

        return None

    async def create_jml_campaign(
        self, org_id: str, campaign_name: str, created_by: str, lookback_days: int = 30
    ) -> dict[str, Any]:
        """
        Create a JML campaign for an organization.

        Detects lifecycle events and creates access review tasks.
        """
        campaign_id = f"jml_{org_id}_{int(datetime.now().timestamp())}"

        # Detect JML events
        jml_events = await self.detect_jml_events(org_id, lookback_days)

        # Identify stale access
        stale_access = await self.identify_stale_access(org_id, jml_events)

        # Group stale access by principal for review
        access_by_principal: dict[str, list[StaleAccessItem]] = {}
        for item in stale_access:
            pid = item.principal_id
            if pid not in access_by_principal:
                access_by_principal[pid] = []
            access_by_principal[pid].append(item)

        # Create campaign summary
        campaign = {
            "campaign_id": campaign_id,
            "name": campaign_name,
            "organization_id": org_id,
            "created_by": created_by,
            "created_at": datetime.now().isoformat(),
            "lookback_days": lookback_days,
            "summary": {
                "jml_events_detected": len(jml_events),
                "principals_affected": len(access_by_principal),
                "stale_access_items": len(stale_access),
                "high_risk_items": len(
                    [item for item in stale_access if item.risk_score >= 0.8]
                ),
                "immediate_action_required": len(
                    [
                        item
                        for item in stale_access
                        if item.recommended_action.startswith("Revoke")
                    ]
                ),
            },
            "events": [
                {
                    "event_id": event.event_id,
                    "principal_id": event.principal_id,
                    "event_type": event.event_type.value,
                    "event_date": event.event_date.isoformat(),
                    "requires_review": event.requires_review,
                    "review_deadline": event.review_deadline.isoformat(),
                    "affected_access_count": len(event.affected_access),
                }
                for event in jml_events
            ],
            "stale_access_by_principal": {
                pid: [
                    {
                        "resource_id": item.resource_id,
                        "permission": item.permission,
                        "provider": item.provider,
                        "risk_score": item.risk_score,
                        "reason_stale": item.reason_stale,
                        "recommended_action": item.recommended_action,
                    }
                    for item in items
                ]
                for pid, items in access_by_principal.items()
            },
        }

        # Log campaign creation
        await self.transparency_log.append_entry(
            LogEntryType.USER_ACTION,
            created_by,
            campaign_id,
            "jml_campaign_created",
            {
                "campaign_id": campaign_id,
                "organization_id": org_id,
                "events_detected": len(jml_events),
                "stale_access_items": len(stale_access),
            },
        )

        logger.info(f"Created JML campaign {campaign_id} with {len(jml_events)} events")

        return campaign

    async def get_campaign_recommendations(
        self, campaign_data: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """
        Generate actionable recommendations from JML campaign.

        Returns prioritized list of actions for ops teams.
        """
        recommendations = []

        # Immediate actions (terminations, high-risk)
        for principal_id, access_items in campaign_data[
            "stale_access_by_principal"
        ].items():
            immediate_actions = [
                item
                for item in access_items
                if item["recommended_action"].startswith("Revoke")
                or item["risk_score"] >= 0.9
            ]

            if immediate_actions:
                recommendations.append(
                    {
                        "priority": "immediate",
                        "principal_id": principal_id,
                        "action": "revoke_access",
                        "items": immediate_actions,
                        "deadline": datetime.now() + timedelta(hours=24),
                        "justification": "High-risk stale access detected",
                    }
                )

        # Weekly review actions
        for principal_id, access_items in campaign_data[
            "stale_access_by_principal"
        ].items():
            review_actions = [
                item
                for item in access_items
                if item["recommended_action"].startswith("Review")
                and item["risk_score"] >= 0.5
            ]

            if review_actions:
                recommendations.append(
                    {
                        "priority": "weekly",
                        "principal_id": principal_id,
                        "action": "review_access",
                        "items": review_actions,
                        "deadline": datetime.now() + timedelta(days=7),
                        "justification": "Role/department change detected",
                    }
                )

        # Sort by priority and risk score
        priority_order = {"immediate": 1, "weekly": 2, "monthly": 3}
        recommendations.sort(
            key=lambda x: (
                priority_order.get(x["priority"], 4),
                -max(item["risk_score"] for item in x["items"]),
            )
        )

        return recommendations


# CEL rule examples for JML detection
JML_CEL_RULES = {
    "finance_github_admin": """
        principal.department == "Finance" &&
        principal.has("GitHub:admin") ->
        violation("Outlier admin outside peer group")
    """,
    "terminated_user_access": """
        principal.status == "terminated" &&
        principal.has_any_access() ->
        violation("Terminated user still has access")
    """,
    "department_change_stale_access": """
        principal.department_changed_in_days(30) &&
        resource.department_specific &&
        resource.department != principal.current_department ->
        violation("Stale department access after transfer")
    """,
}


# Global JML campaign manager
_jml_manager = JMLCampaignManager()


def get_jml_manager() -> JMLCampaignManager:
    """Get global JML campaign manager."""
    return _jml_manager


async def detect_jml_events_for_org(
    org_id: str, lookback_days: int = 7
) -> list[JMLEvent]:
    """Convenience function to detect JML events."""
    return await _jml_manager.detect_jml_events(org_id, lookback_days)
