"""Forensic replay engine for historical state reconstruction."""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, desc

from cerebro.core.models import (
    Organization,
    Resource,
    Principal,
    ConfigSnapshot,
    IamEdge,
    Finding,
    AuditEvent,
)

logger = logging.getLogger(__name__)


@dataclass
class HistoricalPrincipal:
    """Principal state at a point in time."""

    principal_id: UUID
    external_id: str
    display_name: Optional[str]
    email: Optional[str]
    principal_type: str
    provider: str
    was_active: bool
    permissions: List[Dict[str, Any]]
    groups: List[str]


@dataclass
class HistoricalResource:
    """Resource state at a point in time."""

    resource_id: UUID
    external_id: str
    name: Optional[str]
    resource_type: str
    provider: str
    configuration: Dict[str, Any]
    who_had_access: List[Dict[str, Any]]
    security_posture: Dict[str, Any]


@dataclass
class HistoricalState:
    """Complete system state at a point in time."""

    timestamp: datetime
    organization: str
    principals: List[HistoricalPrincipal]
    resources: List[HistoricalResource]
    active_findings: List[Dict[str, Any]]
    security_summary: Dict[str, Any]


class ForensicReplayEngine:
    """Reconstructs historical system state for forensic investigation."""

    def __init__(self, db_session: AsyncSession):
        """Initialize forensic replay engine."""
        self.db = db_session

    async def reconstruct_state_at_time(
        self,
        org_id: UUID,
        target_time: datetime,
        scope: Optional[Dict[str, Any]] = None,
    ) -> HistoricalState:
        """Reconstruct complete system state at a specific time."""
        org = await self.db.get(Organization, org_id)
        if not org:
            raise ValueError(f"Organization {org_id} not found")

        logger.info(f"Reconstructing state for {org.name} at {target_time}")

        # Apply scope filters if provided
        provider_filter = scope.get("providers") if scope else None
        resource_types = scope.get("resource_types") if scope else None

        # Reconstruct principals
        historical_principals = await self._reconstruct_principals(
            org_id, target_time, provider_filter
        )

        # Reconstruct resources
        historical_resources = await self._reconstruct_resources(
            org_id, target_time, provider_filter, resource_types
        )

        # Reconstruct findings that would have been active
        active_findings = await self._reconstruct_active_findings(org_id, target_time)

        # Generate security summary
        security_summary = self._generate_security_summary(
            historical_principals, historical_resources, active_findings
        )

        state = HistoricalState(
            timestamp=target_time,
            organization=org.name,
            principals=historical_principals,
            resources=historical_resources,
            active_findings=active_findings,
            security_summary=security_summary,
        )

        logger.info(
            f"Reconstructed state: {len(historical_principals)} principals, "
            f"{len(historical_resources)} resources, {len(active_findings)} findings"
        )

        return state

    async def _reconstruct_principals(
        self, org_id: UUID, target_time: datetime, provider_filter: Optional[List[str]]
    ) -> List[HistoricalPrincipal]:
        """Reconstruct principal state at target time."""
        # Get principals that existed at target time
        stmt = (
            select(Principal)
            .join(Principal.account)
            .where(Principal.account.has(org_id=org_id))
        )

        if provider_filter:
            stmt = stmt.where(Principal.provider.in_(provider_filter))

        all_principals = await self.db.scalars(stmt)
        historical_principals = []

        for principal in all_principals:
            # Get permissions that were active at target time
            permissions_stmt = select(IamEdge).where(
                and_(
                    IamEdge.principal_id == principal.principal_id,
                    IamEdge.effective_at <= target_time,
                    or_(IamEdge.expires_at.is_(None), IamEdge.expires_at > target_time),
                )
            )

            iam_edges = await self.db.scalars(permissions_stmt)

            permissions = []
            groups = set()

            for edge in iam_edges:
                permissions.append(
                    {
                        "permission": edge.permission,
                        "via": edge.via,
                        "is_admin": edge.is_admin,
                        "resource_id": (
                            str(edge.resource_id) if edge.resource_id else None
                        ),
                    }
                )

                # Extract group information from via field
                if edge.via and "group" in edge.via.lower():
                    groups.add(edge.via)

            historical_principal = HistoricalPrincipal(
                principal_id=principal.principal_id,
                external_id=principal.external_id,
                display_name=principal.display_name,
                email=principal.email,
                principal_type=principal.principal_type,
                provider=principal.provider,
                was_active=len(permissions) > 0,  # Active if had any permissions
                permissions=permissions,
                groups=list(groups),
            )

            historical_principals.append(historical_principal)

        return historical_principals

    async def _reconstruct_resources(
        self,
        org_id: UUID,
        target_time: datetime,
        provider_filter: Optional[List[str]],
        resource_types: Optional[List[str]],
    ) -> List[HistoricalResource]:
        """Reconstruct resource state at target time."""
        # Get resources that existed at target time
        stmt = (
            select(Resource)
            .join(Resource.account)
            .where(Resource.account.has(org_id=org_id))
        )

        if provider_filter:
            stmt = stmt.where(Resource.provider.in_(provider_filter))

        if resource_types:
            stmt = stmt.where(Resource.resource_type.in_(resource_types))

        all_resources = await self.db.scalars(stmt)
        historical_resources = []

        for resource in all_resources:
            # Get configuration at target time
            config_stmt = (
                select(ConfigSnapshot)
                .where(
                    and_(
                        ConfigSnapshot.resource_id == resource.resource_id,
                        ConfigSnapshot.captured_at <= target_time,
                    )
                )
                .order_by(desc(ConfigSnapshot.captured_at))
                .limit(1)
            )

            config_snapshot = await self.db.scalar(config_stmt)
            if not config_snapshot:
                continue  # Resource didn't exist at target time

            # Get who had access at target time
            access_stmt = (
                select(IamEdge, Principal)
                .join(Principal)
                .where(
                    and_(
                        IamEdge.resource_id == resource.resource_id,
                        IamEdge.effective_at <= target_time,
                        or_(
                            IamEdge.expires_at.is_(None),
                            IamEdge.expires_at > target_time,
                        ),
                    )
                )
            )

            access_edges = await self.db.execute(access_stmt)

            who_had_access = []
            for iam_edge, principal in access_edges:
                who_had_access.append(
                    {
                        "principal_id": str(principal.principal_id),
                        "principal_name": principal.display_name
                        or principal.external_id,
                        "permission": iam_edge.permission,
                        "via": iam_edge.via,
                        "is_admin": iam_edge.is_admin,
                    }
                )

            # Assess security posture at that time
            security_posture = self._assess_historical_security_posture(
                resource, config_snapshot.normalized_config
            )

            historical_resource = HistoricalResource(
                resource_id=resource.resource_id,
                external_id=resource.external_id,
                name=resource.name,
                resource_type=resource.resource_type,
                provider=resource.provider,
                configuration=config_snapshot.normalized_config,
                who_had_access=who_had_access,
                security_posture=security_posture,
            )

            historical_resources.append(historical_resource)

        return historical_resources

    async def _reconstruct_active_findings(
        self, org_id: UUID, target_time: datetime
    ) -> List[Dict[str, Any]]:
        """Reconstruct what findings would have been active at target time."""
        # Get findings that were active at target time
        stmt = select(Finding).where(
            and_(
                Finding.org_id == org_id,
                Finding.first_seen <= target_time,
                or_(
                    Finding.status == "open",
                    and_(
                        Finding.status.in_(["fixed", "suppressed"]),
                        Finding.last_seen > target_time,
                    ),
                ),
            )
        )

        findings = await self.db.scalars(stmt)

        active_findings = []
        for finding in findings:
            # Determine if finding would have been "open" at target time
            status_at_time = "open"
            if finding.status == "fixed" and finding.last_seen <= target_time:
                status_at_time = "fixed"
            elif finding.status == "suppressed":
                status_at_time = "suppressed"

            active_findings.append(
                {
                    "finding_id": str(finding.finding_id),
                    "title": finding.title,
                    "severity": finding.severity,
                    "status_at_time": status_at_time,
                    "provider": finding.provider,
                    "first_seen": finding.first_seen.isoformat(),
                    "would_be_active": status_at_time == "open",
                }
            )

        return active_findings

    def _assess_historical_security_posture(
        self, resource: Resource, config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Assess security posture of resource at historical point."""
        issues: List[str] = []
        strengths: List[str] = []
        overall_score = 0.5
        if resource.resource_type == "aws.s3.bucket":
            # Check encryption
            if not config.get("encryption", {}).get("enabled"):
                issues.append("unencrypted")
                overall_score -= 0.2
            else:
                strengths.append("encrypted")

            # Check public access
            if config.get("policyAllowsPublic") or config.get("aclAllowsPublic"):
                issues.append("public_access")
                overall_score -= 0.4
            else:
                strengths.append("private")

        elif resource.resource_type == "github.repo":
            # Check visibility and protection
            if config.get("visibility") == "public":
                if not config.get("branchProtection", {}).get("requirePR"):
                    issues.append("public_no_protection")
                    overall_score -= 0.3

            if config.get("branchProtection", {}).get("requirePR"):
                strengths.append("branch_protection")

        return {
            "overall_score": max(0.0, min(1.0, overall_score)),
            "issues": issues,
            "strengths": strengths,
        }

    def _generate_security_summary(
        self,
        principals: List[HistoricalPrincipal],
        resources: List[HistoricalResource],
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Generate security summary for historical state."""
        # Principal analysis
        total_principals = len(principals)
        active_principals = len([p for p in principals if p.was_active])
        admin_principals = len(
            [
                p
                for p in principals
                if any("admin" in perm["permission"] for perm in p.permissions)
            ]
        )

        # Resource analysis
        total_resources = len(resources)
        high_risk_resources = len(
            [r for r in resources if r.security_posture["overall_score"] < 0.3]
        )
        public_resources = len(
            [
                r
                for r in resources
                if "public" in str(r.security_posture.get("issues", []))
            ]
        )

        # Finding analysis
        active_findings = [f for f in findings if f["would_be_active"]]
        critical_findings = len(
            [f for f in active_findings if f["severity"] == "critical"]
        )

        return {
            "principals": {
                "total": total_principals,
                "active": active_principals,
                "admin": admin_principals,
                "admin_percentage": round(
                    (admin_principals / max(total_principals, 1)) * 100, 1
                ),
            },
            "resources": {
                "total": total_resources,
                "high_risk": high_risk_resources,
                "public": public_resources,
                "avg_security_score": round(
                    sum(r.security_posture["overall_score"] for r in resources)
                    / max(total_resources, 1),
                    2,
                ),
            },
            "findings": {
                "total_active": len(active_findings),
                "critical": critical_findings,
                "by_severity": {
                    severity: len(
                        [f for f in active_findings if f["severity"] == severity]
                    )
                    for severity in ["critical", "high", "medium", "low"]
                },
            },
            "risk_indicators": {
                "admin_ratio_high": admin_principals / max(total_principals, 1) > 0.1,
                "public_resources_present": public_resources > 0,
                "critical_findings_present": critical_findings > 0,
            },
        }

    async def investigate_incident(
        self,
        org_id: UUID,
        incident_time: datetime,
        lookback_hours: int = 24,
        focus_resource: Optional[UUID] = None,
    ) -> Dict[str, Any]:
        """Investigate a security incident using historical reconstruction."""
        start_time = incident_time - timedelta(hours=lookback_hours)

        logger.info(
            f"Investigating incident at {incident_time}, looking back {lookback_hours} hours"
        )

        # Reconstruct state at incident time
        incident_state = await self.reconstruct_state_at_time(org_id, incident_time)

        # Reconstruct state at start of lookback period
        baseline_state = await self.reconstruct_state_at_time(org_id, start_time)

        # Find changes during the period
        changes = await self._find_changes_in_period(
            org_id, start_time, incident_time, focus_resource
        )

        # Analyze what happened
        analysis = self._analyze_incident_changes(
            baseline_state, incident_state, changes
        )

        return {
            "incident_time": incident_time.isoformat(),
            "lookback_period": f"{lookback_hours} hours",
            "baseline_state": baseline_state,
            "incident_state": incident_state,
            "changes_detected": changes,
            "analysis": analysis,
            "investigation_timestamp": datetime.utcnow().isoformat(),
        }

    async def _find_changes_in_period(
        self,
        org_id: UUID,
        start_time: datetime,
        end_time: datetime,
        focus_resource: Optional[UUID] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Find all changes that occurred during a time period."""
        changes: Dict[str, List[Dict[str, Any]]] = {
            "configuration_changes": [],
            "permission_changes": [],
            "principal_changes": [],
            "audit_events": [],
        }

        # Configuration changes
        config_stmt = (
            select(ConfigSnapshot, Resource)
            .join(Resource)
            .join(Resource.account)
            .where(
                and_(
                    Resource.account.has(org_id=org_id),
                    ConfigSnapshot.captured_at.between(start_time, end_time),
                )
            )
        )

        if focus_resource:
            config_stmt = config_stmt.where(
                ConfigSnapshot.resource_id == focus_resource
            )

        config_changes = await self.db.execute(config_stmt)

        for snapshot, resource in config_changes:
            changes["configuration_changes"].append(
                {
                    "timestamp": snapshot.captured_at.isoformat(),
                    "resource_id": str(resource.resource_id),
                    "resource_external_id": resource.external_id,
                    "resource_type": resource.resource_type,
                    "provider": resource.provider,
                    "config_hash": snapshot.config_sha.hex(),
                    "collector_version": snapshot.collector_version,
                }
            )

        # Permission changes (new IAM edges)
        permission_stmt = (
            select(IamEdge, Principal, Resource)
            .join(Principal)
            .outerjoin(Resource)
            .where(
                and_(
                    IamEdge.effective_at.between(start_time, end_time),
                    Principal.account.has(org_id=org_id),
                )
            )
        )

        permission_changes = await self.db.execute(permission_stmt)

        for iam_edge, principal, resource in permission_changes:
            changes["permission_changes"].append(
                {
                    "timestamp": iam_edge.effective_at.isoformat(),
                    "principal_id": str(principal.principal_id),
                    "principal_name": principal.display_name or principal.external_id,
                    "permission": iam_edge.permission,
                    "resource_external_id": resource.external_id if resource else None,
                    "is_admin": iam_edge.is_admin,
                    "via": iam_edge.via,
                    "provider": iam_edge.provider,
                }
            )

        # Audit events
        audit_stmt = (
            select(AuditEvent)
            .join(AuditEvent.account)
            .where(
                and_(
                    AuditEvent.account.has(org_id=org_id),
                    AuditEvent.occurred_at.between(start_time, end_time),
                )
            )
            .order_by(AuditEvent.occurred_at)
        )

        audit_events = await self.db.scalars(audit_stmt)

        for event in audit_events:
            changes["audit_events"].append(
                {
                    "timestamp": event.occurred_at.isoformat(),
                    "provider": event.provider,
                    "action": event.action,
                    "actor": event.actor_external_id,
                    "resource": event.resource_external_id,
                    "raw_event": event.raw,
                }
            )

        return changes

    def _analyze_incident_changes(
        self,
        baseline_state: HistoricalState,
        incident_state: HistoricalState,
        changes: Dict[str, List[Dict[str, Any]]],
    ) -> Dict[str, Any]:
        """Analyze changes to understand what happened during incident."""
        risk_escalations: List[Dict[str, Any]] = []
        timeline: List[Dict[str, Any]] = []
        potential_causes: List[str] = []
        analysis: Dict[str, Any] = {
            "change_summary": {},
            "risk_escalations": risk_escalations,
            "timeline": timeline,
            "potential_causes": potential_causes,
        }

        # Summarize change types
        analysis["change_summary"] = {
            "configuration_changes": len(changes["configuration_changes"]),
            "permission_changes": len(changes["permission_changes"]),
            "audit_events": len(changes["audit_events"]),
        }

        # Identify risk escalations
        baseline_critical = len(
            [f for f in baseline_state.active_findings if f["severity"] == "critical"]
        )
        incident_critical = len(
            [f for f in incident_state.active_findings if f["severity"] == "critical"]
        )

        if incident_critical > baseline_critical:
            risk_escalations.append(
                {
                    "type": "new_critical_findings",
                    "count": incident_critical - baseline_critical,
                    "description": f"{incident_critical - baseline_critical} new critical findings appeared",
                }
            )

        # Create timeline
        all_events: List[Dict[str, Any]] = []

        for change in changes["configuration_changes"]:
            all_events.append(
                {
                    "timestamp": change["timestamp"],
                    "type": "configuration_change",
                    "description": f"Config changed for {change['resource_external_id']}",
                }
            )

        for change in changes["permission_changes"]:
            all_events.append(
                {
                    "timestamp": change["timestamp"],
                    "type": "permission_change",
                    "description": f"Permission {change['permission']} granted to {change['principal_name']}",
                }
            )

        # Sort timeline by timestamp
        timeline.extend(sorted(all_events, key=lambda x: x["timestamp"]))

        # Identify potential causes
        if changes["permission_changes"]:
            admin_grants = [c for c in changes["permission_changes"] if c["is_admin"]]
            if admin_grants:
                potential_causes.append(
                    "Admin privileges granted during incident window"
                )

        if changes["configuration_changes"]:
            public_changes = [
                c
                for c in changes["configuration_changes"]
                if "s3" in c["resource_type"]
            ]
            if public_changes:
                potential_causes.append("S3 configuration changes detected")

        return analysis

    async def compare_states(
        self, org_id: UUID, time1: datetime, time2: datetime
    ) -> Dict[str, Any]:
        """Compare system state between two points in time."""
        state1 = await self.reconstruct_state_at_time(org_id, time1)
        state2 = await self.reconstruct_state_at_time(org_id, time2)

        return {
            "time1": time1.isoformat(),
            "time2": time2.isoformat(),
            "state1_summary": state1.security_summary,
            "state2_summary": state2.security_summary,
            "changes": {
                "principals_added": len(state2.principals) - len(state1.principals),
                "resources_added": len(state2.resources) - len(state1.resources),
                "findings_net_change": len(state2.active_findings)
                - len(state1.active_findings),
                "security_score_change": (
                    state2.security_summary["resources"]["avg_security_score"]
                    - state1.security_summary["resources"]["avg_security_score"]
                ),
            },
        }
