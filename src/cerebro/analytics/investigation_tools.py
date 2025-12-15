"""Investigation tools for security incident analysis and correlation."""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from .sql_dialect import (
    cast_to_string_expr,
    current_timestamp_expr,
    get_dialect_name,
    json_object_function,
    timestamp_minus_days_expr,
    timestamp_minus_hours_expr,
)

logger = logging.getLogger(__name__)


class EventType(Enum):
    """Types of security events for correlation."""
    FINDING_CREATED = "finding_created"
    FINDING_UPDATED = "finding_updated"
    FINDING_RESOLVED = "finding_resolved"
    CONFIG_CHANGED = "config_changed"
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_REVOKED = "permission_revoked"
    LOGIN_EVENT = "login_event"
    ADMIN_ACTION = "admin_action"


@dataclass
class SecurityEvent:
    """Security event for timeline analysis."""
    event_id: str
    event_type: EventType
    timestamp: datetime
    principal_id: Optional[UUID]
    resource_id: Optional[UUID]
    description: str
    metadata: Dict[str, Any]
    correlation_id: Optional[str]


@dataclass
class FindingTimeline:
    """Timeline of events related to a finding."""
    finding_id: UUID
    finding_title: str
    created_at: datetime
    events: List[SecurityEvent]
    related_findings: List[Dict[str, Any]]
    affected_resources: List[Dict[str, Any]]
    involved_identities: List[Dict[str, Any]]


@dataclass
class EventCorrelation:
    """Correlation analysis between security events."""
    correlation_id: str
    event_cluster: List[SecurityEvent]
    correlation_strength: float
    pattern_type: str
    risk_indicators: List[str]
    investigation_priority: str


class InvestigationEngine:
    """Engine for security investigation and event correlation."""
    
    def __init__(self, db_session: AsyncSession):
        """Initialize investigation engine."""
        self.db = db_session
    
    async def generate_finding_timeline(self, finding_id: UUID) -> FindingTimeline:
        """Generate comprehensive timeline for a finding investigation."""
        
        logger.info(f"Generating timeline for finding {finding_id}")
        
        # Get finding details
        finding_query = text("""
            SELECT f.finding_id, f.title, f.first_seen, f.resource_id, f.principal_id, f.rule_id
            FROM findings f
            WHERE f.finding_id = :finding_id
        """)
        
        result = await self.db.execute(finding_query, {"finding_id": finding_id})
        finding_row = result.fetchone()
        
        if not finding_row:
            raise ValueError(f"Finding {finding_id} not found")
        
        # Collect related events
        events = []
        
        # 1. Configuration changes on the affected resource
        if finding_row.resource_id:
            config_events = await self._get_resource_config_timeline(finding_row.resource_id)
            events.extend(config_events)
        
        # 2. Permission changes for involved principals
        if finding_row.principal_id:
            permission_events = await self._get_principal_permission_timeline(finding_row.principal_id)
            events.extend(permission_events)
        
        # 3. Related findings (same rule, same resource, etc.)
        related_finding_events = await self._get_related_finding_events(finding_id, finding_row.rule_id)
        events.extend(related_finding_events)
        
        # Sort events chronologically
        events.sort(key=lambda x: x.timestamp)
        
        # Get related findings
        related_findings = await self._get_related_findings(finding_id, finding_row.rule_id, finding_row.resource_id)
        
        # Get affected resources
        affected_resources = await self._get_affected_resources(finding_row.resource_id)
        
        # Get involved identities
        involved_identities = await self._get_involved_identities(finding_row.principal_id)
        
        return FindingTimeline(
            finding_id=finding_id,
            finding_title=finding_row.title,
            created_at=finding_row.first_seen,
            events=events,
            related_findings=related_findings,
            affected_resources=affected_resources,
            involved_identities=involved_identities
        )
    
    async def _get_resource_config_timeline(self, resource_id: UUID) -> List[SecurityEvent]:
        """Get configuration change timeline for a resource."""

        dialect = get_dialect_name(self.db)
        lookback_90_days = timestamp_minus_days_expr(days=90, dialect=dialect)
        
        config_timeline_query = text(
            f"""
            SELECT 
                cs.snapshot_id,
                cs.captured_at,
                cs.normalized_config,
                LAG(cs.normalized_config) OVER (ORDER BY cs.captured_at) as previous_config
            FROM config_snapshots cs
            WHERE cs.resource_id = :resource_id
                AND cs.captured_at >= {lookback_90_days}
            ORDER BY cs.captured_at
            """
        )
        
        result = await self.db.execute(config_timeline_query, {"resource_id": resource_id})
        
        events = []
        for row in result.fetchall():
            # Detect configuration changes
            if row.previous_config:
                # Simple change detection - in production would use deep diff
                changed_keys = set(row.normalized_config.keys()) - set(row.previous_config.keys())
                
                if changed_keys or row.normalized_config != row.previous_config:
                    events.append(SecurityEvent(
                        event_id=str(row.snapshot_id),
                        event_type=EventType.CONFIG_CHANGED,
                        timestamp=row.captured_at,
                        principal_id=None,
                        resource_id=resource_id,
                        description=f"Configuration changed: {', '.join(changed_keys) if changed_keys else 'values modified'}",
                        metadata={
                            "config_snapshot_id": str(row.snapshot_id),
                            "changed_keys": list(changed_keys)
                        },
                        correlation_id=None
                    ))
        
        return events
    
    async def _get_principal_permission_timeline(self, principal_id: UUID) -> List[SecurityEvent]:
        """Get permission change timeline for a principal."""

        dialect = get_dialect_name(self.db)
        lookback_90_days = timestamp_minus_days_expr(days=90, dialect=dialect)
        
        permission_timeline_query = text(
            f"""
            SELECT 
                ie.edge_id,
                ie.permission,
                ie.effective_at,
                ie.expires_at,
                ie.via,
                ie.is_admin,
                ie.resource_id
            FROM iam_edges ie
            WHERE ie.principal_id = :principal_id
                AND ie.effective_at >= {lookback_90_days}
            ORDER BY ie.effective_at
            """
        )
        
        result = await self.db.execute(permission_timeline_query, {"principal_id": principal_id})
        
        events = []
        for row in result.fetchall():
            events.append(SecurityEvent(
                event_id=str(row.edge_id),
                event_type=EventType.PERMISSION_GRANTED,
                timestamp=row.effective_at,
                principal_id=principal_id,
                resource_id=row.resource_id,
                description=f"Permission granted: {row.permission} via {row.via}",
                metadata={
                    "permission": row.permission,
                    "via": row.via,
                    "is_admin": row.is_admin,
                    "expires_at": row.expires_at.isoformat() if row.expires_at else None
                },
                correlation_id=None
            ))
        
        return events
    
    async def _get_related_finding_events(self, finding_id: UUID, rule_id: UUID) -> List[SecurityEvent]:
        """Get events from related findings (same rule)."""

        dialect = get_dialect_name(self.db)
        lookback_90_days = timestamp_minus_days_expr(days=90, dialect=dialect)
        
        related_findings_query = text(
            f"""
            SELECT f.finding_id, f.title, f.first_seen, f.last_seen, f.status
            FROM findings f
            WHERE f.rule_id = :rule_id
                AND f.finding_id != :finding_id
                AND f.first_seen >= {lookback_90_days}
            ORDER BY f.first_seen
            """
        )
        
        result = await self.db.execute(related_findings_query, {
            "rule_id": rule_id,
            "finding_id": finding_id
        })
        
        events = []
        for row in result.fetchall():
            events.append(SecurityEvent(
                event_id=f"finding_{row.finding_id}",
                event_type=EventType.FINDING_CREATED,
                timestamp=row.first_seen,
                principal_id=None,
                resource_id=None,
                description=f"Related finding created: {row.title}",
                metadata={
                    "finding_id": str(row.finding_id),
                    "status": row.status,
                    "last_seen": row.last_seen.isoformat() if row.last_seen else None
                },
                correlation_id=f"rule_{rule_id}"
            ))
        
        return events
    
    async def _get_related_findings(
        self,
        finding_id: UUID,
        rule_id: UUID,
        resource_id: Optional[UUID]
    ) -> List[Dict[str, Any]]:
        """Get findings related to the current finding."""
        
        related_query = text("""
            SELECT f.finding_id, f.title, f.severity, f.status, f.first_seen
            FROM findings f
            WHERE (f.rule_id = :rule_id OR f.resource_id = :resource_id)
                AND f.finding_id != :finding_id
            ORDER BY f.first_seen DESC
            LIMIT 10
        """)
        
        result = await self.db.execute(related_query, {
            "rule_id": rule_id,
            "resource_id": resource_id,
            "finding_id": finding_id
        })
        
        return [
            {
                "finding_id": str(row.finding_id),
                "title": row.title,
                "severity": row.severity,
                "status": row.status,
                "first_seen": row.first_seen.isoformat(),
                "relationship": "same_rule" if str(row.finding_id) == str(rule_id) else "same_resource"
            }
            for row in result.fetchall()
        ]
    
    async def _get_affected_resources(self, resource_id: Optional[UUID]) -> List[Dict[str, Any]]:
        """Get resources affected by or related to the finding."""
        
        if not resource_id:
            return []
        
        # Get resource details and related resources
        resource_query = text("""
            SELECT 
                r.resource_id,
                r.external_id,
                r.name,
                r.resource_type,
                r.provider,
                COUNT(f.finding_id) as finding_count
            FROM resources r
            LEFT JOIN findings f ON r.resource_id = f.resource_id AND f.status = 'open'
            WHERE r.resource_id = :resource_id 
                OR r.parent_external_id = (
                    SELECT external_id FROM resources WHERE resource_id = :resource_id
                )
            GROUP BY r.resource_id, r.external_id, r.name, r.resource_type, r.provider
        """)
        
        result = await self.db.execute(resource_query, {"resource_id": resource_id})
        
        return [
            {
                "resource_id": str(row.resource_id),
                "external_id": row.external_id,
                "name": row.name,
                "resource_type": row.resource_type,
                "provider": row.provider,
                "open_findings": row.finding_count,
                "relationship": "primary" if row.resource_id == resource_id else "related"
            }
            for row in result.fetchall()
        ]
    
    async def _get_involved_identities(self, principal_id: Optional[UUID]) -> List[Dict[str, Any]]:
        """Get identities involved in or related to the finding."""
        
        if not principal_id:
            return []
        
        # Get principal details and related identities
        dialect = get_dialect_name(self.db)
        now_expr = current_timestamp_expr(dialect=dialect)

        identity_query = text(
            f"""
            SELECT 
                p.principal_id,
                p.display_name,
                p.email,
                p.principal_type,
                p.provider,
                COUNT(DISTINCT ie.permission) as permission_count,
                COUNT(CASE WHEN ie.is_admin THEN 1 END) as admin_permissions
            FROM principals p
            LEFT JOIN iam_edges ie ON p.principal_id = ie.principal_id
                AND (ie.expires_at IS NULL OR ie.expires_at > {now_expr})
            WHERE p.principal_id = :principal_id
                OR p.email = (SELECT email FROM principals WHERE principal_id = :principal_id)
            GROUP BY p.principal_id, p.display_name, p.email, p.principal_type, p.provider
            """
        )
        
        result = await self.db.execute(identity_query, {"principal_id": principal_id})
        
        return [
            {
                "principal_id": str(row.principal_id),
                "display_name": row.display_name,
                "email": row.email,
                "principal_type": row.principal_type,
                "provider": row.provider,
                "permission_count": row.permission_count,
                "admin_permissions": row.admin_permissions,
                "relationship": "primary" if row.principal_id == principal_id else "cross_provider_identity"
            }
            for row in result.fetchall()
        ]
    
    async def correlate_security_events(
        self,
        org_id: UUID,
        time_window_hours: int = 24
    ) -> List[EventCorrelation]:
        """Correlate security events to identify patterns and incidents."""
        
        since_time = datetime.utcnow() - timedelta(hours=time_window_hours)

        dialect = get_dialect_name(self.db)
        json_object = json_object_function(dialect=dialect)
        finding_id_str = cast_to_string_expr(column_expr="f.finding_id", dialect=dialect)
        edge_id_str = cast_to_string_expr(column_expr="ie.edge_id", dialect=dialect)
        
        # Get recent security events
        events_query = text(
            f"""
            WITH recent_events AS (
                -- Findings created
                SELECT 
                    {finding_id_str} as event_id,
                    'finding_created' as event_type,
                    f.first_seen as timestamp,
                    f.principal_id,
                    f.resource_id,
                    f.title as description,
                    {json_object}(
                        'severity', f.severity,
                        'rule_id', f.rule_id,
                        'provider', a.provider
                    ) as metadata
                FROM findings f
                JOIN accounts a ON f.account_id = a.account_id
                WHERE a.org_id = :org_id AND f.first_seen >= :since_time
                
                UNION ALL
                
                -- Permission grants (recent IAM edges)
                SELECT 
                    {edge_id_str} as event_id,
                    'permission_granted' as event_type,
                    ie.effective_at as timestamp,
                    ie.principal_id,
                    ie.resource_id,
                    'Permission granted: ' || ie.permission as description,
                    {json_object}(
                        'permission', ie.permission,
                        'via', ie.via,
                        'is_admin', ie.is_admin,
                        'provider', ie.provider
                    ) as metadata
                FROM iam_edges ie
                JOIN accounts a ON ie.account_id = a.account_id
                WHERE a.org_id = :org_id AND ie.effective_at >= :since_time
            )
            SELECT * FROM recent_events
            ORDER BY timestamp
            """
        )
        
        result = await self.db.execute(events_query, {
            "org_id": org_id,
            "since_time": since_time
        })
        
        events = []
        for row in result.fetchall():
            events.append(SecurityEvent(
                event_id=row.event_id,
                event_type=EventType(row.event_type),
                timestamp=row.timestamp,
                principal_id=row.principal_id,
                resource_id=row.resource_id,
                description=row.description,
                metadata=row.metadata,
                correlation_id=None
            ))
        
        # Perform correlation analysis
        correlations = await self._correlate_events(events)
        
        return correlations
    
    async def _correlate_events(self, events: List[SecurityEvent]) -> List[EventCorrelation]:
        """Correlate events to identify patterns."""
        
        correlations = []
        
        # Group events by time windows (1-hour buckets)
        time_buckets = {}
        for event in events:
            bucket_key = event.timestamp.replace(minute=0, second=0, microsecond=0)
            if bucket_key not in time_buckets:
                time_buckets[bucket_key] = []
            time_buckets[bucket_key].append(event)
        
        # Look for correlated activity
        for bucket_time, bucket_events in time_buckets.items():
            if len(bucket_events) >= 3:  # Threshold for correlation
                
                # Check for principal-based correlation
                principals = {}
                for event in bucket_events:
                    if event.principal_id:
                        principal_key = str(event.principal_id)
                        if principal_key not in principals:
                            principals[principal_key] = []
                        principals[principal_key].append(event)
                
                for principal_id, principal_events in principals.items():
                    if len(principal_events) >= 2:
                        correlations.append(EventCorrelation(
                            correlation_id=f"principal_{principal_id}_{bucket_time.isoformat()}",
                            event_cluster=principal_events,
                            correlation_strength=len(principal_events) / len(bucket_events),
                            pattern_type="principal_activity_burst",
                            risk_indicators=[
                                f"Multiple security events for principal {principal_id}",
                                f"{len(principal_events)} events in 1 hour"
                            ],
                            investigation_priority="medium" if len(principal_events) > 3 else "low"
                        ))
        
        return correlations
    
    async def _get_related_findings(
        self,
        finding_id: UUID,
        rule_id: UUID,
        resource_id: Optional[UUID]
    ) -> List[Dict[str, Any]]:
        """Get findings related by rule or resource."""
        
        related_query = text("""
            SELECT 
                f.finding_id,
                f.title,
                f.severity,
                f.status,
                f.first_seen,
                f.last_seen,
                r.name as rule_name,
                res.name as resource_name,
                a.provider
            FROM findings f
            JOIN rules r ON f.rule_id = r.rule_id
            JOIN accounts a ON f.account_id = a.account_id
            LEFT JOIN resources res ON f.resource_id = res.resource_id
            WHERE (f.rule_id = :rule_id OR f.resource_id = :resource_id)
                AND f.finding_id != :finding_id
            ORDER BY f.first_seen DESC
            LIMIT 20
        """)
        
        result = await self.db.execute(related_query, {
            "rule_id": rule_id,
            "resource_id": resource_id,
            "finding_id": finding_id
        })
        
        return [
            {
                "finding_id": str(row.finding_id),
                "title": row.title,
                "severity": row.severity,
                "status": row.status,
                "first_seen": row.first_seen.isoformat(),
                "last_seen": row.last_seen.isoformat() if row.last_seen else None,
                "rule_name": row.rule_name,
                "resource_name": row.resource_name,
                "provider": row.provider
            }
            for row in result.fetchall()
        ]
    
    async def get_temporal_query_interface(self, org_id: UUID) -> Dict[str, Any]:
        """Get interface for temporal security queries."""

        dialect = get_dialect_name(self.db)
        last_24_hours_expr = timestamp_minus_hours_expr(hours=24, dialect=dialect)
        
        # Provide common temporal query templates
        query_templates = [
            {
                "name": "Who had admin access on specific date?",
                "description": "Find all principals with admin permissions at a specific point in time",
                "template": """
                    SELECT DISTINCT p.display_name, p.email, ie.provider, ie.permission
                    FROM principals p
                    JOIN accounts a ON p.account_id = a.account_id  
                    JOIN iam_edges ie ON p.principal_id = ie.principal_id
                    WHERE a.org_id = '{org_id}'
                        AND ie.is_admin = true
                        AND ie.effective_at <= '{target_date}'
                        AND (ie.expires_at IS NULL OR ie.expires_at > '{target_date}')
                """,
                "parameters": ["target_date"]
            },
            {
                "name": "What changed in the last 24 hours?",
                "description": "Show all security-relevant changes in the last day",
                "template": f"""
                    SELECT 'config_change' as event_type, cs.captured_at, r.name as resource_name
                    FROM config_snapshots cs
                    JOIN resources r ON cs.resource_id = r.resource_id
                    JOIN accounts a ON r.account_id = a.account_id
                    WHERE a.org_id = '{{org_id}}' AND cs.captured_at >= {last_24_hours_expr}

                    UNION ALL

                    SELECT 'new_finding' as event_type, f.first_seen, f.title
                    FROM findings f
                    JOIN accounts a ON f.account_id = a.account_id
                    WHERE a.org_id = '{{org_id}}' AND f.first_seen >= {last_24_hours_expr}

                    ORDER BY captured_at DESC
                """,
                "parameters": []
            },
            {
                "name": "Permission timeline for identity",
                "description": "Show permission changes for a specific identity over time", 
                "template": """
                    SELECT ie.effective_at, ie.permission, ie.via, r.name as resource_name
                    FROM iam_edges ie
                    JOIN principals p ON ie.principal_id = p.principal_id
                    JOIN accounts a ON p.account_id = a.account_id
                    LEFT JOIN resources r ON ie.resource_id = r.resource_id
                    WHERE a.org_id = '{org_id}'
                        AND p.email = '{principal_email}'
                    ORDER BY ie.effective_at DESC
                """,
                "parameters": ["principal_email"]
            }
        ]
        
        return {
            "org_id": str(org_id),
            "available_templates": query_templates,
            "capabilities": [
                "Point-in-time access analysis",
                "Change timeline reconstruction", 
                "Permission evolution tracking",
                "Incident correlation analysis"
            ],
            "usage_note": "Replace {org_id} and parameter placeholders with actual values"
        }
