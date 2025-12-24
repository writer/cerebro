"""
Timeline construction tools for Cerebro agents.

Provides capabilities to build incident timelines from audit events,
configuration snapshots, and other temporal data sources.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

import structlog
from pydantic import BaseModel, Field

from .base import AgentContext, Tool, ToolPermissionLevel, ToolResult

logger = structlog.get_logger(__name__)


# Input/Output Schemas


class BuildTimelineInput(BaseModel):
    """Input for building an incident timeline."""

    incident_id: UUID | None = Field(
        None, description="Incident ID to build timeline for"
    )
    start_time: datetime = Field(description="Timeline start time")
    end_time: datetime = Field(description="Timeline end time")
    event_types: list[str] | None = Field(None, description="Filter by event types")
    include_config_changes: bool = Field(
        default=True, description="Include configuration changes"
    )
    include_audit_events: bool = Field(default=True, description="Include audit events")


class TimelineEvent(BaseModel):
    """A single timeline event."""

    timestamp: datetime
    event_type: str
    source: str  # audit_events, config_snapshots, etc.
    actor: str | None = None
    resource_id: str | None = None
    description: str
    details: dict[str, Any] = Field(default_factory=dict)
    severity: str | None = None


class BuildTimelineOutput(BaseModel):
    """Timeline construction output."""

    incident_id: UUID | None
    timeline_start: datetime
    timeline_end: datetime
    events: list[TimelineEvent]
    event_count: int
    sources_analyzed: list[str]
    construction_time_ms: float


class TimelineTool(Tool):
    """Tool for constructing incident timelines."""

    @property
    def name(self) -> str:
        return "timeline"

    @property
    def description(self) -> str:
        return "Build incident timelines from audit events and configuration changes"

    @property
    def input_schema(self) -> type:
        return BuildTimelineInput

    @property
    def output_schema(self) -> type:
        return BuildTimelineOutput

    @property
    def permission_level(self) -> ToolPermissionLevel:
        return ToolPermissionLevel.READ_ONLY

    async def execute(self, inputs: BaseModel, context: AgentContext) -> ToolResult:
        """Build a timeline from multiple data sources."""
        timeline_inputs = BuildTimelineInput(**inputs.model_dump())

        try:
            import time

            from sqlalchemy import and_, select

            from cerebro.core.models import AuditEvent, ConfigSnapshot, Finding

            start_time = time.time()

            from cerebro.core.database import async_session_factory

            async with async_session_factory() as session:
                all_events = []
                sources_analyzed = []

                # 1. Query audit events within the time range
                if timeline_inputs.include_audit_events:
                    # Note: AuditEvent uses occurred_at not timestamp, account_id not org_id
                    from cerebro.core.models import Account

                    audit_query = (
                        select(AuditEvent)
                        .join(Account, AuditEvent.account_id == Account.account_id)
                        .where(Account.org_id == context.org_id)
                        .where(
                            AuditEvent.occurred_at.between(
                                timeline_inputs.start_time, timeline_inputs.end_time
                            )
                        )
                        .order_by(AuditEvent.occurred_at.asc())
                    )

                    audit_result = await session.execute(audit_query)
                    audit_events = audit_result.scalars().all()

                    for event in audit_events:
                        severity = "medium"
                        if (
                            "error" in event.action.lower()
                            or "fail" in event.action.lower()
                        ):
                            severity = "high"
                        elif (
                            "login" in event.action.lower()
                            or "access" in event.action.lower()
                        ):
                            severity = "low"

                        all_events.append(
                            TimelineEvent(
                                timestamp=event.occurred_at,
                                event_type=event.action,
                                source="audit_events",
                                actor=event.actor_external_id or "system",
                                resource_id=event.resource_external_id,
                                description=f"Audit event: {event.action}",
                                details={"provider": event.provider, "raw": event.raw},
                                severity=severity,
                            )
                        )

                    sources_analyzed.append("audit_events")

                # 2. Query configuration changes within the time range
                if timeline_inputs.include_config_changes:
                    # Note: ConfigSnapshot uses captured_at not collected_at, and has no org_id
                    # Must join through Resource -> Account to filter by org
                    from cerebro.core.models import Account, Resource

                    config_query = (
                        select(ConfigSnapshot, Resource)
                        .join(
                            Resource, ConfigSnapshot.resource_id == Resource.resource_id
                        )
                        .join(Account, Resource.account_id == Account.account_id)
                        .where(Account.org_id == context.org_id)
                        .where(
                            ConfigSnapshot.captured_at.between(
                                timeline_inputs.start_time, timeline_inputs.end_time
                            )
                        )
                        .order_by(ConfigSnapshot.captured_at.asc())
                    )

                    config_result = await session.execute(config_query)
                    config_rows = config_result.all()

                    for snapshot, resource in config_rows:
                        all_events.append(
                            TimelineEvent(
                                timestamp=snapshot.captured_at,
                                event_type="config_change",
                                source="config_snapshots",
                                actor="collector",
                                resource_id=(
                                    str(snapshot.resource_id)
                                    if snapshot.resource_id
                                    else None
                                ),
                                description=f"Configuration captured for {resource.resource_type} ({resource.provider})",
                                details={
                                    "provider": resource.provider,
                                    "resource_type": resource.resource_type,
                                    "resource_name": resource.name or "unnamed",
                                    "config_sha": (
                                        snapshot.config_sha.hex()[:8]
                                        if snapshot.config_sha
                                        else None
                                    ),
                                },
                                severity="low",
                            )
                        )

                    sources_analyzed.append("config_snapshots")

                # 3. Query findings created within the time range
                findings_query = (
                    select(Finding)
                    .where(
                        and_(
                            Finding.org_id == context.org_id,
                            Finding.first_seen.between(
                                timeline_inputs.start_time, timeline_inputs.end_time
                            ),
                        )
                    )
                    .order_by(Finding.first_seen.asc())
                )

                findings_result = await session.execute(findings_query)
                findings = findings_result.scalars().all()

                for finding in findings:
                    all_events.append(
                        TimelineEvent(
                            timestamp=finding.first_seen,
                            event_type="finding_created",
                            source="findings",
                            actor="rule_engine",
                            resource_id=(
                                str(finding.resource_id)
                                if finding.resource_id
                                else None
                            ),
                            description=f"Security finding: {finding.title}",
                            details={
                                "finding_id": str(finding.finding_id),
                                "severity": finding.severity,
                                "provider": finding.provider,
                                "rule_id": str(finding.rule_id),
                                "status": finding.status,
                            },
                            severity=finding.severity,
                        )
                    )

                sources_analyzed.append("findings")

                # 4. Filter by event types if specified
                if timeline_inputs.event_types:
                    all_events = [
                        event
                        for event in all_events
                        if event.event_type in timeline_inputs.event_types
                    ]

                # 5. Sort all events chronologically
                all_events.sort(key=lambda e: e.timestamp)

                # 6. If incident_id specified, try to correlate events
                if timeline_inputs.incident_id:
                    # Look for events related to the incident
                    incident_related_events: list[Any] = []
                    for event in all_events:  # type: ignore[assignment]
                        # Check if event details contain incident references
                        if hasattr(event, "details") and hasattr(event.details, "get") and event.details.get(  # type: ignore[attr-defined]
                            "incident_id"
                        ) == str(timeline_inputs.incident_id):
                            incident_related_events.append(event)
                        # Also include high-severity events as potentially related
                        elif hasattr(event, "severity") and event.severity in ["critical", "high"]:  # type: ignore[attr-defined]
                            incident_related_events.append(event)

                    # If we found incident-related events, use those; otherwise use all
                    if incident_related_events:
                        all_events = incident_related_events  # type: ignore[assignment]

                execution_time = (time.time() - start_time) * 1000

                output = BuildTimelineOutput(
                    incident_id=timeline_inputs.incident_id,
                    timeline_start=timeline_inputs.start_time,
                    timeline_end=timeline_inputs.end_time,
                    events=all_events,
                    event_count=len(all_events),
                    sources_analyzed=sources_analyzed,
                    construction_time_ms=execution_time,
                )

                return ToolResult(
                    success=True,
                    data=output.model_dump(),
                    metadata={
                        "timeline_span_hours": (
                            timeline_inputs.end_time - timeline_inputs.start_time
                        ).total_seconds()
                        / 3600,
                        "incident_focused": timeline_inputs.incident_id is not None,
                        "sources_queried": len(sources_analyzed),
                        "events_found": len(all_events),
                        "execution_time_ms": execution_time,
                    },
                )

        except Exception as e:
            logger.exception("Timeline construction failed", error=str(e))
            return ToolResult(
                success=False,
                error=f"Timeline construction error: {e!s}",
            )
