"""
Forensic Replay Tool

Enables agents to reconstruct security state at any point in time
for incident investigation and forensic analysis.

This tool wraps Cerebro's ForensicReplayEngine to provide temporal
investigation capabilities directly to Claude agents.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field

from .base import StructuredTool, AgentContext, ToolResult, ToolPermissionLevel
from cerebro.analysis.forensic_replay import ForensicReplayEngine
from cerebro.core.database import async_session_factory
import structlog

logger = structlog.get_logger(__name__)


class ForensicReplayInput(BaseModel):
    """Input parameters for forensic replay."""

    timestamp: str = Field(
        ...,
        description="ISO 8601 timestamp to replay state (e.g., '2024-12-01T15:30:00Z')",
    )
    scope: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Scope filters: providers (list), resource_types (list), principal_ids (list)",
    )
    include_changes: bool = Field(
        default=False, description="Include what changed since this timestamp"
    )


class ForensicReplayOutput(BaseModel):
    """Output from forensic replay."""

    timestamp: str
    organization: str
    principals_count: int
    resources_count: int
    active_findings_count: int
    security_summary: Dict[str, Any]
    principals_sample: List[Dict[str, Any]]
    resources_sample: List[Dict[str, Any]]
    active_findings: List[Dict[str, Any]]
    changes_since: Optional[Dict[str, Any]] = None


class ForensicReplayTool(StructuredTool):
    """
    Reconstruct security state at any point in time.

    This tool allows agents to answer questions like:
    - "What permissions did user X have on December 1st?"
    - "Which S3 buckets were publicly accessible last week?"
    - "What was the security posture before the incident?"
    - "When did this overly-permissive IAM policy get created?"

    Uses Cerebro's append-only audit log to reconstruct exact historical state.
    """

    tool_name = "forensic_replay"
    tool_description = "Reconstruct security state at any historical timestamp for incident investigation"
    tool_version = "1.0.0"
    input_model = ForensicReplayInput
    output_model = ForensicReplayOutput

    # Read-only tool, safe for all agents
    required_permission = ToolPermissionLevel.READ_ONLY

    async def _run(  # type: ignore[override]
        self,
        context: AgentContext,
        timestamp: str,
        scope: Optional[Dict[str, Any]] = None,
        include_changes: bool = False,
    ) -> ToolResult:
        """
        Execute forensic replay to reconstruct historical state.

        Args:
            context: Agent execution context
            timestamp: ISO 8601 timestamp to replay
            scope: Optional filters (providers, resource_types, etc.)
            include_changes: Whether to include delta since timestamp

        Returns:
            ToolResult with historical state reconstruction
        """
        try:
            # Parse timestamp
            target_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

            logger.info(
                "Forensic replay requested",
                timestamp=timestamp,
                org_id=context.org_id,
                scope=scope,
            )

            async with async_session_factory() as db_session:
                engine = ForensicReplayEngine(db_session)

                # Reconstruct state at target time
                historical_state = await engine.reconstruct_state_at_time(
                    org_id=context.org_id, target_time=target_time, scope=scope or {}
                )

                # Optionally compute changes since then
                changes_since = None
                if include_changes:
                    changes_since = await engine.compute_changes_since(  # type: ignore[attr-defined]
                        org_id=context.org_id,
                        from_time=target_time,
                        to_time=datetime.utcnow(),
                        scope=scope or {},
                    )

                # Format output for agent consumption
                output = ForensicReplayOutput(
                    timestamp=historical_state.timestamp.isoformat(),
                    organization=historical_state.organization,
                    principals_count=len(historical_state.principals),
                    resources_count=len(historical_state.resources),
                    active_findings_count=len(historical_state.active_findings),
                    security_summary=historical_state.security_summary,
                    # Provide samples for context (limit to avoid token overload)
                    principals_sample=[
                        {
                            "external_id": p.external_id,
                            "display_name": p.display_name,
                            "type": p.principal_type,
                            "provider": p.provider,
                            "was_active": p.was_active,
                            "permissions_count": len(p.permissions),
                            "groups": p.groups[:5],  # Limit groups
                        }
                        for p in historical_state.principals[:10]  # Top 10
                    ],
                    resources_sample=[
                        {
                            "external_id": r.external_id,
                            "name": r.name,
                            "type": r.resource_type,
                            "provider": r.provider,
                            "access_count": len(r.who_had_access),
                            "security_posture": r.security_posture,
                        }
                        for r in historical_state.resources[:10]  # Top 10
                    ],
                    # All findings (usually not too many)
                    active_findings=[
                        {
                            "finding_id": str(f["finding_id"]),
                            "title": f["title"],
                            "severity": f["severity"],
                            "resource": f.get("resource"),
                            "description": f.get("description", "")[:200],  # Truncate
                        }
                        for f in historical_state.active_findings
                    ],
                    changes_since=changes_since if include_changes else None,
                )

                logger.info(
                    "Forensic replay completed",
                    principals=len(historical_state.principals),
                    resources=len(historical_state.resources),
                    findings=len(historical_state.active_findings),
                )

                return ToolResult(
                    success=True,
                    data=output.model_dump(),
                    metadata={
                        "timestamp": timestamp,
                        "scope": scope,
                        "included_changes": include_changes,
                    },
                )

        except ValueError as e:
            logger.error("Invalid timestamp format", error=str(e))
            return ToolResult(
                success=False,
                error=f"Invalid timestamp format: {str(e)}. Use ISO 8601 format.",
            )

        except Exception as e:
            logger.error("Forensic replay failed", error=str(e), exc_info=True)
            return ToolResult(success=False, error=f"Forensic replay failed: {str(e)}")


class ChangeReplayTool(StructuredTool):
    """
    Replay security changes over a time range.

    Shows what changed between two timestamps, enabling agents to:
    - Build incident timelines
    - Identify when something went wrong
    - Track permission drift over time
    - Detect anomalous changes
    """

    tool_name = "change_replay"
    tool_description = "Show all security changes between two timestamps"
    tool_version = "1.0.0"
    required_permission = ToolPermissionLevel.READ_ONLY

    class Input(BaseModel):
        start_time: str = Field(..., description="Start timestamp (ISO 8601)")
        end_time: str = Field(..., description="End timestamp (ISO 8601)")
        scope: Optional[Dict[str, Any]] = Field(
            default_factory=dict, description="Scope filters"
        )

    class Output(BaseModel):
        start_time: str
        end_time: str
        time_span_hours: float
        changes_count: int
        principals_changed: int
        resources_changed: int
        findings_created: int
        findings_resolved: int
        change_summary: Dict[str, Any]
        timeline: List[Dict[str, Any]]

    input_model = Input
    output_model = Output

    async def _run(  # type: ignore[override]
        self,
        context: AgentContext,
        start_time: str,
        end_time: str,
        scope: Optional[Dict[str, Any]] = None,
    ) -> ToolResult:
        """
        Execute change replay over time range.

        Args:
            context: Agent execution context
            start_time: Start timestamp (ISO 8601)
            end_time: End timestamp (ISO 8601)
            scope: Optional filters

        Returns:
            ToolResult with timeline of changes
        """
        try:
            from cerebro.analysis.change_replay import ChangeReplayEngine

            # Parse timestamps
            start_dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
            end_dt = datetime.fromisoformat(end_time.replace("Z", "+00:00"))

            logger.info(
                "Change replay requested",
                start=start_time,
                end=end_time,
                org_id=context.org_id,
            )

            async with async_session_factory() as db_session:
                engine = ChangeReplayEngine(db_session)  # type: ignore[call-arg]

                # Replay changes
                changes = await engine.replay_changes(  # type: ignore[attr-defined]
                    org_id=context.org_id,
                    start_time=start_dt,
                    end_time=end_dt,
                    scope=scope or {},
                )

                # Build timeline
                timeline = []
                for change in changes.changes[:100]:  # Limit to 100 events
                    timeline.append(
                        {
                            "timestamp": change.timestamp.isoformat(),
                            "change_type": change.change_type,
                            "entity_type": change.entity_type,
                            "entity_id": change.entity_id,
                            "description": change.description,
                            "severity": (
                                change.severity if hasattr(change, "severity") else None
                            ),
                        }
                    )

                time_span = (end_dt - start_dt).total_seconds() / 3600  # hours

                output = self.Output(
                    start_time=start_time,
                    end_time=end_time,
                    time_span_hours=round(time_span, 2),
                    changes_count=len(changes.changes),
                    principals_changed=len(changes.principals_affected),
                    resources_changed=len(changes.resources_affected),
                    findings_created=changes.findings_created,
                    findings_resolved=changes.findings_resolved,
                    change_summary=changes.summary,
                    timeline=timeline,
                )

                logger.info(
                    "Change replay completed",
                    changes=len(changes.changes),
                    span_hours=time_span,
                )

                return ToolResult(
                    success=True,
                    data=output.model_dump(),
                    metadata={
                        "start_time": start_time,
                        "end_time": end_time,
                        "scope": scope,
                    },
                )

        except Exception as e:
            logger.error("Change replay failed", error=str(e), exc_info=True)
            return ToolResult(success=False, error=f"Change replay failed: {str(e)}")
