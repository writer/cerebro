"""Scenario store feeding self-play orchestrator batches."""

from __future__ import annotations

from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select

from cerebro.agents.models import AgentType
from cerebro.core.config import settings
from cerebro.core.database import async_session_factory
from cerebro.core.models import Organization

from .models import SelfPlayScenario

logger = structlog.get_logger(__name__)


async def _resolve_default_org_id() -> UUID | None:
    configured = getattr(settings, "self_play_default_org_id", None)
    if configured:
        try:
            return UUID(str(configured))
        except ValueError:
            logger.warning("self_play.invalid_org_override", value=configured)

    async with async_session_factory() as session:
        result = await session.execute(
            select(Organization.org_id).order_by(Organization.created_at.asc()).limit(1)
        )
        return result.scalar_one_or_none()


def _parse_agent_type(value: Any, fallback: AgentType) -> AgentType:
    if value is None:
        return fallback
    if isinstance(value, AgentType):  # pragma: no branch - fast path
        return value
    try:
        return AgentType(str(value))
    except ValueError as exc:  # pragma: no cover - defensive guard
        raise ValueError(f"invalid agent type: {value}") from exc


def _build_configured_scenario(
    data: dict[str, Any],
    org_id: UUID,
) -> SelfPlayScenario:
    try:
        scenario_id = data["id"]
        challenger_prompt = data["challenger_prompt"]
        responder_prompt = data["responder_prompt"]
    except KeyError as exc:
        raise ValueError(f"missing required field: {exc.args[0]}") from exc

    max_turns = int(data.get("max_turns", settings.self_play_max_turns))
    max_tool_calls = int(data.get("max_tool_calls", settings.self_play_max_tool_calls))

    challenger_type = _parse_agent_type(
        data.get("challenger_agent_type"),
        AgentType.SECURITY_ANALYST,
    )
    responder_type = None
    if "responder_agent_type" in data:
        responder_type = _parse_agent_type(
            data.get("responder_agent_type"),
            challenger_type,
        )

    return SelfPlayScenario(
        id=str(scenario_id),
        org_id=org_id,
        challenger_prompt=str(challenger_prompt),
        responder_prompt=str(responder_prompt),
        max_turns=max_turns,
        max_tool_calls=max_tool_calls,
        metadata=data.get("metadata"),
        challenger_agent_type=challenger_type,
        responder_agent_type=responder_type,
        created_by=data.get("created_by", settings.self_play_created_by),
        title=data.get("title"),
    )


def _default_scenario(org_id: UUID) -> SelfPlayScenario:
    return SelfPlayScenario(
        id="baseline-discussion",
        org_id=org_id,
        challenger_prompt=(
            "You are the challenger agent. Present a structured hypothesis "
            "about a tenant's security posture. When you reach a conclusion, "
            "emit 'OUTCOME: SUCCESS' or 'OUTCOME: FAILURE'."
        ),
        responder_prompt=(
            "You are the responder agent. Critically evaluate the "
            "challenger's hypothesis. Refute or support with evidence, and "
            "conclude with an OUTCOME statement."
        ),
        max_turns=settings.self_play_max_turns,
        max_tool_calls=settings.self_play_max_tool_calls,
        metadata={
            "category": "baseline",
            "responder_template": (
                "{challenger_output}\n\nRespond with validation, "
                "counterpoints, and declare an OUTCOME when resolved."
            ),
        },
        challenger_agent_type=AgentType.SECURITY_ANALYST,
        responder_agent_type=AgentType.SECURITY_ANALYST,
        created_by=settings.self_play_created_by,
    )


async def load_scenarios(batch_size: int) -> list[SelfPlayScenario]:
    """Return a batch of scenarios ready for self-play execution."""

    org_id = await _resolve_default_org_id()
    if org_id is None:
        logger.warning(
            "self_play.no_org",
            message="No organization available for self-play",
        )
        return []

    configured: list[SelfPlayScenario] = []
    for entry in getattr(settings, "self_play_static_scenarios", []) or []:
        try:
            configured.append(_build_configured_scenario(entry, org_id))
        except ValueError as exc:
            logger.warning(
                "self_play.invalid_configured_scenario",
                error=str(exc),
                scenario=entry,
            )

    if not configured:
        configured.append(_default_scenario(org_id))

    limit = max(1, batch_size)
    return configured[:limit]
