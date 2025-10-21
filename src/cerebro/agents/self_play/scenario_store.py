"""Temporary scenario store feeding self-play orchestrator batches."""

from __future__ import annotations

from typing import List
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
            select(Organization.org_id)
            .order_by(Organization.created_at.asc())
            .limit(1)
        )
        return result.scalar_one_or_none()


async def load_scenarios(batch_size: int) -> List[SelfPlayScenario]:
    """Return a batch of scenarios ready for self-play execution."""

    org_id = await _resolve_default_org_id()
    if org_id is None:
        logger.warning(
            "self_play.no_org",
            message="No organization available for self-play",
        )
        return []

    scenario = SelfPlayScenario(
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

    return [scenario][: batch_size or 1]
