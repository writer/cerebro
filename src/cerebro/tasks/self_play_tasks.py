"""Celery tasks that orchestrate self-play agent matches."""

from __future__ import annotations

import asyncio
from typing import Any, Dict

import structlog

from cerebro.agents.runtime_facade import AgentRuntimeFacade
from cerebro.agents.self_play.orchestrator import SelfPlayOrchestrator
from cerebro.agents.self_play.scenario_store import load_scenarios
from cerebro.core.config import settings

from .celery_app import celery_app

logger = structlog.get_logger(__name__)


async def run_self_play_batch_async() -> Dict[str, Any]:
    """Execute a batch of self-play matches using configured scenarios."""

    if not settings.self_play_enabled:
        logger.info("self_play.disabled")
        return {"matches_run": 0, "failures": 0, "reason": "disabled"}

    scenarios = await load_scenarios(settings.self_play_scenario_batch_size)
    if not scenarios:
        logger.info("self_play.no_scenarios")
        return {"matches_run": 0, "failures": 0, "reason": "empty"}

    orchestrator = SelfPlayOrchestrator(runtime_facade=AgentRuntimeFacade())

    matches = 0
    failures = 0
    backoff = 1.0
    max_backoff = float(settings.self_play_max_backoff_seconds)

    for scenario in scenarios:
        try:
            await orchestrator.run_match(scenario)
            matches += 1
            backoff = 1.0
        except Exception:  # pragma: no cover - defensive recovery
            failures += 1
            logger.exception("self_play.match_failed", scenario_id=scenario.id)
            await asyncio.sleep(min(backoff, max_backoff))
            backoff = min(backoff * 2, max_backoff)

    logger.info(
        "self_play.batch.complete",
        matches=matches,
        failures=failures,
        total=len(scenarios),
    )

    return {
        "matches_run": matches,
        "failures": failures,
        "total": len(scenarios),
    }


@celery_app.task(name="cerebro.tasks.self_play_tasks.run_self_play_batch")
def run_self_play_batch() -> Dict[str, Any]:
    """Celery task wrapper for the asynchronous batch runner."""

    return asyncio.run(run_self_play_batch_async())
