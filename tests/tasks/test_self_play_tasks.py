from __future__ import annotations

from uuid import uuid4

import pytest

from cerebro.agents.models import AgentType
from cerebro.agents.self_play import SelfPlayScenario
from cerebro.tasks.self_play_tasks import run_self_play_batch_async


@pytest.mark.asyncio
async def test_run_self_play_batch_async_executes_scenarios(monkeypatch):
    executed: list[str] = []

    async def _load_scenarios(batch_size: int):
        return [
            SelfPlayScenario(
                id="scenario-1",
                org_id=uuid4(),
                challenger_prompt="Start",
                responder_prompt="Respond",
                max_turns=2,
                max_tool_calls=4,
                challenger_agent_type=AgentType.SECURITY_ANALYST,
                responder_agent_type=AgentType.SECURITY_ANALYST,
            )
        ]

    class _OrchestratorStub:
        def __init__(self, *args, **kwargs):
            pass

        async def run_match(self, scenario: SelfPlayScenario):
            executed.append(scenario.id)

    monkeypatch.setattr(
        "cerebro.tasks.self_play_tasks.settings.self_play.self_play_enabled",
        True,
        raising=False,
    )

    monkeypatch.setattr(
        "cerebro.tasks.self_play_tasks.load_scenarios",
        _load_scenarios,
    )
    monkeypatch.setattr(
        "cerebro.tasks.self_play_tasks.SelfPlayOrchestrator",
        _OrchestratorStub,
    )

    result = await run_self_play_batch_async()

    assert result["matches_run"] == 1
    assert executed == ["scenario-1"]


@pytest.mark.asyncio
async def test_run_self_play_batch_async_disabled(monkeypatch):
    monkeypatch.setattr(
        "cerebro.tasks.self_play_tasks.settings.self_play.self_play_enabled",
        False,
        raising=False,
    )

    result = await run_self_play_batch_async()

    assert result["matches_run"] == 0
    assert result["reason"] == "disabled"
