from __future__ import annotations

from uuid import uuid4

import pytest

from cerebro.agents.self_play.scenario_store import load_scenarios
from cerebro.core.config import settings


@pytest.mark.asyncio
async def test_load_scenarios_uses_configured_entries(monkeypatch) -> None:
    org_id = uuid4()

    async def _mock_resolve() -> uuid4:
        return org_id

    monkeypatch.setattr(
        "cerebro.agents.self_play.scenario_store._resolve_default_org_id",
        _mock_resolve,
    )
    monkeypatch.setattr(
        settings,
        "self_play_static_scenarios",
        [
            {
                "id": "configured",
                "challenger_prompt": "C",
                "responder_prompt": "R",
                "max_turns": 7,
                "max_tool_calls": 9,
                "challenger_agent_type": "identity_advisor",
                "responder_agent_type": "incident_responder",
                "metadata": {"foo": "bar"},
                "created_by": "tester",
                "title": "Custom scenario",
            }
        ],
        raising=False,
    )

    scenarios = await load_scenarios(batch_size=2)

    assert len(scenarios) == 1
    scenario = scenarios[0]
    assert scenario.id == "configured"
    assert scenario.org_id == org_id
    assert scenario.max_turns == 7
    assert scenario.max_tool_calls == 9
    assert scenario.challenger_agent_type.value == "identity_advisor"
    assert scenario.responder_agent_type.value == "incident_responder"
    assert scenario.metadata == {"foo": "bar"}
    assert scenario.created_by == "tester"
    assert scenario.title == "Custom scenario"


@pytest.mark.asyncio
async def test_load_scenarios_invalid_config_falls_back(monkeypatch) -> None:
    org_id = uuid4()

    async def _mock_resolve() -> uuid4:
        return org_id

    monkeypatch.setattr(
        "cerebro.agents.self_play.scenario_store._resolve_default_org_id",
        _mock_resolve,
    )
    monkeypatch.setattr(
        settings,
        "self_play_static_scenarios",
        [{"challenger_prompt": "missing id", "responder_prompt": "R"}],
        raising=False,
    )

    scenarios = await load_scenarios(batch_size=1)

    assert len(scenarios) == 1
    assert scenarios[0].id == "baseline-discussion"
