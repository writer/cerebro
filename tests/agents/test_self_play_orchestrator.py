from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Dict, List
from uuid import UUID, uuid4

import pytest

from cerebro.agents.models import AgentType, MessageRole
from cerebro.agents.self_play import SelfPlayOrchestrator, SelfPlayScenario


class _AnalyticsStub:
    events: List[Dict[str, Any]] = []

    @staticmethod
    async def record_event(
        *,
        org_id: UUID,
        session_id: UUID,
        event_type: str,
        payload: Dict[str, Any],
    ) -> None:
        _AnalyticsStub.events.append(
            {"event_type": event_type, "payload": payload}
        )

    @classmethod
    def reset(cls) -> None:
        cls.events.clear()


class _RuntimeFacadeStub:
    def __init__(self, scripted_responses: Dict[str, List[Dict[str, Any]]]):
        self._scripted = {
            role: list(responses)
            for role, responses in scripted_responses.items()
        }
        self._history: Dict[UUID, List[Dict[str, Any]]] = {}

    async def create_session(
        self,
        *,
        org_id: UUID,
        agent_type: AgentType,
        created_by: str,
        context: Dict[str, Any],
        title: str | None = None,
    ) -> SimpleNamespace:
        session = SimpleNamespace(
            id=uuid4(),
            org_id=org_id,
            agent_type=agent_type,
            context=dict(context),
            title=title,
        )
        self._history[session.id] = []
        session.context.setdefault("self_play_role", "unknown")
        return session

    async def send_message(
        self,
        *,
        session: SimpleNamespace,
        message: str,
        user_id: str,
        stream: bool,
    ):
        role = session.context.get("self_play_role")
        scripted_list = self._scripted[str(role)]
        scripted = scripted_list.pop(0)

        assistant_record = {
            "role": MessageRole.ASSISTANT,
            "content": {
                "content": scripted.get(
                    "blocks",
                    [{"type": "text", "text": scripted["text"]}],
                ),
                "tool_calls": scripted.get(
                    "tool_calls",
                    len(scripted.get("blocks", [])),
                ),
                "token_usage": scripted.get("token_usage", {}),
            },
            "created_at": datetime.now(timezone.utc).isoformat(),
            "input_tokens": scripted.get("token_usage", {}).get(
                "input_tokens"
            ),
            "output_tokens": scripted.get("token_usage", {}).get(
                "output_tokens"
            ),
        }
        self._history[session.id].insert(0, assistant_record)

        if stream:
            yield {"type": "text", "content": scripted["text"]}

    async def get_session_messages(
        self,
        session: SimpleNamespace,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        return list(self._history[session.id])[:limit]


class _SettingsStub:
    self_play_enabled = True
    self_play_stream_responses = True
    self_play_persist_results = False
    self_play_created_by = "self_play_test"


@pytest.mark.asyncio
async def test_run_match_detects_outcome_completion() -> None:
    _AnalyticsStub.reset()
    org_id = uuid4()
    scenario = SelfPlayScenario(
        id="test-scenario",
        org_id=org_id,
        challenger_prompt="Start",
        responder_prompt="Respond",
        max_turns=4,
        max_tool_calls=5,
        challenger_agent_type=AgentType.SECURITY_ANALYST,
        responder_agent_type=AgentType.SECURITY_ANALYST,
    )

    responses = {
        "challenger": [
            {
                "text": "Hypothesis about exposure",
                "token_usage": {"input_tokens": 10, "output_tokens": 20},
            }
        ],
        "responder": [
            {
                "text": "Verified and agreed. OUTCOME: SUCCESS",
                "token_usage": {"input_tokens": 5, "output_tokens": 15},
            }
        ],
    }

    facade = _RuntimeFacadeStub(scripted_responses=responses)
    orchestrator = SelfPlayOrchestrator(
        runtime_facade=facade,
        analytics=_AnalyticsStub,
        config=_SettingsStub(),
    )

    result = await orchestrator.run_match(scenario)

    assert result.success is True
    assert result.turns == 2
    assert any(
        evt["event_type"] == "self_play_match_completed"
        for evt in _AnalyticsStub.events
    )


@pytest.mark.asyncio
async def test_run_match_respects_tool_call_limit() -> None:
    _AnalyticsStub.reset()
    org_id = uuid4()
    tool_block = {
        "type": "tool_use",
        "tool_name": "scan",
        "input": {"target": "resource"},
        "tool_call_id": "1",
    }
    scenario = SelfPlayScenario(
        id="tool-limit",
        org_id=org_id,
        challenger_prompt="Start",
        responder_prompt="Respond",
        max_turns=5,
        max_tool_calls=1,
        challenger_agent_type=AgentType.SECURITY_ANALYST,
        responder_agent_type=AgentType.SECURITY_ANALYST,
    )

    responses = {
        "challenger": [
            {
                "text": "Invoking scan",
                "blocks": [tool_block],
                "tool_calls": 1,
                "token_usage": {"input_tokens": 3, "output_tokens": 7},
            }
        ],
        "responder": [],
    }

    facade = _RuntimeFacadeStub(scripted_responses=responses)
    orchestrator = SelfPlayOrchestrator(
        runtime_facade=facade,
        analytics=_AnalyticsStub,
        config=_SettingsStub(),
    )

    result = await orchestrator.run_match(scenario)

    assert result.success is False
    assert result.tool_calls == 1
    assert result.fail_reason == "max_tool_calls"
    assert result.turns == 1


@pytest.mark.asyncio
async def test_run_match_respects_disabled_flag() -> None:
    _AnalyticsStub.reset()

    class _DisabledConfig(_SettingsStub):
        self_play_enabled = False

    class _FailingRuntime:
        async def create_session(self, *args, **kwargs):
            raise AssertionError(
                "create_session should not be called when disabled"
            )

    scenario = SelfPlayScenario(
        id="disabled",
        org_id=uuid4(),
        challenger_prompt="Start",
        responder_prompt="Respond",
        max_turns=2,
        max_tool_calls=2,
        challenger_agent_type=AgentType.SECURITY_ANALYST,
        responder_agent_type=AgentType.SECURITY_ANALYST,
    )

    orchestrator = SelfPlayOrchestrator(
        runtime_facade=_FailingRuntime(),
        analytics=_AnalyticsStub,
        config=_DisabledConfig(),
    )

    result = await orchestrator.run_match(scenario)

    assert result.success is False
    assert result.fail_reason == "self_play_disabled"
    assert result.turns == 0
    assert not _AnalyticsStub.events
