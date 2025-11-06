from __future__ import annotations

from dataclasses import dataclass
from typing import Any, AsyncIterator, List

import pytest

from cerebro_sdk.agents.streaming import (
    AgentStreamConsumers,
    AgentStreamEvent,
    collect_agent_stream,
    consume_agent_stream,
    parse_agent_event_stream,
)


@dataclass
class _Stream:
    payload: str

    def __post_init__(self) -> None:
        self._sent = False

    def __aiter__(self) -> AsyncIterator[bytes]:  # type: ignore[override]
        return self._iterate()

    async def _iterate(self) -> AsyncIterator[bytes]:
        if not self._sent:
            self._sent = True
            yield self.payload.encode("utf-8")


def _make_stream(lines: List[str]) -> _Stream:
    return _Stream("".join(lines))


@pytest.mark.asyncio()
async def test_parse_agent_event_stream_emits_typed_events() -> None:
    stream = _make_stream(
        [
            "event: message\n",
            'data: {"message_id":"m1","role":"assistant","content":"Hi"}\n\n',
            "event: status\n",
            'data: {"status":"completed"}\n\n',
        ]
    )

    events: list[AgentStreamEvent] = []
    async for event in parse_agent_event_stream(stream):
        events.append(event)

    assert len(events) == 2
    assert events[0].type == "message"
    assert events[0].payload and events[0].payload["content"] == "Hi"
    assert events[1].type == "status"
    assert events[1].payload and events[1].payload["status"] == "completed"


@pytest.mark.asyncio()
async def test_consume_agent_stream_dispatches_consumers() -> None:
    stream = _make_stream(
        [
            "event: tool\n",
            'data: {"invocation_id":"tool-1","status":"running"}\n\n',
            "event: status\n",
            'data: {"status":"completed","detail":"Done"}\n\n',
        ]
    )

    tool_calls: list[str] = []
    completions: list[str] = []

    async def handle_tool(delta: Any, event: AgentStreamEvent) -> None:
        tool_calls.append(delta.get("invocation_id"))

    async def handle_status(update: Any, event: AgentStreamEvent) -> None:
        completions.append(update.detail or "")

    await consume_agent_stream(
        stream,
        AgentStreamConsumers(on_tool=handle_tool, on_status=handle_status),
    )

    assert tool_calls == ["tool-1"]
    assert completions == ["Done"]


@pytest.mark.asyncio()
async def test_collect_agent_stream_accumulates_events() -> None:
    stream = _make_stream(
        [
            "event: message\n",
            'data: {"message_id":"m1","role":"assistant","content":"Hello"}\n\n',
            "event: tool\n",
            'data: {"invocation_id":"tool-1","status":"completed"}\n\n',
            "event: status\n",
            'data: {"status":"completed"}\n\n',
        ]
    )

    snapshot = await collect_agent_stream(stream)

    assert len(snapshot.messages) == 1
    assert snapshot.messages[0]["content"] == "Hello"
    assert len(snapshot.tool_calls) == 1
    assert snapshot.tool_calls[0]["invocation_id"] == "tool-1"
    assert any(update.done for update in snapshot.completions)
    assert snapshot.unknown == []
