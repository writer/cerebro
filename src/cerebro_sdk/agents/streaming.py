"""Agent event streaming utilities mirroring the TypeScript SDK."""

from __future__ import annotations

import inspect
import json
from collections.abc import AsyncIterable, AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import (
    Any,
)

from cerebro_sdk.streaming import ServerSentEvent, parse_server_sent_events

AgentMessage = Mapping[str, Any]
ToolCallDelta = Mapping[str, Any]


@dataclass
class CompletionUpdate:
    status: str
    detail: str | None
    done: bool
    raw: Mapping[str, Any]


@dataclass
class AgentStreamEvent:
    type: str
    payload: Mapping[str, Any] | None
    raw: ServerSentEvent
    data: Any = None


MessageConsumer = Callable[
    [AgentMessage, AgentStreamEvent], Awaitable[None] | None
]
ToolConsumer = Callable[[ToolCallDelta, AgentStreamEvent], Awaitable[None] | None]
StatusConsumer = Callable[
    [CompletionUpdate, AgentStreamEvent], Awaitable[None] | None
]
HeartbeatConsumer = Callable[[AgentStreamEvent], Awaitable[None] | None]
UnknownConsumer = Callable[[AgentStreamEvent], Awaitable[None] | None]


@dataclass
class AgentStreamConsumers:
    on_message: MessageConsumer | None = None
    on_tool: ToolConsumer | None = None
    on_status: StatusConsumer | None = None
    on_heartbeat: HeartbeatConsumer | None = None
    on_unknown: UnknownConsumer | None = None


TERMINAL_STATUSES = {
    "completed",
    "complete",
    "done",
    "failed",
    "error",
    "errored",
    "canceled",
    "cancelled",
}


async def parse_agent_event_stream(
    stream: AsyncIterable[Any],
) -> AsyncIterator[AgentStreamEvent]:
    """Parse a stream of server-sent events into typed agent events."""

    async for event in parse_server_sent_events(stream):
        if not (event.event or event.data):
            yield AgentStreamEvent(type="heartbeat", payload=None, raw=event)
            continue

        payload = _parse_json(event.data)
        event_type = event.event

        if event_type == "message":
            if isinstance(payload, Mapping):
                yield AgentStreamEvent(type="message", payload=payload, raw=event)
            else:
                yield AgentStreamEvent(
                    type="unknown", payload=None, raw=event, data=payload
                )
        elif event_type == "tool":
            if isinstance(payload, Mapping):
                yield AgentStreamEvent(type="tool", payload=payload, raw=event)
            else:
                yield AgentStreamEvent(
                    type="unknown", payload=None, raw=event, data=payload
                )
        elif event_type == "status":
            if isinstance(payload, Mapping):
                yield AgentStreamEvent(type="status", payload=payload, raw=event)
            else:
                yield AgentStreamEvent(
                    type="unknown", payload=None, raw=event, data=payload
                )
        else:
            yield AgentStreamEvent(
                type="unknown", payload=None, raw=event, data=payload
            )


async def consume_agent_stream(
    stream: AsyncIterable[Any], consumers: AgentStreamConsumers | None = None
) -> None:
    """Consume an agent event stream, dispatching to registered consumers."""

    handlers = consumers or AgentStreamConsumers()
    async for event in parse_agent_event_stream(stream):
        if event.type == "message" and handlers.on_message:
            await _maybe_call(handlers.on_message, event.payload or {}, event)
        elif event.type == "tool" and handlers.on_tool:
            await _maybe_call(handlers.on_tool, event.payload or {}, event)
        elif event.type == "status" and handlers.on_status:
            update = to_completion_update(event.payload)
            await _maybe_call(handlers.on_status, update, event)
        elif event.type == "heartbeat" and handlers.on_heartbeat:
            await _maybe_call(handlers.on_heartbeat, event)
        else:
            if handlers.on_unknown:
                await _maybe_call(handlers.on_unknown, event)


@dataclass
class AgentStreamConsumption:
    messages: list[AgentMessage]
    tool_calls: list[ToolCallDelta]
    completions: list[CompletionUpdate]
    unknown: list[AgentStreamEvent]


async def collect_agent_stream(stream: AsyncIterable[Any]) -> AgentStreamConsumption:
    """Collect agent stream results into in-memory lists."""

    result = AgentStreamConsumption(
        messages=[], tool_calls=[], completions=[], unknown=[]
    )

    async def handle_message(message: AgentMessage, event: AgentStreamEvent) -> None:
        result.messages.append(message)

    async def handle_tool(delta: ToolCallDelta, event: AgentStreamEvent) -> None:
        result.tool_calls.append(delta)

    async def handle_status(update: CompletionUpdate, event: AgentStreamEvent) -> None:
        result.completions.append(update)

    async def handle_unknown(event: AgentStreamEvent) -> None:
        result.unknown.append(event)

    await consume_agent_stream(
        stream,
        AgentStreamConsumers(
            on_message=handle_message,
            on_tool=handle_tool,
            on_status=handle_status,
            on_unknown=handle_unknown,
        ),
    )

    return result


def to_completion_update(payload: Mapping[str, Any] | None) -> CompletionUpdate:
    data: Mapping[str, Any] = dict(payload or {})
    status = str(data.get("status", ""))
    detail = data.get("detail")
    if detail is not None and not isinstance(detail, str):
        detail = str(detail)
    done = status.lower() in TERMINAL_STATUSES
    return CompletionUpdate(status=status, detail=detail, done=done, raw=data)


def is_message_event(event: AgentStreamEvent) -> bool:
    return event.type == "message"


def is_tool_event(event: AgentStreamEvent) -> bool:
    return event.type == "tool"


def is_status_event(event: AgentStreamEvent) -> bool:
    return event.type == "status"


async def _maybe_call(
    fn: Callable[..., Awaitable[None] | None], *args: Any
) -> None:
    result = fn(*args)
    if inspect.isawaitable(result):
        await result


def _parse_json(value: str) -> Any:
    text = value.strip() if isinstance(value, str) else str(value)
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


__all__ = [
    "AgentMessage",
    "AgentStreamConsumers",
    "AgentStreamConsumption",
    "AgentStreamEvent",
    "CompletionUpdate",
    "ToolCallDelta",
    "collect_agent_stream",
    "consume_agent_stream",
    "is_message_event",
    "is_status_event",
    "is_tool_event",
    "parse_agent_event_stream",
    "to_completion_update",
]
