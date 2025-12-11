"""Server-sent event utilities for the Cerebro SDK."""

from __future__ import annotations

from dataclasses import dataclass
from typing import AsyncIterable, AsyncIterator, Optional, Union

SSEChunk = Union[str, bytes, bytearray]


@dataclass
class ServerSentEvent:
    """Represents a parsed server-sent event."""

    event: Optional[str]
    data: str
    id: Optional[str] = None
    retry: Optional[int] = None
    raw: str = ""


async def parse_server_sent_events(source: AsyncIterable[SSEChunk]) -> AsyncIterator[ServerSentEvent]:
    """Parse an async iterable of SSE chunks into structured events."""

    buffer = ""
    async for chunk in source:
        text = _coerce_to_text(chunk)
        if not text:
            continue
        buffer += text
        while True:
            separator = _find_separator(buffer)
            if separator is None:
                break
            block = buffer[:separator]
            buffer = buffer[separator + 2 :]
            event = _parse_event_block(block)
            if event is not None:
                yield event

    if buffer.strip():
        event = _parse_event_block(buffer)
        if event is not None:
            yield event


def to_server_sent_event_iterator(source: AsyncIterable[SSEChunk]) -> AsyncIterator[ServerSentEvent]:
    """Helper alias mirroring the TypeScript SDK naming."""

    return parse_server_sent_events(source)


def _find_separator(buffer: str) -> Optional[int]:
    idx = buffer.find("\n\n")
    if idx == -1:
        idx = buffer.find("\r\n\r\n")
    return idx if idx != -1 else None


def _coerce_to_text(chunk: SSEChunk) -> str:
    if isinstance(chunk, str):
        return chunk
    if isinstance(chunk, (bytes, bytearray)):
        return chunk.decode("utf-8", errors="replace")
    return str(chunk)


def _parse_event_block(block: str) -> Optional[ServerSentEvent]:
    if not block:
        return None

    lines = _normalize_newlines(block).split("\n")
    data_lines: list[str] = []
    event: Optional[str] = None
    event_id: Optional[str] = None
    retry: Optional[int] = None

    for line in lines:
        if not line or line.startswith(":"):
            continue

        field, value = _split_field(line)
        if field == "event":
            event = value or None
        elif field == "data":
            data_lines.append(value)
        elif field == "id":
            event_id = value or None
        elif field == "retry":
            try:
                retry = int(value)
            except (TypeError, ValueError):
                retry = None

    data = "\n".join(data_lines)
    return ServerSentEvent(event=event, data=data, id=event_id, retry=retry, raw=block)


def _split_field(line: str) -> tuple[str, str]:
    if ":" not in line:
        return line.strip(), ""
    field, value = line.split(":", 1)
    return field.strip(), value.lstrip(" ")


def _normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


__all__ = [
    "ServerSentEvent",
    "parse_server_sent_events",
    "to_server_sent_event_iterator",
]
