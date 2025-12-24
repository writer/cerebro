"""Additional stubs for claude_agent_sdk.types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TextBlock:
    text: str
    annotations: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolUseBlock:
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class AssistantMessage:
    content: list[Any]
    finish_reason: str | None = None


@dataclass
class SystemMessage:
    content: list[Any]


@dataclass
class ResultMessage:
    content: list[Any]


class ClaudeAgentError(Exception):
    """Generic error type used by the stub."""
