"""Additional stubs for claude_agent_sdk.types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class TextBlock:
    text: str
    annotations: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolUseBlock:
    id: str
    name: str
    input: Dict[str, Any]


@dataclass
class AssistantMessage:
    content: List[Any]
    finish_reason: Optional[str] = None


@dataclass
class SystemMessage:
    content: List[Any]


@dataclass
class ResultMessage:
    content: List[Any]


class ClaudeAgentError(Exception):
    """Generic error type used by the stub."""
