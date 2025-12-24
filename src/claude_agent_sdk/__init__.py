"""Test stub for claude_agent_sdk dependency."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ClaudeAgentOptions:
    model: str = "claude-stub"
    temperature: float = 0.2
    max_tokens: int = 2048
    system_prompt: str | None = None
    mcp_servers: dict[str, Any] = field(default_factory=dict)
    allowed_tools: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class _StubMCPServer(dict):
    """Lightweight stand-in for SDK MCP servers."""


class CLINotFoundError(RuntimeError):
    """Stubbed exception raised when the Claude CLI is missing."""


class ClaudeSDKClient:
    """Minimal stub implementation used for tests."""

    def __init__(
        self,
        api_key: str | None = None,
        options: ClaudeAgentOptions | None = None,
        **kwargs: Any,
    ):  # pragma: no cover
        self.api_key = api_key
        self.options = options or ClaudeAgentOptions()
        self.kwargs = kwargs
        self._messages: list[str] = []

    async def __aenter__(self):  # pragma: no cover
        return self

    async def __aexit__(self, exc_type, exc, tb):  # pragma: no cover
        return False

    async def connect(self):  # pragma: no cover
        raise CLINotFoundError("Claude CLI not available in test environment")

    async def query(
        self, message: str, session_id: str | None = None
    ):  # pragma: no cover
        self._messages.append(message)
        return {"session_id": session_id, "message": message}

    async def receive_messages(self) -> AsyncIterator[Any]:  # pragma: no cover
        if False:
            yield None
        return

    async def create_session(
        self, options: ClaudeAgentOptions, **kwargs: Any
    ) -> dict[str, Any]:  # pragma: no cover
        return {
            "session_id": "stub-session",
            "options": options,
            "metadata": kwargs,
        }


def tool(name: str, description: str, input_schema: dict[str, Any]):
    """Decorator factory mimicking the SDK's tool decorator."""

    def decorator(func):
        func._claude_tool_metadata = {  # type: ignore[attr-defined]
            "name": name,
            "description": description,
            "input_schema": input_schema,
        }
        return func

    return decorator


def create_sdk_mcp_server(name: str, version: str, tools: list[Any]) -> _StubMCPServer:
    return _StubMCPServer(name=name, version=version, tools=tools)


__all__ = [
    "CLINotFoundError",
    "ClaudeAgentOptions",
    "ClaudeSDKClient",
    "create_sdk_mcp_server",
    "tool",
]
