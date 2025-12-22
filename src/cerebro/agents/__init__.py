"""
Cerebro Agents Module

This module provides Claude Code SDK-powered security agents that integrate deeply with
Cerebro's security system of record. The agents leverage Cerebro's append-only audit trails,
CEL rule engine, and multi-provider integrations to provide intelligent security analysis
and incident response capabilities.

Key Components:
- Runtime: Claude SDK integration with streaming and tool calling
- Tools: Security-focused tools that interact with Cerebro APIs and provider services
- Models: SQLAlchemy models for agent sessions, messages, and audit trails
- Service: High-level orchestration and session management
- API: FastAPI endpoints for agent interactions
"""

from .runtime import CerebroClaudeRuntime
from .service import AgentSessionService
from .models import AgentSession, AgentMessage, ToolInvocation
from .self_play import SelfPlayOrchestrator, SelfPlayScenario

__all__ = [
    "CerebroClaudeRuntime",
    "AgentSessionService",
    "AgentSession",
    "AgentMessage",
    "ToolInvocation",
    "SelfPlayOrchestrator",
    "SelfPlayScenario",
]
