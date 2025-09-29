"""
Cerebro Agent Tools

Security-focused tools that provide Claude agents with safe, audited access to
Cerebro's security system capabilities. All tools implement strict guardrails,
CEL policy checks, and append-only audit logging.
"""

from .base import Tool, ToolRegistry, AgentContext, ToolExecutor, tool
from .findings import FindingsTool
from .rules import RulesTool  
from .query import QueryTool
from .timeline import TimelineTool

# Initialize the global tool registry
tool_registry = ToolRegistry()

# Register all available tools
tool_registry.register(FindingsTool())
tool_registry.register(RulesTool())
tool_registry.register(QueryTool())
tool_registry.register(TimelineTool())

__all__ = [
    "Tool",
    "ToolRegistry", 
    "AgentContext",
    "ToolExecutor",
    "tool",
    "tool_registry",
    "FindingsTool",
    "RulesTool",
    "QueryTool", 
    "TimelineTool",
]
