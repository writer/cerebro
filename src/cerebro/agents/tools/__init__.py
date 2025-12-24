"""
Cerebro Agent Tools

Security-focused tools that provide Claude agents with safe, audited access to
Cerebro's security system capabilities. All tools implement strict guardrails,
CEL policy checks, and append-only audit logging.
"""

from .automation_summary import TelemetryAutomationSummaryTool
from .base import (
    AgentContext,
    StructuredTool,
    Tool,
    ToolExecutor,
    ToolPermissionLevel,
    ToolRegistry,
    tool,
)
from .benchmarks_status import BenchmarksStatusTool
from .findings_list import FindingsListTool
from .findings_update import FindingStatusUpdateTool
from .nl_query import NaturalLanguageQueryTool
from .org_context import GetOrgContextTool
from .orientation_summary import OrientationSummaryTool
from .query import QueryTool
from .remediation import RemediationTool
from .rules import RulesTool
from .security_analysis import SecurityAnalysisTool
from .security_self_service import SecuritySelfServiceTool
from .session_memory import GetSessionHistoryTool, RememberContextTool
from .smart_summarizer import SmartFindingSummarizerTool
from .system_context import GetSystemContextTool
from .timeline import TimelineTool

# Initialize the global tool registry
tool_registry = ToolRegistry()

# Register all available tools - split findings into separate tools
tool_registry.register(FindingsListTool())
tool_registry.register(FindingStatusUpdateTool())
tool_registry.register(QueryTool())
tool_registry.register(RulesTool())
tool_registry.register(TimelineTool())
tool_registry.register(SecurityAnalysisTool())
tool_registry.register(RemediationTool())
tool_registry.register(SmartFindingSummarizerTool())
tool_registry.register(NaturalLanguageQueryTool())
tool_registry.register(GetOrgContextTool())
tool_registry.register(GetSystemContextTool())
tool_registry.register(RememberContextTool())
tool_registry.register(GetSessionHistoryTool())
tool_registry.register(BenchmarksStatusTool())
tool_registry.register(OrientationSummaryTool())
tool_registry.register(TelemetryAutomationSummaryTool())
tool_registry.register(SecuritySelfServiceTool())


def get_tool_registry() -> ToolRegistry:
    """Return the shared tool registry instance."""

    return tool_registry


__all__ = [
    "AgentContext",
    "BenchmarksStatusTool",
    "FindingStatusUpdateTool",
    "FindingsListTool",
    "GetOrgContextTool",
    "GetSessionHistoryTool",
    "GetSystemContextTool",
    "NaturalLanguageQueryTool",
    "OrientationSummaryTool",
    "QueryTool",
    "RemediationTool",
    "RememberContextTool",
    "RulesTool",
    "SecurityAnalysisTool",
    "SecuritySelfServiceTool",
    "SmartFindingSummarizerTool",
    "StructuredTool",
    "TelemetryAutomationSummaryTool",
    "TimelineTool",
    "Tool",
    "ToolExecutor",
    "ToolPermissionLevel",
    "ToolRegistry",
    "get_tool_registry",
    "tool",
    "tool_registry",
]
