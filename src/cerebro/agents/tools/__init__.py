"""
Cerebro Agent Tools

Security-focused tools that provide Claude agents with safe, audited access to
Cerebro's security system capabilities. All tools implement strict guardrails,
CEL policy checks, and append-only audit logging.
"""

from .base import (
    Tool,
    StructuredTool,
    ToolRegistry,
    AgentContext,
    ToolExecutor,
    tool,
    ToolPermissionLevel,
)
from .findings_list import FindingsListTool
from .findings_update import FindingStatusUpdateTool
from .rules import RulesTool
from .query import QueryTool
from .timeline import TimelineTool
from .security_analysis import SecurityAnalysisTool
from .remediation import RemediationTool
from .smart_summarizer import SmartFindingSummarizerTool
from .org_context import GetOrgContextTool
from .system_context import GetSystemContextTool
from .session_memory import RememberContextTool, GetSessionHistoryTool
from .nl_query import NaturalLanguageQueryTool
from .benchmarks_status import BenchmarksStatusTool
from .orientation_summary import OrientationSummaryTool
from .automation_summary import TelemetryAutomationSummaryTool
from .security_self_service import SecuritySelfServiceTool

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
    "Tool",
    "StructuredTool",
    "ToolRegistry",
    "AgentContext",
    "ToolExecutor",
    "tool",
    "ToolPermissionLevel",
    "tool_registry",
    "FindingsListTool",
    "FindingStatusUpdateTool",
    "RulesTool",
    "QueryTool",
    "TimelineTool",
    "SecurityAnalysisTool",
    "RemediationTool",
    "SmartFindingSummarizerTool",
    "NaturalLanguageQueryTool",
    "GetOrgContextTool",
    "GetSystemContextTool",
    "RememberContextTool",
    "GetSessionHistoryTool",
    "BenchmarksStatusTool",
    "OrientationSummaryTool",
    "TelemetryAutomationSummaryTool",
    "SecuritySelfServiceTool",
    "get_tool_registry",
]
