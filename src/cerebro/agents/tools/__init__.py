"""
Cerebro Agent Tools

Security-focused tools that provide Claude agents with safe, audited access to
Cerebro's security system capabilities. All tools implement strict guardrails,
CEL policy checks, and append-only audit logging.
"""

from .base import Tool, ToolRegistry, AgentContext, ToolExecutor, tool, ToolPermissionLevel
from .findings_list import FindingsListTool
from .findings_update import FindingStatusUpdateTool
from .rules import RulesTool
from .query import QueryTool
from .timeline import TimelineTool
from .security_analysis import SecurityAnalysisTool
from .remediation import RemediationTool
from .forensic_replay import ForensicReplayTool, ChangeReplayTool
from .attack_path import AttackPathSimulatorTool, BlastRadiusTool
from .smart_summarizer import SmartFindingSummarizerTool
from .compliance_tester import ComplianceControlTesterTool, EvidenceBundleBuilderTool

# Initialize the global tool registry
tool_registry = ToolRegistry()

# Register all available tools - split findings into separate tools
tool_registry.register(FindingsListTool())
tool_registry.register(FindingStatusUpdateTool())
tool_registry.register(RulesTool())
tool_registry.register(QueryTool())
tool_registry.register(TimelineTool())
tool_registry.register(SecurityAnalysisTool())
tool_registry.register(RemediationTool())
tool_registry.register(ForensicReplayTool())
tool_registry.register(ChangeReplayTool())
tool_registry.register(AttackPathSimulatorTool())
tool_registry.register(BlastRadiusTool())
tool_registry.register(SmartFindingSummarizerTool())
tool_registry.register(ComplianceControlTesterTool())
tool_registry.register(EvidenceBundleBuilderTool())

__all__ = [
    "Tool",
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
    "ForensicReplayTool",
    "ChangeReplayTool",
    "AttackPathSimulatorTool",
    "BlastRadiusTool",
    "SmartFindingSummarizerTool",
    "ComplianceControlTesterTool",
    "EvidenceBundleBuilderTool",
]
