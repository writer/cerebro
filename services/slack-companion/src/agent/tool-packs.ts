import type { AgentTool } from "@earendil-works/pi-agent-core";
import { createCodeModeTools } from "./code-mode/index.js";
import {
  ACTION_SIMULATION_TOOL,
  ATTENTION_DECISION_TOOL,
  CLAIM_LEDGER_TOOL,
  DECISION_LEDGER_TOOL,
  HYPOTHESIS_LEDGER_TOOL,
  RESEARCH_PLAN_TOOL,
  WORKFLOW_COMPILE_TOOL,
  WORLD_STATE_TOOL,
  type AssistantExecutionStyle,
} from "./research-state.js";
import type { AssistantExecutionLane, SecurityDomainLens } from "./operational-intelligence.js";
import type { SecurityAssistantToolHooks } from "./security-assistant-tool-hooks.js";
import type { AppConfig } from "../config/index.js";

const MAX_SELECTED_EVIDENCE_TOOLS = 12;

export interface AdaptiveToolPlan {
  executionLane: AssistantExecutionLane;
  domainLenses: SecurityDomainLens[];
  selectedTools: string[];
  sourceCandidates: string[];
}

export interface NamedTool {
  name: string;
}

export const CODE_MODE_TOOL_NAMES = new Set(["cerebro_tool_search", "cerebro_execute"]);

export function isCodeModeInfrastructureTool(toolName: string): boolean {
  return CODE_MODE_TOOL_NAMES.has(toolName);
}

export function createAssistantCodeModeTools(
  config: AppConfig,
  baseTools: AgentTool[],
  hooks: SecurityAssistantToolHooks,
  additionalReadOnlyToolNames?: ReadonlySet<string>,
): AgentTool[] {
  const codeMode = config.codeMode;
  if (!codeMode?.enabled) return [];
  return createCodeModeTools({
    baseTools,
    additionalReadOnlyToolNames,
    beforeToolCall: hooks.beforeCodeMode,
    afterToolCall: hooks.afterCodeMode,
    maxToolCalls: Math.min(codeMode.maxToolCalls, config.triage.maxResearchSteps),
    maxSideEffectCalls: codeMode.maxSideEffectCalls,
    timeoutMs: Math.min(codeMode.timeoutMs, config.triage.timeoutMs),
    memoryLimitBytes: codeMode.memoryLimitBytes,
    maxScriptBytes: codeMode.maxScriptBytes,
    maxOutputBytes: codeMode.maxOutputBytes,
    allowedToolNames: () => new Set(baseTools.map((tool) => tool.name)),
  });
}

export function selectExecutionToolPack<T extends NamedTool>(
  directTools: T[],
  codeTools: T[],
  plan: AdaptiveToolPlan & { executionStyle: AssistantExecutionStyle },
): { executionStyle: AssistantExecutionStyle; tools: T[] } {
  if (plan.executionStyle === "code" && codeTools.length > 0) {
    return { executionStyle: "code", tools: codeTools };
  }
  return {
    executionStyle: "direct",
    tools: selectAdaptiveToolPack(directTools, plan),
  };
}

export function selectAdaptiveToolPack<T extends NamedTool>(tools: T[], plan: AdaptiveToolPlan): T[] {
  if (plan.executionLane === "converse" || plan.executionLane === "continue" || plan.executionLane === "ignore") return [];
  const available = new Set(tools.map((tool) => tool.name));
  const requested = [...new Set([...plan.selectedTools, ...plan.sourceCandidates])]
    .filter((name) => available.has(name) && !CONTROL_TOOL_NAMES.has(name))
    .slice(0, MAX_SELECTED_EVIDENCE_TOOLS);
  if (requested.length === 0) return tools;
  const allowed = new Set([...CONTROL_TOOL_NAMES, ...requested]);
  return tools.filter((tool) => allowed.has(tool.name));
}

export function toolPackTelemetry<T extends NamedTool>(allTools: T[], selectedTools: T[], plan: AdaptiveToolPlan): Record<string, number | string> {
  return {
    "assistant.tool_pack.available_count": allTools.length,
    "assistant.tool_pack.selected_count": selectedTools.length,
    "assistant.tool_pack.execution_lane": plan.executionLane,
    "assistant.tool_pack.domain_lenses": plan.domainLenses.join(","),
  };
}

export const CONTROL_TOOL_NAMES = new Set([
  RESEARCH_PLAN_TOOL,
  CLAIM_LEDGER_TOOL,
  WORLD_STATE_TOOL,
  HYPOTHESIS_LEDGER_TOOL,
  DECISION_LEDGER_TOOL,
  WORKFLOW_COMPILE_TOOL,
  ACTION_SIMULATION_TOOL,
  ATTENTION_DECISION_TOOL,
  "operator_tool_catalog_search",
  "operator_mission_compile",
  "operator_agent_run_status",
  "operator_agent_run_step_bind",
  "operator_agent_run_step_decide",
]);
