import type { SecurityResearchState } from "./research-state.js";
import { isResearchControlTool } from "./research-state.js";
import { isCodeModeInfrastructureTool } from "./tool-packs.js";
import { evaluateSecurityAgentToolCall, type SecurityAgentIntent } from "./tool-policy.js";
import { securityAgentToolMetadata, securityAgentToolMetadataIsExplicit } from "./tools/tool-metadata.js";
import { annotateMainPhase, incrementMain, telemetryEvent } from "../telemetry.js";

const OFFBOARDING_PREFLIGHT_TOOL = "cerebro_offboarding_preflight";
const REDUNDANT_AFTER_OFFBOARDING_PREFLIGHT = new Set([
  "cerebro_connector_catalog",
  "cerebro_connector_detail",
  "cerebro_connector_coverage",
  "cerebro_connector_activity",
  "cerebro_connector_credentials",
  "cerebro_connector_preflight",
  "cerebro_source_runtimes",
  "cerebro_runtime_health",
  "cerebro_offboarding_snapshot",
]);

interface SecurityAssistantToolHooksInput {
  allowedTools: Set<string>;
  additionalReadOnlyToolNames?: ReadonlySet<string>;
  inferredIntent: SecurityAgentIntent;
  maxResearchSteps: number;
  researchState: SecurityResearchState;
  researchTrail: string[];
  trustedOperator?: boolean;
}

export class SecurityAssistantToolHooks {
  count = 0;
  private selfImprovementSideEffectClaimed = false;
  private offboardingPreflightComplete = false;

  constructor(private readonly input: SecurityAssistantToolHooksInput) {}

  beforePi = async ({ toolCall }: { toolCall: { name: string } }): Promise<{ block: true; reason?: string } | undefined> => {
    const reason = this.blockReason(toolCall.name, "before_tool_call");
    return reason ? { block: true, reason } : undefined;
  };

  beforeFlue = (toolName: string): void => {
    const reason = this.blockReason(toolName, "flue_before_tool_call");
    if (reason) throw new Error(reason);
  };

  beforeCodeMode = (toolName: string): void => {
    const reason = this.blockReason(toolName, "code_mode_before_tool_call");
    if (reason) throw new Error(reason);
  };

  afterPi = async ({ toolCall, isError }: { toolCall: { name: string }; isError: boolean }): Promise<undefined> => {
    this.recordResult(toolCall.name, isError);
    return undefined;
  };

  afterFlue = (toolName: string, isError: boolean): void => {
    this.recordResult(toolName, isError);
  };

  afterCodeMode = (toolName: string, isError: boolean): void => {
    this.recordResult(toolName, isError);
  };

  private blockReason(toolName: string, operation: string): string | undefined {
    if (!this.input.allowedTools.has(toolName)) {
      this.blocked(toolName, operation, "not_available");
      return `Tool ${toolName} is not available to the Slack security assistant.`;
    }
    if (!securityAgentToolMetadataIsExplicit(toolName) && !this.input.additionalReadOnlyToolNames?.has(toolName)) {
      this.blocked(toolName, operation, "authority_metadata_required");
      return `Tool ${toolName} is unavailable until its host authority metadata is registered.`;
    }
    if (isCodeModeInfrastructureTool(toolName)) {
      if (!this.input.researchState.hasPlan()) {
        this.blocked(toolName, operation, "research_plan_required");
        return `Call operator_research_plan before ${toolName}, then continue with the planned checks.`;
      }
      if (this.input.researchState.adaptivePlan().executionStyle !== "code") {
        this.blocked(toolName, operation, "execution_style_mismatch");
        return `${toolName} is available only when operator_research_plan selects execution_style=code.`;
      }
      return undefined;
    }
    const policy = evaluateSecurityAgentToolCall(toolName, this.input.inferredIntent);
    if (!policy.allowed) {
      this.blocked(toolName, operation, "policy", { "tool.policy.tier": policy.policy.tier });
      return policy.reason;
    }
    if (!isResearchControlTool(toolName) && !this.input.researchState.hasPlan()) {
      this.blocked(toolName, operation, "research_plan_required");
      return `Call operator_research_plan before ${toolName}, then continue with the planned evidence checks.`;
    }
    if (isResearchControlTool(toolName)) return undefined;

    if (this.offboardingPreflightComplete && REDUNDANT_AFTER_OFFBOARDING_PREFLIGHT.has(toolName)) {
      this.blocked(toolName, operation, "offboarding_preflight_authoritative");
      return `${OFFBOARDING_PREFLIGHT_TOOL} already completed successfully in this answer. Treat its provider attestation as authoritative and synthesize from it; do not call ${toolName}.`;
    }

    const executionStyle = this.input.researchState.adaptivePlan().executionStyle;
    const nestedCodeModeCall = operation === "code_mode_before_tool_call";
    if (executionStyle === "code" && !nestedCodeModeCall) {
      this.blocked(toolName, operation, "execution_style_mismatch");
      return `${toolName} must run through cerebro_execute because the current research plan selected execution_style=code.`;
    }
    if (executionStyle === "direct" && nestedCodeModeCall) {
      this.blocked(toolName, operation, "execution_style_mismatch");
      return `${toolName} must run directly because the current research plan selected execution_style=direct.`;
    }

    if (!this.input.researchState.toolAllowedByPlan(toolName)) {
      this.blocked(toolName, operation, "outside_selected_tool_pack");
      return `${toolName} is outside the current model-selected tool pack. Update operator_research_plan with this tool before calling it.`;
    }

    const turnFailures = this.input.researchState.toolFailureCount(toolName);
    if (turnFailures >= 2) {
      this.blocked(toolName, operation, "turn_failure_circuit", {
        "tool.turn_failure_count": turnFailures,
      });
      return `${toolName} failed ${turnFailures} times in this answer. Choose another planned source or return the bounded blocker from the recorded failures.`;
    }

    const sourceHealth = this.input.researchState.sourceHealthSnapshot(toolName);
    if (!sourceHealth.allowed) {
      this.blocked(toolName, operation, "source_cooldown", {
        "tool.source_health.status": sourceHealth.status,
        "tool.source_health.consecutive_failures": sourceHealth.consecutive_failures,
        "tool.source_health.retry_after_ms": sourceHealth.retry_after_ms,
      });
      return `${toolName} is temporarily unavailable after ${sourceHealth.consecutive_failures} consecutive failures. Choose another planned source or update the research plan; retry after ${formatRetry(sourceHealth.retry_after_ms)}.`;
    }

    const nextCount = this.count + 1;
    if (nextCount > this.input.maxResearchSteps) {
      this.count = nextCount;
      this.blocked(toolName, operation, "max_research_steps", { "gen_ai.tool.count": this.count });
      return `Research step limit ${this.input.maxResearchSteps} reached. Return the best answer from current evidence.`;
    }

    const metadata = securityAgentToolMetadata(toolName);
    if (this.input.inferredIntent === "self_improvement" && metadata.sideEffect !== "none") {
      if (!this.input.trustedOperator) {
        this.blocked(toolName, operation, "trusted_operator_required", { "tool.policy.tier": policy.policy.tier });
        return `${toolName} can submit a self-improvement candidate only for a configured Slack operator.`;
      }
      if (this.selfImprovementSideEffectClaimed) {
        this.blocked(toolName, operation, "self_improvement_side_effect_limit", { "tool.policy.tier": policy.policy.tier });
        return "This self-improvement turn already used its one side effect. Verify the existing candidate instead of starting another write.";
      }
      this.selfImprovementSideEffectClaimed = true;
    }

    this.count = nextCount;
    incrementMain("gen_ai.tool.request.count", 1);
    annotateMainPhase(`assistant.tool.${toolName}`, "queued", { "tool.last_name": toolName });
    return undefined;
  }

  private recordResult(toolName: string, isError: boolean): void {
    if (isResearchControlTool(toolName) || isCodeModeInfrastructureTool(toolName)) return;
    const failed = isError || this.input.researchState.lastToolFailed(toolName);
    if (toolName === OFFBOARDING_PREFLIGHT_TOOL && !failed) this.offboardingPreflightComplete = true;
    this.input.researchTrail.push(`${toolName}: ${failed ? "failed" : "checked"}`);
    annotateMainPhase(`assistant.tool.${toolName}`, failed ? "failed" : "completed", { "tool.last_name": toolName });
    if (failed) incrementMain("gen_ai.tool.error.count", 1);
  }

  private blocked(toolName: string, operation: string, reason: string, extra: Record<string, unknown> = {}): void {
    telemetryEvent("assistant.tool.blocked", {
      component: "security-assistant",
      operation,
      "tool.name": toolName,
      "tool.block.reason": reason,
      "assistant.intent": this.input.inferredIntent,
      ...extra,
    });
  }
}

function formatRetry(retryAfterMs: number | undefined): string {
  const seconds = Math.max(1, Math.ceil((retryAfterMs ?? 0) / 1000));
  return seconds >= 60 ? `${Math.ceil(seconds / 60)} minutes` : `${seconds} seconds`;
}
