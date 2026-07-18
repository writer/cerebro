import { randomUUID } from "node:crypto";
import type { AgentTool } from "@earendil-works/pi-agent-core";
import { AgentToolCatalog } from "../agent/tool-catalog.js";
import { boundedToolDetails, objectValue } from "../agent/tools/tool-result.js";
import { redactSecurityText } from "../security/redaction.js";
import type { AutonomyPlanStep, AutonomousGoalRecord } from "./goals.js";

export type ToolDispatchPolicyDecision =
  | { decision: "allow"; reason: string }
  | { decision: "approval_required"; reason: string }
  | { decision: "block"; reason: string };

export interface AutonomyToolDispatchResult {
  ok: boolean;
  toolName: string;
  summary: string;
  details: unknown;
  evidenceRefs: string[];
  error?: string;
}

export class AutonomyToolDispatcher {
  readonly catalog: AgentToolCatalog;

  constructor(tools: AgentTool[], private readonly timeoutMs = 60_000) {
    this.catalog = new AgentToolCatalog(tools);
  }

  policy(goal: AutonomousGoalRecord, step: AutonomyPlanStep, approved: boolean): ToolDispatchPolicyDecision {
    const execution = step.execution;
    if (!execution) return { decision: "block", reason: "The plan step has no executable tool." };
    const entry = this.catalog.entry(execution.toolName);
    if (!entry) return { decision: "block", reason: `Tool ${execution.toolName} is not registered.` };
    if (entry.authority === "autonomy_write") {
      return { decision: "block", reason: "Agent runs cannot recursively create or mutate another agent run." };
    }
    const explicitApproval = execution.approvalRequired || goal.capabilityId === "executor";
    const reviewedAuthority = entry.authority === "cerebro_write" || entry.authority === "security_write" || entry.authority === "ticket_write";
    if ((explicitApproval || reviewedAuthority) && !approved) {
      return { decision: "approval_required", reason: `${entry.name} requires reviewed approval before execution.` };
    }
    const codeAuthority = entry.authority === "workspace_write" || entry.authority === "github_write" || entry.authority === "bounded_shell";
    if (codeAuthority && goal.capabilityId !== "self_repair" && goal.capabilityId !== "remediation") {
      return { decision: "block", reason: `${entry.name} is limited to self-repair or security-case remediation runs.` };
    }
    const externalWrite = reviewedAuthority || entry.authority === "github_write";
    if (externalWrite && !execution.verificationToolName) {
      return { decision: "block", reason: `${entry.name} needs an independent read-only verification tool.` };
    }
    if ((entry.authority === "cerebro_write" || entry.authority === "security_write") && (!execution.idempotencyKey || !execution.rollback)) {
      return { decision: "block", reason: `${entry.name} needs an idempotency key and rollback plan.` };
    }
    return { decision: "allow", reason: `${entry.name} is allowed for ${goal.capabilityId}.` };
  }

  verificationPolicy(toolName: string): ToolDispatchPolicyDecision {
    const entry = this.catalog.entry(toolName);
    if (!entry) return { decision: "block", reason: `Verification tool ${toolName} is not registered.` };
    if (entry.authority !== "read" || entry.sideEffect !== "none") {
      return { decision: "block", reason: `Verification tool ${toolName} must be read-only.` };
    }
    return { decision: "allow", reason: `${toolName} is read-only.` };
  }

  async dispatch(step: AutonomyPlanStep, verification = false, priorDetails?: unknown): Promise<AutonomyToolDispatchResult> {
    const execution = step.execution;
    if (!execution) return failed("unknown", "missing_step_execution");
    const toolName = verification ? execution.verificationToolName : execution.toolName;
    const rawArguments = verification ? resolveArgumentTemplates(execution.verificationArguments, priorDetails) : execution.arguments;
    if (!toolName) return failed(execution.toolName, "missing_verification_tool");
    const tool = this.catalog.get(toolName);
    if (!tool) return failed(toolName, "tool_not_registered");
    const validation = this.catalog.validateArguments(toolName, rawArguments);
    if (!validation.valid || !validation.arguments) {
      return failed(toolName, validation.errors.join(" "));
    }
    try {
      const result = await tool.execute(`autonomy-${randomUUID()}`, validation.arguments, AbortSignal.timeout(this.timeoutMs));
      const value = objectValue(result);
      const details = boundedToolDetails(value?.details ?? result);
      const detailsObject = objectValue(details);
      const error = resultError(detailsObject);
      return {
        ok: !error,
        toolName,
        summary: dispatchSummary(toolName, details, error),
        details,
        evidenceRefs: collectEvidenceRefs(details),
        error,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return failed(toolName, redactSecurityText(message).replace(/\s+/g, " ").slice(0, 500));
    }
  }
}

function resolveArgumentTemplates(argumentsValue: Record<string, unknown>, priorDetails: unknown): Record<string, unknown> {
  return Object.fromEntries(Object.entries(argumentsValue).map(([key, value]) => [key, resolveTemplateValue(value, priorDetails)]));
}

function resolveTemplateValue(value: unknown, priorDetails: unknown): unknown {
  if (typeof value === "string" && value.startsWith("$result.")) {
    return value.slice(8).split(".").reduce<unknown>((current, segment) => objectValue(current)?.[segment], priorDetails);
  }
  if (Array.isArray(value)) return value.map((item) => resolveTemplateValue(item, priorDetails));
  const record = objectValue(value);
  return record ? resolveArgumentTemplates(record, priorDetails) : value;
}

function resultError(details: Record<string, unknown> | undefined): string | undefined {
  if (!details) return undefined;
  if (typeof details.error === "string" && details.error.trim()) return redactSecurityText(details.error).trim().slice(0, 500);
  if (details.ok === false) return "tool_returned_not_ok";
  if (details.success === false) return "tool_returned_unsuccessful";
  if (details.allowed === false && typeof details.reason === "string") return details.reason.slice(0, 500);
  return undefined;
}

function dispatchSummary(toolName: string, details: unknown, error: string | undefined): string {
  if (error) return `${toolName} failed: ${error}`;
  const record = objectValue(details);
  for (const field of ["summary", "message", "status", "state", "decision"]) {
    const value = record?.[field];
    if (typeof value === "string" && value.trim()) return `${toolName}: ${redactSecurityText(value).replace(/\s+/g, " ").slice(0, 600)}`;
  }
  return `${toolName} completed.`;
}

function collectEvidenceRefs(value: unknown, depth = 0): string[] {
  if (depth > 5) return [];
  if (Array.isArray(value)) return unique(value.flatMap((item) => collectEvidenceRefs(item, depth + 1))).slice(0, 40);
  const record = objectValue(value);
  if (!record) return [];
  return unique(Object.entries(record).flatMap(([key, item]) => {
    const normalized = key.toLowerCase();
    if (typeof item === "string" && /(receipt|_ref$|_url$|^url$|^path$|^html_url$|^pr_url$)/.test(normalized)) return [item];
    if (Array.isArray(item) && /(refs|artifacts|urls)/.test(normalized)) return item.filter((entry): entry is string => typeof entry === "string");
    return collectEvidenceRefs(item, depth + 1);
  })).slice(0, 40);
}

function failed(toolName: string, error: string): AutonomyToolDispatchResult {
  return { ok: false, toolName, summary: `${toolName} failed: ${error}`, details: { error }, evidenceRefs: [], error };
}

function unique(values: string[]): string[] {
  return [...new Set(values.map((value) => redactSecurityText(value).trim()).filter(Boolean))];
}
