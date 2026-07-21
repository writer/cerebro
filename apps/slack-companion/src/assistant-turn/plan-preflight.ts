import type { AssistantTurnBudgetV1 } from "./contracts.js";
import type { SourceHealthSnapshotV1 } from "../execution/source-health-policy.js";
import type { ToolCatalog } from "../tools/catalog.js";
import {
  assertToolAuthorityDecision,
  type ToolAuthorityDecisionV1,
} from "../tools/contracts.js";

export const ASSISTANT_TURN_START_TOOL_CUTOFF_RATIO = 0.8;

export const ASSISTANT_TURN_PLAN_BLOCKERS = [
  "authority_denied",
  "authority_expired",
  "authority_metadata_required",
  "authority_request_mismatch",
  "lane_capability_budget",
  "lane_tool_budget",
  "outside_selected_tool_pack",
  "replan_limit",
  "source_health_required",
  "source_unavailable",
  "tool_not_registered",
  "turn_start_tool_cutoff",
] as const;

export type AssistantTurnPlanBlockerV1 =
  (typeof ASSISTANT_TURN_PLAN_BLOCKERS)[number];

export interface AssistantTurnPlannedInvocationV1 {
  authority?: ToolAuthorityDecisionV1;
  invocation_id: string;
  request_digest: string;
  run_id: string;
  source_ref?: string;
  step_id: string;
  subject_ref: string;
  tool_id: string;
  tool_version: string;
}

export interface AssistantTurnPlanPreflightInput {
  budget: AssistantTurnBudgetV1;
  catalog: ToolCatalog;
  elapsed_ms: number;
  completed_tool_calls: number;
  invocation: AssistantTurnPlannedInvocationV1;
  observed_at: string;
  replan_count: number;
  selected_capability_refs: readonly string[];
  source_health: readonly SourceHealthSnapshotV1[];
}

export interface AssistantTurnPlanPreflightV1 {
  allowed: boolean;
  blockers: readonly AssistantTurnPlanBlockerV1[];
  cutoff_ms: number;
  remaining_ms: number;
  schema_version: "assistant-turn-plan-preflight/v1";
  tool_calls_after_start: number;
}

/**
 * Validates one model-planned tool invocation before the host starts it.
 * This is a capability and execution-boundary check, not an intent router.
 */
export function preflightAssistantTurnInvocation(
  input: AssistantTurnPlanPreflightInput,
): AssistantTurnPlanPreflightV1 {
  requireNonNegativeInteger(input.elapsed_ms, "elapsed_ms");
  requireNonNegativeInteger(input.completed_tool_calls, "completed_tool_calls");
  requireNonNegativeInteger(input.replan_count, "replan_count");
  const observedAt = requireCanonicalTimestamp(input.observed_at, "observed_at");
  requireDistinctNonEmpty(input.selected_capability_refs, "selected capability");

  const blockers = new Set<AssistantTurnPlanBlockerV1>();
  const cutoffMs = Math.floor(
    input.budget.latency_budget_ms * ASSISTANT_TURN_START_TOOL_CUTOFF_RATIO,
  );
  const toolCallsAfterStart = input.completed_tool_calls + 1;
  if (input.elapsed_ms >= cutoffMs) blockers.add("turn_start_tool_cutoff");
  if (toolCallsAfterStart > input.budget.max_tool_calls) {
    blockers.add("lane_tool_budget");
  }
  if (
    input.selected_capability_refs.length >
    input.budget.max_selected_capabilities
  ) {
    blockers.add("lane_capability_budget");
  }
  if (input.replan_count > 1) blockers.add("replan_limit");

  const tool = input.catalog.resolve(
    input.invocation.tool_id,
    input.invocation.tool_version,
  );
  if (tool === undefined) {
    blockers.add("tool_not_registered");
  } else if (
    tool.required_capabilities.some(
      (capability) => !input.selected_capability_refs.includes(capability),
    )
  ) {
    blockers.add("outside_selected_tool_pack");
  }

  validateAuthority(input.invocation, observedAt, blockers);
  validateSourceHealth(input.invocation.source_ref, input.source_health, blockers);

  return Object.freeze({
    allowed: blockers.size === 0,
    blockers: Object.freeze([...blockers].sort()),
    cutoff_ms: cutoffMs,
    remaining_ms: Math.max(0, input.budget.latency_budget_ms - input.elapsed_ms),
    schema_version: "assistant-turn-plan-preflight/v1",
    tool_calls_after_start: toolCallsAfterStart,
  });
}

function validateAuthority(
  invocation: AssistantTurnPlannedInvocationV1,
  observedAt: number,
  blockers: Set<AssistantTurnPlanBlockerV1>,
): void {
  if (invocation.authority === undefined) {
    blockers.add("authority_metadata_required");
    return;
  }
  try {
    assertToolAuthorityDecision(invocation.authority);
  } catch {
    blockers.add("authority_metadata_required");
    return;
  }
  const authority = invocation.authority;
  if (
    authority.invocation_id !== invocation.invocation_id ||
    authority.run_id !== invocation.run_id ||
    authority.step_id !== invocation.step_id ||
    authority.subject_ref !== invocation.subject_ref ||
    authority.tool_id !== invocation.tool_id ||
    authority.tool_version !== invocation.tool_version ||
    authority.request_digest !== invocation.request_digest
  ) {
    blockers.add("authority_request_mismatch");
  }
  if (authority.outcome !== "allowed") blockers.add("authority_denied");
  if (
    Date.parse(authority.decided_at) > observedAt ||
    (authority.expires_at !== undefined && Date.parse(authority.expires_at) <= observedAt)
  ) {
    blockers.add("authority_expired");
  }
}

function validateSourceHealth(
  sourceRef: string | undefined,
  snapshots: readonly SourceHealthSnapshotV1[],
  blockers: Set<AssistantTurnPlanBlockerV1>,
): void {
  if (sourceRef === undefined) return;
  const matching = snapshots.filter((snapshot) => snapshot.source_ref === sourceRef);
  if (matching.length !== 1) {
    blockers.add("source_health_required");
    return;
  }
  if (!matching[0]!.allowed) blockers.add("source_unavailable");
}

function requireNonNegativeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new AssistantTurnPlanInputError(`${label} must be a non-negative integer`);
  }
}

function requireDistinctNonEmpty(values: readonly string[], label: string): void {
  if (
    values.some((value) => typeof value !== "string" || value.trim() === "") ||
    new Set(values).size !== values.length
  ) {
    throw new AssistantTurnPlanInputError(`${label} references must be distinct and non-empty`);
  }
}

function requireCanonicalTimestamp(value: string, label: string): number {
  const milliseconds = Date.parse(value);
  if (
    !Number.isFinite(milliseconds) ||
    new Date(milliseconds).toISOString() !== value
  ) {
    throw new AssistantTurnPlanInputError(`${label} must be canonical UTC`);
  }
  return milliseconds;
}

export class AssistantTurnPlanInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AssistantTurnPlanInputError";
  }
}
