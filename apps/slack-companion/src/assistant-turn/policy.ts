import {
  ASSISTANT_EXECUTION_LANES,
  ASSISTANT_TURN_PROGRESS_PHASES,
  type AssistantExecutionLaneV1,
  type AssistantTurnBudgetV1,
  type AssistantTurnProgressInput,
  type AssistantTurnProgressV1,
} from "./contracts.js";

const TURN_BUDGETS: Record<AssistantExecutionLaneV1, Omit<AssistantTurnBudgetV1, "schema_version" | "execution_lane">> = {
  ignore: { latency_budget_ms: 5_000, max_selected_capabilities: 0, max_tool_calls: 0 },
  converse: { latency_budget_ms: 5_000, max_selected_capabilities: 0, max_tool_calls: 0 },
  continue: { latency_budget_ms: 5_000, max_selected_capabilities: 0, max_tool_calls: 0 },
  lookup: { latency_budget_ms: 30_000, max_selected_capabilities: 4, max_tool_calls: 3 },
  investigate: { latency_budget_ms: 180_000, max_selected_capabilities: 10, max_tool_calls: 8 },
  act: { latency_budget_ms: 300_000, max_selected_capabilities: 12, max_tool_calls: 12 },
};

export class AssistantTurnInputError extends Error {}

export function assistantTurnBudget(
  lane: AssistantExecutionLaneV1,
  configured?: { max_tool_calls?: number; timeout_ms?: number },
): AssistantTurnBudgetV1 {
  if (!ASSISTANT_EXECUTION_LANES.includes(lane)) {
    throw new AssistantTurnInputError("The assistant execution lane is unsupported.");
  }
  const policy = TURN_BUDGETS[lane];
  return {
    execution_lane: lane,
    latency_budget_ms: boundedLimit(configured?.timeout_ms, policy.latency_budget_ms),
    max_selected_capabilities: policy.max_selected_capabilities,
    max_tool_calls: boundedLimit(configured?.max_tool_calls, policy.max_tool_calls),
    schema_version: "assistant-turn-budget/v1",
  };
}

export function normalizeAssistantTurnProgress(
  input: AssistantTurnProgressInput,
): AssistantTurnProgressV1 {
  if (!ASSISTANT_TURN_PROGRESS_PHASES.includes(input.phase)) {
    throw new AssistantTurnInputError("The assistant progress phase is unsupported.");
  }
  if (
    input.execution_lane !== undefined
    && !ASSISTANT_EXECUTION_LANES.includes(input.execution_lane)
  ) {
    throw new AssistantTurnInputError("The assistant progress lane is unsupported.");
  }
  if (!Number.isSafeInteger(input.sequence) || input.sequence < 1 || input.sequence > 128) {
    throw new AssistantTurnInputError("The assistant progress sequence is out of bounds.");
  }
  if (!Number.isFinite(Date.parse(input.occurred_at))) {
    throw new AssistantTurnInputError("Assistant progress requires a timestamp.");
  }
  const status = boundedText(input.status, 160);
  if (!status) throw new AssistantTurnInputError("Assistant progress requires a concrete status.");
  const capabilityRef = boundedText(input.capability_ref, 2_048);
  return {
    ...(capabilityRef ? { capability_ref: capabilityRef } : {}),
    ...(input.execution_lane ? { execution_lane: input.execution_lane } : {}),
    occurred_at: input.occurred_at,
    phase: input.phase,
    schema_version: "assistant-turn-progress/v1",
    sequence: input.sequence,
    status,
  };
}

function boundedLimit(configured: number | undefined, policy: number): number {
  if (configured === undefined) return policy;
  if (!Number.isSafeInteger(configured) || configured < 0) {
    throw new AssistantTurnInputError("Configured assistant bounds must be non-negative integers.");
  }
  return Math.min(configured, policy);
}

function boundedText(value: string | undefined, limit: number): string {
  return typeof value === "string"
    ? value.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim().slice(0, limit)
    : "";
}
