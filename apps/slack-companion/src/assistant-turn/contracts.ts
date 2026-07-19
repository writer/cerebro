export const ASSISTANT_EXECUTION_LANES = [
  "ignore",
  "converse",
  "continue",
  "lookup",
  "investigate",
  "act",
] as const;

export type AssistantExecutionLaneV1 = (typeof ASSISTANT_EXECUTION_LANES)[number];

export const ASSISTANT_TURN_PROGRESS_PHASES = [
  "planning",
  "checking",
  "synthesizing",
  "delivering",
  "completed",
  "blocked",
] as const;

export type AssistantTurnProgressPhaseV1 =
  (typeof ASSISTANT_TURN_PROGRESS_PHASES)[number];

export const ASSISTANT_TURN_OUTPUT_STATES = [
  "answered",
  "partial",
  "needs_input",
  "blocked",
] as const;

export type AssistantTurnOutputStateV1 =
  (typeof ASSISTANT_TURN_OUTPUT_STATES)[number];

/**
 * User-facing content produced by an assistant turn before Slack projection.
 * Evidence, tool results, errors, and host metadata stay in their own durable
 * records rather than crossing this display boundary.
 */
export interface AssistantTurnOutputInputV1 {
  answer?: string;
  coverage_notice?: string;
  next_action?: string;
  question?: string;
  state: AssistantTurnOutputStateV1;
}

export interface AssistantTurnOutputV1 extends AssistantTurnOutputInputV1 {
  content_digest: `sha256:${string}`;
  schema_version: "assistant-turn-output/v1";
}

/** Portable execution bounds for one model-selected assistant lane. */
export interface AssistantTurnBudgetV1 {
  execution_lane: AssistantExecutionLaneV1;
  latency_budget_ms: number;
  max_selected_capabilities: number;
  max_tool_calls: number;
  schema_version: "assistant-turn-budget/v1";
}

/**
 * A Slack host may render this state, while durable workers can persist it as
 * opaque progress. Status text is bounded operator copy, never hidden model
 * reasoning or raw tool output.
 */
export interface AssistantTurnProgressInput {
  capability_ref?: string;
  execution_lane?: AssistantExecutionLaneV1;
  occurred_at: string;
  phase: AssistantTurnProgressPhaseV1;
  sequence: number;
  status: string;
}

export interface AssistantTurnProgressV1 extends AssistantTurnProgressInput {
  schema_version: "assistant-turn-progress/v1";
}
