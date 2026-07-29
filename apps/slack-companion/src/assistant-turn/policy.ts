import { createHash } from "node:crypto";
import {
  ASSISTANT_EXECUTION_LANES,
  ASSISTANT_TURN_OUTPUT_STATES,
  ASSISTANT_TURN_PROGRESS_PHASES,
  type AssistantExecutionLaneV1,
  type AssistantTurnBudgetV1,
  type AssistantTurnOutputInputV1,
  type AssistantTurnOutputStateV1,
  type AssistantTurnOutputV1,
  type AssistantTurnProgressInput,
  type AssistantTurnProgressV1,
} from "./contracts.js";

export const MAX_ASSISTANT_TURN_ANSWER_LENGTH = 12_000;
export const MAX_ASSISTANT_TURN_OUTPUT_LENGTH = 12_800;

const OUTPUT_TEXT_LIMITS = {
  answer: MAX_ASSISTANT_TURN_ANSWER_LENGTH,
  coverage_notice: 600,
  next_action: 600,
  question: 600,
} as const;

const OUTPUT_FIELDS = [
  "answer",
  "coverage_notice",
  "next_action",
  "question",
  "state",
] as const;

const TURN_BUDGETS: Record<AssistantExecutionLaneV1, Omit<AssistantTurnBudgetV1, "schema_version" | "execution_lane">> = {
  ignore: { latency_budget_ms: 5_000, max_selected_capabilities: 0, max_tool_calls: 0 },
  converse: { latency_budget_ms: 5_000, max_selected_capabilities: 0, max_tool_calls: 0 },
  continue: { latency_budget_ms: 5_000, max_selected_capabilities: 0, max_tool_calls: 0 },
  lookup: { latency_budget_ms: 60_000, max_selected_capabilities: 4, max_tool_calls: 3 },
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

/**
 * Validates the exact user-facing output shape before it reaches a transport
 * projector. The state rules prevent partial or blocked work from being labeled
 * answered and keep non-display records out of the payload.
 */
export function normalizeAssistantTurnOutput(
  value: unknown,
): AssistantTurnOutputV1 {
  const input = requireOutputObject(value);
  requireExactOutputFields(input);
  const state = requireOutputState(ownOutputField(input, "state"));
  const answer = optionalOutputText(ownOutputField(input, "answer"), "answer");
  const coverageNotice = optionalOutputText(
    ownOutputField(input, "coverage_notice"),
    "coverage_notice",
  );
  const nextAction = optionalOutputText(
    ownOutputField(input, "next_action"),
    "next_action",
  );
  const question = optionalOutputText(
    ownOutputField(input, "question"),
    "question",
  );

  validateOutputState(state, {
    answer,
    coverage_notice: coverageNotice,
    next_action: nextAction,
    question,
  });
  const outputLength = [answer, coverageNotice, nextAction, question]
    .reduce((total, field) => total + codePointLength(field), 0);
  if (outputLength > MAX_ASSISTANT_TURN_OUTPUT_LENGTH) {
    throw new AssistantTurnInputError("Assistant output exceeds its total text bound.");
  }

  const content = {
    ...(answer === undefined ? {} : { answer }),
    ...(coverageNotice === undefined ? {} : { coverage_notice: coverageNotice }),
    ...(nextAction === undefined ? {} : { next_action: nextAction }),
    ...(question === undefined ? {} : { question }),
    schema_version: "assistant-turn-output/v1" as const,
    state,
  };
  return Object.freeze({
    ...content,
    content_digest: `sha256:${createHash("sha256")
      .update(JSON.stringify(content), "utf8")
      .digest("hex")}`,
  });
}

function requireOutputObject(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new AssistantTurnInputError("Assistant output must be a plain object.");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new AssistantTurnInputError("Assistant output must be a plain object.");
  }
  return value as Record<string, unknown>;
}

function requireExactOutputFields(input: Record<string, unknown>): void {
  const allowed = new Set<string>(OUTPUT_FIELDS);
  if (Object.keys(input).some((field) => !allowed.has(field))) {
    throw new AssistantTurnInputError("Assistant output contains an unsupported field.");
  }
}

function ownOutputField(
  input: Record<string, unknown>,
  field: (typeof OUTPUT_FIELDS)[number],
): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(input, field);
  if (descriptor === undefined) return undefined;
  if (!("value" in descriptor)) {
    throw new AssistantTurnInputError("Assistant output fields must be data fields.");
  }
  return descriptor.value;
}

function requireOutputState(value: unknown): AssistantTurnOutputStateV1 {
  if (
    typeof value !== "string"
    || !ASSISTANT_TURN_OUTPUT_STATES.includes(value as AssistantTurnOutputStateV1)
  ) {
    throw new AssistantTurnInputError("The assistant output state is unsupported.");
  }
  return value as AssistantTurnOutputStateV1;
}

function optionalOutputText(
  value: unknown,
  field: keyof typeof OUTPUT_TEXT_LIMITS,
): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string") {
    throw new AssistantTurnInputError(`Assistant output ${field} must be text.`);
  }
  const normalized = value
    .replace(/\r\n?/g, "\n")
    .normalize("NFC")
    .split("\n")
    .map((line) => line.trimEnd())
    .join("\n")
    .trim();
  if (
    normalized.length === 0
    || normalized.length > OUTPUT_TEXT_LIMITS[field] * 2
    || codePointLength(normalized) > OUTPUT_TEXT_LIMITS[field]
    || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(normalized)
  ) {
    throw new AssistantTurnInputError(`Assistant output ${field} is invalid.`);
  }
  return normalized;
}

function validateOutputState(
  state: AssistantTurnOutputStateV1,
  fields: Omit<AssistantTurnOutputInputV1, "state">,
): void {
  const { answer, coverage_notice: coverageNotice, next_action: nextAction, question } = fields;
  if (state === "answered" && (answer === undefined || question !== undefined)) {
    throw new AssistantTurnInputError("An answered output requires an answer and cannot ask a question.");
  }
  if (
    state === "partial"
    && (answer === undefined || coverageNotice === undefined || question !== undefined)
  ) {
    throw new AssistantTurnInputError(
      "A partial output requires an answer and coverage notice and cannot ask a question.",
    );
  }
  if (
    state === "needs_input"
    && (question === undefined || answer !== undefined || nextAction !== undefined)
  ) {
    throw new AssistantTurnInputError(
      "A needs-input output requires one question and cannot include an answer or next action.",
    );
  }
  if (
    state === "blocked"
    && (coverageNotice === undefined || answer !== undefined || question !== undefined)
  ) {
    throw new AssistantTurnInputError(
      "A blocked output requires a coverage notice and cannot include an answer or question.",
    );
  }
}

function codePointLength(value: string | undefined): number {
  return value === undefined ? 0 : Array.from(value).length;
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
