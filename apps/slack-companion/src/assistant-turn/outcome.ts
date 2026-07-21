import { createHash } from "node:crypto";
import {
  ASSISTANT_EXECUTION_LANES,
  type AssistantExecutionLaneV1,
} from "./contracts.js";
import {
  ASSISTANT_TURN_EVALUATION_BLOCKERS,
  ASSISTANT_TURN_OUTCOME_STATES,
  type AssistantTurnOutcomeStateV1,
} from "./evaluation.js";

export type AssistantTurnOutcomeQualificationV1 =
  | "eligible_failure"
  | "eligible_success"
  | "excluded"
  | "pending_observation";

export interface AssistantTurnOutcomeAssessmentInput {
  assessment_at: string;
  evaluation_blockers: readonly string[];
  execution_lane: AssistantExecutionLaneV1;
  latency_budget_ms: number;
  negative_feedback_count: number;
  opened_at: string;
  outcome_state: AssistantTurnOutcomeStateV1;
  request_id: string;
  request_kind: "human" | "machine_handoff";
  user_correction_count: number;
  useful_answer_at?: string;
  verified: boolean;
}

export interface AssistantTurnOutcomeAssessmentV1
  extends AssistantTurnOutcomeAssessmentInput {
  assessment_digest: `sha256:${string}`;
  eligible: boolean;
  observation_window_complete: boolean;
  qualification: AssistantTurnOutcomeQualificationV1;
  schema_version: "assistant-turn-outcome-assessment/v1";
  useful_answer_latency_ms?: number;
  verified_outcome_within_slo: boolean;
}

export const ASSISTANT_TURN_OUTCOME_OBSERVATION_WINDOW_MS = 24 * 60 * 60 * 1_000;

/** Assess one human request after the correction/feedback observation window. */
export function assessAssistantTurnOutcome(
  input: AssistantTurnOutcomeAssessmentInput,
): AssistantTurnOutcomeAssessmentV1 {
  requireOpaque(input.request_id, "request_id");
  if (!ASSISTANT_EXECUTION_LANES.includes(input.execution_lane)) {
    throw new AssistantTurnOutcomeInputError("Execution lane is unsupported");
  }
  if (input.request_kind !== "human" && input.request_kind !== "machine_handoff") {
    throw new AssistantTurnOutcomeInputError("Request kind is unsupported");
  }
  if (typeof input.verified !== "boolean") {
    throw new AssistantTurnOutcomeInputError("Verified must be boolean");
  }
  if (!ASSISTANT_TURN_OUTCOME_STATES.includes(input.outcome_state)) {
    throw new AssistantTurnOutcomeInputError("Outcome state is unsupported");
  }
  requireNonNegativeInteger(input.latency_budget_ms, "latency_budget_ms");
  requireNonNegativeInteger(input.negative_feedback_count, "negative_feedback_count");
  requireNonNegativeInteger(input.user_correction_count, "user_correction_count");
  requireDistinctCodes(input.evaluation_blockers);
  const openedAt = timestamp(input.opened_at, "opened_at");
  const assessmentAt = timestamp(input.assessment_at, "assessment_at");
  if (assessmentAt < openedAt) {
    throw new AssistantTurnOutcomeInputError("Assessment cannot precede the request");
  }
  const usefulAnswerAt = input.useful_answer_at === undefined
    ? undefined
    : timestamp(input.useful_answer_at, "useful_answer_at");
  if (usefulAnswerAt !== undefined && usefulAnswerAt < openedAt) {
    throw new AssistantTurnOutcomeInputError("Useful answer cannot precede the request");
  }

  const eligible = input.request_kind === "human";
  const observationWindowComplete =
    assessmentAt - openedAt >= ASSISTANT_TURN_OUTCOME_OBSERVATION_WINDOW_MS;
  const usefulAnswerLatency = usefulAnswerAt === undefined
    ? undefined
    : usefulAnswerAt - openedAt;
  const verifiedOutcomeWithinSlo = Boolean(
    eligible &&
    observationWindowComplete &&
    input.outcome_state === "completed" &&
    input.verified &&
    usefulAnswerLatency !== undefined &&
    usefulAnswerLatency <= input.latency_budget_ms &&
    input.user_correction_count === 0 &&
    input.negative_feedback_count === 0 &&
    input.evaluation_blockers.length === 0
  );
  const qualification: AssistantTurnOutcomeQualificationV1 = !eligible
    ? "excluded"
    : !observationWindowComplete
      ? "pending_observation"
      : verifiedOutcomeWithinSlo
        ? "eligible_success"
        : "eligible_failure";

  const content = {
    ...input,
    eligible,
    observation_window_complete: observationWindowComplete,
    qualification,
    schema_version: "assistant-turn-outcome-assessment/v1" as const,
    ...(usefulAnswerLatency === undefined
      ? {}
      : { useful_answer_latency_ms: usefulAnswerLatency }),
    verified_outcome_within_slo: verifiedOutcomeWithinSlo,
  };
  return Object.freeze({
    ...content,
    assessment_digest: `sha256:${createHash("sha256")
      .update(JSON.stringify(content), "utf8")
      .digest("hex")}`,
  });
}

function timestamp(value: string, label: string): number {
  const milliseconds = Date.parse(value);
  if (
    !Number.isFinite(milliseconds) ||
    new Date(milliseconds).toISOString() !== value
  ) {
    throw new AssistantTurnOutcomeInputError(`${label} must be canonical UTC`);
  }
  return milliseconds;
}

function requireOpaque(value: string, label: string): void {
  if (typeof value !== "string" || value.trim() === "" || value.length > 2_048) {
    throw new AssistantTurnOutcomeInputError(`${label} is invalid`);
  }
}

function requireNonNegativeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new AssistantTurnOutcomeInputError(`${label} must be a non-negative integer`);
  }
}

function requireDistinctCodes(values: readonly string[]): void {
  if (
    values.some((value) =>
      !ASSISTANT_TURN_EVALUATION_BLOCKERS.includes(
        value as (typeof ASSISTANT_TURN_EVALUATION_BLOCKERS)[number],
      )
    ) ||
    new Set(values).size !== values.length
  ) {
    throw new AssistantTurnOutcomeInputError(
      "Evaluation blockers must be distinct stable codes",
    );
  }
}

export class AssistantTurnOutcomeInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AssistantTurnOutcomeInputError";
  }
}
