export type QuestionWorkDispatchOutcome = "publication_failed" | "published";

export interface QuestionWorkDispatchBackoffPolicyV1 {
  initial_delay_ms: number;
  max_delay_ms: number;
  schema_version: "question-work-dispatch-backoff-policy/v1";
}

export interface QuestionWorkDispatchBackoffStateV1 {
  consecutive_failures: number;
  schema_version: "question-work-dispatch-backoff-state/v1";
}

export interface QuestionWorkDispatchDecisionV1 {
  delay_ms: number;
  next_state: QuestionWorkDispatchBackoffStateV1;
  queued_work_disposition: "retain";
  schema_version: "question-work-dispatch-decision/v1";
}

export class QuestionWorkDispatchPolicyError extends Error {}

export const QUESTION_WORK_DISPATCH_INITIAL_STATE: QuestionWorkDispatchBackoffStateV1 = {
  consecutive_failures: 0,
  schema_version: "question-work-dispatch-backoff-state/v1",
};

/**
 * Computes portable retry timing only. A durable adapter persists the returned
 * state and schedules another publication attempt; this decision never removes
 * or terminally changes the already-queued work.
 */
export function decideQuestionWorkDispatch(
  policy: QuestionWorkDispatchBackoffPolicyV1,
  state: QuestionWorkDispatchBackoffStateV1,
  outcome: QuestionWorkDispatchOutcome,
): QuestionWorkDispatchDecisionV1 {
  validatePolicy(policy);
  validateState(state);
  if (outcome !== "publication_failed" && outcome !== "published") {
    throw new QuestionWorkDispatchPolicyError("The dispatch outcome is unsupported.");
  }

  if (outcome === "published") {
    return decision(0, 0);
  }

  const consecutiveFailures = Math.min(
    Number.MAX_SAFE_INTEGER,
    state.consecutive_failures + 1,
  );
  return decision(backoffDelay(policy, consecutiveFailures), consecutiveFailures);
}

function backoffDelay(
  policy: QuestionWorkDispatchBackoffPolicyV1,
  consecutiveFailures: number,
): number {
  const maximumDoublings = Math.ceil(
    Math.log2(policy.max_delay_ms / policy.initial_delay_ms),
  );
  const doublings = Math.min(consecutiveFailures - 1, maximumDoublings);
  let delay = policy.initial_delay_ms;
  for (let index = 0; index < doublings; index += 1) {
    delay = delay >= Math.ceil(policy.max_delay_ms / 2)
      ? policy.max_delay_ms
      : delay * 2;
  }
  return Math.min(delay, policy.max_delay_ms);
}

function decision(
  delayMs: number,
  consecutiveFailures: number,
): QuestionWorkDispatchDecisionV1 {
  return {
    delay_ms: delayMs,
    next_state: {
      consecutive_failures: consecutiveFailures,
      schema_version: "question-work-dispatch-backoff-state/v1",
    },
    queued_work_disposition: "retain",
    schema_version: "question-work-dispatch-decision/v1",
  };
}

function validatePolicy(policy: QuestionWorkDispatchBackoffPolicyV1): void {
  if (policy.schema_version !== "question-work-dispatch-backoff-policy/v1") {
    throw new QuestionWorkDispatchPolicyError("The dispatch policy version is unsupported.");
  }
  requirePositiveSafeInteger(policy.initial_delay_ms, "initial_delay_ms");
  requirePositiveSafeInteger(policy.max_delay_ms, "max_delay_ms");
  if (policy.max_delay_ms < policy.initial_delay_ms) {
    throw new QuestionWorkDispatchPolicyError(
      "max_delay_ms cannot be less than initial_delay_ms.",
    );
  }
}

function validateState(state: QuestionWorkDispatchBackoffStateV1): void {
  if (state.schema_version !== "question-work-dispatch-backoff-state/v1") {
    throw new QuestionWorkDispatchPolicyError("The dispatch state version is unsupported.");
  }
  if (!Number.isSafeInteger(state.consecutive_failures) || state.consecutive_failures < 0) {
    throw new QuestionWorkDispatchPolicyError(
      "consecutive_failures must be a non-negative safe integer.",
    );
  }
}

function requirePositiveSafeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new QuestionWorkDispatchPolicyError(`${label} must be a positive safe integer.`);
  }
}
