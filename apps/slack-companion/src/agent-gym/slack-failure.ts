import { AgentGymContractError } from "./contract-error.js";

export interface AgentGymSlackApiAttemptV1 {
  readonly attempt_index: number;
  readonly observed_at: string;
  readonly outcome: "rate_limited" | "success" | "timeout";
  readonly retry_after_ms?: number;
}

export interface AgentGymSlackRetryPolicyV1 {
  readonly maximum_attempts: number;
  readonly maximum_delay_ms: number;
  readonly timeout_base_delay_ms: number;
}

export interface AgentGymSlackRetryPlanV1 {
  readonly attempt_index: number;
  readonly delay_ms?: number;
  readonly disposition: "completed" | "exhausted" | "retry";
  readonly next_attempt_at?: string;
  readonly reason: "rate_limited" | "success" | "timeout";
  readonly schema_version: "agent-gym-slack-retry-plan/v1";
}

/** Produces deterministic retry behavior for simulated Slack API outcomes. */
export function planAgentGymSlackApiRetry(
  attempt: AgentGymSlackApiAttemptV1,
  policy: AgentGymSlackRetryPolicyV1,
): AgentGymSlackRetryPlanV1 {
  integer(attempt.attempt_index, 20);
  timestamp(attempt.observed_at);
  integer(policy.maximum_attempts, 20, false);
  integer(policy.maximum_delay_ms, 15 * 60_000, false);
  integer(policy.timeout_base_delay_ms, policy.maximum_delay_ms, false);
  if (attempt.attempt_index >= policy.maximum_attempts) invalid();
  if (!["rate_limited", "success", "timeout"].includes(attempt.outcome)) invalid();
  if (attempt.outcome === "rate_limited") {
    if (attempt.retry_after_ms === undefined) invalid();
    integer(attempt.retry_after_ms, policy.maximum_delay_ms, false);
  } else if (attempt.retry_after_ms !== undefined) invalid();
  if (attempt.outcome === "success") {
    return result(attempt, "completed");
  }
  if (attempt.attempt_index + 1 >= policy.maximum_attempts) {
    return result(attempt, "exhausted");
  }
  const delay = attempt.outcome === "rate_limited"
    ? attempt.retry_after_ms ?? invalid()
    : Math.min(
        policy.maximum_delay_ms,
        policy.timeout_base_delay_ms * (2 ** attempt.attempt_index),
      );
  return result(attempt, "retry", delay);
}

function result(
  attempt: AgentGymSlackApiAttemptV1,
  disposition: AgentGymSlackRetryPlanV1["disposition"],
  delay?: number,
): AgentGymSlackRetryPlanV1 {
  return Object.freeze({
    attempt_index: attempt.attempt_index,
    ...(delay === undefined ? {} : {
      delay_ms: delay,
      next_attempt_at: new Date(Date.parse(attempt.observed_at) + delay).toISOString(),
    }),
    disposition,
    reason: attempt.outcome,
    schema_version: "agent-gym-slack-retry-plan/v1",
  });
}
function integer(value: number, maximum: number, allowZero = true): void {
  if (!Number.isSafeInteger(value) || value < (allowZero ? 0 : 1) || value > maximum) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || !Number.isFinite(Date.parse(value))) invalid();
}
function invalid(): never { throw new AgentGymContractError("Agent gym Slack retry input is invalid."); }
