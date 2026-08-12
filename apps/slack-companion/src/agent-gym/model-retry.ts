import { AgentGymContractError } from "./contract-error.js";
import type { AgentGymModelFailureV1 } from "./model-failure.js";
import { AgentGymModelInvocationError } from "./model-failure.js";
import type {
  AgentGymModelInvocationRequestV1,
  AgentGymModelPort,
  AgentGymModelResponseV1,
} from "./model-runtime.js";

export interface AgentGymModelRetryPolicyV1 {
  readonly backoff_ms: readonly number[];
  readonly max_attempts: number;
  readonly max_elapsed_ms: number;
  readonly retryable_error_codes: readonly string[];
  readonly schema_version: "agent-gym-model-retry-policy/v1";
}

export interface AgentGymModelRetryDecisionV1 {
  readonly attempt: number;
  readonly delay_ms: number | null;
  readonly reason_code: string;
  readonly retry: boolean;
  readonly schema_version: "agent-gym-model-retry-decision/v1";
}

export interface AgentGymModelRetryAttemptV1 {
  readonly attempt: number;
  readonly delay_ms: number;
  readonly error_code?: string;
  readonly outcome: "failure" | "success";
}

export interface AgentGymModelRetryResultV1 {
  readonly attempts: readonly AgentGymModelRetryAttemptV1[];
  readonly response: AgentGymModelResponseV1;
  readonly schema_version: "agent-gym-model-retry-result/v1";
  readonly virtual_elapsed_ms: number;
}

/** Executes retries using virtual delay accounting; it never sleeps. */
export async function invokeAgentGymModelWithRetry(
  request: AgentGymModelInvocationRequestV1,
  policy: AgentGymModelRetryPolicyV1,
  model: AgentGymModelPort,
): Promise<AgentGymModelRetryResultV1> {
  const attempts: AgentGymModelRetryAttemptV1[] = [];
  let elapsedMs = 0;
  for (let attempt = 1; attempt <= policy.max_attempts; attempt += 1) {
    try {
      const response = await model.invoke(request);
      attempts.push(Object.freeze({ attempt, delay_ms: 0, outcome: "success" }));
      return Object.freeze({
        attempts: Object.freeze(attempts),
        response,
        schema_version: "agent-gym-model-retry-result/v1",
        virtual_elapsed_ms: elapsedMs,
      });
    } catch (error: unknown) {
      if (!(error instanceof AgentGymModelInvocationError)) throw error;
      const decision = decideAgentGymModelRetry(policy, error.failure, attempt, elapsedMs);
      attempts.push(Object.freeze({
        attempt,
        delay_ms: decision.delay_ms ?? 0,
        error_code: error.failure.error_code,
        outcome: "failure",
      }));
      if (!decision.retry) throw error;
      elapsedMs += decision.delay_ms ?? 0;
    }
  }
  throw new AgentGymContractError("Agent gym model retry execution is invalid.");
}

/** Makes a deterministic retry decision without sleeping or reading wall time. */
export function decideAgentGymModelRetry(
  rawPolicy: AgentGymModelRetryPolicyV1,
  failure: AgentGymModelFailureV1,
  attempt: number,
  elapsedMs: number,
): AgentGymModelRetryDecisionV1 {
  const policy = validatePolicy(rawPolicy);
  integer(attempt, policy.max_attempts);
  if (!Number.isSafeInteger(elapsedMs) || elapsedMs < 0
    || elapsedMs > policy.max_elapsed_ms) invalid();
  const delay = failure.retry_after_ms ?? policy.backoff_ms[attempt - 1] ?? 0;
  const reasonCode = !failure.retryable
    ? "failure.not_retryable"
    : !policy.retryable_error_codes.includes(failure.error_code)
      ? "failure.code_not_allowed"
      : attempt >= policy.max_attempts
        ? "retry.attempts_exhausted"
        : elapsedMs + delay > policy.max_elapsed_ms
          ? "retry.elapsed_budget_exhausted"
          : "retry.scheduled";
  const retry = reasonCode === "retry.scheduled";
  return Object.freeze({
    attempt,
    delay_ms: retry ? delay : null,
    reason_code: reasonCode,
    retry,
    schema_version: "agent-gym-model-retry-decision/v1",
  });
}

function validatePolicy(policy: AgentGymModelRetryPolicyV1): AgentGymModelRetryPolicyV1 {
  if (policy.schema_version !== "agent-gym-model-retry-policy/v1") invalid();
  integer(policy.max_attempts, 10);
  integer(policy.max_elapsed_ms, 60 * 60_000);
  if (!Array.isArray(policy.backoff_ms) || policy.backoff_ms.length > 9
    || policy.backoff_ms.length < policy.max_attempts - 1
    || !Array.isArray(policy.retryable_error_codes)
    || policy.retryable_error_codes.length < 1
    || policy.retryable_error_codes.length > 64
    || new Set(policy.retryable_error_codes).size !== policy.retryable_error_codes.length) invalid();
  for (const delay of policy.backoff_ms) integer(delay, policy.max_elapsed_ms, true);
  for (const code of policy.retryable_error_codes) {
    if (!/^[a-z0-9][a-z0-9._-]*$/u.test(code)) invalid();
  }
  return Object.freeze({
    ...policy,
    backoff_ms: Object.freeze([...policy.backoff_ms]),
    retryable_error_codes: Object.freeze([...policy.retryable_error_codes]),
  });
}

function integer(value: number, maximum: number, allowZero = false): void {
  if (!Number.isSafeInteger(value) || value < (allowZero ? 0 : 1) || value > maximum) {
    invalid();
  }
}

function invalid(): never {
  throw new AgentGymContractError("Agent gym model retry policy is invalid.");
}
