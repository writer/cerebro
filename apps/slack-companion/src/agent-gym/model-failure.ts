import { AgentGymContractError } from "./contract-error.js";

export interface AgentGymModelFailureV1 {
  readonly error_code: string;
  readonly invocation_ref: string;
  readonly message: string;
  readonly model_id: string;
  readonly provider_request_ref?: string;
  readonly retry_after_ms?: number;
  readonly retryable: boolean;
  readonly schema_version: "agent-gym-model-failure/v1";
}

/** A typed model failure that can be replayed without leaking provider errors. */
export class AgentGymModelInvocationError extends AgentGymContractError {
  readonly failure: AgentGymModelFailureV1;

  constructor(rawFailure: AgentGymModelFailureV1) {
    const failure = validateAgentGymModelFailure(rawFailure);
    super(failure.message);
    this.name = "AgentGymModelInvocationError";
    this.failure = failure;
  }
}

export function validateAgentGymModelFailure(
  failure: AgentGymModelFailureV1,
): AgentGymModelFailureV1 {
  if (failure.schema_version !== "agent-gym-model-failure/v1") invalid();
  reference(failure.invocation_ref);
  bounded(failure.model_id, 240);
  bounded(failure.error_code, 160);
  bounded(failure.message, 2_000);
  if (!/^[a-z0-9][a-z0-9._-]*$/u.test(failure.error_code)) invalid();
  if (failure.provider_request_ref !== undefined) reference(failure.provider_request_ref);
  if (failure.retry_after_ms !== undefined
    && (!Number.isSafeInteger(failure.retry_after_ms) || failure.retry_after_ms < 1
      || failure.retry_after_ms > 60 * 60_000 || !failure.retryable)) invalid();
  return Object.freeze({ ...failure });
}

function bounded(value: string, maximum: number): void {
  if (typeof value !== "string" || !value.trim() || value.length > maximum
    || /[\u0000-\u001f\u007f]/u.test(value)) invalid();
}

function reference(value: string): void {
  bounded(value, 240);
  if (!value.includes("://")) invalid();
}

function invalid(): never {
  throw new AgentGymContractError("Agent gym model failure is invalid.");
}
