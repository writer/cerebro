import { createHash } from "node:crypto";
import { AgentGymContractError } from "./index.js";
import {
  evaluateAgentGymModelBudget,
  type AgentGymModelBudgetEvaluationV1,
  type AgentGymModelBudgetV1,
} from "./model-budget.js";
import {
  agentGymModelRequestDigest,
  type AgentGymModelInvocationRequestV1,
  type AgentGymModelPort,
  type AgentGymModelResponseV1,
  validateAgentGymModelRequest,
  validateAgentGymModelResponse,
} from "./model-runtime.js";

export interface AgentGymModelInvocationReceiptV1 {
  readonly budget: AgentGymModelBudgetEvaluationV1;
  readonly candidate_ref: string;
  readonly evaluated_at: string;
  readonly invocation_ref: string;
  readonly latency_ms: number;
  readonly model_id: string;
  readonly provider_request_ref?: string;
  readonly request_digest: `sha256:${string}`;
  readonly response_digest: `sha256:${string}`;
  readonly response_source: "live" | "recorded";
  readonly schema_version: "agent-gym-model-invocation-receipt/v1";
  readonly stop_reason: AgentGymModelResponseV1["stop_reason"];
  readonly token_usage: AgentGymModelResponseV1["token_usage"];
}

export interface AgentGymModelInvocationResultV1 {
  readonly receipt: AgentGymModelInvocationReceiptV1;
  readonly response: AgentGymModelResponseV1;
}

/** Invokes one model port and emits a response-bound, replayable receipt. */
export async function invokeAgentGymModel(
  rawRequest: AgentGymModelInvocationRequestV1,
  budget: AgentGymModelBudgetV1,
  model: AgentGymModelPort,
  evaluatedAt: string,
): Promise<AgentGymModelInvocationResultV1> {
  const request = validateAgentGymModelRequest(rawRequest);
  timestamp(evaluatedAt);
  const requestDigest = agentGymModelRequestDigest(request);
  const response = validateAgentGymModelResponse(await model.invoke(request));
  if (response.invocation_ref !== request.invocation_ref
    || response.model_id !== request.model_id
    || response.request_digest !== requestDigest) invalidBinding();
  const budgetEvaluation = evaluateAgentGymModelBudget(budget, [response]);
  const receipt = Object.freeze({
    budget: budgetEvaluation,
    candidate_ref: request.candidate_ref,
    evaluated_at: evaluatedAt,
    invocation_ref: request.invocation_ref,
    latency_ms: response.latency_ms,
    model_id: response.model_id,
    ...(response.provider_request_ref === undefined
      ? {}
      : { provider_request_ref: response.provider_request_ref }),
    request_digest: requestDigest,
    response_digest: digest(response),
    response_source: response.response_source,
    schema_version: "agent-gym-model-invocation-receipt/v1" as const,
    stop_reason: response.stop_reason,
    token_usage: response.token_usage,
  });
  return Object.freeze({ receipt, response });
}

function digest(value: AgentGymModelResponseV1): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(JSON.stringify(value)).digest("hex")}`;
}

function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || !Number.isFinite(Date.parse(value))) {
    throw new AgentGymContractError("Agent gym model invocation time is invalid.");
  }
}

function invalidBinding(): never {
  throw new AgentGymContractError("Agent gym model invocation binding is invalid.");
}
