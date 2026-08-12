import { AgentGymContractError } from "./index.js";
import {
  type AgentGymModelResponseV1,
  validateAgentGymModelResponse,
} from "./model-runtime.js";

export interface AgentGymModelBudgetV1 {
  readonly max_input_tokens: number;
  readonly max_invocations: number;
  readonly max_latency_ms: number;
  readonly max_output_tokens: number;
  readonly max_total_tokens: number;
  readonly schema_version: "agent-gym-model-budget/v1";
}

export interface AgentGymModelBudgetEvaluationV1 {
  readonly allowed: boolean;
  readonly blockers: readonly string[];
  readonly input_tokens: number;
  readonly invocation_count: number;
  readonly latency_ms: number;
  readonly output_tokens: number;
  readonly schema_version: "agent-gym-model-budget-evaluation/v1";
  readonly total_tokens: number;
}

/** Evaluates aggregate replay use without hiding which limit was exceeded. */
export function evaluateAgentGymModelBudget(
  rawBudget: AgentGymModelBudgetV1,
  rawResponses: readonly AgentGymModelResponseV1[],
): AgentGymModelBudgetEvaluationV1 {
  const budget = validateBudget(rawBudget);
  if (!Array.isArray(rawResponses) || rawResponses.length > 10_000) invalidBudget();
  const invocationRefs = new Set<string>();
  const responses = rawResponses.map((rawResponse) => {
    const response = validateAgentGymModelResponse(rawResponse);
    if (invocationRefs.has(response.invocation_ref)) invalidBudget();
    invocationRefs.add(response.invocation_ref);
    return response;
  });
  const inputTokens = sum(responses.map((response) => response.token_usage.input_tokens));
  const outputTokens = sum(responses.map((response) => response.token_usage.output_tokens));
  const totalTokens = sum(responses.map((response) => response.token_usage.total_tokens));
  const latencyMs = sum(responses.map((response) => response.latency_ms));
  const blockers = [
    responses.length > budget.max_invocations ? "model_invocations_exceeded" : undefined,
    inputTokens > budget.max_input_tokens ? "model_input_tokens_exceeded" : undefined,
    outputTokens > budget.max_output_tokens ? "model_output_tokens_exceeded" : undefined,
    totalTokens > budget.max_total_tokens ? "model_total_tokens_exceeded" : undefined,
    latencyMs > budget.max_latency_ms ? "model_latency_exceeded" : undefined,
  ].filter((value): value is string => value !== undefined);
  return Object.freeze({
    allowed: blockers.length === 0,
    blockers: Object.freeze(blockers),
    input_tokens: inputTokens,
    invocation_count: responses.length,
    latency_ms: latencyMs,
    output_tokens: outputTokens,
    schema_version: "agent-gym-model-budget-evaluation/v1",
    total_tokens: totalTokens,
  });
}

function validateBudget(budget: AgentGymModelBudgetV1): AgentGymModelBudgetV1 {
  if (budget.schema_version !== "agent-gym-model-budget/v1") invalidBudget();
  integer(budget.max_invocations, 10_000);
  integer(budget.max_input_tokens, 100_000_000);
  integer(budget.max_output_tokens, 100_000_000);
  integer(budget.max_total_tokens, 200_000_000);
  integer(budget.max_latency_ms, 24 * 60 * 60_000);
  return Object.freeze({ ...budget });
}

function integer(value: number, maximum: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) invalidBudget();
}

function sum(values: readonly number[]): number {
  return values.reduce((total, value) => total + value, 0);
}

function invalidBudget(): never {
  throw new AgentGymContractError("Agent gym model budget is invalid.");
}
