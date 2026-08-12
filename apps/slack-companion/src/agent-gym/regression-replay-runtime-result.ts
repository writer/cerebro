import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import type { AgentGymModelInvocationReceiptV1 } from "./model-invocation.js";
import { validateAgentGymRegressionReplayPlan, type AgentGymRegressionReplayPlanV1 } from "./regression-replay-plan.js";
import { recordAgentGymRegressionReplayResult, type AgentGymRegressionReplayResultV1 } from "./regression-replay-result.js";
import type { AgentGymRegressionReplayExecutionV1 } from "./regression-replay-execution.js";

/** Converts a successful transient model execution into a text-free durable result. */
export function recordExecutedAgentGymRegressionReplay(
  planValue: AgentGymRegressionReplayPlanV1,
  execution: AgentGymRegressionReplayExecutionV1,
  input: Pick<AgentGymRegressionReplayResultV1, "completed_at" | "result_ref">,
): AgentGymRegressionReplayResultV1 {
  const plan = validateAgentGymRegressionReplayPlan(planValue);
  if (execution.schema_version !== "agent-gym-regression-replay-execution/v1"
    || execution.plan_digest !== plan.plan_digest || !execution.aggregate_budget.allowed
    || execution.batch.results.length !== 2 || execution.batch.ledger.invocation_count !== 2
    || execution.batch.ledger.blocked_invocation_count !== 0) invalid();
  const baseline = execution.batch.results[0]!;
  const challenger = execution.batch.results[1]!;
  if (baseline.receipt.invocation_ref !== plan.baseline_invocation_ref
    || challenger.receipt.invocation_ref !== plan.challenger_invocation_ref
    || !baseline.receipt.budget.allowed || !challenger.receipt.budget.allowed) invalid();
  return recordAgentGymRegressionReplayResult(plan, {
    baseline: candidateResult(baseline.receipt), challenger: candidateResult(challenger.receipt),
    completed_at: input.completed_at, result_ref: input.result_ref,
  });
}

function candidateResult(receipt: AgentGymModelInvocationReceiptV1) {
  return {
    candidate_ref: receipt.candidate_ref, invocation_receipt_digest: receiptDigest(receipt),
    invocation_ref: receipt.invocation_ref, latency_ms: receipt.latency_ms,
    response_digest: receipt.response_digest, total_tokens: receipt.token_usage.total_tokens,
  };
}

function receiptDigest(receipt: AgentGymModelInvocationReceiptV1): string {
  const body = {
    budget: { allowed: receipt.budget.allowed, blockers: [...receipt.budget.blockers],
      input_tokens: receipt.budget.input_tokens, invocation_count: receipt.budget.invocation_count,
      latency_ms: receipt.budget.latency_ms, output_tokens: receipt.budget.output_tokens,
      schema_version: receipt.budget.schema_version, total_tokens: receipt.budget.total_tokens },
    candidate_ref: receipt.candidate_ref, evaluated_at: receipt.evaluated_at,
    invocation_ref: receipt.invocation_ref, latency_ms: receipt.latency_ms, model_id: receipt.model_id,
    ...(receipt.provider_request_ref === undefined ? {} : { provider_request_ref: receipt.provider_request_ref }),
    request_digest: receipt.request_digest, response_digest: receipt.response_digest,
    response_source: receipt.response_source, schema_version: receipt.schema_version,
    stop_reason: receipt.stop_reason, token_usage: { input_tokens: receipt.token_usage.input_tokens,
      output_tokens: receipt.token_usage.output_tokens, total_tokens: receipt.token_usage.total_tokens },
  };
  return digestAgentGymJson(body);
}

function invalid(): never { throw new AgentGymContractError("Agent gym executed regression replay result is invalid."); }
