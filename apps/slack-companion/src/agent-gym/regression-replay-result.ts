import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import { validateAgentGymRegressionReplayPlan, type AgentGymRegressionReplayPlanV1 } from "./regression-replay-plan.js";

export interface AgentGymRegressionReplayCandidateResultV1 {
  readonly candidate_ref: string;
  readonly invocation_receipt_digest: string;
  readonly invocation_ref: string;
  readonly latency_ms: number;
  readonly response_digest: string;
  readonly total_tokens: number;
}

export interface AgentGymRegressionReplayResultV1 {
  readonly baseline: AgentGymRegressionReplayCandidateResultV1;
  readonly case_digest: string;
  readonly case_ref: string;
  readonly challenger: AgentGymRegressionReplayCandidateResultV1;
  readonly completed_at: string;
  readonly plan_digest: string;
  readonly result_digest: string;
  readonly result_ref: string;
  readonly schema_version: "agent-gym-regression-replay-result/v1";
}

/** Records the two response-bound outcomes without retaining model output text. */
export function recordAgentGymRegressionReplayResult(
  planValue: AgentGymRegressionReplayPlanV1,
  input: Pick<AgentGymRegressionReplayResultV1, "baseline" | "challenger" | "completed_at" | "result_ref">,
): AgentGymRegressionReplayResultV1 {
  const plan = validateAgentGymRegressionReplayPlan(planValue);
  reference(input.result_ref); timestamp(input.completed_at);
  candidate(input.baseline); candidate(input.challenger);
  if (input.baseline.invocation_ref !== plan.baseline_invocation_ref
    || input.challenger.invocation_ref !== plan.challenger_invocation_ref
    || input.baseline.candidate_ref === input.challenger.candidate_ref
    || input.baseline.response_digest === input.challenger.response_digest
    || Date.parse(input.completed_at) < Date.parse(plan.planned_at)) invalid();
  const baseline = candidateBody(input.baseline);
  const challenger = candidateBody(input.challenger);
  const body = {
    baseline, case_digest: plan.case_digest, case_ref: plan.case_ref,
    challenger, completed_at: input.completed_at,
    plan_digest: plan.plan_digest, result_ref: input.result_ref,
    schema_version: "agent-gym-regression-replay-result/v1" as const,
  };
  return Object.freeze({ ...body, result_digest: digestAgentGymJson(body) });
}

export function validateAgentGymRegressionReplayResult(value: AgentGymRegressionReplayResultV1): AgentGymRegressionReplayResultV1 {
  if (value.schema_version !== "agent-gym-regression-replay-result/v1") invalid();
  reference(value.case_ref); reference(value.result_ref); timestamp(value.completed_at);
  candidate(value.baseline); candidate(value.challenger);
  for (const item of [value.case_digest, value.plan_digest, value.result_digest]) digest(item);
  if (value.baseline.candidate_ref === value.challenger.candidate_ref
    || value.baseline.invocation_ref === value.challenger.invocation_ref
    || value.baseline.response_digest === value.challenger.response_digest) invalid();
  const body = {
    baseline: candidateBody(value.baseline), case_digest: value.case_digest, case_ref: value.case_ref,
    challenger: candidateBody(value.challenger), completed_at: value.completed_at, plan_digest: value.plan_digest,
    result_ref: value.result_ref, schema_version: value.schema_version,
  };
  if (digestAgentGymJson(body) !== value.result_digest) invalid();
  return Object.freeze({ ...value, baseline: Object.freeze({ ...value.baseline }), challenger: Object.freeze({ ...value.challenger }) });
}

function candidateBody(value: AgentGymRegressionReplayCandidateResultV1) {
  return Object.freeze({ candidate_ref: value.candidate_ref, invocation_receipt_digest: value.invocation_receipt_digest,
    invocation_ref: value.invocation_ref, latency_ms: value.latency_ms, response_digest: value.response_digest,
    total_tokens: value.total_tokens });
}

function candidate(value: AgentGymRegressionReplayCandidateResultV1): void {
  reference(value.candidate_ref); reference(value.invocation_ref);
  digest(value.invocation_receipt_digest); digest(value.response_digest);
  if (!Number.isSafeInteger(value.latency_ms) || value.latency_ms < 0
    || !Number.isSafeInteger(value.total_tokens) || value.total_tokens < 0) invalid();
}
function reference(value: string): void { if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid(); }
function timestamp(value: string): void { if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) invalid(); }
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function invalid(): never { throw new AgentGymContractError("Agent gym regression replay result is invalid."); }
