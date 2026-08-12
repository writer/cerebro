import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import { validateAgentGymRegressionReplayComparison, type AgentGymRegressionReplayComparisonV1 } from "./regression-replay-comparison.js";
import { validateAgentGymRegressionReplayEvaluation, type AgentGymRegressionReplayEvaluationV1 } from "./regression-replay-evaluation.js";

export interface AgentGymRegressionReplayAdmissionPolicyV1 {
  readonly maximum_latency_increase_ms: number;
  readonly minimum_challenger_score: number;
  readonly minimum_score_delta: number;
  readonly policy_ref: string;
  readonly schema_version: "agent-gym-regression-replay-admission-policy/v1";
}

export interface AgentGymRegressionReplayAdmissionV1 {
  readonly admitted_at: string;
  readonly admission_digest: string;
  readonly admission_ref: string;
  readonly blocker_codes: readonly string[];
  readonly challenger_candidate_ref: string;
  readonly comparison_digest: string;
  readonly decision: "admitted" | "blocked";
  readonly evaluation_digest: string;
  readonly policy_digest: string;
  readonly schema_version: "agent-gym-regression-replay-admission/v1";
}

/** Admits a challenger only when every regression, safety, quality, and latency gate passes. */
export function admitAgentGymRegressionReplay(
  comparisonValue: AgentGymRegressionReplayComparisonV1,
  evaluationValue: AgentGymRegressionReplayEvaluationV1,
  policyValue: AgentGymRegressionReplayAdmissionPolicyV1,
  input: Pick<AgentGymRegressionReplayAdmissionV1, "admitted_at" | "admission_ref">,
): AgentGymRegressionReplayAdmissionV1 {
  const comparison = validateAgentGymRegressionReplayComparison(comparisonValue);
  const evaluation = validateAgentGymRegressionReplayEvaluation(evaluationValue);
  const policy = validatePolicy(policyValue);
  reference(input.admission_ref); timestamp(input.admitted_at);
  if (comparison.evaluation_digest !== evaluation.evaluation_digest
    || comparison.challenger_candidate_ref !== evaluation.challenger.candidate_ref
    || Date.parse(input.admitted_at) < Date.parse(comparison.compared_at)) invalid();
  const blockers = new Set<string>(evaluation.challenger.blocker_codes);
  if (!evaluation.challenger.safety_passed) blockers.add("challenger_safety_failed");
  if (evaluation.challenger.score < policy.minimum_challenger_score) blockers.add("challenger_score_below_minimum");
  if (comparison.score_delta < policy.minimum_score_delta) blockers.add("score_delta_below_minimum");
  if (comparison.latency_delta_ms > policy.maximum_latency_increase_ms) blockers.add("latency_increase_exceeded");
  if (comparison.outcome === "regressed") blockers.add("regression_detected");
  const blockerCodes = Object.freeze([...blockers].sort());
  const body = {
    admitted_at: input.admitted_at, admission_ref: input.admission_ref, blocker_codes: blockerCodes,
    challenger_candidate_ref: comparison.challenger_candidate_ref, comparison_digest: comparison.comparison_digest,
    decision: blockerCodes.length === 0 ? "admitted" as const : "blocked" as const,
    evaluation_digest: evaluation.evaluation_digest, policy_digest: digestAgentGymJson(policyBody(policy)),
    schema_version: "agent-gym-regression-replay-admission/v1" as const,
  };
  return Object.freeze({ ...body, admission_digest: digestAgentGymJson(body) });
}

export function validateAgentGymRegressionReplayAdmission(value: AgentGymRegressionReplayAdmissionV1): AgentGymRegressionReplayAdmissionV1 {
  if (value.schema_version !== "agent-gym-regression-replay-admission/v1") invalid();
  reference(value.admission_ref); reference(value.challenger_candidate_ref); timestamp(value.admitted_at);
  for (const item of [value.admission_digest, value.comparison_digest, value.evaluation_digest, value.policy_digest]) digest(item);
  if (!Array.isArray(value.blocker_codes) || value.blocker_codes.some((code) => !/^[a-z][a-z0-9_.-]{0,79}$/u.test(code))
    || new Set(value.blocker_codes).size !== value.blocker_codes.length
    || (value.decision === "admitted") !== (value.blocker_codes.length === 0)) invalid();
  const body = { admitted_at: value.admitted_at, admission_ref: value.admission_ref,
    blocker_codes: Object.freeze([...value.blocker_codes].sort()), challenger_candidate_ref: value.challenger_candidate_ref,
    comparison_digest: value.comparison_digest, decision: value.decision, evaluation_digest: value.evaluation_digest,
    policy_digest: value.policy_digest, schema_version: value.schema_version };
  if (digestAgentGymJson(body) !== value.admission_digest) invalid();
  return Object.freeze({ ...value, blocker_codes: body.blocker_codes });
}

function validatePolicy(value: AgentGymRegressionReplayAdmissionPolicyV1): AgentGymRegressionReplayAdmissionPolicyV1 {
  if (value.schema_version !== "agent-gym-regression-replay-admission-policy/v1") invalid();
  reference(value.policy_ref);
  if (!Number.isSafeInteger(value.maximum_latency_increase_ms) || value.maximum_latency_increase_ms < 0
    || !Number.isFinite(value.minimum_challenger_score) || value.minimum_challenger_score < 0 || value.minimum_challenger_score > 1
    || !Number.isFinite(value.minimum_score_delta) || value.minimum_score_delta < -1 || value.minimum_score_delta > 1) invalid();
  return Object.freeze({ ...value });
}
function policyBody(value: AgentGymRegressionReplayAdmissionPolicyV1) { return { maximum_latency_increase_ms: value.maximum_latency_increase_ms, minimum_challenger_score: value.minimum_challenger_score, minimum_score_delta: value.minimum_score_delta, policy_ref: value.policy_ref, schema_version: value.schema_version }; }
function reference(value: string): void { if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid(); }
function timestamp(value: string): void { if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) invalid(); }
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function invalid(): never { throw new AgentGymContractError("Agent gym regression replay admission is invalid."); }
