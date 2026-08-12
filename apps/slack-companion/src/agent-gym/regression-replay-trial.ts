import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import { validateAgentGymRegressionReplayComparison, type AgentGymRegressionReplayComparisonV1 } from "./regression-replay-comparison.js";
import { validateAgentGymRegressionReplayEvaluation, type AgentGymRegressionReplayEvaluationV1 } from "./regression-replay-evaluation.js";
import { validateAgentGymRegressionReplayEvaluatorBinding, type AgentGymRegressionReplayEvaluatorBindingV1 } from "./regression-replay-evaluator-binding.js";
import { validateAgentGymRegressionReplayPlan, type AgentGymRegressionReplayPlanV1 } from "./regression-replay-plan.js";
import { validateAgentGymRegressionReplayResult, type AgentGymRegressionReplayResultV1 } from "./regression-replay-result.js";

export interface AgentGymRegressionReplayTrialV1 {
  readonly baseline_candidate_ref: string;
  readonly case_digest: string;
  readonly case_ref: string;
  readonly challenger_candidate_ref: string;
  readonly comparison_digest: string;
  readonly completed_at: string;
  readonly evaluation_digest: string;
  readonly evaluator_admission_digest: string;
  readonly evaluator_binding_digest: string;
  readonly evaluator_digests: readonly string[];
  readonly outcome: AgentGymRegressionReplayComparisonV1["outcome"];
  readonly plan_digest: string;
  readonly replay_result_digest: string;
  readonly rubric_digest: string;
  readonly schema_version: "agent-gym-regression-replay-trial/v1";
  readonly trial_digest: string;
  readonly trial_ref: string;
}

/** Seals one complete, text-free replay chain for campaign aggregation. */
export function sealAgentGymRegressionReplayTrial(
  planValue: AgentGymRegressionReplayPlanV1,
  resultValue: AgentGymRegressionReplayResultV1,
  bindingValue: AgentGymRegressionReplayEvaluatorBindingV1,
  evaluationValue: AgentGymRegressionReplayEvaluationV1,
  comparisonValue: AgentGymRegressionReplayComparisonV1,
  input: Pick<AgentGymRegressionReplayTrialV1, "completed_at" | "trial_ref">,
): AgentGymRegressionReplayTrialV1 {
  const plan = validateAgentGymRegressionReplayPlan(planValue);
  const result = validateAgentGymRegressionReplayResult(resultValue);
  const binding = validateAgentGymRegressionReplayEvaluatorBinding(bindingValue);
  const evaluation = validateAgentGymRegressionReplayEvaluation(evaluationValue);
  const comparison = validateAgentGymRegressionReplayComparison(comparisonValue);
  reference(input.trial_ref);
  timestamp(input.completed_at);
  if (result.plan_digest !== plan.plan_digest
    || result.case_ref !== plan.case_ref || result.case_digest !== plan.case_digest
    || binding.replay_result_digest !== result.result_digest
    || binding.baseline_candidate_ref !== result.baseline.candidate_ref
    || binding.challenger_candidate_ref !== result.challenger.candidate_ref
    || evaluation.replay_result_digest !== result.result_digest
    || comparison.replay_result_digest !== result.result_digest
    || comparison.evaluation_digest !== evaluation.evaluation_digest
    || comparison.baseline_candidate_ref !== result.baseline.candidate_ref
    || comparison.challenger_candidate_ref !== result.challenger.candidate_ref
    || Date.parse(input.completed_at) < Date.parse(comparison.compared_at)) invalid();
  const body = {
    baseline_candidate_ref: result.baseline.candidate_ref,
    case_digest: result.case_digest,
    case_ref: result.case_ref,
    challenger_candidate_ref: result.challenger.candidate_ref,
    comparison_digest: comparison.comparison_digest,
    completed_at: input.completed_at,
    evaluation_digest: evaluation.evaluation_digest,
    evaluator_admission_digest: binding.evaluator_admission_digest,
    evaluator_binding_digest: binding.binding_digest,
    evaluator_digests: [...binding.evaluator_digests],
    outcome: comparison.outcome,
    plan_digest: plan.plan_digest,
    replay_result_digest: result.result_digest,
    rubric_digest: binding.rubric_digest,
    schema_version: "agent-gym-regression-replay-trial/v1" as const,
    trial_ref: input.trial_ref,
  };
  return Object.freeze({ ...body, evaluator_digests: Object.freeze(body.evaluator_digests),
    trial_digest: digestAgentGymJson(body) });
}

export function validateAgentGymRegressionReplayTrial(
  value: AgentGymRegressionReplayTrialV1,
): AgentGymRegressionReplayTrialV1 {
  if (value.schema_version !== "agent-gym-regression-replay-trial/v1") invalid();
  for (const ref of [value.baseline_candidate_ref, value.case_ref,
    value.challenger_candidate_ref, value.trial_ref]) reference(ref);
  for (const item of [value.case_digest, value.comparison_digest, value.evaluation_digest,
    value.evaluator_admission_digest, value.evaluator_binding_digest, value.plan_digest,
    value.replay_result_digest, value.rubric_digest, value.trial_digest]) digest(item);
  if (!Array.isArray(value.evaluator_digests) || value.evaluator_digests.length < 1
    || value.evaluator_digests.length > 2
    || new Set(value.evaluator_digests).size !== value.evaluator_digests.length) invalid();
  value.evaluator_digests.forEach(digest);
  timestamp(value.completed_at);
  if (value.baseline_candidate_ref === value.challenger_candidate_ref
    || !["equivalent", "improved", "regressed"].includes(value.outcome)) invalid();
  const { trial_digest: _digest, ...body } = value;
  if (digestAgentGymJson(body) !== value.trial_digest) invalid();
  return Object.freeze({ ...value, evaluator_digests: Object.freeze([...value.evaluator_digests]) });
}

function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240
    || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || !Number.isFinite(Date.parse(value))) invalid();
}
function digest(value: string): void {
  if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid();
}
function invalid(): never {
  throw new AgentGymContractError("Agent gym regression replay trial is invalid.");
}
