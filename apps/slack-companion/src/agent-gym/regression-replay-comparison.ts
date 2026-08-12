import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import { validateAgentGymRegressionReplayEvaluation, type AgentGymRegressionReplayEvaluationV1 } from "./regression-replay-evaluation.js";
import { validateAgentGymRegressionReplayResult, type AgentGymRegressionReplayResultV1 } from "./regression-replay-result.js";

export interface AgentGymRegressionReplayComparisonV1 {
  readonly baseline_candidate_ref: string;
  readonly challenger_candidate_ref: string;
  readonly compared_at: string;
  readonly comparison_digest: string;
  readonly comparison_ref: string;
  readonly evaluation_digest: string;
  readonly latency_delta_ms: number;
  readonly outcome: "equivalent" | "improved" | "regressed";
  readonly replay_result_digest: string;
  readonly safety_regressed: boolean;
  readonly schema_version: "agent-gym-regression-replay-comparison/v1";
  readonly score_delta: number;
}

/** Produces a deterministic paired comparison from sealed result and evaluator evidence. */
export function compareAgentGymRegressionReplay(
  resultValue: AgentGymRegressionReplayResultV1,
  evaluationValue: AgentGymRegressionReplayEvaluationV1,
  input: Pick<AgentGymRegressionReplayComparisonV1, "compared_at" | "comparison_ref">,
): AgentGymRegressionReplayComparisonV1 {
  const result = validateAgentGymRegressionReplayResult(resultValue);
  const evaluation = validateAgentGymRegressionReplayEvaluation(evaluationValue);
  reference(input.comparison_ref); timestamp(input.compared_at);
  if (evaluation.replay_result_digest !== result.result_digest
    || evaluation.baseline.candidate_ref !== result.baseline.candidate_ref
    || evaluation.challenger.candidate_ref !== result.challenger.candidate_ref
    || Date.parse(input.compared_at) < Date.parse(evaluation.evaluated_at)) invalid();
  const scoreDelta = rounded(evaluation.challenger.score - evaluation.baseline.score);
  const safetyRegressed = evaluation.baseline.safety_passed && !evaluation.challenger.safety_passed;
  const outcome: AgentGymRegressionReplayComparisonV1["outcome"] = safetyRegressed || scoreDelta < -0.001
    ? "regressed" : scoreDelta > 0.001 ? "improved" : "equivalent";
  const body = {
    baseline_candidate_ref: result.baseline.candidate_ref, challenger_candidate_ref: result.challenger.candidate_ref,
    compared_at: input.compared_at, comparison_ref: input.comparison_ref, evaluation_digest: evaluation.evaluation_digest,
    latency_delta_ms: result.challenger.latency_ms - result.baseline.latency_ms, outcome,
    replay_result_digest: result.result_digest, safety_regressed: safetyRegressed,
    schema_version: "agent-gym-regression-replay-comparison/v1" as const, score_delta: scoreDelta,
  };
  return Object.freeze({ ...body, comparison_digest: digestAgentGymJson(body) });
}

export function validateAgentGymRegressionReplayComparison(value: AgentGymRegressionReplayComparisonV1): AgentGymRegressionReplayComparisonV1 {
  if (value.schema_version !== "agent-gym-regression-replay-comparison/v1") invalid();
  for (const ref of [value.baseline_candidate_ref, value.challenger_candidate_ref, value.comparison_ref]) reference(ref);
  for (const item of [value.comparison_digest, value.evaluation_digest, value.replay_result_digest]) digest(item);
  timestamp(value.compared_at);
  if (value.baseline_candidate_ref === value.challenger_candidate_ref || !Number.isSafeInteger(value.latency_delta_ms)
    || !Number.isFinite(value.score_delta) || !["equivalent", "improved", "regressed"].includes(value.outcome)
    || (value.safety_regressed && value.outcome !== "regressed")) invalid();
  const { comparison_digest: _digest, ...body } = value;
  if (digestAgentGymJson(body) !== value.comparison_digest) invalid();
  return Object.freeze({ ...value });
}

function rounded(value: number): number { return Math.round(value * 1_000_000) / 1_000_000; }
function reference(value: string): void { if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid(); }
function timestamp(value: string): void { if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) invalid(); }
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function invalid(): never { throw new AgentGymContractError("Agent gym regression replay comparison is invalid."); }
