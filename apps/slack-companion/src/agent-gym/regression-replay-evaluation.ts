import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import { validateAgentGymRegressionReplayResult, type AgentGymRegressionReplayResultV1 } from "./regression-replay-result.js";

export interface AgentGymRegressionReplayCandidateEvaluationV1 {
  readonly blocker_codes: readonly string[];
  readonly candidate_ref: string;
  readonly evidence_digest: string;
  readonly safety_passed: boolean;
  readonly score: number;
}

export interface AgentGymRegressionReplayEvaluationV1 {
  readonly baseline: AgentGymRegressionReplayCandidateEvaluationV1;
  readonly case_digest: string;
  readonly challenger: AgentGymRegressionReplayCandidateEvaluationV1;
  readonly evaluated_at: string;
  readonly evaluation_digest: string;
  readonly evaluation_ref: string;
  readonly replay_result_digest: string;
  readonly schema_version: "agent-gym-regression-replay-evaluation/v1";
}

/** Binds independent evaluator evidence to both replay candidates. */
export function evaluateAgentGymRegressionReplay(
  resultValue: AgentGymRegressionReplayResultV1,
  input: Pick<AgentGymRegressionReplayEvaluationV1, "baseline" | "challenger" | "evaluated_at" | "evaluation_ref">,
): AgentGymRegressionReplayEvaluationV1 {
  const result = validateAgentGymRegressionReplayResult(resultValue);
  reference(input.evaluation_ref); timestamp(input.evaluated_at);
  evaluation(input.baseline); evaluation(input.challenger);
  if (input.baseline.candidate_ref !== result.baseline.candidate_ref
    || input.challenger.candidate_ref !== result.challenger.candidate_ref
    || Date.parse(input.evaluated_at) < Date.parse(result.completed_at)) invalid();
  const body = {
    baseline: evaluationBody(input.baseline), case_digest: result.case_digest,
    challenger: evaluationBody(input.challenger), evaluated_at: input.evaluated_at,
    evaluation_ref: input.evaluation_ref, replay_result_digest: result.result_digest,
    schema_version: "agent-gym-regression-replay-evaluation/v1" as const,
  };
  return Object.freeze({ ...body, evaluation_digest: digestAgentGymJson(body) });
}

export function validateAgentGymRegressionReplayEvaluation(value: AgentGymRegressionReplayEvaluationV1): AgentGymRegressionReplayEvaluationV1 {
  if (value.schema_version !== "agent-gym-regression-replay-evaluation/v1") invalid();
  reference(value.evaluation_ref); timestamp(value.evaluated_at);
  evaluation(value.baseline); evaluation(value.challenger);
  for (const item of [value.case_digest, value.evaluation_digest, value.replay_result_digest]) digest(item);
  if (value.baseline.candidate_ref === value.challenger.candidate_ref) invalid();
  const body = { baseline: evaluationBody(value.baseline), case_digest: value.case_digest,
    challenger: evaluationBody(value.challenger), evaluated_at: value.evaluated_at, evaluation_ref: value.evaluation_ref,
    replay_result_digest: value.replay_result_digest, schema_version: value.schema_version };
  if (digestAgentGymJson(body) !== value.evaluation_digest) invalid();
  return Object.freeze({ ...value, baseline: evaluationBody(value.baseline), challenger: evaluationBody(value.challenger) });
}

function evaluation(value: AgentGymRegressionReplayCandidateEvaluationV1): void {
  reference(value.candidate_ref); digest(value.evidence_digest);
  if (!Number.isFinite(value.score) || value.score < 0 || value.score > 1 || typeof value.safety_passed !== "boolean"
    || !Array.isArray(value.blocker_codes) || value.blocker_codes.length > 100
    || value.blocker_codes.some((code) => !/^[a-z][a-z0-9_.-]{0,79}$/u.test(code))
    || new Set(value.blocker_codes).size !== value.blocker_codes.length
    || (value.safety_passed && value.blocker_codes.length > 0)) invalid();
}
function evaluationBody(value: AgentGymRegressionReplayCandidateEvaluationV1) {
  return Object.freeze({ blocker_codes: Object.freeze([...value.blocker_codes].sort()), candidate_ref: value.candidate_ref,
    evidence_digest: value.evidence_digest, safety_passed: value.safety_passed, score: value.score });
}
function reference(value: string): void { if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid(); }
function timestamp(value: string): void { if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) invalid(); }
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function invalid(): never { throw new AgentGymContractError("Agent gym regression replay evaluation is invalid."); }
