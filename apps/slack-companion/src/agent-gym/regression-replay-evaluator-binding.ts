import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import type { AgentGymEvaluatorAdmissionDecisionV1 } from "./evaluator-admission.js";
import { defineAgentGymEvaluatorManifest, type AgentGymEvaluatorManifestV1 } from "./evaluator-manifest.js";
import { defineAgentGymEvaluatorRubric, type AgentGymEvaluatorRubricV1 } from "./evaluator-rubric.js";
import { validateAgentGymRegressionReplayResult, type AgentGymRegressionReplayResultV1 } from "./regression-replay-result.js";

export interface AgentGymRegressionReplayEvaluatorBindingV1 {
  readonly baseline_candidate_ref: string;
  readonly binding_digest: string;
  readonly binding_ref: string;
  readonly bound_at: string;
  readonly challenger_candidate_ref: string;
  readonly evaluator_admission_digest: string;
  readonly evaluator_digests: readonly string[];
  readonly replay_result_digest: string;
  readonly rubric_digest: string;
  readonly schema_version: "agent-gym-regression-replay-evaluator-binding/v1";
}

/** Binds replay evaluation to an admitted rubric and exact evaluator implementations. */
export function bindAgentGymRegressionReplayEvaluators(
  resultValue: AgentGymRegressionReplayResultV1,
  rubricValue: AgentGymEvaluatorRubricV1,
  evaluatorValues: readonly AgentGymEvaluatorManifestV1[],
  admissionValue: AgentGymEvaluatorAdmissionDecisionV1,
  input: Pick<AgentGymRegressionReplayEvaluatorBindingV1, "binding_ref" | "bound_at">,
): AgentGymRegressionReplayEvaluatorBindingV1 {
  const result = validateAgentGymRegressionReplayResult(resultValue);
  const rubric = validateRubric(rubricValue);
  const evaluatorDigests = validateEvaluators(evaluatorValues, rubric.rubric_digest);
  validateAdmission(admissionValue);
  reference(input.binding_ref); timestamp(input.bound_at);
  if (!admissionValue.admitted || admissionValue.rubric_digest !== rubric.rubric_digest
    || admissionValue.evaluator_digests.length !== evaluatorDigests.length
    || admissionValue.evaluator_digests.some((value, index) => value !== evaluatorDigests[index])
    || Date.parse(input.bound_at) < Date.parse(admissionValue.decided_at)) invalid();
  const body = {
    baseline_candidate_ref: result.baseline.candidate_ref, binding_ref: input.binding_ref, bound_at: input.bound_at,
    challenger_candidate_ref: result.challenger.candidate_ref, evaluator_admission_digest: admissionValue.decision_digest,
    evaluator_digests: evaluatorDigests, replay_result_digest: result.result_digest, rubric_digest: rubric.rubric_digest,
    schema_version: "agent-gym-regression-replay-evaluator-binding/v1" as const,
  };
  return Object.freeze({ ...body, evaluator_digests: Object.freeze(evaluatorDigests), binding_digest: digestAgentGymJson(body) });
}

export function validateAgentGymRegressionReplayEvaluatorBinding(value: AgentGymRegressionReplayEvaluatorBindingV1): AgentGymRegressionReplayEvaluatorBindingV1 {
  if (value.schema_version !== "agent-gym-regression-replay-evaluator-binding/v1") invalid();
  for (const ref of [value.baseline_candidate_ref, value.binding_ref, value.challenger_candidate_ref]) reference(ref);
  timestamp(value.bound_at);
  for (const item of [value.binding_digest, value.evaluator_admission_digest, value.replay_result_digest, value.rubric_digest]) digest(item);
  if (value.baseline_candidate_ref === value.challenger_candidate_ref || !Array.isArray(value.evaluator_digests)
    || value.evaluator_digests.length < 1 || value.evaluator_digests.length > 2
    || new Set(value.evaluator_digests).size !== value.evaluator_digests.length) invalid();
  value.evaluator_digests.forEach(digest);
  const { binding_digest: _digest, ...body } = value;
  if (digestAgentGymJson(body) !== value.binding_digest) invalid();
  return Object.freeze({ ...value, evaluator_digests: Object.freeze([...value.evaluator_digests]) });
}

function validateRubric(value: AgentGymEvaluatorRubricV1) {
  const expected = defineAgentGymEvaluatorRubric({ metrics: value.metrics, rubric_ref: value.rubric_ref, schema_version: value.schema_version });
  if (expected.rubric_digest !== value.rubric_digest) invalid(); return expected;
}
function validateEvaluators(values: readonly AgentGymEvaluatorManifestV1[], rubricDigest: string): string[] {
  if (!Array.isArray(values) || values.length < 1 || values.length > 2) invalid();
  const kinds = new Set<string>();
  const digests = values.map((value) => {
    const expected = defineAgentGymEvaluatorManifest({ evaluator_kind: value.evaluator_kind, evaluator_ref: value.evaluator_ref,
      implementation_digest: value.implementation_digest, ...(value.model === undefined ? {} : { model: value.model }),
      output_schema_digest: value.output_schema_digest, rubric_digest: value.rubric_digest, schema_version: value.schema_version });
    if (expected.evaluator_digest !== value.evaluator_digest || value.rubric_digest !== rubricDigest || kinds.has(value.evaluator_kind)) invalid();
    kinds.add(value.evaluator_kind); return value.evaluator_digest;
  }).sort();
  return digests;
}
function validateAdmission(value: AgentGymEvaluatorAdmissionDecisionV1): void {
  if (value.schema_version !== "agent-gym-evaluator-admission-decision/v1") invalid();
  timestamp(value.decided_at); reference(value.policy_ref); digest(value.decision_digest); digest(value.rubric_digest);
  const body = { admitted: value.admitted, blocker_codes: value.blocker_codes, calibration_digests: value.calibration_digests,
    decided_at: value.decided_at, evaluator_digests: value.evaluator_digests, policy_ref: value.policy_ref,
    rubric_digest: value.rubric_digest, schema_version: value.schema_version };
  if (digestAgentGymJson(body) !== value.decision_digest || value.admitted !== (value.blocker_codes.length === 0)) invalid();
}
function reference(value: string): void { if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid(); }
function timestamp(value: string): void { if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) invalid(); }
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function invalid(): never { throw new AgentGymContractError("Agent gym regression replay evaluator binding is invalid."); }
