import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  defineAgentGymEvaluatorManifest,
  type AgentGymEvaluatorManifestV1,
} from "./evaluator-manifest.js";

export interface AgentGymCalibrationPolicyV1 {
  readonly maximum_mean_absolute_error: number;
  readonly maximum_sample_absolute_error: number;
  readonly minimum_sample_count: number;
  readonly policy_ref: string;
  readonly schema_version: "agent-gym-calibration-policy/v1";
}

export interface AgentGymCalibrationSampleV1 {
  readonly expected_score: number;
  readonly observed_score: number;
  readonly sample_ref: string;
}

export interface AgentGymEvaluatorCalibrationV1 {
  readonly calibration_dataset_digest: string;
  readonly calibration_digest: string;
  readonly calibrated_at: string;
  readonly evaluator_digest: string;
  readonly maximum_absolute_error: number;
  readonly mean_absolute_error: number;
  readonly passed: boolean;
  readonly policy_ref: string;
  readonly sample_count: number;
  readonly schema_version: "agent-gym-evaluator-calibration/v1";
}

/** Measures one model judge against a sealed human-labeled calibration set. */
export function calibrateAgentGymEvaluator(
  evaluator: AgentGymEvaluatorManifestV1,
  policy: AgentGymCalibrationPolicyV1,
  input: {
    readonly calibrated_at: string;
    readonly calibration_dataset_digest: string;
    readonly samples: readonly AgentGymCalibrationSampleV1[];
  },
): AgentGymEvaluatorCalibrationV1 {
  validateEvaluator(evaluator);
  if (evaluator.evaluator_kind !== "model_judge") invalid();
  validatePolicy(policy);
  timestamp(input.calibrated_at);
  digest(input.calibration_dataset_digest);
  if (!Array.isArray(input.samples) || input.samples.length > 10_000) invalid();
  const sampleRefs = new Set<string>();
  const errors = input.samples.map((sample) => {
    reference(sample.sample_ref);
    if (sampleRefs.has(sample.sample_ref)) invalid();
    sampleRefs.add(sample.sample_ref);
    unit(sample.expected_score);
    unit(sample.observed_score);
    return Math.abs(sample.expected_score - sample.observed_score);
  });
  const meanAbsoluteError = errors.length === 0
    ? 1
    : errors.reduce((total, value) => total + value, 0) / errors.length;
  const maximumAbsoluteError = errors.length === 0 ? 1 : Math.max(...errors);
  const body = {
    calibration_dataset_digest: input.calibration_dataset_digest,
    calibrated_at: input.calibrated_at,
    evaluator_digest: evaluator.evaluator_digest,
    maximum_absolute_error: maximumAbsoluteError,
    mean_absolute_error: meanAbsoluteError,
    passed: errors.length >= policy.minimum_sample_count
      && meanAbsoluteError <= policy.maximum_mean_absolute_error
      && maximumAbsoluteError <= policy.maximum_sample_absolute_error,
    policy_ref: policy.policy_ref,
    sample_count: errors.length,
    schema_version: "agent-gym-evaluator-calibration/v1" as const,
  };
  return Object.freeze({ ...body, calibration_digest: digestAgentGymJson(body) });
}

function validateEvaluator(value: AgentGymEvaluatorManifestV1): void {
  const expected = defineAgentGymEvaluatorManifest({
    evaluator_kind: value.evaluator_kind,
    evaluator_ref: value.evaluator_ref,
    implementation_digest: value.implementation_digest,
    ...(value.model === undefined ? {} : { model: value.model }),
    output_schema_digest: value.output_schema_digest,
    rubric_digest: value.rubric_digest,
    schema_version: value.schema_version,
  });
  if (expected.evaluator_digest !== value.evaluator_digest) invalid();
}
function validatePolicy(value: AgentGymCalibrationPolicyV1): void {
  if (value.schema_version !== "agent-gym-calibration-policy/v1") invalid();
  reference(value.policy_ref);
  unit(value.maximum_mean_absolute_error);
  unit(value.maximum_sample_absolute_error);
  if (value.maximum_mean_absolute_error > value.maximum_sample_absolute_error
    || !Number.isSafeInteger(value.minimum_sample_count)
    || value.minimum_sample_count < 1 || value.minimum_sample_count > 10_000) invalid();
}
function digest(value: string): void {
  if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid();
}
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) invalid();
}
function unit(value: number): void {
  if (!Number.isFinite(value) || value < 0 || value > 1) invalid();
}
function invalid(): never {
  throw new AgentGymContractError("Agent gym evaluator calibration is invalid.");
}
