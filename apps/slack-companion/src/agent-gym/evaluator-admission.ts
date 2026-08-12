import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import type { AgentGymEvaluatorCalibrationV1 } from "./evaluator-calibration.js";
import {
  defineAgentGymEvaluatorManifest,
  type AgentGymEvaluatorManifestV1,
} from "./evaluator-manifest.js";
import {
  defineAgentGymEvaluatorRubric,
  type AgentGymEvaluatorRubricV1,
} from "./evaluator-rubric.js";

export type AgentGymEvaluatorAdmissionBlockerCode =
  | "evaluator.calibration_failed"
  | "evaluator.calibration_future"
  | "evaluator.calibration_missing"
  | "evaluator.calibration_policy_mismatch"
  | "evaluator.calibration_stale"
  | "evaluator.calibration_dataset_mismatch"
  | "evaluator.kind_missing"
  | "evaluator.rubric_mismatch";

export interface AgentGymEvaluatorAdmissionPolicyV1 {
  readonly maximum_calibration_age_ms: number;
  readonly policy_ref: string;
  readonly required_calibration_dataset_digest: string;
  readonly required_calibration_policy_digest: string;
  readonly schema_version: "agent-gym-evaluator-admission-policy/v1";
}

export interface AgentGymEvaluatorAdmissionDecisionV1 {
  readonly admitted: boolean;
  readonly blocker_codes: readonly AgentGymEvaluatorAdmissionBlockerCode[];
  readonly calibration_digests: readonly string[];
  readonly decided_at: string;
  readonly decision_digest: string;
  readonly evaluator_digests: readonly string[];
  readonly policy_ref: string;
  readonly rubric_digest: string;
  readonly schema_version: "agent-gym-evaluator-admission-decision/v1";
}

/** Fails evaluator admission closed when identity or calibration evidence is incomplete. */
export function decideAgentGymEvaluatorAdmission(
  rubric: AgentGymEvaluatorRubricV1,
  evaluators: readonly AgentGymEvaluatorManifestV1[],
  calibrations: readonly AgentGymEvaluatorCalibrationV1[],
  policy: AgentGymEvaluatorAdmissionPolicyV1,
  decidedAt: string,
): AgentGymEvaluatorAdmissionDecisionV1 {
  validateRubric(rubric);
  validatePolicy(policy);
  timestamp(decidedAt);
  if (!Array.isArray(evaluators) || evaluators.length === 0 || evaluators.length > 2
    || !Array.isArray(calibrations) || calibrations.length > 2) invalid();
  const blockerCodes = new Set<AgentGymEvaluatorAdmissionBlockerCode>();
  const evaluatorByKind = new Map<AgentGymEvaluatorManifestV1["evaluator_kind"], AgentGymEvaluatorManifestV1>();
  for (const evaluator of evaluators) {
    validateEvaluator(evaluator);
    if (evaluatorByKind.has(evaluator.evaluator_kind)) invalid();
    evaluatorByKind.set(evaluator.evaluator_kind, evaluator);
    if (evaluator.rubric_digest !== rubric.rubric_digest) blockerCodes.add("evaluator.rubric_mismatch");
  }
  const requiredKinds = new Set(rubric.metrics.map((metric) => metric.evaluator_kind));
  for (const kind of requiredKinds) if (!evaluatorByKind.has(kind)) blockerCodes.add("evaluator.kind_missing");
  const calibrationByEvaluator = new Map<string, AgentGymEvaluatorCalibrationV1>();
  const modelJudgeDigests = new Set(evaluators
    .filter((value) => value.evaluator_kind === "model_judge")
    .map((value) => value.evaluator_digest));
  for (const calibration of calibrations) {
    validateCalibration(calibration);
    if (!modelJudgeDigests.has(calibration.evaluator_digest)
      || calibrationByEvaluator.has(calibration.evaluator_digest)) invalid();
    calibrationByEvaluator.set(calibration.evaluator_digest, calibration);
  }
  const decidedTime = Date.parse(decidedAt);
  for (const evaluator of evaluators) {
    if (evaluator.evaluator_kind !== "model_judge") continue;
    const calibration = calibrationByEvaluator.get(evaluator.evaluator_digest);
    if (calibration === undefined) {
      blockerCodes.add("evaluator.calibration_missing");
      continue;
    }
    if (!calibration.passed) blockerCodes.add("evaluator.calibration_failed");
    if (calibration.calibration_dataset_digest !== policy.required_calibration_dataset_digest) {
      blockerCodes.add("evaluator.calibration_dataset_mismatch");
    }
    if (calibration.policy_digest !== policy.required_calibration_policy_digest) {
      blockerCodes.add("evaluator.calibration_policy_mismatch");
    }
    const calibratedTime = Date.parse(calibration.calibrated_at);
    if (calibratedTime > decidedTime) blockerCodes.add("evaluator.calibration_future");
    if (decidedTime - calibratedTime > policy.maximum_calibration_age_ms) {
      blockerCodes.add("evaluator.calibration_stale");
    }
  }
  const blockers = [...blockerCodes].sort();
  const body = {
    admitted: blockers.length === 0,
    blocker_codes: blockers,
    calibration_digests: [...calibrations.map((value) => value.calibration_digest)].sort(),
    decided_at: decidedAt,
    evaluator_digests: [...evaluators.map((value) => value.evaluator_digest)].sort(),
    policy_ref: policy.policy_ref,
    rubric_digest: rubric.rubric_digest,
    schema_version: "agent-gym-evaluator-admission-decision/v1" as const,
  };
  return Object.freeze({
    ...body,
    blocker_codes: Object.freeze(blockers),
    calibration_digests: Object.freeze(body.calibration_digests),
    evaluator_digests: Object.freeze(body.evaluator_digests),
    decision_digest: digestAgentGymJson(body),
  });
}

function validateRubric(value: AgentGymEvaluatorRubricV1): void {
  if (defineAgentGymEvaluatorRubric({
    metrics: value.metrics,
    rubric_ref: value.rubric_ref,
    schema_version: value.schema_version,
  }).rubric_digest !== value.rubric_digest) invalid();
}
function validateEvaluator(value: AgentGymEvaluatorManifestV1): void {
  if (defineAgentGymEvaluatorManifest({
    evaluator_kind: value.evaluator_kind,
    evaluator_ref: value.evaluator_ref,
    implementation_digest: value.implementation_digest,
    ...(value.model === undefined ? {} : { model: value.model }),
    output_schema_digest: value.output_schema_digest,
    rubric_digest: value.rubric_digest,
    schema_version: value.schema_version,
  }).evaluator_digest !== value.evaluator_digest) invalid();
}
function validateCalibration(value: AgentGymEvaluatorCalibrationV1): void {
  if (value.schema_version !== "agent-gym-evaluator-calibration/v1") invalid();
  timestamp(value.calibrated_at);
  for (const digest of [value.calibration_dataset_digest, value.evaluator_digest,
    value.calibration_digest, value.policy_digest]) digestValue(digest);
  reference(value.policy_ref);
  unit(value.maximum_absolute_error);
  unit(value.mean_absolute_error);
  if (value.mean_absolute_error > value.maximum_absolute_error
    || !Number.isSafeInteger(value.sample_count) || value.sample_count < 0 || value.sample_count > 10_000) invalid();
  const body = {
    calibration_dataset_digest: value.calibration_dataset_digest,
    calibrated_at: value.calibrated_at,
    evaluator_digest: value.evaluator_digest,
    maximum_absolute_error: value.maximum_absolute_error,
    mean_absolute_error: value.mean_absolute_error,
    passed: value.passed,
    policy_digest: value.policy_digest,
    policy_ref: value.policy_ref,
    sample_count: value.sample_count,
    schema_version: value.schema_version,
  };
  if (digestAgentGymJson(body) !== value.calibration_digest) invalid();
}
function validatePolicy(value: AgentGymEvaluatorAdmissionPolicyV1): void {
  if (value.schema_version !== "agent-gym-evaluator-admission-policy/v1") invalid();
  reference(value.policy_ref);
  digestValue(value.required_calibration_dataset_digest);
  digestValue(value.required_calibration_policy_digest);
  if (!Number.isSafeInteger(value.maximum_calibration_age_ms)
    || value.maximum_calibration_age_ms < 1 || value.maximum_calibration_age_ms > 366 * 24 * 60 * 60 * 1_000) invalid();
}
function digestValue(value: string): void {
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
  throw new AgentGymContractError("Agent gym evaluator admission is invalid.");
}
