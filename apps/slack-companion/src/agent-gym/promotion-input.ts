import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymPairedCaseDeltaReport,
  type AgentGymPairedCaseDeltaReportV1,
} from "./paired-case-deltas.js";
import {
  validateAgentGymPairedEvaluation,
  type AgentGymPairedEvaluationV1,
} from "./paired-evaluation.js";
import {
  validateAgentGymPairedSliceReport,
  type AgentGymPairedSliceReportV1,
} from "./paired-slices.js";
import {
  validateAgentGymPairedUncertainty,
  type AgentGymPairedUncertaintyV1,
} from "./paired-uncertainty.js";

export type AgentGymPromotionInputBlockerCode =
  | "comparison.case_regression"
  | "comparison.confidence_below_minimum"
  | "comparison.interval_not_positive"
  | "comparison.mean_below_threshold"
  | "comparison.required_slice_missing"
  | "comparison.slice_regression";

export interface AgentGymPromotionInputPolicyV1 {
  readonly maximum_case_regressions: number;
  readonly minimum_mean_delta: number;
  readonly minimum_probability_positive: number;
  readonly policy_ref: string;
  readonly required_slice_ids: readonly string[];
  readonly schema_version: "agent-gym-promotion-input-policy/v1";
}

export interface AgentGymPromotionInputReceiptV1 {
  readonly baseline_candidate_ref: string;
  readonly blocker_codes: readonly AgentGymPromotionInputBlockerCode[];
  readonly candidate_ref: string;
  readonly case_delta_report_digest: string;
  readonly eligible: boolean;
  readonly evaluated_at: string;
  readonly pair_digest: string;
  readonly policy_digest: string;
  readonly policy_ref: string;
  readonly receipt_digest: string;
  readonly schema_version: "agent-gym-promotion-input-receipt/v1";
  readonly slice_report_digest: string;
  readonly uncertainty_digest: string;
}

/** Converts paired evidence into one policy-bound, fail-closed promotion input. */
export function issueAgentGymPromotionInput(
  pairInput: AgentGymPairedEvaluationV1,
  deltasInput: AgentGymPairedCaseDeltaReportV1,
  uncertaintyInput: AgentGymPairedUncertaintyV1,
  slicesInput: AgentGymPairedSliceReportV1,
  policy: AgentGymPromotionInputPolicyV1,
  evaluatedAt: string,
): AgentGymPromotionInputReceiptV1 {
  const pair = validateAgentGymPairedEvaluation(pairInput);
  const deltas = validateAgentGymPairedCaseDeltaReport(deltasInput);
  const uncertainty = validateAgentGymPairedUncertainty(uncertaintyInput);
  const slices = validateAgentGymPairedSliceReport(slicesInput);
  validatePolicy(policy);
  timestamp(evaluatedAt);
  if (deltas.pair_digest !== pair.pair_digest
    || uncertainty.delta_report_digest !== deltas.report_digest
    || slices.delta_report_digest !== deltas.report_digest
    || slices.suite_digest !== pair.suite_digest
    || Date.parse(evaluatedAt) < Date.parse(pair.paired_at)) invalid();
  const blockers = new Set<AgentGymPromotionInputBlockerCode>();
  if (deltas.mean_delta < policy.minimum_mean_delta) blockers.add("comparison.mean_below_threshold");
  if (deltas.regression_count > policy.maximum_case_regressions) blockers.add("comparison.case_regression");
  if (uncertainty.lower_bound <= 0) blockers.add("comparison.interval_not_positive");
  if (uncertainty.probability_positive < policy.minimum_probability_positive) {
    blockers.add("comparison.confidence_below_minimum");
  }
  const sliceById = new Map(slices.slices.map((slice) => [slice.slice_id, slice]));
  for (const sliceId of policy.required_slice_ids) {
    const slice = sliceById.get(sliceId);
    if (slice === undefined) blockers.add("comparison.required_slice_missing");
    else if (slice.delta < 0 || slice.regression_count > 0) blockers.add("comparison.slice_regression");
  }
  const blockerCodes = [...blockers].sort();
  const policyBody = {
    maximum_case_regressions: policy.maximum_case_regressions,
    minimum_mean_delta: policy.minimum_mean_delta,
    minimum_probability_positive: policy.minimum_probability_positive,
    policy_ref: policy.policy_ref,
    required_slice_ids: [...policy.required_slice_ids],
    schema_version: policy.schema_version,
  };
  const body = {
    baseline_candidate_ref: pair.baseline_candidate_ref,
    blocker_codes: blockerCodes,
    candidate_ref: pair.candidate_ref,
    case_delta_report_digest: deltas.report_digest,
    eligible: blockerCodes.length === 0,
    evaluated_at: evaluatedAt,
    pair_digest: pair.pair_digest,
    policy_digest: digestAgentGymJson(policyBody),
    policy_ref: policy.policy_ref,
    schema_version: "agent-gym-promotion-input-receipt/v1" as const,
    slice_report_digest: slices.report_digest,
    uncertainty_digest: uncertainty.uncertainty_digest,
  };
  return Object.freeze({
    ...body,
    blocker_codes: Object.freeze(blockerCodes),
    receipt_digest: digestAgentGymJson(body),
  });
}

export function validateAgentGymPromotionInput(
  value: AgentGymPromotionInputReceiptV1,
): AgentGymPromotionInputReceiptV1 {
  if (value.schema_version !== "agent-gym-promotion-input-receipt/v1") invalid();
  for (const ref of [value.baseline_candidate_ref, value.candidate_ref, value.policy_ref]) reference(ref);
  if (value.baseline_candidate_ref === value.candidate_ref) invalid();
  timestamp(value.evaluated_at);
  for (const digest of [value.case_delta_report_digest, value.pair_digest, value.policy_digest,
    value.receipt_digest, value.slice_report_digest, value.uncertainty_digest]) digestValue(digest);
  const allowed: readonly AgentGymPromotionInputBlockerCode[] = [
    "comparison.case_regression", "comparison.confidence_below_minimum",
    "comparison.interval_not_positive", "comparison.mean_below_threshold",
    "comparison.required_slice_missing", "comparison.slice_regression",
  ];
  if (!Array.isArray(value.blocker_codes) || value.blocker_codes.length > allowed.length
    || new Set(value.blocker_codes).size !== value.blocker_codes.length
    || value.blocker_codes.some((code) => !allowed.includes(code))
    || value.blocker_codes.some((code, index) => index > 0 && value.blocker_codes[index - 1]! >= code)
    || value.eligible !== (value.blocker_codes.length === 0)) invalid();
  const body = {
    baseline_candidate_ref: value.baseline_candidate_ref,
    blocker_codes: value.blocker_codes,
    candidate_ref: value.candidate_ref,
    case_delta_report_digest: value.case_delta_report_digest,
    eligible: value.eligible,
    evaluated_at: value.evaluated_at,
    pair_digest: value.pair_digest,
    policy_digest: value.policy_digest,
    policy_ref: value.policy_ref,
    schema_version: value.schema_version,
    slice_report_digest: value.slice_report_digest,
    uncertainty_digest: value.uncertainty_digest,
  };
  if (digestAgentGymJson(body) !== value.receipt_digest) invalid();
  return Object.freeze({ ...value, blocker_codes: Object.freeze([...value.blocker_codes]) });
}

function validatePolicy(value: AgentGymPromotionInputPolicyV1): void {
  if (value.schema_version !== "agent-gym-promotion-input-policy/v1") invalid();
  reference(value.policy_ref);
  finite(value.minimum_mean_delta, 0, 1);
  finite(value.minimum_probability_positive, 0.5, 1);
  if (!Number.isSafeInteger(value.maximum_case_regressions)
    || value.maximum_case_regressions < 0 || value.maximum_case_regressions > 100_000
    || !Array.isArray(value.required_slice_ids) || value.required_slice_ids.length > 1_000
    || new Set(value.required_slice_ids).size !== value.required_slice_ids.length) invalid();
  for (const sliceId of value.required_slice_ids) text(sliceId);
}
function digestValue(value: string): void {
  if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid();
}
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function text(value: string): void {
  if (typeof value !== "string" || !value.trim() || value.length > 160
    || /[\u0000-\u001f\u007f]/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) invalid();
}
function finite(value: number, minimum: number, maximum: number): void {
  if (!Number.isFinite(value) || value < minimum || value > maximum) invalid();
}
function invalid(): never {
  throw new AgentGymContractError("Agent gym promotion input is invalid.");
}
