import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymEvaluationRunResult,
  type AgentGymEvaluationRunResultV1,
} from "./evaluation-run-result.js";
import {
  validateAgentGymEvaluationSliceReport,
  type AgentGymEvaluationSliceReportV1,
} from "./evaluation-slices.js";
import type { AgentGymEvaluationSuiteV1 } from "./evaluation-suite.js";

export type AgentGymEvaluationReadinessBlockerCode =
  | "evaluation.blocking_cases"
  | "evaluation.case_count_below_minimum"
  | "evaluation.invalid_cases"
  | "evaluation.required_slice_missing"
  | "evaluation.required_slice_underfilled";

export interface AgentGymEvaluationReadinessPolicyV1 {
  readonly minimum_case_count: number;
  readonly policy_ref: string;
  readonly required_slices: readonly {
    readonly minimum_valid_case_count: number;
    readonly slice_id: string;
  }[];
  readonly schema_version: "agent-gym-evaluation-readiness-policy/v1";
}

export interface AgentGymEvaluationReadinessDecisionV1 {
  readonly blocker_codes: readonly AgentGymEvaluationReadinessBlockerCode[];
  readonly decided_at: string;
  readonly decision_digest: string;
  readonly invalid_case_count: number;
  readonly policy_ref: string;
  readonly ready: boolean;
  readonly run_result_digest: string;
  readonly schema_version: "agent-gym-evaluation-readiness-decision/v1";
  readonly slice_report_digest: string;
  readonly suite_digest: string;
  readonly valid_case_count: number;
}

/** Decides evidence completeness without treating candidate score as evaluator validity. */
export function decideAgentGymEvaluationReadiness(
  suite: AgentGymEvaluationSuiteV1,
  resultInput: AgentGymEvaluationRunResultV1,
  reportInput: AgentGymEvaluationSliceReportV1,
  policy: AgentGymEvaluationReadinessPolicyV1,
  decidedAt: string,
): AgentGymEvaluationReadinessDecisionV1 {
  validateSuite(suite);
  const result = validateAgentGymEvaluationRunResult(resultInput);
  const report = validateAgentGymEvaluationSliceReport(reportInput);
  validatePolicy(policy);
  timestamp(decidedAt);
  if (result.suite_digest !== suite.suite_digest
    || report.suite_digest !== suite.suite_digest
    || report.run_result_digest !== result.result_digest
    || Date.parse(decidedAt) < Date.parse(result.completed_at)) invalid();
  const blockerCodes = new Set<AgentGymEvaluationReadinessBlockerCode>();
  if (result.invalid_case_count > 0) blockerCodes.add("evaluation.invalid_cases");
  if (result.blocker_case_count > 0) blockerCodes.add("evaluation.blocking_cases");
  if (result.valid_case_count < policy.minimum_case_count) {
    blockerCodes.add("evaluation.case_count_below_minimum");
  }
  const sliceById = new Map(report.slices.map((slice) => [slice.slice_id, slice]));
  for (const requirement of policy.required_slices) {
    const slice = sliceById.get(requirement.slice_id);
    if (slice === undefined) blockerCodes.add("evaluation.required_slice_missing");
    else if (slice.valid_case_count < requirement.minimum_valid_case_count) {
      blockerCodes.add("evaluation.required_slice_underfilled");
    }
  }
  const blockers = [...blockerCodes].sort();
  const body = {
    blocker_codes: blockers,
    decided_at: decidedAt,
    invalid_case_count: result.invalid_case_count,
    policy_ref: policy.policy_ref,
    ready: blockers.length === 0,
    run_result_digest: result.result_digest,
    schema_version: "agent-gym-evaluation-readiness-decision/v1" as const,
    slice_report_digest: report.report_digest,
    suite_digest: suite.suite_digest,
    valid_case_count: result.valid_case_count,
  };
  return Object.freeze({
    ...body,
    blocker_codes: Object.freeze(blockers),
    decision_digest: digestAgentGymJson(body),
  });
}

export function validateAgentGymEvaluationReadinessDecision(
  value: AgentGymEvaluationReadinessDecisionV1,
): AgentGymEvaluationReadinessDecisionV1 {
  if (value.schema_version !== "agent-gym-evaluation-readiness-decision/v1") invalid();
  timestamp(value.decided_at);
  reference(value.policy_ref);
  for (const digest of [value.run_result_digest, value.slice_report_digest,
    value.suite_digest, value.decision_digest]) digestValue(digest);
  integer(value.valid_case_count, 100_000, true);
  integer(value.invalid_case_count, 100_000, true);
  if (!Array.isArray(value.blocker_codes) || value.blocker_codes.length > 5
    || new Set(value.blocker_codes).size !== value.blocker_codes.length
    || value.blocker_codes.some((code) => ![
      "evaluation.blocking_cases", "evaluation.case_count_below_minimum",
      "evaluation.invalid_cases", "evaluation.required_slice_missing",
      "evaluation.required_slice_underfilled",
    ].includes(code))
    || value.blocker_codes.some((code, index) => index > 0 && value.blocker_codes[index - 1]! >= code)
    || value.ready !== (value.blocker_codes.length === 0)) invalid();
  const body = {
    blocker_codes: value.blocker_codes,
    decided_at: value.decided_at,
    invalid_case_count: value.invalid_case_count,
    policy_ref: value.policy_ref,
    ready: value.ready,
    run_result_digest: value.run_result_digest,
    schema_version: value.schema_version,
    slice_report_digest: value.slice_report_digest,
    suite_digest: value.suite_digest,
    valid_case_count: value.valid_case_count,
  };
  if (digestAgentGymJson(body) !== value.decision_digest) invalid();
  return Object.freeze({ ...value, blocker_codes: Object.freeze([...value.blocker_codes]) });
}

function validatePolicy(value: AgentGymEvaluationReadinessPolicyV1): void {
  if (value.schema_version !== "agent-gym-evaluation-readiness-policy/v1") invalid();
  reference(value.policy_ref);
  integer(value.minimum_case_count, 100_000, false);
  if (!Array.isArray(value.required_slices) || value.required_slices.length > 1_000) invalid();
  const sliceIds = new Set<string>();
  for (const requirement of value.required_slices) {
    text(requirement.slice_id);
    integer(requirement.minimum_valid_case_count, 100_000, false);
    if (sliceIds.has(requirement.slice_id)) invalid();
    sliceIds.add(requirement.slice_id);
  }
}

function validateSuite(value: AgentGymEvaluationSuiteV1): void {
  if (value.schema_version !== "agent-gym-evaluation-suite/v1") invalid();
  const body = {
    case_count: value.case_count,
    case_set_digest: value.case_set_digest,
    cases: value.cases.map((entry) => ({
      case_digest: entry.case_digest,
      case_ref: entry.case_ref,
      labels: [...entry.labels],
      partition: entry.partition,
    })),
    corpus_digest: value.corpus_digest,
    corpus_quality_receipt_digest: value.corpus_quality_receipt_digest,
    evaluator_admission_decision_digest: value.evaluator_admission_decision_digest,
    evaluator_digests: [...value.evaluator_digests],
    partitions: [...value.partitions],
    rubric_digest: value.rubric_digest,
    schema_version: value.schema_version,
    suite_ref: value.suite_ref,
  };
  if (digestAgentGymJson(body) !== value.suite_digest) invalid();
}
function text(value: string): void {
  if (typeof value !== "string" || !value.trim() || value.length > 160
    || /[\u0000-\u001f\u007f]/u.test(value)) invalid();
}
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function digestValue(value: string): void {
  if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) invalid();
}
function integer(value: number, maximum: number, allowZero: boolean): void {
  if (!Number.isSafeInteger(value) || value < (allowZero ? 0 : 1) || value > maximum) invalid();
}
function invalid(): never {
  throw new AgentGymContractError("Agent gym evaluation readiness is invalid.");
}
