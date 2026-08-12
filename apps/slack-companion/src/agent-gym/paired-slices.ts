import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import type { AgentGymEvaluationSuiteV1 } from "./evaluation-suite.js";
import {
  validateAgentGymPairedCaseDeltaReport,
  type AgentGymPairedCaseDeltaReportV1,
} from "./paired-case-deltas.js";

export interface AgentGymPairedSliceV1 {
  readonly baseline_score: number;
  readonly candidate_score: number;
  readonly case_count: number;
  readonly delta: number;
  readonly improvement_count: number;
  readonly regression_count: number;
  readonly slice_id: string;
  readonly tie_count: number;
}

export interface AgentGymPairedSliceReportV1 {
  readonly delta_report_digest: string;
  readonly report_digest: string;
  readonly schema_version: "agent-gym-paired-slice-report/v1";
  readonly slices: readonly AgentGymPairedSliceV1[];
  readonly suite_digest: string;
}

/** Preserves paired movement across overall, partition, and label slices. */
export function summarizeAgentGymPairedSlices(
  suite: AgentGymEvaluationSuiteV1,
  deltaInput: AgentGymPairedCaseDeltaReportV1,
): AgentGymPairedSliceReportV1 {
  validateSuite(suite);
  const deltaReport = validateAgentGymPairedCaseDeltaReport(deltaInput);
  const deltaByCase = new Map(deltaReport.cases.map((entry) => [entry.case_ref, entry]));
  if (suite.cases.some((entry) => deltaByCase.get(entry.case_ref)?.case_digest !== entry.case_digest)
    || deltaReport.case_count !== suite.case_count) invalid();
  const definitions: { readonly slice_id: string; readonly case_refs: readonly string[] }[] = [{
    case_refs: suite.cases.map((entry) => entry.case_ref),
    slice_id: "overall:all",
  }];
  for (const partition of suite.partitions) definitions.push({
    case_refs: suite.cases.filter((entry) => entry.partition === partition).map((entry) => entry.case_ref),
    slice_id: `partition:${partition}`,
  });
  for (const label of [...new Set(suite.cases.flatMap((entry) => entry.labels))].sort()) definitions.push({
    case_refs: suite.cases.filter((entry) => entry.labels.includes(label)).map((entry) => entry.case_ref),
    slice_id: `label:${label}`,
  });
  const slices = definitions.map((definition) => {
    const cases = definition.case_refs.map((caseRef) => deltaByCase.get(caseRef) ?? invalid());
    const baselineScore = mean(cases.map((entry) => entry.baseline_score));
    const candidateScore = mean(cases.map((entry) => entry.candidate_score));
    return Object.freeze({
      baseline_score: baselineScore,
      candidate_score: candidateScore,
      case_count: cases.length,
      delta: candidateScore - baselineScore,
      improvement_count: cases.filter((entry) => entry.disposition === "improved").length,
      regression_count: cases.filter((entry) => entry.disposition === "regressed").length,
      slice_id: definition.slice_id,
      tie_count: cases.filter((entry) => entry.disposition === "tied").length,
    });
  }).sort((left, right) => left.slice_id.localeCompare(right.slice_id));
  const body = {
    delta_report_digest: deltaReport.report_digest,
    schema_version: "agent-gym-paired-slice-report/v1" as const,
    slices: slices.map((entry) => ({ ...entry })),
    suite_digest: suite.suite_digest,
  };
  return Object.freeze({
    ...body,
    slices: Object.freeze(slices),
    report_digest: digestAgentGymJson(body),
  });
}

export function validateAgentGymPairedSliceReport(
  value: AgentGymPairedSliceReportV1,
): AgentGymPairedSliceReportV1 {
  if (value.schema_version !== "agent-gym-paired-slice-report/v1") invalid();
  for (const digest of [value.delta_report_digest, value.report_digest, value.suite_digest]) digestValue(digest);
  if (!Array.isArray(value.slices) || value.slices.length === 0 || value.slices.length > 1_000) invalid();
  const sliceIds = new Set<string>();
  const slices = value.slices.map((entry) => {
    text(entry.slice_id);
    unit(entry.baseline_score);
    unit(entry.candidate_score);
    finite(entry.delta, -1, 1);
    integer(entry.case_count, 100_000, false);
    integer(entry.improvement_count, entry.case_count, true);
    integer(entry.regression_count, entry.case_count, true);
    integer(entry.tie_count, entry.case_count, true);
    if (sliceIds.has(entry.slice_id)
      || entry.improvement_count + entry.regression_count + entry.tie_count !== entry.case_count
      || Math.abs(entry.candidate_score - entry.baseline_score - entry.delta) > 1e-12) invalid();
    sliceIds.add(entry.slice_id);
    return Object.freeze({ ...entry });
  });
  if (!sliceIds.has("overall:all")
    || slices.some((entry, index) => index > 0 && slices[index - 1]!.slice_id >= entry.slice_id)) invalid();
  const body = {
    delta_report_digest: value.delta_report_digest,
    schema_version: value.schema_version,
    slices: slices.map((entry) => ({ ...entry })),
    suite_digest: value.suite_digest,
  };
  if (digestAgentGymJson(body) !== value.report_digest) invalid();
  return Object.freeze({ ...value, slices: Object.freeze(slices) });
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
function mean(values: readonly number[]): number {
  if (values.length === 0) invalid();
  return values.reduce((total, value) => total + value, 0) / values.length;
}
function digestValue(value: string): void {
  if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid();
}
function text(value: string): void {
  if (typeof value !== "string" || !value.trim() || value.length > 160
    || /[\u0000-\u001f\u007f]/u.test(value)) invalid();
}
function integer(value: number, maximum: number, allowZero: boolean): void {
  if (!Number.isSafeInteger(value) || value < (allowZero ? 0 : 1) || value > maximum) invalid();
}
function finite(value: number, minimum: number, maximum: number): void {
  if (!Number.isFinite(value) || value < minimum || value > maximum) invalid();
}
function unit(value: number): void { finite(value, 0, 1); }
function invalid(): never {
  throw new AgentGymContractError("Agent gym paired slice report is invalid.");
}
