import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymEvaluationRunResult,
  type AgentGymEvaluationRunResultV1,
} from "./evaluation-run-result.js";
import type { AgentGymEvaluationSuiteV1 } from "./evaluation-suite.js";

export interface AgentGymEvaluationSliceV1 {
  readonly blocker_case_count: number;
  readonly case_count: number;
  readonly dimension: "label" | "overall" | "partition";
  readonly invalid_case_count: number;
  readonly mean_score: number | null;
  readonly slice_id: string;
  readonly valid_case_count: number;
  readonly value: string;
}

export interface AgentGymEvaluationSliceReportV1 {
  readonly report_digest: string;
  readonly run_result_digest: string;
  readonly schema_version: "agent-gym-evaluation-slice-report/v1";
  readonly slices: readonly AgentGymEvaluationSliceV1[];
  readonly suite_digest: string;
}

/** Produces stable overall, partition, and label slices from one complete run. */
export function summarizeAgentGymEvaluationSlices(
  suite: AgentGymEvaluationSuiteV1,
  resultInput: AgentGymEvaluationRunResultV1,
): AgentGymEvaluationSliceReportV1 {
  validateSuite(suite);
  const result = validateAgentGymEvaluationRunResult(resultInput);
  if (result.suite_digest !== suite.suite_digest) invalid();
  const resultByCase = new Map(result.cases.map((entry) => [entry.case_ref, entry]));
  const definitions: {
    readonly dimension: AgentGymEvaluationSliceV1["dimension"];
    readonly value: string;
    readonly case_refs: readonly string[];
  }[] = [{ dimension: "overall", value: "all", case_refs: suite.cases.map((entry) => entry.case_ref) }];
  for (const partition of suite.partitions) definitions.push({
    dimension: "partition",
    value: partition,
    case_refs: suite.cases.filter((entry) => entry.partition === partition).map((entry) => entry.case_ref),
  });
  const labels = [...new Set(suite.cases.flatMap((entry) => entry.labels))].sort();
  for (const label of labels) definitions.push({
    dimension: "label",
    value: label,
    case_refs: suite.cases.filter((entry) => entry.labels.includes(label)).map((entry) => entry.case_ref),
  });
  const slices = definitions.map((definition) => {
    const cases = definition.case_refs.map((caseRef) => resultByCase.get(caseRef) ?? invalid());
    const validScores = cases.flatMap((entry) => entry.weighted_score === null ? [] : [entry.weighted_score]);
    return Object.freeze({
      blocker_case_count: cases.filter((entry) => entry.blocker_codes.length > 0).length,
      case_count: cases.length,
      dimension: definition.dimension,
      invalid_case_count: cases.filter((entry) => !entry.valid).length,
      mean_score: validScores.length === 0
        ? null
        : validScores.reduce((total, score) => total + score, 0) / validScores.length,
      slice_id: `${definition.dimension}:${definition.value}`,
      valid_case_count: validScores.length,
      value: definition.value,
    });
  }).sort((left, right) => left.slice_id.localeCompare(right.slice_id));
  const body = {
    run_result_digest: result.result_digest,
    schema_version: "agent-gym-evaluation-slice-report/v1" as const,
    slices: slices.map((entry) => ({ ...entry })),
    suite_digest: suite.suite_digest,
  };
  return Object.freeze({
    ...body,
    slices: Object.freeze(slices),
    report_digest: digestAgentGymJson(body),
  });
}

export function validateAgentGymEvaluationSliceReport(
  value: AgentGymEvaluationSliceReportV1,
): AgentGymEvaluationSliceReportV1 {
  if (value.schema_version !== "agent-gym-evaluation-slice-report/v1") invalid();
  digest(value.run_result_digest);
  digest(value.suite_digest);
  digest(value.report_digest);
  if (!Array.isArray(value.slices) || value.slices.length === 0 || value.slices.length > 1_000) invalid();
  const sliceIds = new Set<string>();
  const slices = value.slices.map((entry) => {
    text(entry.slice_id);
    text(entry.value);
    if (sliceIds.has(entry.slice_id)
      || !["label", "overall", "partition"].includes(entry.dimension)
      || entry.slice_id !== `${entry.dimension}:${entry.value}`) invalid();
    sliceIds.add(entry.slice_id);
    integer(entry.case_count, 100_000);
    integer(entry.valid_case_count, entry.case_count);
    integer(entry.invalid_case_count, entry.case_count);
    integer(entry.blocker_case_count, entry.case_count);
    if (entry.case_count === 0 || entry.valid_case_count + entry.invalid_case_count !== entry.case_count
      || (entry.mean_score === null) !== (entry.valid_case_count === 0)) invalid();
    if (entry.mean_score !== null) unit(entry.mean_score);
    return Object.freeze({ ...entry });
  });
  if (slices.some((entry, index) => index > 0 && slices[index - 1]!.slice_id >= entry.slice_id)
    || !sliceIds.has("overall:all")) invalid();
  const body = {
    run_result_digest: value.run_result_digest,
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
function digest(value: string): void {
  if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid();
}
function text(value: string): void {
  if (typeof value !== "string" || !value.trim() || value.length > 160
    || /[\u0000-\u001f\u007f]/u.test(value)) invalid();
}
function integer(value: number, maximum: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) invalid();
}
function unit(value: number): void {
  if (!Number.isFinite(value) || value < 0 || value > 1) invalid();
}
function invalid(): never {
  throw new AgentGymContractError("Agent gym evaluation slice report is invalid.");
}
