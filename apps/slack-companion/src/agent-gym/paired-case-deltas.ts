import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymEvaluationRunResult,
  type AgentGymEvaluationRunResultV1,
} from "./evaluation-run-result.js";
import {
  validateAgentGymPairedEvaluation,
  type AgentGymPairedEvaluationV1,
} from "./paired-evaluation.js";

export interface AgentGymPairedCaseDeltaV1 {
  readonly baseline_evaluation_digest: string;
  readonly baseline_score: number;
  readonly candidate_evaluation_digest: string;
  readonly candidate_score: number;
  readonly case_digest: string;
  readonly case_ref: string;
  readonly delta: number;
  readonly disposition: "improved" | "regressed" | "tied";
}

export interface AgentGymPairedCaseDeltaReportV1 {
  readonly case_count: number;
  readonly cases: readonly AgentGymPairedCaseDeltaV1[];
  readonly improvement_count: number;
  readonly mean_delta: number;
  readonly pair_digest: string;
  readonly regression_count: number;
  readonly report_digest: string;
  readonly schema_version: "agent-gym-paired-case-delta-report/v1";
  readonly tie_count: number;
}

/** Computes exact per-case score movement without dropping tied or regressed cases. */
export function calculateAgentGymPairedCaseDeltas(
  pairInput: AgentGymPairedEvaluationV1,
  baselineInput: AgentGymEvaluationRunResultV1,
  candidateInput: AgentGymEvaluationRunResultV1,
): AgentGymPairedCaseDeltaReportV1 {
  const pair = validateAgentGymPairedEvaluation(pairInput);
  const baseline = validateAgentGymEvaluationRunResult(baselineInput);
  const candidate = validateAgentGymEvaluationRunResult(candidateInput);
  if (baseline.result_digest !== pair.baseline_result_digest
    || candidate.result_digest !== pair.candidate_result_digest
    || baseline.candidate_ref !== pair.baseline_candidate_ref
    || candidate.candidate_ref !== pair.candidate_ref
    || baseline.case_count !== pair.case_count || candidate.case_count !== pair.case_count) invalid();
  const candidateByCase = new Map(candidate.cases.map((entry) => [entry.case_ref, entry]));
  const cases = baseline.cases.map((baselineCase) => {
    const candidateCase = candidateByCase.get(baselineCase.case_ref);
    if (candidateCase === undefined || candidateCase.case_digest !== baselineCase.case_digest
      || baselineCase.weighted_score === null || candidateCase.weighted_score === null) invalid();
    const delta = candidateCase.weighted_score - baselineCase.weighted_score;
    return Object.freeze({
      baseline_evaluation_digest: baselineCase.evaluation_digest,
      baseline_score: baselineCase.weighted_score,
      candidate_evaluation_digest: candidateCase.evaluation_digest,
      candidate_score: candidateCase.weighted_score,
      case_digest: baselineCase.case_digest,
      case_ref: baselineCase.case_ref,
      delta,
      disposition: delta > 0 ? "improved" as const : delta < 0 ? "regressed" as const : "tied" as const,
    });
  });
  const body = {
    case_count: cases.length,
    cases: cases.map((entry) => ({ ...entry })),
    improvement_count: cases.filter((entry) => entry.disposition === "improved").length,
    mean_delta: cases.reduce((total, entry) => total + entry.delta, 0) / cases.length,
    pair_digest: pair.pair_digest,
    regression_count: cases.filter((entry) => entry.disposition === "regressed").length,
    schema_version: "agent-gym-paired-case-delta-report/v1" as const,
    tie_count: cases.filter((entry) => entry.disposition === "tied").length,
  };
  return Object.freeze({
    ...body,
    cases: Object.freeze(cases),
    report_digest: digestAgentGymJson(body),
  });
}

export function validateAgentGymPairedCaseDeltaReport(
  value: AgentGymPairedCaseDeltaReportV1,
): AgentGymPairedCaseDeltaReportV1 {
  if (value.schema_version !== "agent-gym-paired-case-delta-report/v1") invalid();
  for (const digest of [value.pair_digest, value.report_digest]) digestValue(digest);
  integer(value.case_count, 100_000, false);
  integer(value.improvement_count, value.case_count, true);
  integer(value.regression_count, value.case_count, true);
  integer(value.tie_count, value.case_count, true);
  finite(value.mean_delta, -1, 1);
  if (!Array.isArray(value.cases) || value.cases.length !== value.case_count
    || value.improvement_count + value.regression_count + value.tie_count !== value.case_count) invalid();
  const caseRefs = new Set<string>();
  const cases = value.cases.map((entry) => {
    reference(entry.case_ref);
    for (const digest of [entry.case_digest, entry.baseline_evaluation_digest,
      entry.candidate_evaluation_digest]) digestValue(digest);
    unit(entry.baseline_score);
    unit(entry.candidate_score);
    finite(entry.delta, -1, 1);
    const expectedDelta = entry.candidate_score - entry.baseline_score;
    const expectedDisposition = expectedDelta > 0 ? "improved" : expectedDelta < 0 ? "regressed" : "tied";
    if (caseRefs.has(entry.case_ref) || Math.abs(entry.delta - expectedDelta) > 1e-12
      || entry.disposition !== expectedDisposition) invalid();
    caseRefs.add(entry.case_ref);
    return Object.freeze({ ...entry });
  });
  const mean = cases.reduce((total, entry) => total + entry.delta, 0) / cases.length;
  if (Math.abs(mean - value.mean_delta) > 1e-12
    || cases.filter((entry) => entry.disposition === "improved").length !== value.improvement_count
    || cases.filter((entry) => entry.disposition === "regressed").length !== value.regression_count
    || cases.filter((entry) => entry.disposition === "tied").length !== value.tie_count) invalid();
  const body = {
    case_count: value.case_count,
    cases: cases.map((entry) => ({ ...entry })),
    improvement_count: value.improvement_count,
    mean_delta: value.mean_delta,
    pair_digest: value.pair_digest,
    regression_count: value.regression_count,
    schema_version: value.schema_version,
    tie_count: value.tie_count,
  };
  if (digestAgentGymJson(body) !== value.report_digest) invalid();
  return Object.freeze({ ...value, cases: Object.freeze(cases) });
}

function digestValue(value: string): void {
  if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid();
}
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function integer(value: number, maximum: number, allowZero: boolean): void {
  if (!Number.isSafeInteger(value) || value < (allowZero ? 0 : 1) || value > maximum) invalid();
}
function finite(value: number, minimum: number, maximum: number): void {
  if (!Number.isFinite(value) || value < minimum || value > maximum) invalid();
}
function unit(value: number): void { finite(value, 0, 1); }
function invalid(): never {
  throw new AgentGymContractError("Agent gym paired case delta report is invalid.");
}
