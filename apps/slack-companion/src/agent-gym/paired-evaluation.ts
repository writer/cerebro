import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymEvaluationReadinessDecision,
  type AgentGymEvaluationReadinessDecisionV1,
} from "./evaluation-readiness.js";
import {
  validateAgentGymEvaluationRunResult,
  type AgentGymEvaluationRunResultV1,
} from "./evaluation-run-result.js";
import type { AgentGymEvaluationSuiteV1 } from "./evaluation-suite.js";

export interface AgentGymPairedEvaluationV1 {
  readonly baseline_candidate_ref: string;
  readonly baseline_readiness_digest: string;
  readonly baseline_result_digest: string;
  readonly candidate_ref: string;
  readonly candidate_readiness_digest: string;
  readonly candidate_result_digest: string;
  readonly case_count: number;
  readonly case_set_digest: string;
  readonly pair_digest: string;
  readonly pair_ref: string;
  readonly paired_at: string;
  readonly schema_version: "agent-gym-paired-evaluation/v1";
  readonly suite_digest: string;
}

/** Binds ready baseline and challenger runs over one identical sealed case set. */
export function pairAgentGymEvaluationRuns(
  suite: AgentGymEvaluationSuiteV1,
  baselineResultInput: AgentGymEvaluationRunResultV1,
  baselineReadinessInput: AgentGymEvaluationReadinessDecisionV1,
  candidateResultInput: AgentGymEvaluationRunResultV1,
  candidateReadinessInput: AgentGymEvaluationReadinessDecisionV1,
  input: { readonly pair_ref: string; readonly paired_at: string },
): AgentGymPairedEvaluationV1 {
  validateSuite(suite);
  const baselineResult = validateAgentGymEvaluationRunResult(baselineResultInput);
  const candidateResult = validateAgentGymEvaluationRunResult(candidateResultInput);
  const baselineReadiness = validateAgentGymEvaluationReadinessDecision(baselineReadinessInput);
  const candidateReadiness = validateAgentGymEvaluationReadinessDecision(candidateReadinessInput);
  reference(input.pair_ref);
  timestamp(input.paired_at);
  if (!baselineReadiness.ready || !candidateReadiness.ready
    || baselineResult.suite_digest !== suite.suite_digest
    || candidateResult.suite_digest !== suite.suite_digest
    || baselineReadiness.suite_digest !== suite.suite_digest
    || candidateReadiness.suite_digest !== suite.suite_digest
    || baselineReadiness.run_result_digest !== baselineResult.result_digest
    || candidateReadiness.run_result_digest !== candidateResult.result_digest
    || baselineResult.candidate_ref === candidateResult.candidate_ref
    || Date.parse(input.paired_at) < Date.parse(baselineReadiness.decided_at)
    || Date.parse(input.paired_at) < Date.parse(candidateReadiness.decided_at)) invalid();
  const expectedCases = suite.cases.map((entry) => `${entry.case_ref}\0${entry.case_digest}`);
  const baselineCases = baselineResult.cases.map((entry) => `${entry.case_ref}\0${entry.case_digest}`);
  const candidateCases = candidateResult.cases.map((entry) => `${entry.case_ref}\0${entry.case_digest}`);
  if (digestAgentGymJson(expectedCases) !== digestAgentGymJson(baselineCases)
    || digestAgentGymJson(expectedCases) !== digestAgentGymJson(candidateCases)) invalid();
  const body = {
    baseline_candidate_ref: baselineResult.candidate_ref,
    baseline_readiness_digest: baselineReadiness.decision_digest,
    baseline_result_digest: baselineResult.result_digest,
    candidate_ref: candidateResult.candidate_ref,
    candidate_readiness_digest: candidateReadiness.decision_digest,
    candidate_result_digest: candidateResult.result_digest,
    case_count: suite.case_count,
    case_set_digest: suite.case_set_digest,
    pair_ref: input.pair_ref,
    paired_at: input.paired_at,
    schema_version: "agent-gym-paired-evaluation/v1" as const,
    suite_digest: suite.suite_digest,
  };
  return Object.freeze({ ...body, pair_digest: digestAgentGymJson(body) });
}

export function validateAgentGymPairedEvaluation(
  value: AgentGymPairedEvaluationV1,
): AgentGymPairedEvaluationV1 {
  if (value.schema_version !== "agent-gym-paired-evaluation/v1") invalid();
  for (const ref of [value.baseline_candidate_ref, value.candidate_ref, value.pair_ref]) reference(ref);
  if (value.baseline_candidate_ref === value.candidate_ref) invalid();
  timestamp(value.paired_at);
  for (const digest of [value.baseline_readiness_digest, value.baseline_result_digest,
    value.candidate_readiness_digest, value.candidate_result_digest, value.case_set_digest,
    value.pair_digest, value.suite_digest]) digestValue(digest);
  if (!Number.isSafeInteger(value.case_count) || value.case_count < 1 || value.case_count > 100_000) invalid();
  const body = {
    baseline_candidate_ref: value.baseline_candidate_ref,
    baseline_readiness_digest: value.baseline_readiness_digest,
    baseline_result_digest: value.baseline_result_digest,
    candidate_ref: value.candidate_ref,
    candidate_readiness_digest: value.candidate_readiness_digest,
    candidate_result_digest: value.candidate_result_digest,
    case_count: value.case_count,
    case_set_digest: value.case_set_digest,
    pair_ref: value.pair_ref,
    paired_at: value.paired_at,
    schema_version: value.schema_version,
    suite_digest: value.suite_digest,
  };
  if (digestAgentGymJson(body) !== value.pair_digest) invalid();
  return Object.freeze({ ...value });
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
function digestValue(value: string): void {
  if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid();
}
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) invalid();
}
function invalid(): never {
  throw new AgentGymContractError("Agent gym paired evaluation is invalid.");
}
