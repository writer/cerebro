import type { AgentGymCaseEvaluationV1 } from "./case-evaluation.js";
import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymEvaluationRunPlan,
  type AgentGymEvaluationRunPlanV1,
} from "./evaluation-run-plan.js";
import type { AgentGymEvaluationSuiteV1 } from "./evaluation-suite.js";

export interface AgentGymEvaluationCaseResultV1 {
  readonly blocker_codes: readonly string[];
  readonly case_digest: string;
  readonly case_plan_ref: string;
  readonly case_ref: string;
  readonly evaluation_digest: string;
  readonly valid: boolean;
  readonly weighted_score: number | null;
}

export interface AgentGymEvaluationRunResultV1 {
  readonly blocker_case_count: number;
  readonly candidate_ref: string;
  readonly case_count: number;
  readonly cases: readonly AgentGymEvaluationCaseResultV1[];
  readonly completed_at: string;
  readonly invalid_case_count: number;
  readonly plan_digest: string;
  readonly result_digest: string;
  readonly run_ref: string;
  readonly schema_version: "agent-gym-evaluation-run-result/v1";
  readonly started_at: string;
  readonly suite_digest: string;
  readonly valid_case_count: number;
}

/** Completes a run only when every planned case has one content-bound evaluation. */
export function completeAgentGymEvaluationRun(
  suite: AgentGymEvaluationSuiteV1,
  planInput: AgentGymEvaluationRunPlanV1,
  evaluations: readonly AgentGymCaseEvaluationV1[],
  input: { readonly completed_at: string; readonly started_at: string },
): AgentGymEvaluationRunResultV1 {
  validateSuite(suite);
  const plan = validateAgentGymEvaluationRunPlan(planInput);
  if (plan.suite_digest !== suite.suite_digest || plan.case_count !== suite.case_count) invalid();
  timestamp(input.started_at);
  timestamp(input.completed_at);
  if (Date.parse(input.completed_at) < Date.parse(input.started_at)
    || Date.parse(input.started_at) < Date.parse(plan.planned_at)
    || !Array.isArray(evaluations) || evaluations.length !== plan.case_count) invalid();
  const evaluationByCase = new Map<string, AgentGymCaseEvaluationV1>();
  for (const evaluation of evaluations) {
    validateEvaluation(evaluation);
    if (evaluation.candidate_ref !== plan.candidate_ref
      || evaluation.rubric_digest !== suite.rubric_digest
      || digestAgentGymJson([...evaluation.evaluator_digests].sort())
        !== digestAgentGymJson([...suite.evaluator_digests].sort())
      || Date.parse(evaluation.evaluated_at) < Date.parse(input.started_at)
      || Date.parse(evaluation.evaluated_at) > Date.parse(input.completed_at)
      || evaluationByCase.has(evaluation.case_ref)) invalid();
    evaluationByCase.set(evaluation.case_ref, evaluation);
  }
  const cases = plan.cases.map((casePlan) => {
    const evaluation = evaluationByCase.get(casePlan.case_ref);
    if (evaluation === undefined) invalid();
    return Object.freeze({
      blocker_codes: Object.freeze([...evaluation.blocker_codes]),
      case_digest: casePlan.case_digest,
      case_plan_ref: casePlan.case_plan_ref,
      case_ref: casePlan.case_ref,
      evaluation_digest: evaluation.evaluation_digest,
      valid: evaluation.valid,
      weighted_score: evaluation.weighted_score,
    });
  });
  const invalidCaseCount = cases.filter((entry) => !entry.valid).length;
  const blockerCaseCount = cases.filter((entry) => entry.blocker_codes.length > 0).length;
  const body = {
    blocker_case_count: blockerCaseCount,
    candidate_ref: plan.candidate_ref,
    case_count: cases.length,
    cases: cases.map((entry) => ({ ...entry, blocker_codes: [...entry.blocker_codes] })),
    completed_at: input.completed_at,
    invalid_case_count: invalidCaseCount,
    plan_digest: plan.plan_digest,
    run_ref: plan.run_ref,
    schema_version: "agent-gym-evaluation-run-result/v1" as const,
    started_at: input.started_at,
    suite_digest: suite.suite_digest,
    valid_case_count: cases.length - invalidCaseCount,
  };
  return Object.freeze({
    ...body,
    cases: Object.freeze(cases),
    result_digest: digestAgentGymJson(body),
  });
}

export function validateAgentGymEvaluationRunResult(
  value: AgentGymEvaluationRunResultV1,
): AgentGymEvaluationRunResultV1 {
  if (value.schema_version !== "agent-gym-evaluation-run-result/v1") invalid();
  reference(value.candidate_ref);
  reference(value.run_ref);
  timestamp(value.started_at);
  timestamp(value.completed_at);
  if (Date.parse(value.completed_at) < Date.parse(value.started_at)) invalid();
  for (const digest of [value.plan_digest, value.suite_digest, value.result_digest]) digestValue(digest);
  integer(value.case_count, 100_000);
  integer(value.valid_case_count, value.case_count);
  integer(value.invalid_case_count, value.case_count);
  integer(value.blocker_case_count, value.case_count);
  if (!Array.isArray(value.cases) || value.cases.length !== value.case_count
    || value.valid_case_count + value.invalid_case_count !== value.case_count) invalid();
  const caseRefs = new Set<string>();
  const cases = value.cases.map((entry) => {
    reference(entry.case_ref);
    reference(entry.case_plan_ref);
    digestValue(entry.case_digest);
    digestValue(entry.evaluation_digest);
    strings(entry.blocker_codes);
    if (caseRefs.has(entry.case_ref)
      || (entry.valid !== (entry.weighted_score !== null))) invalid();
    caseRefs.add(entry.case_ref);
    if (entry.weighted_score !== null) unit(entry.weighted_score);
    return Object.freeze({ ...entry, blocker_codes: Object.freeze([...entry.blocker_codes]) });
  });
  if (cases.filter((entry) => !entry.valid).length !== value.invalid_case_count
    || cases.filter((entry) => entry.blocker_codes.length > 0).length !== value.blocker_case_count) invalid();
  const body = {
    blocker_case_count: value.blocker_case_count,
    candidate_ref: value.candidate_ref,
    case_count: value.case_count,
    cases: cases.map((entry) => ({ ...entry, blocker_codes: [...entry.blocker_codes] })),
    completed_at: value.completed_at,
    invalid_case_count: value.invalid_case_count,
    plan_digest: value.plan_digest,
    run_ref: value.run_ref,
    schema_version: value.schema_version,
    started_at: value.started_at,
    suite_digest: value.suite_digest,
    valid_case_count: value.valid_case_count,
  };
  if (digestAgentGymJson(body) !== value.result_digest) invalid();
  return Object.freeze({ ...value, cases: Object.freeze(cases) });
}

function validateEvaluation(value: AgentGymCaseEvaluationV1): void {
  if (value.schema_version !== "agent-gym-case-evaluation/v1") invalid();
  timestamp(value.evaluated_at);
  const body = {
    blocker_codes: value.blocker_codes,
    candidate_ref: value.candidate_ref,
    case_ref: value.case_ref,
    evaluated_at: value.evaluated_at,
    evaluation_ref: value.evaluation_ref,
    evaluator_digests: value.evaluator_digests,
    invalid_reason_codes: value.invalid_reason_codes,
    metrics: value.metrics.map((metric) => ({ ...metric, reason_codes: [...metric.reason_codes] })),
    replay_ref: value.replay_ref,
    rubric_digest: value.rubric_digest,
    schema_version: value.schema_version,
    valid: value.valid,
    weighted_score: value.weighted_score,
  };
  if (digestAgentGymJson(body) !== value.evaluation_digest
    || value.valid !== (value.weighted_score !== null)) invalid();
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
function strings(values: readonly string[]): void {
  if (!Array.isArray(values) || values.length > 128 || new Set(values).size !== values.length
    || values.some((value) => !value.trim() || value.length > 160 || /[\u0000-\u001f\u007f]/u.test(value))) invalid();
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
function integer(value: number, maximum: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) invalid();
}
function unit(value: number): void {
  if (!Number.isFinite(value) || value < 0 || value > 1) invalid();
}
function invalid(): never {
  throw new AgentGymContractError("Agent gym evaluation run result is invalid.");
}
