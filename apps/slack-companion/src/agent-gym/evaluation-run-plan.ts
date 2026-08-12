import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import type { AgentGymEvaluationSuiteV1 } from "./evaluation-suite.js";

export interface AgentGymEvaluationCasePlanV1 {
  readonly case_digest: string;
  readonly case_plan_ref: string;
  readonly case_ref: string;
  readonly ordinal: number;
}

export interface AgentGymEvaluationRunPlanV1 {
  readonly candidate_ref: string;
  readonly case_count: number;
  readonly case_timeout_ms: number;
  readonly cases: readonly AgentGymEvaluationCasePlanV1[];
  readonly maximum_parallel_cases: number;
  readonly plan_digest: string;
  readonly planned_at: string;
  readonly run_ref: string;
  readonly schema_version: "agent-gym-evaluation-run-plan/v1";
  readonly suite_digest: string;
  readonly suite_ref: string;
}

/** Plans one candidate over every case in an exact sealed evaluation suite. */
export function planAgentGymEvaluationRun(
  suite: AgentGymEvaluationSuiteV1,
  input: {
    readonly candidate_ref: string;
    readonly case_timeout_ms: number;
    readonly maximum_parallel_cases: number;
    readonly planned_at: string;
    readonly run_ref: string;
  },
): AgentGymEvaluationRunPlanV1 {
  validateSuite(suite);
  reference(input.candidate_ref);
  reference(input.run_ref);
  timestamp(input.planned_at);
  integer(input.case_timeout_ms, 3_600_000, false);
  integer(input.maximum_parallel_cases, 1_000, false);
  if (input.maximum_parallel_cases > suite.case_count) invalid();
  const cases = suite.cases.map((entry, ordinal) => Object.freeze({
    case_digest: entry.case_digest,
    case_plan_ref: `agent-gym-evaluation-case://${digestAgentGymJson([
      input.run_ref, entry.case_ref, entry.case_digest,
    ]).slice("sha256:".length)}`,
    case_ref: entry.case_ref,
    ordinal,
  }));
  const body = {
    candidate_ref: input.candidate_ref,
    case_count: cases.length,
    case_timeout_ms: input.case_timeout_ms,
    cases: cases.map((entry) => ({ ...entry })),
    maximum_parallel_cases: input.maximum_parallel_cases,
    planned_at: input.planned_at,
    run_ref: input.run_ref,
    schema_version: "agent-gym-evaluation-run-plan/v1" as const,
    suite_digest: suite.suite_digest,
    suite_ref: suite.suite_ref,
  };
  return Object.freeze({
    ...body,
    cases: Object.freeze(cases),
    plan_digest: digestAgentGymJson(body),
  });
}

export function validateAgentGymEvaluationRunPlan(
  value: AgentGymEvaluationRunPlanV1,
): AgentGymEvaluationRunPlanV1 {
  if (value.schema_version !== "agent-gym-evaluation-run-plan/v1") invalid();
  for (const ref of [value.candidate_ref, value.run_ref, value.suite_ref]) reference(ref);
  timestamp(value.planned_at);
  digest(value.suite_digest);
  integer(value.case_count, 100_000, false);
  integer(value.case_timeout_ms, 3_600_000, false);
  integer(value.maximum_parallel_cases, 1_000, false);
  if (!Array.isArray(value.cases) || value.cases.length !== value.case_count
    || value.maximum_parallel_cases > value.case_count) invalid();
  const caseRefs = new Set<string>();
  const casePlanRefs = new Set<string>();
  const cases = value.cases.map((entry, ordinal) => {
    reference(entry.case_ref);
    reference(entry.case_plan_ref);
    digest(entry.case_digest);
    if (entry.ordinal !== ordinal || caseRefs.has(entry.case_ref)
      || casePlanRefs.has(entry.case_plan_ref)) invalid();
    caseRefs.add(entry.case_ref);
    casePlanRefs.add(entry.case_plan_ref);
    const expectedRef = `agent-gym-evaluation-case://${digestAgentGymJson([
      value.run_ref, entry.case_ref, entry.case_digest,
    ]).slice("sha256:".length)}`;
    if (entry.case_plan_ref !== expectedRef) invalid();
    return Object.freeze({ ...entry });
  });
  const body = {
    candidate_ref: value.candidate_ref,
    case_count: value.case_count,
    case_timeout_ms: value.case_timeout_ms,
    cases: cases.map((entry) => ({ ...entry })),
    maximum_parallel_cases: value.maximum_parallel_cases,
    planned_at: value.planned_at,
    run_ref: value.run_ref,
    schema_version: value.schema_version,
    suite_digest: value.suite_digest,
    suite_ref: value.suite_ref,
  };
  if (digestAgentGymJson(body) !== value.plan_digest) invalid();
  return Object.freeze({ ...value, cases: Object.freeze(cases) });
}

function validateSuite(value: AgentGymEvaluationSuiteV1): void {
  if (value.schema_version !== "agent-gym-evaluation-suite/v1") invalid();
  if (!Array.isArray(value.cases) || value.cases.length !== value.case_count
    || value.cases.length === 0 || new Set(value.cases.map((entry) => entry.case_ref)).size !== value.case_count
    || value.cases.some((entry) => !value.partitions.includes(entry.partition))) invalid();
  const caseSetBody = value.cases.map((entry) => ({
    case_digest: entry.case_digest,
    case_ref: entry.case_ref,
    labels: [...entry.labels],
    partition: entry.partition,
  }));
  if (digestAgentGymJson(caseSetBody) !== value.case_set_digest) invalid();
  const body = {
    case_count: value.case_count,
    case_set_digest: value.case_set_digest,
    cases: caseSetBody,
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
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) invalid();
}
function integer(value: number, maximum: number, allowZero: boolean): void {
  if (!Number.isSafeInteger(value) || value < (allowZero ? 0 : 1) || value > maximum) invalid();
}
function invalid(): never {
  throw new AgentGymContractError("Agent gym evaluation run plan is invalid.");
}
