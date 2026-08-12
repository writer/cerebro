import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  defineAgentGymEvaluatorManifest,
  type AgentGymEvaluatorManifestV1,
} from "./evaluator-manifest.js";
import {
  defineAgentGymEvaluatorRubric,
  type AgentGymEvaluatorRubricV1,
} from "./evaluator-rubric.js";

export interface AgentGymMetricEvaluationV1 {
  readonly evaluator_digest: string;
  readonly metric_id: string;
  readonly reason_codes: readonly string[];
  readonly score: number;
}

export interface AgentGymCaseEvaluationV1 {
  readonly blocker_codes: readonly string[];
  readonly candidate_ref: string;
  readonly case_ref: string;
  readonly evaluated_at: string;
  readonly evaluation_digest: string;
  readonly evaluation_ref: string;
  readonly evaluator_digests: readonly string[];
  readonly invalid_reason_codes: readonly string[];
  readonly metrics: readonly AgentGymMetricEvaluationV1[];
  readonly replay_ref: string;
  readonly rubric_digest: string;
  readonly schema_version: "agent-gym-case-evaluation/v1";
  readonly valid: boolean;
  readonly weighted_score: number | null;
}

export interface AgentGymCaseEvaluationInputV1 {
  readonly candidate_ref: string;
  readonly case_ref: string;
  readonly evaluated_at: string;
  readonly evaluation_ref: string;
  readonly invalid_reason_codes: readonly string[];
  readonly metrics: readonly AgentGymMetricEvaluationV1[];
  readonly replay_ref: string;
  readonly schema_version: "agent-gym-case-evaluation/v1";
  readonly valid: boolean;
}

/** Records valid scores or an explicit invalid evaluator result, never both. */
export function recordAgentGymCaseEvaluation(
  rubric: AgentGymEvaluatorRubricV1,
  evaluators: readonly AgentGymEvaluatorManifestV1[],
  input: AgentGymCaseEvaluationInputV1,
): AgentGymCaseEvaluationV1 {
  validateRubric(rubric);
  const evaluatorByKind = validateEvaluators(evaluators, rubric.rubric_digest);
  if (input.schema_version !== "agent-gym-case-evaluation/v1") invalid();
  for (const value of [input.candidate_ref, input.case_ref, input.evaluation_ref, input.replay_ref]) reference(value);
  timestamp(input.evaluated_at);
  strings(input.invalid_reason_codes, 32, input.valid ? "empty" : "nonempty");
  if (!input.valid && input.metrics.length !== 0) invalid();
  const metrics = input.valid
    ? validateMetrics(input.metrics, rubric, evaluatorByKind)
    : Object.freeze([] as AgentGymMetricEvaluationV1[]);
  const blockerCodes = input.valid ? rubric.metrics
    .filter((metric, index) => metric.blocking && metrics[index]!.score < metric.minimum_score)
    .map((metric) => `metric.${metric.metric_id}.below_minimum`) : [];
  const totalWeight = rubric.metrics.reduce((total, metric) => total + metric.weight, 0);
  const weightedScore = input.valid
    ? metrics.reduce((total, metric, index) => total + metric.score * rubric.metrics[index]!.weight, 0) / totalWeight
    : null;
  const evaluatorDigests = [...evaluators.map((value) => value.evaluator_digest)].sort();
  const body = {
    blocker_codes: blockerCodes,
    candidate_ref: input.candidate_ref,
    case_ref: input.case_ref,
    evaluated_at: input.evaluated_at,
    evaluation_ref: input.evaluation_ref,
    evaluator_digests: evaluatorDigests,
    invalid_reason_codes: [...input.invalid_reason_codes],
    metrics: metrics.map((metric) => ({ ...metric, reason_codes: [...metric.reason_codes] })),
    replay_ref: input.replay_ref,
    rubric_digest: rubric.rubric_digest,
    schema_version: input.schema_version,
    valid: input.valid,
    weighted_score: weightedScore,
  };
  return Object.freeze({
    ...body,
    blocker_codes: Object.freeze(blockerCodes),
    evaluator_digests: Object.freeze(evaluatorDigests),
    invalid_reason_codes: Object.freeze([...input.invalid_reason_codes]),
    metrics,
    evaluation_digest: digestAgentGymJson(body),
  });
}

function validateRubric(value: AgentGymEvaluatorRubricV1): void {
  const expected = defineAgentGymEvaluatorRubric({
    metrics: value.metrics,
    rubric_ref: value.rubric_ref,
    schema_version: value.schema_version,
  });
  if (expected.rubric_digest !== value.rubric_digest) invalid();
}

function validateEvaluators(
  values: readonly AgentGymEvaluatorManifestV1[],
  rubricDigest: string,
): ReadonlyMap<AgentGymEvaluatorManifestV1["evaluator_kind"], AgentGymEvaluatorManifestV1> {
  if (!Array.isArray(values) || values.length === 0 || values.length > 2) invalid();
  const byKind = new Map<AgentGymEvaluatorManifestV1["evaluator_kind"], AgentGymEvaluatorManifestV1>();
  for (const value of values) {
    const expected = defineAgentGymEvaluatorManifest({
      evaluator_kind: value.evaluator_kind,
      evaluator_ref: value.evaluator_ref,
      implementation_digest: value.implementation_digest,
      ...(value.model === undefined ? {} : { model: value.model }),
      output_schema_digest: value.output_schema_digest,
      rubric_digest: value.rubric_digest,
      schema_version: value.schema_version,
    });
    if (expected.evaluator_digest !== value.evaluator_digest
      || value.rubric_digest !== rubricDigest || byKind.has(value.evaluator_kind)) invalid();
    byKind.set(value.evaluator_kind, value);
  }
  return byKind;
}

function validateMetrics(
  values: readonly AgentGymMetricEvaluationV1[],
  rubric: AgentGymEvaluatorRubricV1,
  evaluators: ReadonlyMap<AgentGymEvaluatorManifestV1["evaluator_kind"], AgentGymEvaluatorManifestV1>,
): readonly AgentGymMetricEvaluationV1[] {
  if (!Array.isArray(values) || values.length !== rubric.metrics.length) invalid();
  return Object.freeze(values.map((value, index) => {
    const metric = rubric.metrics[index]!;
    const evaluator = evaluators.get(metric.evaluator_kind);
    if (value.metric_id !== metric.metric_id || value.evaluator_digest !== evaluator?.evaluator_digest) invalid();
    unit(value.score);
    strings(value.reason_codes, 32, "any");
    return Object.freeze({ ...value, reason_codes: Object.freeze([...value.reason_codes]) });
  }));
}

function strings(
  values: readonly string[],
  maximum: number,
  emptiness: "any" | "empty" | "nonempty",
): void {
  if (!Array.isArray(values) || values.length > maximum || new Set(values).size !== values.length
    || (emptiness === "empty" && values.length !== 0)
    || (emptiness === "nonempty" && values.length === 0)) invalid();
  for (const value of values) bounded(value, 160);
}
function bounded(value: string, maximum: number): void {
  if (typeof value !== "string" || !value.trim() || value.length > maximum
    || /[\u0000-\u001f\u007f]/u.test(value)) invalid();
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
  throw new AgentGymContractError("Agent gym case evaluation is invalid.");
}
