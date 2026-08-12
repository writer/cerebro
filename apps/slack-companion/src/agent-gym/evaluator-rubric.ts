import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";

export interface AgentGymRubricMetricV1 {
  readonly blocking: boolean;
  readonly evaluator_kind: "deterministic" | "model_judge";
  readonly metric_id: string;
  readonly minimum_score: number;
  readonly weight: number;
}

export interface AgentGymEvaluatorRubricV1 {
  readonly metrics: readonly AgentGymRubricMetricV1[];
  readonly rubric_digest: string;
  readonly rubric_ref: string;
  readonly schema_version: "agent-gym-evaluator-rubric/v1";
}

export type AgentGymEvaluatorRubricInputV1 = Omit<AgentGymEvaluatorRubricV1, "rubric_digest">;

/** Seals the metric contract used to judge every candidate in a comparison. */
export function defineAgentGymEvaluatorRubric(
  input: AgentGymEvaluatorRubricInputV1,
): AgentGymEvaluatorRubricV1 {
  if (input.schema_version !== "agent-gym-evaluator-rubric/v1") invalid();
  reference(input.rubric_ref);
  if (!Array.isArray(input.metrics) || input.metrics.length === 0 || input.metrics.length > 128) invalid();
  const metricIds = new Set<string>();
  const metrics = input.metrics.map((metric) => {
    bounded(metric.metric_id, 160);
    if (metricIds.has(metric.metric_id)
      || !["deterministic", "model_judge"].includes(metric.evaluator_kind)) invalid();
    metricIds.add(metric.metric_id);
    unit(metric.minimum_score);
    if (!Number.isFinite(metric.weight) || metric.weight <= 0 || metric.weight > 100) invalid();
    return Object.freeze({ ...metric });
  });
  const body = {
    metrics: metrics.map((metric) => ({ ...metric })),
    rubric_ref: input.rubric_ref,
    schema_version: input.schema_version,
  };
  return Object.freeze({
    ...body,
    metrics: Object.freeze(metrics),
    rubric_digest: digestAgentGymJson(body),
  });
}

function bounded(value: string, maximum: number): void {
  if (typeof value !== "string" || !value.trim() || value.length > maximum
    || /[\u0000-\u001f\u007f]/u.test(value)) invalid();
}
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function unit(value: number): void {
  if (!Number.isFinite(value) || value < 0 || value > 1) invalid();
}
function invalid(): never {
  throw new AgentGymContractError("Agent gym evaluator rubric is invalid.");
}
