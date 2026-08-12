import { AgentGymContractError } from "./contract-error.js";

export interface AgentGymMetricScoreV1 {
  readonly evaluator: "deterministic" | "model_judge";
  readonly metric_id: string;
  readonly passed: boolean;
  readonly reason_codes: readonly string[];
  readonly score: number;
  readonly weight: number;
}

export interface AgentGymScorecardV1 {
  readonly blocker_codes: readonly string[];
  readonly candidate_ref: string;
  readonly evaluated_at: string;
  readonly fixture_ref: string;
  readonly metrics: readonly AgentGymMetricScoreV1[];
  readonly replay_ref: string;
  readonly schema_version: "agent-gym-scorecard/v1";
  readonly scorecard_ref: string;
  readonly weighted_score: number;
}

/** Validates one fail-closed deterministic and judge scorecard. */
export function validateAgentGymScorecard(scorecard: AgentGymScorecardV1): AgentGymScorecardV1 {
  if (scorecard.schema_version !== "agent-gym-scorecard/v1") invalid();
  for (const ref of [scorecard.scorecard_ref, scorecard.candidate_ref,
    scorecard.fixture_ref, scorecard.replay_ref]) reference(ref);
  timestamp(scorecard.evaluated_at);
  strings(scorecard.blocker_codes, 64);
  if (!Array.isArray(scorecard.metrics) || scorecard.metrics.length === 0
    || scorecard.metrics.length > 128) invalid();
  const metricIds = new Set<string>();
  const metrics = scorecard.metrics.map((metric) => {
    bounded(metric.metric_id, 160);
    if (metricIds.has(metric.metric_id)
      || !["deterministic", "model_judge"].includes(metric.evaluator)) invalid();
    metricIds.add(metric.metric_id);
    unit(metric.score);
    if (!Number.isFinite(metric.weight) || metric.weight <= 0 || metric.weight > 100) invalid();
    strings(metric.reason_codes, 32);
    if (metric.evaluator === "deterministic" && metric.passed !== (metric.score === 1)) invalid();
    return Object.freeze({ ...metric, reason_codes: Object.freeze([...metric.reason_codes]) });
  });
  const expected = metrics.reduce((total, metric) => total + metric.score * metric.weight, 0)
    / metrics.reduce((total, metric) => total + metric.weight, 0);
  unit(scorecard.weighted_score);
  if (Math.abs(expected - scorecard.weighted_score) > 1e-9) invalid();
  const failedDeterministic = metrics.filter((metric) =>
    metric.evaluator === "deterministic" && !metric.passed
  );
  if (failedDeterministic.length > 0 && scorecard.blocker_codes.length === 0) invalid();
  return Object.freeze({
    ...scorecard,
    blocker_codes: Object.freeze([...scorecard.blocker_codes]),
    metrics: Object.freeze(metrics),
  });
}

function bounded(value: string, maximum: number): void {
  if (typeof value !== "string" || !value.trim() || value.length > maximum
    || /[\u0000-\u001f\u007f]/u.test(value)) invalid();
}
function reference(value: string): void { bounded(value, 240); if (!value.includes("://")) invalid(); }
function strings(values: readonly string[], maximum: number): void {
  if (!Array.isArray(values) || values.length > maximum || new Set(values).size !== values.length) invalid();
  for (const value of values) bounded(value, 160);
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || !Number.isFinite(Date.parse(value))) invalid();
}
function unit(value: number): void { if (!Number.isFinite(value) || value < 0 || value > 1) invalid(); }
function invalid(): never { throw new AgentGymContractError("Agent gym scorecard is invalid."); }
