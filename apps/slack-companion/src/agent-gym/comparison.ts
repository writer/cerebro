import { AgentGymContractError } from "./contract-error.js";

export interface AgentGymSliceDeltaV1 {
  readonly baseline_score: number;
  readonly candidate_score: number;
  readonly case_count: number;
  readonly delta: number;
  readonly slice_id: string;
}

export interface AgentGymComparisonV1 {
  readonly baseline_candidate_ref: string;
  readonly candidate_ref: string;
  readonly compared_at: string;
  readonly comparison_ref: string;
  readonly confidence_interval_95: readonly [number, number];
  readonly paired_case_count: number;
  readonly practical_threshold: number;
  readonly schema_version: "agent-gym-comparison/v1";
  readonly slices: readonly AgentGymSliceDeltaV1[];
  readonly weighted_score_delta: number;
}

/** Validates a paired comparison without deciding whether to promote it. */
export function validateAgentGymComparison(
  comparison: AgentGymComparisonV1,
): AgentGymComparisonV1 {
  if (comparison.schema_version !== "agent-gym-comparison/v1") invalid();
  for (const ref of [comparison.comparison_ref, comparison.baseline_candidate_ref,
    comparison.candidate_ref]) reference(ref);
  if (comparison.baseline_candidate_ref === comparison.candidate_ref) invalid();
  timestamp(comparison.compared_at);
  integer(comparison.paired_case_count, 1_000_000, false);
  finite(comparison.weighted_score_delta, -1, 1);
  finite(comparison.practical_threshold, 0, 1);
  const [lower, upper] = comparison.confidence_interval_95;
  finite(lower, -1, 1);
  finite(upper, -1, 1);
  if (lower > comparison.weighted_score_delta || upper < comparison.weighted_score_delta) invalid();
  if (!Array.isArray(comparison.slices) || comparison.slices.length === 0
    || comparison.slices.length > 128) invalid();
  const sliceIds = new Set<string>();
  const slices = comparison.slices.map((slice) => {
    bounded(slice.slice_id, 160);
    if (sliceIds.has(slice.slice_id)) invalid();
    sliceIds.add(slice.slice_id);
    unit(slice.baseline_score);
    unit(slice.candidate_score);
    finite(slice.delta, -1, 1);
    if (Math.abs(slice.candidate_score - slice.baseline_score - slice.delta) > 1e-9) invalid();
    integer(slice.case_count, comparison.paired_case_count, false);
    return Object.freeze({ ...slice });
  });
  return Object.freeze({
    ...comparison,
    confidence_interval_95: Object.freeze([lower, upper] as const),
    slices: Object.freeze(slices),
  });
}

function bounded(value: string, maximum: number): void {
  if (typeof value !== "string" || !value.trim() || value.length > maximum
    || /[\u0000-\u001f\u007f]/u.test(value)) invalid();
}
function finite(value: number, minimum: number, maximum: number): void {
  if (!Number.isFinite(value) || value < minimum || value > maximum) invalid();
}
function integer(value: number, maximum: number, allowZero = true): void {
  if (!Number.isSafeInteger(value) || value < (allowZero ? 0 : 1) || value > maximum) invalid();
}
function reference(value: string): void { bounded(value, 240); if (!value.includes("://")) invalid(); }
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || !Number.isFinite(Date.parse(value))) invalid();
}
function unit(value: number): void { finite(value, 0, 1); }
function invalid(): never { throw new AgentGymContractError("Agent gym comparison is invalid."); }
