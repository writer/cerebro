import type { HostedHillclimbComparisonV1 } from "./hosted-hillclimb-comparison.js";

export interface HostedHillclimbRepeatWindowV1 {
  readonly candidate_max_absolute_delta: {
    readonly authority_boundary_rate: number;
    readonly context_recall_rate: number;
    readonly evidence_context_retention_rate: number;
    readonly expected_restatement_turns_per_case: number;
    readonly p95_inference_latency_ms: number;
    readonly semantic_state_contract_rate: number;
  };
  readonly comparison_count: number;
  readonly first_evaluated_at: string;
  readonly last_evaluated_at: string;
  readonly maximum_absolute_judge_p95_latency_ms_delta: number;
  readonly maximum_absolute_model_token_count_delta: number;
  readonly schema_version: "slack-working-state-hosted-hillclimb-repeat-window/v1";
}

/** Seals a contiguous chronological sequence of content-free repeat comparisons. */
export function buildHostedHillclimbRepeatWindow(
  comparisons: readonly HostedHillclimbComparisonV1[],
): HostedHillclimbRepeatWindowV1 {
  if (comparisons.length === 0) {
    throw new Error("Hosted hillclimb repeat window requires at least one comparison.");
  }
  for (const [index, comparison] of comparisons.entries()) {
    if (comparison.schema_version !== "slack-working-state-hosted-hillclimb-comparison/v1") {
      throw new Error("Hosted hillclimb repeat window requires v1 comparisons.");
    }
    if (index > 0
      && comparisons[index - 1]?.current_evaluated_at !== comparison.previous_evaluated_at) {
      throw new Error("Hosted hillclimb repeat window requires a contiguous evaluation chain.");
    }
  }
  return Object.freeze({
    candidate_max_absolute_delta: Object.freeze({
      authority_boundary_rate: maximumAbsolute(comparisons.map(
        (comparison) => comparison.candidate_delta.authority_boundary_rate,
      )),
      context_recall_rate: maximumAbsolute(comparisons.map(
        (comparison) => comparison.candidate_delta.context_recall_rate,
      )),
      evidence_context_retention_rate: maximumAbsolute(comparisons.map(
        (comparison) => comparison.candidate_delta.evidence_context_retention_rate,
      )),
      expected_restatement_turns_per_case: maximumAbsolute(comparisons.map(
        (comparison) => comparison.candidate_delta.expected_restatement_turns_per_case,
      )),
      p95_inference_latency_ms: maximumAbsolute(comparisons.map(
        (comparison) => comparison.candidate_delta.p95_inference_latency_ms,
      )),
      semantic_state_contract_rate: maximumAbsolute(comparisons.map(
        (comparison) => comparison.candidate_delta.semantic_state_contract_rate,
      )),
    }),
    comparison_count: comparisons.length,
    first_evaluated_at: comparisons[0]!.previous_evaluated_at,
    last_evaluated_at: comparisons[comparisons.length - 1]!.current_evaluated_at,
    maximum_absolute_judge_p95_latency_ms_delta: maximumAbsolute(comparisons.map(
      (comparison) => comparison.judge_p95_latency_ms_delta,
    )),
    maximum_absolute_model_token_count_delta: maximumAbsolute(comparisons.map(
      (comparison) => comparison.model_token_count_delta,
    )),
    schema_version: "slack-working-state-hosted-hillclimb-repeat-window/v1",
  });
}

function maximumAbsolute(values: readonly number[]): number {
  return Math.max(...values.map((value) => Math.abs(value)));
}
