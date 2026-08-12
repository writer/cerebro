import type { HostedHillclimbComparisonV1 } from "./hosted-hillclimb-comparison.js";

export interface HostedHillclimbRepeatPolicyV1 {
  readonly maximum_window_span_ms: number;
  readonly minimum_comparison_count: number;
}

const DEFAULT_REPEAT_POLICY: HostedHillclimbRepeatPolicyV1 = Object.freeze({
  maximum_window_span_ms: 86_400_000,
  minimum_comparison_count: 2,
});

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
  readonly corpus_digest: string;
  readonly efficiency_regression_count: number;
  readonly evaluation_span_ms: number;
  readonly execution_boundary: HostedHillclimbComparisonV1["execution_boundary"];
  readonly generator_model_id: string;
  readonly first_evaluated_at: string;
  readonly last_evaluated_at: string;
  readonly judge_model_id: string;
  readonly maximum_absolute_judge_p95_latency_ms_delta: number;
  readonly maximum_absolute_model_token_count_delta: number;
  readonly maximum_evaluation_gap_ms: number;
  readonly policy: HostedHillclimbRepeatPolicyV1;
  readonly quality_instability_count: number;
  readonly schema_version: "slack-working-state-hosted-hillclimb-repeat-window/v1";
  readonly stability: {
    readonly blockers: readonly string[];
    readonly stable: boolean;
  };
}

/** Seals a contiguous chronological sequence of content-free repeat comparisons. */
export function buildHostedHillclimbRepeatWindow(
  comparisons: readonly HostedHillclimbComparisonV1[],
  policy: HostedHillclimbRepeatPolicyV1 = DEFAULT_REPEAT_POLICY,
): HostedHillclimbRepeatWindowV1 {
  if (!Number.isSafeInteger(policy.minimum_comparison_count)
    || policy.minimum_comparison_count < 1
    || policy.minimum_comparison_count > 100) {
    throw new Error("Hosted hillclimb repeat policy requires a bounded sample minimum.");
  }
  if (!Number.isSafeInteger(policy.maximum_window_span_ms)
    || policy.maximum_window_span_ms < 1
    || policy.maximum_window_span_ms > 2_678_400_000) {
    throw new Error("Hosted hillclimb repeat policy requires a bounded window span.");
  }
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
    if (!sameComparisonBoundary(comparisons[0]!, comparison)) {
      throw new Error("Hosted hillclimb repeat window requires one corpus and execution boundary.");
    }
    const previousTime = Date.parse(comparison.previous_evaluated_at);
    const currentTime = Date.parse(comparison.current_evaluated_at);
    if (!Number.isFinite(previousTime) || !Number.isFinite(currentTime)
      || currentTime <= previousTime) {
      throw new Error("Hosted hillclimb repeat window requires increasing canonical times.");
    }
  }
  const evaluationSpanMs =
    Date.parse(comparisons[comparisons.length - 1]!.current_evaluated_at)
    - Date.parse(comparisons[0]!.previous_evaluated_at);
  const stabilityBlockers = [
    ...(comparisons.length < policy.minimum_comparison_count
      ? ["insufficient_repeat_comparisons"] : []),
    ...(comparisons.some((comparison) => !comparison.promotion_stable)
      ? ["promotion_state_changed"] : []),
    ...(comparisons.some((comparison) => !comparison.quality_stable)
      ? ["repeat_quality_regressed"] : []),
    ...(evaluationSpanMs > policy.maximum_window_span_ms
      ? ["repeat_window_too_wide"] : []),
  ];
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
    corpus_digest: comparisons[0]!.corpus_digest,
    efficiency_regression_count: comparisons.filter(
      (comparison) => !comparison.efficiency_stable,
    ).length,
    evaluation_span_ms: evaluationSpanMs,
    execution_boundary: Object.freeze({ ...comparisons[0]!.execution_boundary }),
    generator_model_id: comparisons[0]!.generator_model_id,
    first_evaluated_at: comparisons[0]!.previous_evaluated_at,
    last_evaluated_at: comparisons[comparisons.length - 1]!.current_evaluated_at,
    judge_model_id: comparisons[0]!.judge_model_id,
    maximum_absolute_judge_p95_latency_ms_delta: maximumAbsolute(comparisons.map(
      (comparison) => comparison.judge_p95_latency_ms_delta,
    )),
    maximum_absolute_model_token_count_delta: maximumAbsolute(comparisons.map(
      (comparison) => comparison.model_token_count_delta,
    )),
    maximum_evaluation_gap_ms: Math.max(...comparisons.map(
      (comparison) => Date.parse(comparison.current_evaluated_at)
        - Date.parse(comparison.previous_evaluated_at),
    )),
    policy: Object.freeze({ ...policy }),
    quality_instability_count: comparisons.filter(
      (comparison) => !comparison.quality_stable,
    ).length,
    schema_version: "slack-working-state-hosted-hillclimb-repeat-window/v1",
    stability: Object.freeze({
      blockers: Object.freeze(stabilityBlockers),
      stable: stabilityBlockers.length === 0,
    }),
  });
}

function sameComparisonBoundary(
  first: HostedHillclimbComparisonV1,
  current: HostedHillclimbComparisonV1,
): boolean {
  return first.corpus_digest === current.corpus_digest
    && first.generator_model_id === current.generator_model_id
    && first.judge_model_id === current.judge_model_id
    && first.execution_boundary.distinct_model_id === current.execution_boundary.distinct_model_id
    && first.execution_boundary.generator_provider === current.execution_boundary.generator_provider
    && first.execution_boundary.generator_region === current.execution_boundary.generator_region
    && first.execution_boundary.generator_sampling_parameters
      === current.execution_boundary.generator_sampling_parameters
    && first.execution_boundary.judge_provider === current.execution_boundary.judge_provider
    && first.execution_boundary.judge_region === current.execution_boundary.judge_region
    && first.execution_boundary.judge_sampling_parameters
      === current.execution_boundary.judge_sampling_parameters
    && first.execution_boundary.separate_model_ports
      === current.execution_boundary.separate_model_ports;
}

function maximumAbsolute(values: readonly number[]): number {
  return Math.max(...values.map((value) => Math.abs(value)));
}
