import type { HostedHillclimbRepeatWindowV1 } from "./hosted-hillclimb-repeat-window.js";

export interface HostedHillclimbRepeatVerdictV1 {
  readonly blockers: readonly string[];
  readonly comparison_count: number;
  readonly corpus_digest: string;
  readonly decision: "hold" | "stable";
  readonly evaluated_at: string;
  readonly generator_model_id: string;
  readonly judge_model_id: string;
  readonly judge_repair_increase_count: number;
  readonly promotion_flip_count: number;
  readonly regression_increase_count: number;
  readonly schema_version: "slack-working-state-hosted-hillclimb-repeat-verdict/v1";
}

/** Projects a bounded content-free decision from one sealed repeat window. */
export function decideHostedHillclimbRepeatVerdict(
  window: HostedHillclimbRepeatWindowV1,
): HostedHillclimbRepeatVerdictV1 {
  if (window.schema_version !== "slack-working-state-hosted-hillclimb-repeat-window/v1") {
    throw new Error("Hosted hillclimb repeat verdict requires a v1 window.");
  }
  return Object.freeze({
    blockers: Object.freeze([...window.stability.blockers]),
    comparison_count: window.comparison_count,
    corpus_digest: window.corpus_digest,
    decision: window.stability.stable ? "stable" : "hold",
    evaluated_at: window.last_evaluated_at,
    generator_model_id: window.generator_model_id,
    judge_model_id: window.judge_model_id,
    judge_repair_increase_count: window.judge_repair_increase_count,
    promotion_flip_count: window.promotion_flip_count,
    regression_increase_count: window.regression_increase_count,
    schema_version: "slack-working-state-hosted-hillclimb-repeat-verdict/v1",
  });
}
