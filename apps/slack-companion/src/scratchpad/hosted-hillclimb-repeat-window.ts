import type { HostedHillclimbComparisonV1 } from "./hosted-hillclimb-comparison.js";

export interface HostedHillclimbRepeatWindowV1 {
  readonly comparison_count: number;
  readonly first_evaluated_at: string;
  readonly last_evaluated_at: string;
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
    comparison_count: comparisons.length,
    first_evaluated_at: comparisons[0]!.previous_evaluated_at,
    last_evaluated_at: comparisons[comparisons.length - 1]!.current_evaluated_at,
    schema_version: "slack-working-state-hosted-hillclimb-repeat-window/v1",
  });
}
