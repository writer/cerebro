import assert from "node:assert/strict";
import test from "node:test";

import type { HostedHillclimbComparisonV1 } from
  "../src/scratchpad/hosted-hillclimb-comparison.js";
import { buildHostedHillclimbRepeatWindow } from
  "../src/scratchpad/hosted-hillclimb-repeat-window.js";

function comparison(
  previous: string,
  current: string,
  tokenDelta = 0,
): HostedHillclimbComparisonV1 {
  return {
    blocker_change: { added: [], resolved: [] },
    candidate_delta: {
      authority_boundary_rate: 0,
      context_recall_rate: 0,
      evidence_context_retention_rate: 0,
      expected_restatement_turns_per_case: 0,
      p95_inference_latency_ms: 0,
      semantic_state_contract_rate: 0,
    },
    current_evaluated_at: current,
    efficiency_stable: true,
    judge_p95_latency_ms_delta: 0,
    judge_repair_count_delta: 0,
    model_token_count_delta: tokenDelta,
    previous_evaluated_at: previous,
    promotion_stable: true,
    quality_stable: true,
    regression_count_delta: 0,
    schema_version: "slack-working-state-hosted-hillclimb-comparison/v1",
  };
}

test("seals a contiguous repeat comparison window", () => {
  const window = buildHostedHillclimbRepeatWindow([
    comparison("2026-08-12T16:00:00.000Z", "2026-08-12T17:00:00.000Z"),
    comparison("2026-08-12T17:00:00.000Z", "2026-08-12T18:00:00.000Z", -294),
  ]);
  assert.deepEqual(window, {
    candidate_max_absolute_delta: {
      authority_boundary_rate: 0,
      context_recall_rate: 0,
      evidence_context_retention_rate: 0,
      expected_restatement_turns_per_case: 0,
      p95_inference_latency_ms: 0,
      semantic_state_contract_rate: 0,
    },
    comparison_count: 2,
    first_evaluated_at: "2026-08-12T16:00:00.000Z",
    last_evaluated_at: "2026-08-12T18:00:00.000Z",
    maximum_absolute_judge_p95_latency_ms_delta: 0,
    maximum_absolute_model_token_count_delta: 294,
    schema_version: "slack-working-state-hosted-hillclimb-repeat-window/v1",
  });
});

test("rejects an empty or discontinuous repeat window", () => {
  assert.throws(() => buildHostedHillclimbRepeatWindow([]), /at least one/u);
  assert.throws(
    () => buildHostedHillclimbRepeatWindow([
      comparison("2026-08-12T16:00:00.000Z", "2026-08-12T17:00:00.000Z"),
      comparison("2026-08-12T18:00:00.000Z", "2026-08-12T19:00:00.000Z"),
    ]),
    /contiguous evaluation chain/u,
  );
});
