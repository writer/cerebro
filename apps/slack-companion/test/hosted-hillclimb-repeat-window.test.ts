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
    corpus_digest: `sha256:${"a".repeat(64)}`,
    current_evaluated_at: current,
    efficiency_stable: true,
    execution_boundary: {
      distinct_model_id: true,
      generator_provider: "aws_bedrock",
      generator_region: "us-east-1",
      generator_sampling_parameters: "provider_default",
      judge_provider: "aws_bedrock",
      judge_region: "us-east-1",
      judge_sampling_parameters: "provider_default",
      separate_model_ports: true,
    },
    generator_model_id: "us.anthropic.claude-opus-4-8",
    judge_p95_latency_ms_delta: 0,
    judge_model_id: "us.anthropic.claude-opus-5",
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
    efficiency_regression_count: 0,
    first_evaluated_at: "2026-08-12T16:00:00.000Z",
    last_evaluated_at: "2026-08-12T18:00:00.000Z",
    maximum_absolute_judge_p95_latency_ms_delta: 0,
    maximum_absolute_model_token_count_delta: 294,
    quality_instability_count: 0,
    schema_version: "slack-working-state-hosted-hillclimb-repeat-window/v1",
    stability: { blockers: [], stable: true },
  });
});

test("holds stability until repeats are sufficient and quality remains stable", () => {
  const oneComparison = comparison(
    "2026-08-12T16:00:00.000Z",
    "2026-08-12T17:00:00.000Z",
  );
  const window = buildHostedHillclimbRepeatWindow([{
    ...oneComparison,
    quality_stable: false,
  }]);
  assert.deepEqual(window.stability, {
    blockers: ["insufficient_repeat_comparisons", "repeat_quality_regressed"],
    stable: false,
  });
  assert.equal(window.quality_instability_count, 1);
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

test("rejects repeat comparisons from another corpus or model boundary", () => {
  const first = comparison("2026-08-12T16:00:00.000Z", "2026-08-12T17:00:00.000Z");
  const second = comparison("2026-08-12T17:00:00.000Z", "2026-08-12T18:00:00.000Z");
  assert.throws(
    () => buildHostedHillclimbRepeatWindow([
      first,
      { ...second, corpus_digest: `sha256:${"b".repeat(64)}` },
    ]),
    /one corpus and execution boundary/u,
  );
  assert.throws(
    () => buildHostedHillclimbRepeatWindow([
      first,
      { ...second, judge_model_id: "us.anthropic.claude-opus-5-1" },
    ]),
    /one corpus and execution boundary/u,
  );
});
