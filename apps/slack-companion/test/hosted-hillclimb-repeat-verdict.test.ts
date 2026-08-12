import assert from "node:assert/strict";
import test from "node:test";

import { decideHostedHillclimbRepeatVerdict } from
  "../src/scratchpad/hosted-hillclimb-repeat-verdict.js";
import type { HostedHillclimbRepeatWindowV1 } from
  "../src/scratchpad/hosted-hillclimb-repeat-window.js";

function window(stable: boolean): HostedHillclimbRepeatWindowV1 {
  return {
    candidate_max_absolute_delta: {
      authority_boundary_rate: 0,
      context_recall_rate: 0,
      evidence_context_retention_rate: 0,
      expected_restatement_turns_per_case: 0,
      p95_inference_latency_ms: 0,
      semantic_state_contract_rate: 0,
    },
    comparison_count: 2,
    corpus_digest: `sha256:${"a".repeat(64)}`,
    efficiency_regression_count: 0,
    evaluation_span_ms: 7_200_000,
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
    first_evaluated_at: "2026-08-12T16:00:00.000Z",
    generator_model_id: "us.anthropic.claude-opus-4-8",
    judge_model_id: "us.anthropic.claude-opus-5",
    judge_repair_increase_count: stable ? 0 : 1,
    last_evaluated_at: "2026-08-12T18:00:00.000Z",
    maximum_absolute_judge_p95_latency_ms_delta: 0,
    maximum_absolute_model_token_count_delta: 0,
    maximum_evaluation_gap_ms: 3_600_000,
    policy: { maximum_window_span_ms: 86_400_000, minimum_comparison_count: 2 },
    promotion_flip_count: 0,
    quality_instability_count: stable ? 0 : 1,
    regression_increase_count: 0,
    schema_version: "slack-working-state-hosted-hillclimb-repeat-window/v1",
    stability: { blockers: stable ? [] : ["repeat_quality_regressed"], stable },
  };
}

test("projects a stable content-free repeat verdict", () => {
  const verdict = decideHostedHillclimbRepeatVerdict(window(true));
  assert.equal(verdict.decision, "stable");
  assert.deepEqual(verdict.blockers, []);
  assert.equal(verdict.generator_model_id, "us.anthropic.claude-opus-4-8");
  assert.equal(verdict.judge_model_id, "us.anthropic.claude-opus-5");
});

test("holds a repeat verdict with exact window blockers", () => {
  const verdict = decideHostedHillclimbRepeatVerdict(window(false));
  assert.equal(verdict.decision, "hold");
  assert.deepEqual(verdict.blockers, ["repeat_quality_regressed"]);
  assert.equal(verdict.judge_repair_increase_count, 1);
});
