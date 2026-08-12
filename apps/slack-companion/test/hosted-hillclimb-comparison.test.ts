import assert from "node:assert/strict";
import test from "node:test";

import { compareHostedSlackWorkingStateHillclimbs } from
  "../src/scratchpad/hosted-hillclimb-comparison.js";
import type { HostedHillclimbReceipt } from "../src/scratchpad/hosted-hillclimb.js";

function receipt(overrides: {
  blockers?: string[];
  contextRecall?: number;
  corpusDigest?: string;
  evaluatedAt?: string;
  repairCount?: number;
  judgeLatency?: number;
  regressions?: number;
} = {}): HostedHillclimbReceipt {
  return {
    baseline: summary(0.1),
    candidate: summary(overrides.contextRecall ?? 0.9),
    corpus_digest: overrides.corpusDigest ?? `sha256:${"a".repeat(64)}`,
    evaluated_at: overrides.evaluatedAt ?? "2026-08-12T16:00:00.000Z",
    evaluation_independence: { distinct_model_id: true, separate_model_ports: true },
    generator: {
      model_id: "us.anthropic.claude-opus-4-8",
      provider: "aws_bedrock",
      region: "us-east-1",
      sampling_parameters: "provider_default",
    },
    goal: {
      maximum_candidate_expected_restatement_turns_per_case: 0.1,
      maximum_candidate_p95_inference_latency_ms: 10_000,
      minimum_candidate_authority_boundary_rate: 1,
      minimum_candidate_context_recall_rate: 0.9,
      minimum_candidate_evidence_context_retention_rate: 0.9,
      minimum_candidate_semantic_state_contract_rate: 0.9,
      minimum_context_recall_gain: 0.25,
    },
    judge: {
      input_tokens: 10,
      invocation_count: 1,
      model_id: "us.anthropic.claude-opus-5",
      output_tokens: 5,
      p95_latency_ms: overrides.judgeLatency ?? 200,
      provider: "aws_bedrock",
      repair_count: overrides.repairCount ?? 0,
      region: "us-east-1",
      sampling_parameters: "provider_default",
      total_tokens: 15,
    },
    promotion: {
      blockers: overrides.blockers ?? [],
      context_recall_gain: 0.8,
      promotion_ready: (overrides.blockers ?? []).length === 0,
      regression_count: overrides.regressions ?? 0,
    },
    results: [],
    schema_version: "slack-working-state-hosted-hillclimb-receipt/v1",
    structural_preflight: {
      corpus_digest: overrides.corpusDigest ?? `sha256:${"a".repeat(64)}`,
      promotion_ready: true,
    },
  };
}

function summary(contextRecall: number): HostedHillclimbReceipt["candidate"] {
  return {
    authority_boundary_rate: 1,
    case_count: 22,
    case_pass_rate: contextRecall,
    context_recall_rate: contextRecall,
    evidence_context_retention_rate: 1,
    expected_restatement_turns_per_case: 0,
    input_tokens: 100,
    output_tokens: 50,
    p95_inference_latency_ms: 3_000,
    semantic_state_contract_rate: 1,
    total_tokens: 150,
  };
}

test("compares repeat measurements without answer content", () => {
  const comparison = compareHostedSlackWorkingStateHillclimbs(
    receipt({ blockers: ["old_blocker"] }),
    receipt({
      blockers: ["new_blocker"],
      contextRecall: 1,
      evaluatedAt: "2026-08-12T17:00:00.000Z",
      repairCount: 2,
      judgeLatency: 350,
      regressions: 2,
    }),
  );
  assert.equal(comparison.candidate_delta.context_recall_rate, 0.1);
  assert.deepEqual(comparison.blocker_change, {
    added: ["new_blocker"],
    resolved: ["old_blocker"],
  });
  assert.equal(comparison.regression_count_delta, 2);
  assert.equal(comparison.judge_repair_count_delta, 2);
  assert.equal(comparison.judge_p95_latency_ms_delta, 150);
  assert.equal(comparison.promotion_stable, true);
});

test("rejects comparisons across corpora or reversed time", () => {
  assert.throws(
    () => compareHostedSlackWorkingStateHillclimbs(
      receipt(),
      receipt({
        corpusDigest: `sha256:${"b".repeat(64)}`,
        evaluatedAt: "2026-08-12T17:00:00.000Z",
      }),
    ),
    /same corpus digest/u,
  );
  assert.throws(
    () => compareHostedSlackWorkingStateHillclimbs(
      receipt(),
      receipt({ evaluatedAt: "2026-08-12T15:00:00.000Z" }),
    ),
    /increasing evaluation times/u,
  );
});
