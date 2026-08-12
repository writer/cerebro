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
  candidateTokens?: number;
  judgeTokens?: number;
  region?: string;
  regressions?: number;
} = {}): HostedHillclimbReceipt {
  return {
    baseline: summary(0.1),
    candidate: summary(overrides.contextRecall ?? 0.9, overrides.candidateTokens),
    corpus_digest: overrides.corpusDigest ?? `sha256:${"a".repeat(64)}`,
    evaluated_at: overrides.evaluatedAt ?? "2026-08-12T16:00:00.000Z",
    evaluation_independence: { distinct_model_id: true, separate_model_ports: true },
    generator: {
      model_id: "us.anthropic.claude-opus-4-8",
      provider: "aws_bedrock",
      region: overrides.region ?? "us-east-1",
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
      region: overrides.region ?? "us-east-1",
      sampling_parameters: "provider_default",
      total_tokens: overrides.judgeTokens ?? 15,
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

function summary(
  contextRecall: number,
  totalTokens = 150,
): HostedHillclimbReceipt["candidate"] {
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
    total_tokens: totalTokens,
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
      candidateTokens: 175,
      judgeTokens: 25,
      regressions: 2,
    }),
  );
  assert.equal(comparison.candidate_delta.context_recall_rate, 0.1);
  assert.equal(comparison.corpus_digest, `sha256:${"a".repeat(64)}`);
  assert.equal(comparison.generator_model_id, "us.anthropic.claude-opus-4-8");
  assert.equal(comparison.judge_model_id, "us.anthropic.claude-opus-5");
  assert.deepEqual(comparison.execution_boundary, {
    distinct_model_id: true,
    generator_provider: "aws_bedrock",
    generator_region: "us-east-1",
    generator_sampling_parameters: "provider_default",
    judge_provider: "aws_bedrock",
    judge_region: "us-east-1",
    judge_sampling_parameters: "provider_default",
    separate_model_ports: true,
  });
  assert.deepEqual(comparison.blocker_change, {
    added: ["new_blocker"],
    resolved: ["old_blocker"],
  });
  assert.equal(comparison.regression_count_delta, 2);
  assert.equal(comparison.judge_repair_count_delta, 2);
  assert.equal(comparison.judge_p95_latency_ms_delta, 150);
  assert.equal(comparison.model_token_count_delta, 35);
  assert.equal(comparison.promotion_stable, true);
  assert.equal(comparison.quality_stable, false);
  assert.equal(comparison.efficiency_stable, false);
});

test("marks quality stable when repeats add no failures or repairs", () => {
  const comparison = compareHostedSlackWorkingStateHillclimbs(
    receipt({ blockers: ["old_blocker"], repairCount: 1, regressions: 1 }),
    receipt({ evaluatedAt: "2026-08-12T17:00:00.000Z" }),
  );
  assert.equal(comparison.quality_stable, true);
  assert.equal(comparison.efficiency_stable, true);
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
  assert.throws(
    () => compareHostedSlackWorkingStateHillclimbs(
      receipt(),
      receipt({ evaluatedAt: "2026-08-12T17:00:00Z" }),
    ),
    /canonical evaluation times/u,
  );
});

test("rejects comparisons across execution boundaries", () => {
  assert.throws(
    () => compareHostedSlackWorkingStateHillclimbs(
      receipt(),
      receipt({
        evaluatedAt: "2026-08-12T17:00:00.000Z",
        region: "us-west-2",
      }),
    ),
    /same execution boundary/u,
  );
});
