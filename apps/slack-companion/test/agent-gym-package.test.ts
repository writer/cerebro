import assert from "node:assert/strict";
import test from "node:test";

import {
  AgentGymContractError,
  CEREBRO_AGENT_GYM,
  validateAgentGymCandidateManifest,
  validateAgentGymFixtureCase,
  validateAgentGymReplayRun,
} from "../src/index.js";

test("agent gym exposes a stable public contract identity", () => {
  assert.deepEqual(CEREBRO_AGENT_GYM, {
    artifact_namespace: "cerebro-agent-gym",
    schema_version: "cerebro-agent-gym/v1",
  });
  assert.equal(Object.isFrozen(CEREBRO_AGENT_GYM), true);
  assert.equal(new AgentGymContractError("invalid").name, "AgentGymContractError");
});

test("replay runs preserve ordered model and effect receipts", () => {
  const digest = `sha256:${"c".repeat(64)}` as const;
  const run = validateAgentGymReplayRun({
    artifact_digest: digest,
    candidate_ref: "candidate://agent-gym/one",
    completed_at: "2026-08-12T08:00:02.000Z",
    fixture_ref: "case://agent-gym/mention-one",
    run_ref: "replay://agent-gym/one",
    schema_version: "agent-gym-replay-run/v1",
    started_at: "2026-08-12T08:00:00.000Z",
    status: "passed",
    turns: [{
      content_digest: digest,
      kind: "model",
      latency_ms: 800,
      recorded_at: "2026-08-12T08:00:01.000Z",
      token_usage: { input_tokens: 100, output_tokens: 25 },
      turn_index: 0,
    }],
  });
  assert.equal(Object.isFrozen(run.turns[0]?.token_usage), true);
  assert.throws(() => validateAgentGymReplayRun({
    ...run,
    status: "failed",
  }), /replay run is invalid/u);
});

test("candidate manifests bind every evaluation input to immutable digests", () => {
  const digest = `sha256:${"a".repeat(64)}` as const;
  const candidate = validateAgentGymCandidateManifest({
    candidate_ref: "candidate://agent-gym/one",
    max_output_tokens: 800,
    model_id: "inference-profile.example-model",
    policy_digest: digest,
    prompt_digest: digest,
    provider: "aws_bedrock",
    region: "us-east-1",
    schema_version: "agent-gym-candidate-manifest/v1",
    source_revision: "b".repeat(40),
    tool_catalog_digest: digest,
    tool_ids: ["cerebro.search"],
  });
  assert.equal(Object.isFrozen(candidate.tool_ids), true);
  assert.throws(() => validateAgentGymCandidateManifest({
    ...candidate,
    provider: "recorded",
  }), /candidate manifest is invalid/u);
});

test("fixture cases retain ordered Slack events and deterministic tool results", () => {
  const fixture = validateAgentGymFixtureCase({
    case_ref: "case://agent-gym/mention-one",
    expected_invariants: ["answer_has_evidence"],
    labels: ["lookup"],
    partition: "train",
    schema_version: "agent-gym-fixture-case/v1",
    slack_events: [{
      event_ref: "slack-event://one",
      kind: "mention",
      occurred_at: "2026-08-12T08:00:00.000Z",
      payload: { text: "What changed?" },
    }],
    tool_fixtures: [{
      call_ref: "tool-call://one",
      input: { query: "recent changes" },
      outcome: "success",
      output: { count: 2 },
      tool_id: "cerebro.search",
    }],
  });
  assert.equal(fixture.slack_events[0]?.kind, "mention");
  assert.equal(Object.isFrozen(fixture.tool_fixtures[0]?.output), true);
  assert.throws(() => validateAgentGymFixtureCase({
    ...fixture,
    slack_events: [fixture.slack_events[0]!, fixture.slack_events[0]!],
  }), /fixture is invalid/u);
});
