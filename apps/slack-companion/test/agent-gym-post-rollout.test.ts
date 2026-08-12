import assert from "node:assert/strict";
import test from "node:test";

import {
  digestAgentGymJson,
  openAgentGymRollbackReserve,
  validateAgentGymRollbackReserve,
  type AgentGymRolloutSummaryV1,
} from "../src/index.js";

test("rollback reserves retain an evidenced fallback for a completed rollout", () => {
  const reserve = openAgentGymRollbackReserve(completedRollout(), {
    evidence_refs: ["agent-gym-evidence://fallback/ready"],
    expires_at: "2026-08-19T11:27:00.000Z",
    fallback_candidate_ref: "agent-gym-candidate://nightly/baseline",
    opened_at: "2026-08-12T11:27:00.000Z",
    reserve_ref: "agent-gym-rollback-reserve://nightly/one",
  });
  assert.equal(reserve.candidate_ref, "agent-gym-candidate://nightly/challenger");
  assert.deepEqual(validateAgentGymRollbackReserve(reserve), reserve);
});

test("rollback reserves reject the active candidate as its own fallback", () => {
  assert.throws(() => openAgentGymRollbackReserve(completedRollout(), {
    evidence_refs: ["agent-gym-evidence://fallback/ready"],
    expires_at: "2026-08-19T11:27:00.000Z",
    fallback_candidate_ref: "agent-gym-candidate://nightly/challenger",
    opened_at: "2026-08-12T11:27:00.000Z",
    reserve_ref: "agent-gym-rollback-reserve://nightly/invalid",
  }), /rollback reserve is invalid/u);
});

function completedRollout(): AgentGymRolloutSummaryV1 {
  const body = {
    active_candidate_ref: "agent-gym-candidate://nightly/challenger",
    candidate_ref: "agent-gym-candidate://nightly/challenger",
    completed_at: "2026-08-12T11:26:00.000Z",
    completion_decision_digest: digest("a"),
    outcome: "completed" as const,
    schema_version: "agent-gym-rollout-summary/v1" as const,
    started_at: "2026-08-12T11:25:00.000Z",
    state_count: 1,
    state_digests: [digest("b")],
    summary_ref: "agent-gym-rollout-summary://nightly/completed",
    target_ref: "agent-gym-target://slack-companion/default",
    terminal: true,
  };
  return { ...body, summary_digest: digestAgentGymJson(body) };
}

function digest(character: string): string {
  return `sha256:${character.repeat(64)}`;
}
