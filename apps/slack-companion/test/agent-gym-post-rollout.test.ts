import assert from "node:assert/strict";
import test from "node:test";

import {
  digestAgentGymJson,
  decideAgentGymPostRolloutGate,
  openAgentGymRollbackReserve,
  recordAgentGymPostRolloutObservation,
  sealAgentGymPostRolloutWindow,
  triggerAgentGymRollback,
  validateAgentGymRollbackReserve,
  validateAgentGymRollbackTrigger,
  validateAgentGymPostRolloutObservation,
  validateAgentGymPostRolloutWindow,
  validateAgentGymPostRolloutGate,
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

test("post-rollout observations bind live evidence to the completed candidate", () => {
  const observation = recordAgentGymPostRolloutObservation(completedRollout(), {
    blocker_codes: [],
    evidence_refs: ["agent-gym-evidence://post-rollout/one"],
    latency_ms: 900,
    observation_ref: "agent-gym-post-rollout-observation://nightly/one",
    observed_at: "2026-08-12T11:28:00.000Z",
    outcome: "passed",
    quality_score: 0.91,
    sample_ref: "agent-gym-live-sample://nightly/one",
  });
  assert.equal(observation.candidate_ref, completedRollout().candidate_ref);
  assert.deepEqual(validateAgentGymPostRolloutObservation(observation), observation);
});

test("post-rollout failures require explicit blocker codes", () => {
  assert.throws(() => recordAgentGymPostRolloutObservation(completedRollout(), {
    blocker_codes: [],
    evidence_refs: [],
    latency_ms: 900,
    observation_ref: "agent-gym-post-rollout-observation://nightly/invalid",
    observed_at: "2026-08-12T11:28:00.000Z",
    outcome: "failed",
    quality_score: 0.4,
    sample_ref: "agent-gym-live-sample://nightly/invalid",
  }), /post-rollout observation is invalid/u);
});

test("post-rollout windows aggregate chronological live observations", () => {
  const observations = [liveObservation("one", "2026-08-12T11:28:00.000Z", 700, 0.95),
    liveObservation("two", "2026-08-12T11:29:00.000Z", 1200, 0.85)];
  const window = sealAgentGymPostRolloutWindow(observations, {
    evidence_refs: ["agent-gym-evidence://post-rollout/window-one"],
    sealed_at: "2026-08-12T11:30:00.000Z",
    window_ref: "agent-gym-post-rollout-window://nightly/one",
  });
  assert.equal(window.observation_count, 2);
  assert.equal(window.mean_quality_score, 0.9);
  assert.equal(window.p95_latency_ms, 1200);
  assert.deepEqual(validateAgentGymPostRolloutWindow(window), window);
});

test("post-rollout windows reject observations presented out of order", () => {
  const observations = [liveObservation("two", "2026-08-12T11:29:00.000Z", 1200, 0.85),
    liveObservation("one", "2026-08-12T11:28:00.000Z", 700, 0.95)];
  assert.throws(() => sealAgentGymPostRolloutWindow(observations, {
    evidence_refs: ["agent-gym-evidence://post-rollout/window-invalid"],
    sealed_at: "2026-08-12T11:30:00.000Z",
    window_ref: "agent-gym-post-rollout-window://nightly/invalid",
  }), /post-rollout window is invalid/u);
});

test("post-rollout gates mark a threshold-compliant window healthy", () => {
  const gate = decideAgentGymPostRolloutGate(liveWindow(), {
    decided_at: "2026-08-12T11:31:00.000Z",
    evidence_refs: ["agent-gym-evidence://post-rollout/gate-one"],
    gate_ref: "agent-gym-post-rollout-gate://nightly/one",
    policy: postRolloutPolicy(2),
  });
  assert.equal(gate.decision, "healthy");
  assert.deepEqual(validateAgentGymPostRolloutGate(gate), gate);
});

test("post-rollout gates hold when the evidence window is undersampled", () => {
  const gate = decideAgentGymPostRolloutGate(liveWindow(), {
    decided_at: "2026-08-12T11:31:00.000Z",
    evidence_refs: ["agent-gym-evidence://post-rollout/gate-hold"],
    gate_ref: "agent-gym-post-rollout-gate://nightly/hold",
    policy: postRolloutPolicy(3),
  });
  assert.equal(gate.decision, "hold");
  assert.deepEqual(gate.blocker_codes, ["post_rollout_samples_insufficient"]);
});

test("rollback triggers bind a regression gate to an unexpired fallback reserve", () => {
  const trigger = triggerAgentGymRollback(rollbackGate(), rollbackReserve(), {
    evidence_refs: ["agent-gym-evidence://rollback/trigger-one"],
    executor_action_ref: "agent-gym-executor-action://rollout/rollback-one",
    triggered_at: "2026-08-12T11:32:00.000Z",
    trigger_ref: "agent-gym-rollback-trigger://nightly/one",
  });
  assert.equal(trigger.fallback_candidate_ref, "agent-gym-candidate://nightly/baseline");
  assert.deepEqual(validateAgentGymRollbackTrigger(trigger), trigger);
});

test("rollback triggers reject expired fallback reserves", () => {
  assert.throws(() => triggerAgentGymRollback(rollbackGate(), rollbackReserve(), {
    evidence_refs: ["agent-gym-evidence://rollback/expired"],
    executor_action_ref: "agent-gym-executor-action://rollout/rollback-expired",
    triggered_at: "2026-08-20T11:32:00.000Z",
    trigger_ref: "agent-gym-rollback-trigger://nightly/expired",
  }), /rollback trigger is invalid/u);
});

function rollbackGate() {
  const window = sealAgentGymPostRolloutWindow([
    recordAgentGymPostRolloutObservation(completedRollout(), {
      blocker_codes: ["live_sample_failed"],
      evidence_refs: ["agent-gym-evidence://post-rollout/failure"],
      latency_ms: 2200,
      observation_ref: "agent-gym-post-rollout-observation://nightly/failure",
      observed_at: "2026-08-12T11:28:00.000Z",
      outcome: "failed",
      quality_score: 0.4,
      sample_ref: "agent-gym-live-sample://nightly/failure",
    }),
  ], {
    evidence_refs: ["agent-gym-evidence://post-rollout/window-failure"],
    sealed_at: "2026-08-12T11:30:00.000Z",
    window_ref: "agent-gym-post-rollout-window://nightly/failure",
  });
  return decideAgentGymPostRolloutGate(window, {
    decided_at: "2026-08-12T11:31:00.000Z",
    evidence_refs: ["agent-gym-evidence://post-rollout/gate-failure"],
    gate_ref: "agent-gym-post-rollout-gate://nightly/failure",
    policy: postRolloutPolicy(1),
  });
}

function rollbackReserve() {
  return openAgentGymRollbackReserve(completedRollout(), {
    evidence_refs: ["agent-gym-evidence://fallback/ready"],
    expires_at: "2026-08-19T11:27:00.000Z",
    fallback_candidate_ref: "agent-gym-candidate://nightly/baseline",
    opened_at: "2026-08-12T11:27:00.000Z",
    reserve_ref: "agent-gym-rollback-reserve://nightly/one",
  });
}

function liveWindow() {
  return sealAgentGymPostRolloutWindow([
    liveObservation("one", "2026-08-12T11:28:00.000Z", 700, 0.95),
    liveObservation("two", "2026-08-12T11:29:00.000Z", 1200, 0.85),
  ], {
    evidence_refs: ["agent-gym-evidence://post-rollout/window-one"],
    sealed_at: "2026-08-12T11:30:00.000Z",
    window_ref: "agent-gym-post-rollout-window://nightly/one",
  });
}

function postRolloutPolicy(minimum: number) {
  return {
    max_failed_rate: 0,
    max_p95_latency_ms: 1500,
    min_mean_quality_score: 0.85,
    min_observation_count: minimum,
    policy_ref: "agent-gym-post-rollout-policy://nightly/default",
    schema_version: "agent-gym-post-rollout-policy/v1" as const,
  };
}

function liveObservation(ref: string, observedAt: string, latencyMs: number, qualityScore: number) {
  return recordAgentGymPostRolloutObservation(completedRollout(), {
    blocker_codes: [],
    evidence_refs: [`agent-gym-evidence://post-rollout/${ref}`],
    latency_ms: latencyMs,
    observation_ref: `agent-gym-post-rollout-observation://nightly/${ref}`,
    observed_at: observedAt,
    outcome: "passed",
    quality_score: qualityScore,
    sample_ref: `agent-gym-live-sample://nightly/${ref}`,
  });
}

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
