import assert from "node:assert/strict";
import test from "node:test";

import {
  digestAgentGymJson,
  decideAgentGymPostRolloutGate,
  openAgentGymRollbackReserve,
  observeAgentGymRollbackState,
  recordAgentGymPostRolloutObservation,
  recordAgentGymRollbackActionReceipt,
  sealAgentGymPostRolloutWindow,
  triggerAgentGymRollback,
  verifyAgentGymRollback,
  validateAgentGymRollbackReserve,
  validateAgentGymRollbackTrigger,
  validateAgentGymRollbackActionReceipt,
  validateAgentGymRollbackStateObservation,
  validateAgentGymRollbackVerification,
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

test("rollback action receipts retain the exact executor outcome", () => {
  const receipt = recordAgentGymRollbackActionReceipt(rollbackTrigger(), {
    action_outcome: "applied",
    completed_at: "2026-08-12T11:33:00.000Z",
    evidence_refs: ["agent-gym-evidence://rollback/action-one"],
    executor_ref: "agent-gym-executor://rollout/default",
    external_receipt_ref: "agent-gym-external-receipt://rollback/action-one",
    observed_candidate_ref: "agent-gym-candidate://nightly/baseline",
    receipt_ref: "agent-gym-rollback-action-receipt://nightly/one",
  });
  assert.equal(receipt.action_outcome, "applied");
  assert.deepEqual(validateAgentGymRollbackActionReceipt(receipt), receipt);
});

test("rollback action receipts cannot claim the failed candidate was applied", () => {
  assert.throws(() => recordAgentGymRollbackActionReceipt(rollbackTrigger(), {
    action_outcome: "applied",
    completed_at: "2026-08-12T11:33:00.000Z",
    evidence_refs: ["agent-gym-evidence://rollback/action-invalid"],
    executor_ref: "agent-gym-executor://rollout/default",
    external_receipt_ref: "agent-gym-external-receipt://rollback/action-invalid",
    observed_candidate_ref: "agent-gym-candidate://nightly/challenger",
    receipt_ref: "agent-gym-rollback-action-receipt://nightly/invalid",
  }), /rollback action receipt is invalid/u);
});

test("rollback state observations use a fresh independent observer", () => {
  const observation = observeAgentGymRollbackState(appliedRollbackReceipt(), {
    availability: "available",
    evidence_refs: ["agent-gym-evidence://rollback/state-one"],
    observation_ref: "agent-gym-rollback-state-observation://nightly/one",
    observed_at: "2026-08-12T11:34:00.000Z",
    observed_candidate_ref: "agent-gym-candidate://nightly/baseline",
    observer_ref: "agent-gym-observer://rollout/independent",
  });
  assert.equal(observation.observed_candidate_ref, "agent-gym-candidate://nightly/baseline");
  assert.deepEqual(validateAgentGymRollbackStateObservation(observation), observation);
});

test("rollback executors cannot independently observe their own action", () => {
  assert.throws(() => observeAgentGymRollbackState(appliedRollbackReceipt(), {
    availability: "available",
    evidence_refs: ["agent-gym-evidence://rollback/state-invalid"],
    observation_ref: "agent-gym-rollback-state-observation://nightly/invalid",
    observed_at: "2026-08-12T11:34:00.000Z",
    observed_candidate_ref: "agent-gym-candidate://nightly/baseline",
    observer_ref: "agent-gym-executor://rollout/default",
  }), /rollback state observation is invalid/u);
});

test("rollback verification closes only from independently observed fallback state", () => {
  const verification = verifyAgentGymRollback(rollbackTrigger(), appliedRollbackReceipt(), rollbackObservation(), {
    evidence_refs: ["agent-gym-evidence://rollback/verification-one"],
    verification_ref: "agent-gym-rollback-verification://nightly/one",
    verified_at: "2026-08-12T11:35:00.000Z",
  });
  assert.equal(verification.outcome, "verified");
  assert.deepEqual(validateAgentGymRollbackVerification(verification), verification);
});

test("rollback verification remains indeterminate when state is unavailable", () => {
  const observation = observeAgentGymRollbackState(appliedRollbackReceipt(), {
    availability: "unavailable",
    evidence_refs: ["agent-gym-evidence://rollback/state-unavailable"],
    observation_ref: "agent-gym-rollback-state-observation://nightly/unavailable",
    observed_at: "2026-08-12T11:34:00.000Z",
    observed_candidate_ref: null,
    observer_ref: "agent-gym-observer://rollout/independent",
  });
  const verification = verifyAgentGymRollback(rollbackTrigger(), appliedRollbackReceipt(), observation, {
    evidence_refs: ["agent-gym-evidence://rollback/verification-unavailable"],
    verification_ref: "agent-gym-rollback-verification://nightly/unavailable",
    verified_at: "2026-08-12T11:35:00.000Z",
  });
  assert.equal(verification.outcome, "indeterminate");
});

function rollbackObservation() {
  return observeAgentGymRollbackState(appliedRollbackReceipt(), {
    availability: "available",
    evidence_refs: ["agent-gym-evidence://rollback/state-one"],
    observation_ref: "agent-gym-rollback-state-observation://nightly/one",
    observed_at: "2026-08-12T11:34:00.000Z",
    observed_candidate_ref: "agent-gym-candidate://nightly/baseline",
    observer_ref: "agent-gym-observer://rollout/independent",
  });
}

function appliedRollbackReceipt() {
  return recordAgentGymRollbackActionReceipt(rollbackTrigger(), {
    action_outcome: "applied",
    completed_at: "2026-08-12T11:33:00.000Z",
    evidence_refs: ["agent-gym-evidence://rollback/action-one"],
    executor_ref: "agent-gym-executor://rollout/default",
    external_receipt_ref: "agent-gym-external-receipt://rollback/action-one",
    observed_candidate_ref: "agent-gym-candidate://nightly/baseline",
    receipt_ref: "agent-gym-rollback-action-receipt://nightly/one",
  });
}

function rollbackTrigger() {
  return triggerAgentGymRollback(rollbackGate(), rollbackReserve(), {
    evidence_refs: ["agent-gym-evidence://rollback/trigger-one"],
    executor_action_ref: "agent-gym-executor-action://rollout/rollback-one",
    triggered_at: "2026-08-12T11:32:00.000Z",
    trigger_ref: "agent-gym-rollback-trigger://nightly/one",
  });
}

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
