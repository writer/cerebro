import assert from "node:assert/strict";
import test from "node:test";

import {
  digestAgentGymJson,
  decideAgentGymCanaryGate,
  recordAgentGymCanaryObservation,
  sealAgentGymCanaryWindow,
  validateAgentGymCanaryObservation,
  validateAgentGymCanaryWindow,
  validateAgentGymCanaryGateDecision,
  type AgentGymChampionTransitionV1,
} from "../src/index.js";

test("canary observations bind evidence to one champion transition", () => {
  const observation = recordAgentGymCanaryObservation(championTransition(), {
    blocker_codes: [],
    evidence_refs: ["agent-gym-evidence://canary/sample-one"],
    latency_ms: 850,
    observation_ref: "agent-gym-canary-observation://nightly/one",
    observed_at: "2026-08-12T11:16:00.000Z",
    outcome: "passed",
    quality_score: 0.92,
    sample_ref: "agent-gym-sample://nightly/one",
  });
  assert.equal(observation.candidate_ref, championTransition().active_candidate_ref);
  assert.deepEqual(validateAgentGymCanaryObservation(observation), observation);
});

test("passed canary observations require evidence and no blockers", () => {
  assert.throws(() => recordAgentGymCanaryObservation(championTransition(), {
    blocker_codes: ["answer.missing_evidence"],
    evidence_refs: [],
    latency_ms: 850,
    observation_ref: "agent-gym-canary-observation://nightly/invalid",
    observed_at: "2026-08-12T11:16:00.000Z",
    outcome: "passed",
    quality_score: 0.92,
    sample_ref: "agent-gym-sample://nightly/invalid",
  }), /canary observation is invalid/u);
});

test("canary windows seal ordered samples and aggregate failures", () => {
  const window = sealAgentGymCanaryWindow([
    canaryObservation("two", "2026-08-12T11:17:00.000Z", "failed", 1_100, 0.4),
    canaryObservation("one", "2026-08-12T11:16:00.000Z", "passed", 800, 0.9),
  ], {
    ended_at: "2026-08-12T11:18:00.000Z",
    started_at: "2026-08-12T11:15:00.000Z",
    window_ref: "agent-gym-canary-window://nightly/one",
  });
  assert.equal(window.observation_count, 2);
  assert.equal(window.failed_count, 1);
  assert.equal(window.p95_latency_ms, 1_100);
  assert.deepEqual(window.blocker_codes, ["answer.missing_evidence"]);
  assert.deepEqual(validateAgentGymCanaryWindow(window), window);
});

test("canary windows reject samples from another transition", () => {
  const changed = { ...championTransition(), transition_ref: "agent-gym-champion-transition://nightly/two" };
  const { transition_digest: _ignored, ...changedBody } = changed;
  const other = recordAgentGymCanaryObservation({
    ...changedBody,
    transition_digest: digestAgentGymJson(changedBody),
  }, observationInput("other", "2026-08-12T11:17:00.000Z", "passed", 900, 0.9));
  assert.throws(() => sealAgentGymCanaryWindow([
    canaryObservation("one", "2026-08-12T11:16:00.000Z", "passed", 800, 0.9),
    other,
  ], {
    ended_at: "2026-08-12T11:18:00.000Z",
    started_at: "2026-08-12T11:15:00.000Z",
    window_ref: "agent-gym-canary-window://nightly/mixed",
  }), /canary window is invalid/u);
});

test("canary gates roll back complete windows above thresholds", () => {
  const decision = decideAgentGymCanaryGate(canaryWindow(), canaryPolicy(), {
    decision_ref: "agent-gym-canary-gate://nightly/one",
    evaluated_at: "2026-08-12T11:19:00.000Z",
  });
  assert.equal(decision.disposition, "rollback");
  assert.deepEqual(decision.blocker_codes, [
    "canary.failure_rate_exceeded",
    "canary.quality_below_minimum",
  ]);
  assert.deepEqual(validateAgentGymCanaryGateDecision(decision), decision);
});

test("canary gates hold incomplete windows without overriding evidence", () => {
  const oneSample = sealAgentGymCanaryWindow([
    canaryObservation("one", "2026-08-12T11:16:00.000Z", "passed", 800, 0.9),
  ], {
    ended_at: "2026-08-12T11:18:00.000Z",
    started_at: "2026-08-12T11:15:00.000Z",
    window_ref: "agent-gym-canary-window://nightly/incomplete",
  });
  const decision = decideAgentGymCanaryGate(oneSample, canaryPolicy(), {
    decision_ref: "agent-gym-canary-gate://nightly/incomplete",
    evaluated_at: "2026-08-12T11:19:00.000Z",
  });
  assert.equal(decision.disposition, "hold");
  assert.deepEqual(decision.blocker_codes, ["canary.insufficient_samples"]);
});

function canaryWindow() {
  return sealAgentGymCanaryWindow([
    canaryObservation("two", "2026-08-12T11:17:00.000Z", "failed", 1_100, 0.4),
    canaryObservation("one", "2026-08-12T11:16:00.000Z", "passed", 800, 0.9),
  ], {
    ended_at: "2026-08-12T11:18:00.000Z",
    started_at: "2026-08-12T11:15:00.000Z",
    window_ref: "agent-gym-canary-window://nightly/one",
  });
}

function canaryPolicy() {
  return {
    maximum_failure_rate: 0.1,
    maximum_p95_latency_ms: 1_500,
    minimum_mean_quality_score: 0.8,
    minimum_observation_count: 2,
    policy_ref: "agent-gym-canary-policy://nightly/default",
    rollback_blocker_codes: ["safety.blocker"],
    schema_version: "agent-gym-canary-gate-policy/v1" as const,
  };
}

function canaryObservation(
  id: string,
  observedAt: string,
  outcome: "failed" | "passed",
  latencyMs: number,
  qualityScore: number,
) {
  return recordAgentGymCanaryObservation(
    championTransition(),
    observationInput(id, observedAt, outcome, latencyMs, qualityScore),
  );
}

function observationInput(
  id: string,
  observedAt: string,
  outcome: "failed" | "passed",
  latencyMs: number,
  qualityScore: number,
) {
  return {
    blocker_codes: outcome === "passed" ? [] : ["answer.missing_evidence"],
    evidence_refs: outcome === "passed" ? [`agent-gym-evidence://canary/${id}`] : [],
    latency_ms: latencyMs,
    observation_ref: `agent-gym-canary-observation://nightly/${id}`,
    observed_at: observedAt,
    outcome,
    quality_score: qualityScore,
    sample_ref: `agent-gym-sample://nightly/${id}`,
  };
}

function championTransition(): AgentGymChampionTransitionV1 {
  const body = {
    activation_receipt_digest: digest("a"),
    active_candidate_ref: "agent-gym-candidate://nightly/challenger",
    effective_at: "2026-08-12T11:15:00.000Z",
    from_candidate_ref: "agent-gym-candidate://nightly/baseline",
    mode: "promote" as const,
    previous_transition_digest: null,
    rollback_of_transition_digest: null,
    schema_version: "agent-gym-champion-transition/v1" as const,
    sequence: 1,
    target_ref: "agent-gym-target://slack-companion/default",
    traffic_percent: 10,
    transition_ref: "agent-gym-champion-transition://nightly/one",
  };
  return { ...body, transition_digest: digestAgentGymJson(body) };
}

function digest(character: string): string {
  return `sha256:${character.repeat(64)}`;
}
