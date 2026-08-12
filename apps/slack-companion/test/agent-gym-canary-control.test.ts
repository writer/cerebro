import assert from "node:assert/strict";
import test from "node:test";

import {
  digestAgentGymJson,
  recordAgentGymCanaryObservation,
  validateAgentGymCanaryObservation,
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
