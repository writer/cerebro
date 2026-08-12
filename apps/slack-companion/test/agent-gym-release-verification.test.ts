import assert from "node:assert/strict";
import test from "node:test";

import {
  digestAgentGymJson,
  recordAgentGymCanaryStateObservation,
  validateAgentGymCanaryStateObservation,
  type AgentGymCanaryActionPlanV1,
} from "../src/index.js";

test("canary state observations retain fresh independent evidence", () => {
  const observation = recordAgentGymCanaryStateObservation(actionPlan(), {
    active_candidate_ref: "agent-gym-candidate://nightly/challenger",
    candidate_traffic_percent: 20,
    evidence_refs: ["agent-gym-evidence://state/one"],
    observation_ref: "agent-gym-state-observation://nightly/one",
    observed_at: "2026-08-12T11:23:00.000Z",
    observer_ref: "agent-gym-observer://verification/one",
    reason_codes: [],
    status: "observed",
  });
  assert.equal(observation.status, "observed");
  assert.deepEqual(validateAgentGymCanaryStateObservation(observation), observation);
});

test("unavailable state observations cannot guess active state", () => {
  assert.throws(() => recordAgentGymCanaryStateObservation(actionPlan(), {
    active_candidate_ref: "agent-gym-candidate://nightly/challenger",
    candidate_traffic_percent: 20,
    evidence_refs: [],
    observation_ref: "agent-gym-state-observation://nightly/unavailable",
    observed_at: "2026-08-12T11:23:00.000Z",
    observer_ref: "agent-gym-observer://verification/one",
    reason_codes: ["observation.source_unavailable"],
    status: "unavailable",
  }), /state observation is invalid/u);
});

function actionPlan(): AgentGymCanaryActionPlanV1 {
  const identity = {
    action_ref: "agent-gym-canary-action://nightly/increase",
    gate_decision_digest: digest("a"),
    target_ref: "agent-gym-target://slack-companion/default",
    transition_digest: digest("e"),
  };
  const body = {
    action: "increase_traffic" as const,
    action_ref: identity.action_ref,
    candidate_ref: "agent-gym-candidate://nightly/challenger",
    expires_at: "2026-08-12T11:30:00.000Z",
    from_traffic_percent: 10,
    gate_decision_digest: identity.gate_decision_digest,
    idempotency_key: digestAgentGymJson(identity),
    planned_at: "2026-08-12T11:20:00.000Z",
    policy_digest: digest("d"),
    policy_ref: "agent-gym-canary-action-policy://nightly/default",
    rollback_candidate_ref: null,
    schema_version: "agent-gym-canary-action-plan/v1" as const,
    target_ref: identity.target_ref,
    to_traffic_percent: 20,
    transition_digest: identity.transition_digest,
  };
  return { ...body, plan_digest: digestAgentGymJson(body) };
}

function digest(character: string): string {
  return `sha256:${character.repeat(64)}`;
}
