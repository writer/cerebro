import assert from "node:assert/strict";
import test from "node:test";

import {
  digestAgentGymJson,
  recordAgentGymCanaryAction,
  recordAgentGymCanaryStateObservation,
  verifyAgentGymCanaryAction,
  advanceAgentGymRolloutState,
  decideAgentGymRolloutCompletion,
  summarizeAgentGymRollout,
  validateAgentGymRolloutState,
  validateAgentGymRolloutCompletion,
  validateAgentGymRolloutSummary,
  validateAgentGymCanaryActionVerification,
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

test("canary action verification requires a fresh independent observer", () => {
  const verification = verifyAgentGymCanaryAction(
    actionPlan(), actionReceipt(), stateObservation("agent-gym-observer://verification/one"), {
      verification_ref: "agent-gym-action-verification://nightly/one",
      verified_at: "2026-08-12T11:24:00.000Z",
      verifier_ref: "agent-gym-observer://verification/one",
    },
  );
  assert.equal(verification.verified, true);
  assert.deepEqual(verification.blocker_codes, []);
  assert.deepEqual(validateAgentGymCanaryActionVerification(verification), verification);
});

test("an action executor cannot independently verify its own state", () => {
  const verification = verifyAgentGymCanaryAction(
    actionPlan(), actionReceipt(), stateObservation("agent-gym-executor://canary/default"), {
      verification_ref: "agent-gym-action-verification://nightly/self",
      verified_at: "2026-08-12T11:24:00.000Z",
      verifier_ref: "agent-gym-executor://canary/default",
    },
  );
  assert.equal(verification.verified, false);
  assert.deepEqual(verification.blocker_codes, ["verification.non_independent_observer"]);
});

test("rollout state advances only from verified observed actions", () => {
  const state = advanceAgentGymRolloutState(
    actionPlan(), actionReceipt(), independentVerification(), undefined, {
      effective_at: "2026-08-12T11:25:00.000Z",
      state_ref: "agent-gym-rollout-state://nightly/one",
    },
  );
  assert.equal(state.phase, "canary");
  assert.equal(state.candidate_traffic_percent, 20);
  assert.equal(state.sequence, 1);
  assert.deepEqual(validateAgentGymRolloutState(state), state);
});

test("unverified actions cannot advance rollout state", () => {
  const selfVerification = verifyAgentGymCanaryAction(
    actionPlan(), actionReceipt(), stateObservation("agent-gym-executor://canary/default"), {
      verification_ref: "agent-gym-action-verification://nightly/self-state",
      verified_at: "2026-08-12T11:24:00.000Z",
      verifier_ref: "agent-gym-executor://canary/default",
    },
  );
  assert.throws(() => advanceAgentGymRolloutState(
    actionPlan(), actionReceipt(), selfVerification, undefined, {
      effective_at: "2026-08-12T11:25:00.000Z",
      state_ref: "agent-gym-rollout-state://nightly/unverified",
    },
  ), /rollout state is invalid/u);
});

test("rollout completion keeps partial traffic explicitly incomplete", () => {
  const decision = decideAgentGymRolloutCompletion(canaryRolloutState(), {
    decided_at: "2026-08-12T11:26:00.000Z",
    decision_ref: "agent-gym-rollout-completion://nightly/incomplete",
  });
  assert.equal(decision.outcome, "incomplete");
  assert.equal(decision.terminal, false);
  assert.deepEqual(decision.blocker_codes, ["rollout.canary_in_progress"]);
});

test("rollout completion accepts independently verified full traffic", () => {
  const decision = decideAgentGymRolloutCompletion(activeRolloutState(), {
    decided_at: "2026-08-12T11:26:00.000Z",
    decision_ref: "agent-gym-rollout-completion://nightly/complete",
  });
  assert.equal(decision.outcome, "completed");
  assert.equal(decision.terminal, true);
  assert.deepEqual(validateAgentGymRolloutCompletion(decision), decision);
});

test("rollout summaries seal the verified state chain and closure", () => {
  const state = canaryRolloutState();
  const completion = decideAgentGymRolloutCompletion(state, {
    decided_at: "2026-08-12T11:26:00.000Z",
    decision_ref: "agent-gym-rollout-completion://nightly/incomplete",
  });
  const summary = summarizeAgentGymRollout(
    [state], completion, "agent-gym-rollout-summary://nightly/one",
  );
  assert.equal(summary.state_count, 1);
  assert.equal(summary.outcome, "incomplete");
  assert.equal(summary.terminal, false);
  assert.deepEqual(validateAgentGymRolloutSummary(summary), summary);
});

test("rollout summaries reject a completion for another state", () => {
  const state = canaryRolloutState();
  const completion = decideAgentGymRolloutCompletion(activeRolloutState(), {
    decided_at: "2026-08-12T11:26:00.000Z",
    decision_ref: "agent-gym-rollout-completion://nightly/other",
  });
  assert.throws(() => summarizeAgentGymRollout(
    [state], completion, "agent-gym-rollout-summary://nightly/mismatch",
  ), /rollout summary is invalid/u);
});

function canaryRolloutState() {
  return advanceAgentGymRolloutState(
    actionPlan(), actionReceipt(), independentVerification(), undefined, {
      effective_at: "2026-08-12T11:25:00.000Z",
      state_ref: "agent-gym-rollout-state://nightly/one",
    },
  );
}

function activeRolloutState() {
  const body = {
    action: "complete_rollout" as const,
    action_receipt_digest: digest("1"),
    active_candidate_ref: "agent-gym-candidate://nightly/challenger",
    candidate_ref: "agent-gym-candidate://nightly/challenger",
    candidate_traffic_percent: 100,
    effective_at: "2026-08-12T11:25:00.000Z",
    phase: "active" as const,
    previous_state_digest: digest("2"),
    schema_version: "agent-gym-rollout-state/v1" as const,
    sequence: 2,
    state_ref: "agent-gym-rollout-state://nightly/active",
    target_ref: "agent-gym-target://slack-companion/default",
    verification_digest: digest("3"),
  };
  return { ...body, state_digest: digestAgentGymJson(body) };
}

function independentVerification() {
  return verifyAgentGymCanaryAction(
    actionPlan(), actionReceipt(), stateObservation("agent-gym-observer://verification/one"), {
      verification_ref: "agent-gym-action-verification://nightly/one",
      verified_at: "2026-08-12T11:24:00.000Z",
      verifier_ref: "agent-gym-observer://verification/one",
    },
  );
}

function actionReceipt() {
  return recordAgentGymCanaryAction(actionPlan(), {
    completed_at: "2026-08-12T11:22:00.000Z",
    executor_ref: "agent-gym-executor://canary/default",
    failure_codes: [],
    observed_active_candidate_ref: "agent-gym-candidate://nightly/challenger",
    observed_candidate_traffic_percent: 20,
    receipt_ref: "agent-gym-canary-action-receipt://nightly/increase",
    started_at: "2026-08-12T11:21:00.000Z",
    status: "applied",
  });
}

function stateObservation(observerRef: string) {
  return recordAgentGymCanaryStateObservation(actionPlan(), {
    active_candidate_ref: "agent-gym-candidate://nightly/challenger",
    candidate_traffic_percent: 20,
    evidence_refs: ["agent-gym-evidence://state/one"],
    observation_ref: `agent-gym-state-observation://nightly/${observerRef.split("/").at(-1)}`,
    observed_at: "2026-08-12T11:23:00.000Z",
    observer_ref: observerRef,
    reason_codes: [],
    status: "observed",
  });
}

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
