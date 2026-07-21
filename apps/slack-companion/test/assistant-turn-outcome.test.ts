import assert from "node:assert/strict";
import test from "node:test";
import {
  assessAssistantTurnOutcome,
  AssistantTurnOutcomeInputError,
} from "../src/index.js";

const base = {
  assessment_at: "2026-07-22T12:00:01.000Z",
  evaluation_blockers: [],
  execution_lane: "lookup",
  latency_budget_ms: 30_000,
  negative_feedback_count: 0,
  opened_at: "2026-07-21T12:00:00.000Z",
  outcome_state: "completed",
  request_id: "request://1",
  request_kind: "human",
  user_correction_count: 0,
  useful_answer_at: "2026-07-21T12:00:20.000Z",
  verified: true,
} as const;

test("outcome assessment records a verified human outcome inside the lane SLO", () => {
  const result = assessAssistantTurnOutcome(base);

  assert.equal(result.qualification, "eligible_success");
  assert.equal(result.verified_outcome_within_slo, true);
  assert.equal(result.useful_answer_latency_ms, 20_000);
  assert.match(result.assessment_digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(Object.isFrozen(result), true);
});

test("outcome assessment waits for the correction window and excludes handoffs", () => {
  assert.equal(
    assessAssistantTurnOutcome({
      ...base,
      assessment_at: "2026-07-21T12:10:00.000Z",
    }).qualification,
    "pending_observation",
  );
  assert.equal(
    assessAssistantTurnOutcome({ ...base, request_kind: "machine_handoff" }).qualification,
    "excluded",
  );
});

test("correction, blocker, missed SLO, or unclosed work fails the outcome", () => {
  for (const input of [
    { ...base, user_correction_count: 1 },
    { ...base, evaluation_blockers: ["claim_not_grounded"] },
    { ...base, useful_answer_at: "2026-07-21T12:00:31.000Z" },
    { ...base, outcome_state: "owned" as const },
  ]) {
    const result = assessAssistantTurnOutcome(input);
    assert.equal(result.qualification, "eligible_failure");
    assert.equal(result.verified_outcome_within_slo, false);
  }
});

test("outcome assessment rejects malformed blocker codes and time ordering", () => {
  assert.throws(
    () => assessAssistantTurnOutcome({ ...base, evaluation_blockers: ["Not stable"] }),
    AssistantTurnOutcomeInputError,
  );
  assert.throws(
    () => assessAssistantTurnOutcome({ ...base, assessment_at: "2026-07-20T12:00:00.000Z" }),
    AssistantTurnOutcomeInputError,
  );
});
