import assert from "node:assert/strict";
import test from "node:test";

import {
  decodeSlackActionEnvelope,
  decideSlackAction,
  projectSlackAnswerFeedbackActions,
  projectSlackNextStepActions,
  SLACK_OPERATOR_ACTION_CATALOG_V1,
  SLACK_OPERATOR_ACTION_REGISTRY,
  SlackBlockProjectionError,
} from "../src/index.js";

const issuedAt = "2026-07-20T10:00:00.000Z";

test("exposes stable feedback action contracts for delivered answers", () => {
  assert.equal(
    SLACK_OPERATOR_ACTION_CATALOG_V1.catalog_id,
    "cerebro.slack.operator_actions",
  );
  assert.deepEqual(
    SLACK_OPERATOR_ACTION_REGISTRY.actions().map((action) => action.action_id),
    [
      "answer.feedback.helpful",
      "answer.feedback.missed_source",
      "answer.feedback.needs_followup",
      "answer.feedback.wrong_owner",
      "answer.watch.start",
      "evidence.recheck.request",
      "triage.open",
      "watch.stop",
    ],
  );
  for (const action of SLACK_OPERATOR_ACTION_REGISTRY.actions().filter((candidate) =>
    candidate.command === "answer_feedback"
  )) {
    assert.equal(action.command, "answer_feedback");
    assert.deepEqual(action.parameters, []);
    assert.equal(action.subject_requirement, "required");
    assert.deepEqual(action.required_capabilities, [
      {
        capability_id: "assistant.feedback",
        level: "required",
        version: "v1",
      },
    ]);
  }
});

test("projects deterministic feedback buttons with portable action envelopes", () => {
  const actions = projectSlackAnswerFeedbackActions({
    feedback_key: "delivery-123",
    issued_at: issuedAt,
    subject_ref: "delivery://assistant-turn/123",
  });
  assert.deepEqual(
    actions.map((action) => action.action_key),
    [
      "feedback_helpful",
      "feedback_missed_source",
      "feedback_wrong_owner",
      "feedback_needs_followup",
    ],
  );
  assert.equal(actions[0]?.style, "primary");
  assert.equal(Object.isFrozen(actions), true);
  assert.equal(Object.isFrozen(actions[0]), true);

  const decoded = actions.map((action) => decodeSlackActionEnvelope(action.value));
  assert.deepEqual(
    decoded.map((action) => action.action),
    [
      "answer.feedback.helpful",
      "answer.feedback.missed_source",
      "answer.feedback.wrong_owner",
      "answer.feedback.needs_followup",
    ],
  );
  for (const action of decoded) {
    assert.equal(action.command, "answer_feedback");
    assert.equal(action.issued_at, issuedAt);
    assert.equal(action.subject_ref, "delivery://assistant-turn/123");
    assert.match(action.idempotency_key, /^feedback:[a-f0-9]{64}$/);
    assert.equal(action.parameters, undefined);
    const decision = decideSlackAction(SLACK_OPERATOR_ACTION_REGISTRY, {
      action,
      available_capabilities: [
        {
          capability_id: "assistant.feedback",
          level: "required",
          version: "v1",
        },
      ],
    });
    assert.equal(decision.disposition, "admit");
    assert.equal(decision.reason_code, "accepted");
  }
});

test("feedback buttons fail closed without the feedback capability", () => {
  const [button] = projectSlackAnswerFeedbackActions({
    feedback_key: "delivery-123",
    issued_at: issuedAt,
    subject_ref: "delivery://assistant-turn/123",
  });
  assert.ok(button);
  const decision = decideSlackAction(SLACK_OPERATOR_ACTION_REGISTRY, {
    action: decodeSlackActionEnvelope(button.value),
    available_capabilities: [],
  });
  assert.equal(decision.disposition, "reject");
  assert.equal(decision.reason_code, "missing_capability");
});

test("projects deterministic next-step actions for watch, recheck, triage, and stop", () => {
  const actions = projectSlackNextStepActions({
    issued_at: issuedAt,
    next_step_key: "turn-one:next",
    steps: [
      { kind: "watch_answer", subject_ref: "answer://delivered/123" },
      { kind: "recheck_evidence", subject_ref: "evidence://binding/456" },
      { kind: "open_triage", subject_ref: "triage://case/789" },
      { kind: "stop_watch", subject_ref: "watch://active/abc" },
    ],
  });

  assert.deepEqual(actions.map((action) => action.action_key), [
    "watch_answer",
    "recheck_evidence",
    "open_triage",
    "stop_watch",
  ]);
  assert.equal(actions[2]?.style, "primary");
  assert.equal(actions[3]?.style, "danger");
  const decoded = actions.map((action) => decodeSlackActionEnvelope(action.value));
  assert.deepEqual(decoded.map((action) => action.action), [
    "answer.watch.start",
    "evidence.recheck.request",
    "triage.open",
    "watch.stop",
  ]);
  assert.deepEqual(decoded.map((action) => action.command), [
    "answer_watch",
    "evidence_recheck",
    "triage_open",
    "watch_stop",
  ]);
  assert.equal(new Set(decoded.map((action) => action.idempotency_key)).size, 4);
  assert.equal(decoded.every((action) => action.idempotency_key.startsWith("next:")), true);

  const triage = decoded[2];
  assert.ok(triage);
  const admitted = decideSlackAction(SLACK_OPERATOR_ACTION_REGISTRY, {
    action: triage,
    available_capabilities: [
      {
        capability_id: "triage.open",
        level: "required",
        version: "v1",
      },
    ],
  });
  assert.equal(admitted.disposition, "admit");
});

test("next-step actions reject sparse, accessor-backed, and extra-field input shapes", () => {
  const sparse = new Array<{ kind: "watch_answer"; subject_ref: string }>(1);
  assert.throws(
    () => projectSlackNextStepActions({
      issued_at: issuedAt,
      next_step_key: "turn-two:next",
      steps: sparse,
    }),
    /must not be sparse/,
  );

  assert.throws(
    () => projectSlackNextStepActions({
      issued_at: issuedAt,
      next_step_key: "turn-two:extra",
      steps: [{
        kind: "watch_answer",
        subject_ref: "answer://delivered/123",
        unexpected: true,
      } as never],
    }),
    /unsupported fields/,
  );

  let invoked = 0;
  const accessorStep = { kind: "watch_answer" };
  Object.defineProperty(accessorStep, "subject_ref", {
    enumerable: true,
    get() {
      invoked += 1;
      throw new Error("caller accessor was invoked");
    },
  });
  assert.throws(
    () => projectSlackNextStepActions({
      issued_at: issuedAt,
      next_step_key: "turn-two:accessor",
      steps: [accessorStep as never],
    }),
    SlackBlockProjectionError,
  );
  assert.equal(invoked, 0);
});
