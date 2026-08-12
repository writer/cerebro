import assert from "node:assert/strict";
import test from "node:test";

import {
  AgentGymSlackEffectIdempotencyLedger,
  captureAgentGymSlackPostMessage,
  captureAgentGymSlackUpdateMessage,
  orderAgentGymSlackEffects,
  resumeAgentGymSlackEffects,
  snapshotAgentGymSlackEffects,
  planAgentGymSlackAcknowledgement,
} from "../src/index.js";

test("effect snapshots are stable across input order", () => {
  const first = captureAgentGymSlackPostMessage({
    channel_ref: "slack-channel://one",
    idempotency_key: "answer:one",
    text: "First.",
  });
  const second = captureAgentGymSlackUpdateMessage({
    idempotency_key: "answer:one:complete",
    message_ref: "slack-message://one",
    text: "Complete.",
  });
  const snapshot = snapshotAgentGymSlackEffects([second, first]);
  assert.deepEqual(snapshot, snapshotAgentGymSlackEffects([first, second]));
  assert.deepEqual(snapshot.operations, { post_message: 1, update_message: 1 });
  assert.match(snapshot.snapshot_digest, /^sha256:[0-9a-f]{64}$/u);
  assert.equal(Object.isFrozen(snapshot.operations), true);
});

test("effect snapshots reject duplicate effect identities", () => {
  const effect = captureAgentGymSlackPostMessage({
    channel_ref: "slack-channel://one",
    idempotency_key: "answer:one",
    text: "First.",
  });
  assert.throws(() => snapshotAgentGymSlackEffects([effect, effect]), /snapshot is invalid/u);
});

test("effect resume returns accepted work not completed before a crash", () => {
  const first = captureAgentGymSlackPostMessage({
    channel_ref: "slack-channel://one",
    idempotency_key: "answer:one",
    text: "First.",
  });
  const second = captureAgentGymSlackPostMessage({
    channel_ref: "slack-channel://one",
    idempotency_key: "answer:two",
    text: "Second.",
  });
  assert.deepEqual(resumeAgentGymSlackEffects({
    accepted_effect_refs: [first.effect_ref, second.effect_ref],
    checkpoint_ref: "checkpoint://effects/one",
    completed_effect_refs: [first.effect_ref],
    schema_version: "agent-gym-slack-effect-checkpoint/v1",
  }, [second, first]), [second]);
});

test("effect resume rejects completion without prior acceptance", () => {
  const effect = captureAgentGymSlackPostMessage({
    channel_ref: "slack-channel://one",
    idempotency_key: "answer:one",
    text: "First.",
  });
  assert.throws(() => resumeAgentGymSlackEffects({
    accepted_effect_refs: [],
    checkpoint_ref: "checkpoint://effects/one",
    completed_effect_refs: [effect.effect_ref],
    schema_version: "agent-gym-slack-effect-checkpoint/v1",
  }, [effect]), /checkpoint is invalid/u);
});

test("effect ordering honors dependencies independent of input order", () => {
  const posted = captureAgentGymSlackPostMessage({
    channel_ref: "slack-channel://one",
    idempotency_key: "answer:one",
    text: "Working.",
  });
  const updated = captureAgentGymSlackUpdateMessage({
    idempotency_key: "answer:one:complete",
    message_ref: "slack-message://one",
    text: "Complete.",
  });
  assert.deepEqual(orderAgentGymSlackEffects([
    { after_effect_refs: [posted.effect_ref], effect: updated },
    { after_effect_refs: [], effect: posted },
  ]).map((effect) => effect.effect_ref), [posted.effect_ref, updated.effect_ref]);
});

test("effect ordering rejects dependency cycles", () => {
  const first = captureAgentGymSlackPostMessage({
    channel_ref: "slack-channel://one",
    idempotency_key: "answer:one",
    text: "First.",
  });
  const second = captureAgentGymSlackPostMessage({
    channel_ref: "slack-channel://one",
    idempotency_key: "answer:two",
    text: "Second.",
  });
  assert.throws(() => orderAgentGymSlackEffects([
    { after_effect_refs: [second.effect_ref], effect: first },
    { after_effect_refs: [first.effect_ref], effect: second },
  ]), /effect plan is invalid/u);
});

test("effect idempotency admits once and recognizes exact retries", () => {
  const ledger = new AgentGymSlackEffectIdempotencyLedger();
  const effect = captureAgentGymSlackPostMessage({
    channel_ref: "slack-channel://one",
    idempotency_key: "answer:one",
    text: "Verified answer.",
  });
  assert.equal(ledger.admit(effect).disposition, "accepted");
  assert.equal(ledger.admit(effect).disposition, "duplicate");
});

test("effect idempotency rejects changed output under one key", () => {
  const ledger = new AgentGymSlackEffectIdempotencyLedger();
  const input = {
    channel_ref: "slack-channel://one",
    idempotency_key: "answer:one",
    text: "Verified answer.",
  };
  ledger.admit(captureAgentGymSlackPostMessage(input));
  assert.throws(() => ledger.admit(captureAgentGymSlackPostMessage({
    ...input,
    text: "Different answer.",
  })), /idempotency key changed effect/u);
});

test("acknowledgement simulation waits for durable admission", () => {
  assert.deepEqual(planAgentGymSlackAcknowledgement({
    durable_admission: false,
    event_received_at: "2026-08-12T08:52:00.000Z",
    maximum_ack_latency_ms: 3_000,
  }), {
    disposition: "withhold",
    schema_version: "agent-gym-slack-acknowledgement/v1",
  });
  assert.equal(planAgentGymSlackAcknowledgement({
    admitted_at: "2026-08-12T08:52:02.500Z",
    durable_admission: true,
    event_received_at: "2026-08-12T08:52:00.000Z",
    maximum_ack_latency_ms: 3_000,
  }).disposition, "acknowledge");
});

test("acknowledgement simulation reports a missed deadline", () => {
  const receipt = planAgentGymSlackAcknowledgement({
    admitted_at: "2026-08-12T08:52:03.001Z",
    durable_admission: true,
    event_received_at: "2026-08-12T08:52:00.000Z",
    maximum_ack_latency_ms: 3_000,
  });
  assert.equal(receipt.disposition, "deadline_missed");
  assert.equal(receipt.ack_latency_ms, 3_001);
});
