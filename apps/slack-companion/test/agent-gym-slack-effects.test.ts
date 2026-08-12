import assert from "node:assert/strict";
import test from "node:test";

import {
  captureAgentGymSlackOpenModal,
  captureAgentGymSlackPostMessage,
  captureAgentGymSlackPublishHome,
  captureAgentGymSlackUpdateMessage,
} from "../src/index.js";

test("modal capture binds a valid modal to the actor and trigger", () => {
  const effect = captureAgentGymSlackOpenModal({
    idempotency_key: "modal:approval:one",
    trigger_ref: "slack-trigger://one",
    user_ref: "slack-user://one",
    view: {
      callback_id: "approval.confirm",
      title: { text: "Confirm action", type: "plain_text" },
      type: "modal",
    },
  });
  assert.equal(effect.operation, "open_modal");
  assert.deepEqual(effect.target_refs, [
    "slack-trigger://one",
    "slack-user://one",
  ]);
});

test("modal capture rejects a Home-shaped view", () => {
  assert.throws(() => captureAgentGymSlackOpenModal({
    idempotency_key: "modal:approval:one",
    trigger_ref: "slack-trigger://one",
    user_ref: "slack-user://one",
    view: { type: "home" },
  }), /modal view type is invalid/u);
});

test("Home publication capture retains a deeply frozen view", () => {
  const blocks = [{ text: "2 outcome checks pending", type: "section" }];
  const view = { blocks, type: "home" };
  const effect = captureAgentGymSlackPublishHome({
    idempotency_key: "home:user-one:revision-one",
    user_ref: "slack-user://one",
    view,
  });
  assert.equal(effect.operation, "publish_home");
  assert.equal(Object.isFrozen(view), true);
  assert.equal(Object.isFrozen(blocks), true);
  assert.equal(Object.isFrozen(blocks[0]), true);
});

test("Home publication capture rejects a modal-shaped view", () => {
  assert.throws(() => captureAgentGymSlackPublishHome({
    idempotency_key: "home:user-one:revision-one",
    user_ref: "slack-user://one",
    view: { type: "modal" },
  }), /Home view type is invalid/u);
});

test("message update capture binds replacement content to one message", () => {
  const effect = captureAgentGymSlackUpdateMessage({
    idempotency_key: "status:one:complete",
    message_ref: "slack-message://one",
    text: "Verification complete.",
  });
  assert.equal(effect.operation, "update_message");
  assert.deepEqual(effect.target_refs, ["slack-message://one"]);
  assert.deepEqual(effect.payload, { text: "Verification complete." });
});

test("message update capture rejects control characters", () => {
  assert.throws(() => captureAgentGymSlackUpdateMessage({
    idempotency_key: "status:one:complete",
    message_ref: "slack-message://one",
    text: "bad\u0000text",
  }), /message text is invalid/u);
});

test("message capture records a deterministic Slack-free effect", () => {
  const input = {
    channel_ref: "slack-channel://one",
    idempotency_key: "answer:one",
    text: "Current evidence:\n- one verified record",
    thread_ref: "slack-thread://one",
  };
  const first = captureAgentGymSlackPostMessage(input);
  assert.deepEqual(captureAgentGymSlackPostMessage(input), first);
  assert.equal(first.operation, "post_message");
  assert.match(first.effect_ref, /^slack-effect:\/\/sha256\/[0-9a-f]{64}$/u);
  assert.equal(Object.isFrozen(first.payload), true);
  assert.equal(Object.isFrozen(first.target_refs), true);
});

test("message capture rejects empty text and non-reference targets", () => {
  assert.throws(() => captureAgentGymSlackPostMessage({
    channel_ref: "channel-one",
    idempotency_key: "answer:one",
    text: "Answer",
  }), /channel reference is invalid/u);
});
