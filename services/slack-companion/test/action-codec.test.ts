import assert from "node:assert/strict";
import test from "node:test";
import { decodeAction, encodeAction } from "../src/slack/action-codec.js";

test("action payload round trips through Slack-safe value", () => {
  const payload = {
    kind: "finding_note" as const,
    runtimeId: "writer-okta",
    findingId: "finding-1",
    channelId: "C123",
  };
  assert.deepEqual(decodeAction(encodeAction(payload)), payload);
});

test("decodeAction rejects empty action value", () => {
  assert.throws(() => decodeAction(""), /missing/);
});
