import assert from "node:assert/strict";
import test from "node:test";

import { simulateSlackMention } from "../src/index.js";

test("mention simulation produces a Slack-independent assistant invocation", () => {
  const invocation = simulateSlackMention({
    event_ref: "slack-event://mention/one",
    kind: "mention",
    occurred_at: "2026-08-12T08:30:00.000Z",
    payload: {
      bot_user_id: "U_BOT",
      channel_id: "C_ONE",
      team_id: "T_ONE",
      text: "<@U_BOT> What changed?",
      thread_ts: "1786523400.000001",
      ts: "1786523401.000001",
      user_id: "U_ONE",
    },
  });
  assert.equal(invocation.route, "assistant_turn");
  assert.equal(invocation.text, "What changed?");
  assert.match(invocation.actor_ref, /^slack-user:\/\/sha256\/[0-9a-f]{64}$/u);
  assert.match(invocation.conversation_ref, /^slack-thread:\/\/sha256\/[0-9a-f]{64}$/u);
  assert.match(invocation.invocation_ref, /^slack-invocation:\/\/sha256\/[0-9a-f]{64}$/u);
  assert.equal(Object.isFrozen(invocation), true);
});

test("mention simulation rejects events without the addressed bot", () => {
  assert.throws(() => simulateSlackMention({
    event_ref: "slack-event://mention/missing",
    kind: "mention",
    occurred_at: "2026-08-12T08:30:00.000Z",
    payload: {
      bot_user_id: "U_BOT",
      channel_id: "C_ONE",
      team_id: "T_ONE",
      text: "What changed?",
      ts: "1786523401.000001",
      user_id: "U_ONE",
    },
  }), /mention text is invalid/u);
});
