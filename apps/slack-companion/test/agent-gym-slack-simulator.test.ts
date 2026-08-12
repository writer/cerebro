import assert from "node:assert/strict";
import test from "node:test";

import {
  simulateSlackDirectMessage,
  simulateSlackMention,
  simulateSlackThreadReply,
} from "../src/index.js";

test("thread-reply simulation preserves the root conversation identity", () => {
  const base = {
    event_ref: "slack-event://reply/one",
    kind: "thread_reply" as const,
    occurred_at: "2026-08-12T08:32:00.000Z",
    payload: {
      channel_id: "C12345",
      team_id: "T_ONE",
      text: "Use the second option.",
      thread_ts: "1786523400.000001",
      ts: "1786523520.000001",
      user_id: "U_ONE",
    },
  };
  const invocation = simulateSlackThreadReply(base);
  const anotherReply = simulateSlackThreadReply({
    ...base,
    event_ref: "slack-event://reply/two",
    payload: { ...base.payload, ts: "1786523521.000001" },
  });
  assert.equal(invocation.conversation_ref, anotherReply.conversation_ref);
  assert.equal(invocation.text, "Use the second option.");
});

test("thread-reply simulation rejects a root message posing as a reply", () => {
  assert.throws(() => simulateSlackThreadReply({
    event_ref: "slack-event://reply/root",
    kind: "thread_reply",
    occurred_at: "2026-08-12T08:32:00.000Z",
    payload: {
      channel_id: "C12345",
      team_id: "T_ONE",
      text: "Use the second option.",
      thread_ts: "1786523520.000001",
      ts: "1786523520.000001",
      user_id: "U_ONE",
    },
  }), /thread-reply timestamp is invalid/u);
});

test("direct-message simulation routes one bounded private request", () => {
  const invocation = simulateSlackDirectMessage({
    event_ref: "slack-event://dm/one",
    kind: "direct_message",
    occurred_at: "2026-08-12T08:31:00.000Z",
    payload: {
      channel_id: "D12345",
      team_id: "T_ONE",
      text: "Summarize the current evidence.",
      ts: "1786523460.000001",
      user_id: "U_ONE",
    },
  });
  assert.equal(invocation.route, "assistant_turn");
  assert.equal(invocation.text, "Summarize the current evidence.");
  assert.match(invocation.conversation_ref, /^slack-dm:\/\/sha256\/[0-9a-f]{64}$/u);
});

test("direct-message simulation rejects a public channel payload", () => {
  assert.throws(() => simulateSlackDirectMessage({
    event_ref: "slack-event://dm/public",
    kind: "direct_message",
    occurred_at: "2026-08-12T08:31:00.000Z",
    payload: {
      channel_id: "C12345",
      team_id: "T_ONE",
      text: "Summarize the current evidence.",
      ts: "1786523460.000001",
      user_id: "U_ONE",
    },
  }), /direct-message channel is invalid/u);
});

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
