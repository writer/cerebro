import assert from "node:assert/strict";
import test from "node:test";

import {
  AgentGymSlackDeliveryLedger,
  planAgentGymSlackApiRetry,
  simulateSlackAppHomeOpened,
  simulateSlackButtonAction,
  simulateSlackDirectMessage,
  simulateSlackMention,
  simulateSlackMessageChanged,
  simulateSlackMessageDeleted,
  simulateSlackReactionAdded,
  simulateSlackThreadReply,
} from "../src/index.js";

test("Slack API simulation honors retry-after and bounded timeout backoff", () => {
  const policy = {
    maximum_attempts: 4,
    maximum_delay_ms: 60_000,
    timeout_base_delay_ms: 1_000,
  };
  assert.deepEqual(planAgentGymSlackApiRetry({
    attempt_index: 0,
    observed_at: "2026-08-12T08:39:00.000Z",
    outcome: "rate_limited",
    retry_after_ms: 30_000,
  }, policy), {
    attempt_index: 0,
    delay_ms: 30_000,
    disposition: "retry",
    next_attempt_at: "2026-08-12T08:39:30.000Z",
    reason: "rate_limited",
    schema_version: "agent-gym-slack-retry-plan/v1",
  });
  assert.equal(planAgentGymSlackApiRetry({
    attempt_index: 2,
    observed_at: "2026-08-12T08:39:00.000Z",
    outcome: "timeout",
  }, policy).delay_ms, 4_000);
});

test("Slack API simulation exhausts retries and rejects ambiguous outcomes", () => {
  const policy = {
    maximum_attempts: 2,
    maximum_delay_ms: 60_000,
    timeout_base_delay_ms: 1_000,
  };
  assert.equal(planAgentGymSlackApiRetry({
    attempt_index: 1,
    observed_at: "2026-08-12T08:39:00.000Z",
    outcome: "timeout",
  }, policy).disposition, "exhausted");
  assert.throws(() => planAgentGymSlackApiRetry({
    attempt_index: 0,
    observed_at: "2026-08-12T08:39:00.000Z",
    outcome: "success",
    retry_after_ms: 1_000,
  }, policy), /retry input is invalid/u);
});

test("delivery simulation admits once and suppresses exact Slack retries", () => {
  const event = {
    event_ref: "slack-event://retry/one",
    kind: "direct_message" as const,
    occurred_at: "2026-08-12T08:38:00.000Z",
    payload: {
      channel_id: "D12345",
      team_id: "T_ONE",
      text: "Continue.",
      ts: "1786523880.000001",
      user_id: "U_ONE",
    },
  };
  const ledger = new AgentGymSlackDeliveryLedger();
  const invocation = simulateSlackDirectMessage(event);
  assert.equal(ledger.admit(invocation).disposition, "admitted");
  assert.equal(ledger.admit(simulateSlackDirectMessage(event)).disposition, "duplicate");
});

test("delivery simulation rejects changed payload under one event identity", () => {
  const ledger = new AgentGymSlackDeliveryLedger();
  const event = {
    event_ref: "slack-event://retry/changed",
    kind: "direct_message" as const,
    occurred_at: "2026-08-12T08:38:00.000Z",
    payload: {
      channel_id: "D12345",
      team_id: "T_ONE",
      text: "Continue.",
      ts: "1786523880.000001",
      user_id: "U_ONE",
    },
  };
  ledger.admit(simulateSlackDirectMessage(event));
  assert.throws(() => ledger.admit(simulateSlackDirectMessage({
    ...event,
    payload: { ...event.payload, text: "Do something else." },
  })), /event retry changed payload/u);
});

test("message-delete simulation emits a text-free tombstone", () => {
  const invocation = simulateSlackMessageDeleted({
    event_ref: "slack-event://deleted/one",
    kind: "message_deleted",
    occurred_at: "2026-08-12T08:37:00.000Z",
    payload: {
      channel_id: "C12345",
      deleted_ts: "1786523640.000001",
      team_id: "T_ONE",
      thread_ts: "1786523400.000001",
      user_id: "U_ONE",
    },
  });
  assert.deepEqual(invocation.action, {
    action_id: "message.deleted",
    value: "1786523640.000001",
  });
  assert.equal(invocation.text, undefined);
});

test("message-delete simulation rejects a deletion without stable identity", () => {
  assert.throws(() => simulateSlackMessageDeleted({
    event_ref: "slack-event://deleted/missing",
    kind: "message_deleted",
    occurred_at: "2026-08-12T08:37:00.000Z",
    payload: {
      channel_id: "C12345",
      team_id: "T_ONE",
      user_id: "U_ONE",
    },
  }), /deleted_ts is invalid/u);
});

test("message-change simulation emits the correction and prior-content digest", () => {
  const invocation = simulateSlackMessageChanged({
    event_ref: "slack-event://changed/one",
    kind: "message_changed",
    occurred_at: "2026-08-12T08:36:00.000Z",
    payload: {
      channel_id: "C12345",
      previous_text: "Use the first option.",
      team_id: "T_ONE",
      text: "Use the second option.",
      thread_ts: "1786523400.000001",
      ts: "1786523640.000001",
      user_id: "U_ONE",
    },
  });
  assert.equal(invocation.route, "assistant_turn");
  assert.equal(invocation.text, "Use the second option.");
  assert.equal(invocation.action?.action_id, "message.changed");
  assert.match(invocation.action?.value ?? "", /^sha256:[0-9a-f]{64}$/u);
});

test("message-change simulation rejects a no-op edit", () => {
  assert.throws(() => simulateSlackMessageChanged({
    event_ref: "slack-event://changed/noop",
    kind: "message_changed",
    occurred_at: "2026-08-12T08:36:00.000Z",
    payload: {
      channel_id: "C12345",
      previous_text: "No change.",
      team_id: "T_ONE",
      text: "No change.",
      ts: "1786523640.000001",
      user_id: "U_ONE",
    },
  }), /message-change text is invalid/u);
});

test("reaction simulation records exact message feedback without Slack", () => {
  const invocation = simulateSlackReactionAdded({
    event_ref: "slack-event://reaction/one",
    kind: "reaction_added",
    occurred_at: "2026-08-12T08:35:00.000Z",
    payload: {
      channel_id: "C12345",
      item_ts: "1786523640.000001",
      reaction: "thumbsup",
      team_id: "T_ONE",
      user_id: "U_ONE",
    },
  });
  assert.deepEqual(invocation.action, {
    action_id: "reaction.added",
    value: "thumbsup",
  });
  assert.match(invocation.conversation_ref, /^slack-message:\/\/sha256\/[0-9a-f]{64}$/u);
});

test("reaction simulation rejects display emoji instead of stable names", () => {
  assert.throws(() => simulateSlackReactionAdded({
    event_ref: "slack-event://reaction/emoji",
    kind: "reaction_added",
    occurred_at: "2026-08-12T08:35:00.000Z",
    payload: {
      channel_id: "C12345",
      item_ts: "1786523640.000001",
      reaction: "👍",
      team_id: "T_ONE",
      user_id: "U_ONE",
    },
  }), /reaction name is invalid/u);
});

test("button simulation binds the exact action to its actor and thread", () => {
  const invocation = simulateSlackButtonAction({
    event_ref: "slack-event://button/one",
    kind: "button_action",
    occurred_at: "2026-08-12T08:34:00.000Z",
    payload: {
      action_id: "answer.feedback.correct",
      channel_id: "C12345",
      message_ts: "1786523640.000001",
      team_id: "T_ONE",
      thread_ts: "1786523400.000001",
      user_id: "U_ONE",
      value: "feedback://answer/one",
    },
  });
  assert.equal(invocation.route, "interaction");
  assert.deepEqual(invocation.action, {
    action_id: "answer.feedback.correct",
    value: "feedback://answer/one",
  });
  assert.equal(Object.isFrozen(invocation.action), true);
});

test("button simulation rejects an unbounded action identifier", () => {
  assert.throws(() => simulateSlackButtonAction({
    event_ref: "slack-event://button/bad",
    kind: "button_action",
    occurred_at: "2026-08-12T08:34:00.000Z",
    payload: {
      action_id: "Not a stable id",
      channel_id: "C12345",
      message_ts: "1786523640.000001",
      team_id: "T_ONE",
      user_id: "U_ONE",
      value: "feedback://answer/one",
    },
  }), /button action id is invalid/u);
});

test("App Home simulation emits a publish request without message text", () => {
  const invocation = simulateSlackAppHomeOpened({
    event_ref: "slack-event://home/one",
    kind: "app_home_opened",
    occurred_at: "2026-08-12T08:33:00.000Z",
    payload: { tab: "home", team_id: "T_ONE", user_id: "U_ONE" },
  });
  assert.equal(invocation.route, "publish_home");
  assert.equal(invocation.text, undefined);
  assert.equal(invocation.action, undefined);
  assert.match(invocation.conversation_ref, /^slack-home:\/\/sha256\/[0-9a-f]{64}$/u);
});

test("App Home simulation rejects non-home tabs", () => {
  assert.throws(() => simulateSlackAppHomeOpened({
    event_ref: "slack-event://home/messages",
    kind: "app_home_opened",
    occurred_at: "2026-08-12T08:33:00.000Z",
    payload: { tab: "messages", team_id: "T_ONE", user_id: "U_ONE" },
  }), /App Home tab is invalid/u);
});

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
