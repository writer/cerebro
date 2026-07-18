import assert from "node:assert/strict";
import test from "node:test";
import { Authorization } from "../src/auth.js";
import { encodeAction } from "../src/slack/action-codec.js";
import { actionIds } from "../src/slack/blocks/index.js";
import { registerProactiveSuggestionActions } from "../src/slack/actions/proactive-suggestions.js";
import { handleAlertTriage } from "../src/slack/events/alert-triage-route.js";
import { monitorSuggestionFor } from "../src/triage/monitor-suggestions.js";
import { proactiveSuggestionFor, shouldPostProactiveSuggestion } from "../src/triage/proactive-suggestions.js";
import type { AlertTriageResult } from "../src/triage/alert-triage-types.js";
import { ProactiveSlackContextCollector, renderProactiveContextPromptBlock } from "../src/triage/proactive-context.js";
import { SlackThreadSessionStateStore } from "../src/triage/slack-thread-state.js";
import { testConfig } from "./fixtures.js";

const config = testConfig();

test("SlackThreadSessionStateStore persists per-thread state through Dynamo", async () => {
  const dynamo = new FakeThreadStateDynamo();
  const config = testConfig({ triage: { threadStateTableName: "learning" } });
  const now = () => new Date("2026-06-29T12:00:00.000Z");
  const first = new SlackThreadSessionStateStore(config, { dynamo, now });

  await first.recordOutcome({
    channelId: "CSEC",
    threadTs: "1782500000.000000",
    sourceTs: "1782500001.000000",
    channelPolicy: "watch",
    outcome: "posted",
    classification: "needs_context",
    confidence: 0.82,
    summary: "PR #1488 needs a rollout check.",
    reason: "The status changes the release path.",
    research: ["cerebro_code_github_pr_status: checked"],
  });

  const second = new SlackThreadSessionStateStore(config, { dynamo, now });
  const restored = await second.get("CSEC", "1782500000.000000");

  assert.equal(restored?.channelId, "CSEC");
  assert.equal(restored?.threadTs, "1782500000.000000");
  assert.equal(restored?.lastReviewedTs, "1782500001.000000");
  assert.equal(restored?.lastPostedTs, "1782500001.000000");
  assert.equal(restored?.outcomes[0]?.outcome, "posted");
  assert.equal(restored?.outcomes[0]?.summary, "PR #1488 needs a rollout check.");
});

test("ProactiveSlackContextCollector uses durable thread state to avoid repeated full context fetches", async () => {
  const config = testConfig();
  const store = new SlackThreadSessionStateStore(config, { now: () => new Date("2026-06-29T12:00:00.000Z") });
  const slack = new FakeSlackResearch();
  const collector = new ProactiveSlackContextCollector(
    config,
    { search: async () => [] } as any,
    store,
    { slack: slack as any },
  );

  const first = await collector.collect({
    channelId: "CSEC",
    userId: "U1",
    ts: "1782500001.000000",
    threadTs: "1782500000.000000",
    text: "Is this PR #1488 release blocked?",
  });
  const firstBlock = renderProactiveContextPromptBlock(first);

  assert.equal(slack.threadCalls, 1);
  assert.match(firstBlock, /durable_thread_state/);
  assert.match(firstBlock, /visible_thread_context/);

  await collector.collect({
    channelId: "CSEC",
    userId: "U1",
    ts: "1782500002.000000",
    threadTs: "1782500000.000000",
    text: "Here is a longer release status update with enough detail that Cerebro can use the durable thread state instead of fetching the full Slack thread again.",
  });

  assert.equal(slack.threadCalls, 1);
});

test("monitorSuggestionFor drafts short-lived checks for actionable operational threads", () => {
  const suggestion = monitorSuggestionFor({
    channelId: "CSEC",
    userId: "U1",
    ts: "1782500001.000000",
    threadTs: "1782500000.000000",
    text: "PR #1488 merged but sec-dev still needs the new image rolled out.",
  }, {
    topic: "operational_update",
    classification: "needs_context",
    severity: "low",
    confidence: 0.8,
    shouldRespond: true,
    responseReason: "The rollout state changes the next release step.",
    summary: "PR #1488 is merged, but the release still needs a rollout check.",
    evidence: ["GitHub PR #1488 is merged."],
    actionsTaken: ["Checked GitHub PR status."],
    recommendedActions: ["Watch the rollout until sec-dev reports the new image."],
    research: ["cerebro_code_github_pr_status: checked"],
    source: "pi",
  }, "watch");

  assert.equal(suggestion?.title, "Watch PR #1488 rollout");
  assert.match(suggestion?.scheduleText ?? "", /Every 30 minutes/);
  assert.match(suggestion?.dedupKey ?? "", /PR #1488/i);
});

test("proactiveSuggestionFor drafts goal-backed follow-up work from verified triage", () => {
  const result = proactiveResult({ shouldRespond: false });
  const suggestion = proactiveSuggestionFor(config, {
    channelId: "CSEC",
    userId: "U1",
    ts: "1782500001.000000",
    threadTs: "1782500000.000000",
    text: "PR #1488 merged but sec-dev still needs rollout follow-up.",
  }, result, "watch");

  assert.equal(shouldPostProactiveSuggestion(config, result, "watch"), true);
  assert.equal(suggestion?.title, "Close the loop on PR #1488");
  assert.match(suggestion?.goalText ?? "", /Suggested action: Confirm sec-dev is running the merged image/);
  assert.match(suggestion?.dedupKey ?? "", /pr #1488/i);
});

test("handleAlertTriage posts a proactive suggestion when the full triage reply stays quiet", async () => {
  const posts: any[] = [];
  const notes: any[] = [];
  const config = testConfig();
  const threadState = new SlackThreadSessionStateStore(config, { now: () => new Date("2026-06-29T12:00:00.000Z") });

  await handleAlertTriage({
    config,
    auth: new Authorization(config),
    cerebro: { recordInteraction: async () => undefined } as any,
    memory: {} as any,
    coordinator: {} as any,
    notes: { record: async (note: any) => notes.push(note) } as any,
    threadState,
  }, {
    triage: async () => proactiveResult({ shouldRespond: false }),
  } as any, {
    chat: {
      postMessage: async (message: any) => posts.push(message),
    },
  }, {
    channelId: "CSEC",
    userId: "U1",
    ts: "1782500001.000000",
    threadTs: "1782500000.000000",
    text: "PR #1488 merged but rollout status still needs a sec-dev check.",
  });

  const state = await threadState.get("CSEC", "1782500000.000000");
  assert.equal(posts.length, 1);
  assert.match(posts[0].text, /Suggested action: Close the loop on PR #1488/);
  assert.match(JSON.stringify(posts[0].blocks), /Create goal/);
  assert.match(JSON.stringify(posts[0].blocks), /cerebro_proactive_suggestion_accept/);
  assert.equal(state?.proactiveSuggestions[0]?.status, "pending");
  assert.equal(state?.outcomes[0]?.outcome, "suggested");
  assert.equal(state?.lastPostedTs, "1782500001.000000");
  assert.equal(notes.some((note) => note.outcome === "suggested"), true);
});

test("proactive suggestion accept creates an autonomy goal from stored thread state", async () => {
  const config = testConfig();
  const threadState = new SlackThreadSessionStateStore(config, { now: () => new Date("2026-06-29T12:00:00.000Z") });
  const write = await threadState.addProactiveSuggestion({
    channelId: "CSEC",
    threadTs: "1782500000.000000",
    channelPolicy: "watch",
    title: "Close the loop on PR #1488",
    description: "Confirm sec-dev is running the merged image.",
    goalText: "Close the loop on PR #1488. Suggested action: Confirm sec-dev is running the merged image.",
    dedupKey: "release:CSEC:1782500000.000000:pr #1488:confirm",
    sourceTs: "1782500001.000000",
  });
  const responses: any[] = [];
  const createdGoals: any[] = [];
  const handlers = new Map<string, (args: any) => Promise<void>>();
  registerProactiveSuggestionActions({
    action: (id: string, handler: (args: any) => Promise<void>) => handlers.set(id, handler),
  }, {
    config,
    auth: new Authorization(config),
    cerebro: {} as any,
    notes: { record: async () => undefined } as any,
    goals: {
      createFromText: async (input: any) => {
        createdGoals.push(input);
        return { id: "goal-1", objective: input.text };
      },
    } as any,
    scheduler: {} as any,
    threadState,
  });

  await handlers.get(actionIds.proactiveSuggestionAccept)!({
    body: { user: { id: "U1" }, channel: { id: "CSEC" } },
    action: {
      value: encodeAction({
        kind: "proactive_suggestion_accept",
        suggestionId: write.suggestion!.id,
        channelId: "CSEC",
        threadTs: "1782500000.000000",
      }),
    },
    ack: async () => undefined,
    respond: async (message: any) => responses.push(message),
  });

  const state = await threadState.get("CSEC", "1782500000.000000");
  assert.equal(createdGoals.length, 1);
  assert.equal(createdGoals[0].threadTs, "1782500000.000000");
  assert.match(createdGoals[0].text, /Confirm sec-dev is running/);
  assert.equal(state?.proactiveSuggestions[0]?.status, "accepted");
  assert.equal(state?.proactiveSuggestions[0]?.goalId, "goal-1");
  assert.match(responses[0].text, /Created goal goal-1/);
});

class FakeThreadStateDynamo {
  readonly items = new Map<string, Record<string, unknown>>();

  async send(command: any): Promise<unknown> {
    const input = command.input;
    if (input.Item) {
      this.items.set(`${input.Item.pk}#${input.Item.sk}`, input.Item);
      return {};
    }
    const values = input.ExpressionAttributeValues ?? {};
    const key = `${values[":pk"]}#${values[":sk"]}`;
    const item = this.items.get(key);
    return { Items: item ? [item] : [] };
  }
}

function proactiveResult(overrides: Partial<AlertTriageResult> = {}): AlertTriageResult {
  return {
    topic: "operational_update" as const,
    classification: "needs_context" as const,
    severity: "low" as const,
    confidence: 0.82,
    shouldRespond: true,
    responseReason: "The release state needs a concrete owner action.",
    summary: "PR #1488 is merged, and sec-dev needs rollout follow-up.",
    evidence: ["GitHub PR #1488 is merged and checks passed."],
    actionsTaken: ["Checked GitHub PR status."],
    recommendedActions: ["Confirm sec-dev is running the merged image before closing the release thread."],
    research: ["cerebro_code_github_pr_status: checked"],
    source: "pi" as const,
    ...overrides,
  };
}

class FakeSlackResearch {
  threadCalls = 0;

  async threadContext(channelId: string, threadTs: string) {
    this.threadCalls += 1;
    return {
      channel_id: channelId,
      thread_ts: threadTs,
      messages: [
        {
          ts: threadTs,
          datetime: "2026-06-29T12:00:00.000Z",
          user_id: "U1",
          user_name: "Maya",
          text: "PR #1488 merged but rollout is not done.",
        },
      ],
    };
  }

  async messageContext(channelId: string, ts: string) {
    return {
      channel_id: channelId,
      ts,
      permalink: `https://slack.example/${channelId}/${ts}`,
      reactions: [],
      errors: [],
    };
  }

  async channelContext(channelId: string) {
    return {
      channel_id: channelId,
      channel: { id: channelId, name: "security-team-agents" },
      bookmarks: [],
      pins: [],
      recent_messages: [],
      errors: [],
    };
  }

  async scopeCapabilities() {
    return {
      ok: true,
      granted_scopes: [],
      capabilities: [],
      missing_recommended_scopes: [],
      note: "test scope",
    };
  }
}
