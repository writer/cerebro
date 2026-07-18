import assert from "node:assert/strict";
import test from "node:test";
import { handleMessageEvent } from "../src/slack/events/message-route.js";
import type { TelemetrySpan } from "../src/telemetry.js";
import { SlackThreadSessionStateStore } from "../src/triage/slack-thread-state.js";
import { testConfig } from "./fixtures.js";

test("direct app messages are queued as assistant questions", async () => {
  const reactions: any[] = [];
  const posts: any[] = [];
  const apiCalls: any[] = [];
  const notes: any[] = [];
  const queued: any[] = [];
  const claims: any[] = [];
  const event = {
    channel: "DSEC",
    channel_type: "im",
    user: "UUSER",
    ts: "1782511000.000000",
    event_ts: "1782511000.000000",
    team: "TSEC",
    text: "Can you respond to this thread?",
  };

  await handleMessageEvent(
    {
      config: testConfig(),
      auth: { actorFor: () => ({ slackUserId: "UUSER", actorId: "slack:UUSER", displayName: "Jonathan" }) } as any,
      cerebro: {} as any,
      memory: {} as any,
      coordinator: {
        claimSlackEvent: async (input: any) => {
          claims.push(input);
          return { claimed: true, reason: "claimed", eventKey: "assistant-message" };
        },
        claimBotHandoff: () => ({ accepted: true, reason: "not_bot" }),
      } as any,
      notes: {
        record: async (input: any) => {
          notes.push(input);
        },
      } as any,
    },
    {} as any,
    {
      enqueueSlackQuestion: (_client: any, input: any) => {
        queued.push(input);
        return { id: "work-1", position: 1, accepted: true, reason: "queued" };
      },
    } as any,
    fakeClient(posts, reactions, apiCalls),
    event,
    fakeSpan(),
    { botUserId: "UCEREBRO" },
  );

  assert.equal(claims[0]?.kind, "assistant_message");
  assert.equal(queued.length, 1);
  assert.equal(queued[0].question, "Can you respond to this thread?");
  assert.equal(queued[0].replyThreadTs, event.ts);
  assert.equal(queued[0].senderKind, "human");
  assert.equal(reactions.some((reaction) => reaction.name === "eyes"), true);
  assert.equal(apiCalls.some((call) => call.method === "assistant.threads.setStatus"), true);
  assert.equal(notes.some((note) => note.kind === "encounter_story" && note.tags.includes("assistant-message")), true);
  assert.equal(posts.length, 0);
});

test("allowlisted bot messages that mention Cerebro are queued as assistant questions", async () => {
  const queued: any[] = [];
  const claims: any[] = [];
  const handoffs: any[] = [];
  const reactions: any[] = [];
  const apiCalls: any[] = [];
  const event = {
    channel: "CSEC",
    channel_type: "channel",
    user: "UHELPER",
    bot_id: "BHELPER",
    subtype: "bot_message",
    ts: "1782511002.000000",
    event_ts: "1782511002.000000",
    team: "TSEC",
    text: "<@UCEREBRO> can you check the source registration?",
    thread_ts: "1782511000.000000",
  };

  await handleMessageEvent(
    {
      config: testConfig({ slack: { assistantBotUserIds: new Set(["BHELPER"]) } }),
      auth: { actorFor: () => ({ slackUserId: "UHELPER", actorId: "slack:UHELPER", displayName: "Helper" }) } as any,
      cerebro: {} as any,
      memory: {} as any,
      coordinator: {
        claimSlackEvent: async (input: any) => {
          claims.push(input);
          return { claimed: true, reason: "claimed", eventKey: "assistant-message" };
        },
        claimBotHandoff: (input: any) => {
          handoffs.push(input);
          return { accepted: true, reason: "allowed", senderId: "BHELPER" };
        },
      } as any,
      notes: { record: async () => undefined } as any,
    },
    {} as any,
    {
      enqueueSlackQuestion: (_client: any, input: any) => {
        queued.push(input);
        return { id: "work-1", position: 1, accepted: true, reason: "queued" };
      },
    } as any,
    fakeClient([], reactions, apiCalls),
    event,
    fakeSpan(),
    { botUserId: "UCEREBRO" },
  );

  assert.equal(claims[0]?.kind, "assistant_message");
  assert.equal(handoffs[0]?.botId, "BHELPER");
  assert.equal(queued.length, 1);
  assert.equal(queued[0].question, "can you check the source registration?");
  assert.equal(queued[0].replyThreadTs, event.thread_ts);
  assert.equal(queued[0].senderKind, "bot");
  assert.deepEqual(reactions, []);
  assert.equal(apiCalls.some((call) => call.method === "assistant.threads.setStatus"), false);
});

test("bot messages are not queued when the handoff gate rejects them", async () => {
  const queued: any[] = [];

  await handleMessageEvent(
    {
      config: testConfig(),
      auth: { actorFor: () => ({ slackUserId: "UHELPER", actorId: "slack:UHELPER", displayName: "Helper" }) } as any,
      cerebro: {} as any,
      memory: {} as any,
      coordinator: {
        claimSlackEvent: async () => ({ claimed: true, reason: "claimed", eventKey: "assistant-message" }),
        claimBotHandoff: () => ({ accepted: false, reason: "bot_not_allowed", senderId: "BHELPER" }),
      } as any,
      notes: { record: async () => undefined } as any,
    },
    {} as any,
    {
      enqueueSlackQuestion: (_client: any, input: any) => {
        queued.push(input);
        return { id: "work-1", position: 1, accepted: true, reason: "queued" };
      },
    } as any,
    fakeClient([], [], []),
    {
      channel: "CSEC",
      channel_type: "channel",
      user: "UHELPER",
      bot_id: "BHELPER",
      subtype: "bot_message",
      ts: "1782511003.000000",
      event_ts: "1782511003.000000",
      team: "TSEC",
      text: "<@UCEREBRO> can you check this?",
    },
    fakeSpan(),
    { botUserId: "UCEREBRO" },
  );

  assert.equal(queued.length, 0);
});

test("bot message loop-limit rejections do not queue assistant work", async () => {
  const queued: any[] = [];

  await handleMessageEvent(
    {
      config: testConfig(),
      auth: { actorFor: () => ({ slackUserId: "UHELPER", actorId: "slack:UHELPER", displayName: "Helper" }) } as any,
      cerebro: {} as any,
      memory: {} as any,
      coordinator: {
        claimSlackEvent: async () => ({ claimed: true, reason: "claimed", eventKey: "assistant-message" }),
        claimBotHandoff: () => ({
          accepted: false,
          reason: "loop_limit",
          senderId: "BHELPER",
          handoffCount: 2,
          maxHandoffsPerThread: 2,
          windowSeconds: 3600,
        }),
      } as any,
      notes: { record: async () => undefined } as any,
    },
    {} as any,
    {
      enqueueSlackQuestion: (_client: any, input: any) => {
        queued.push(input);
        return { id: "work-1", position: 1, accepted: true, reason: "queued" };
      },
    } as any,
    fakeClient([], [], []),
    {
      channel: "CSEC",
      channel_type: "channel",
      user: "UHELPER",
      bot_id: "BHELPER",
      subtype: "bot_message",
      ts: "1782511004.000000",
      event_ts: "1782511004.000000",
      team: "TSEC",
      text: "<@UCEREBRO> can you check this again?",
    },
    fakeSpan(),
    { botUserId: "UCEREBRO" },
  );

  assert.equal(queued.length, 0);
});

test("channel messages without a bot mention are not queued as assistant questions", async () => {
  const queued: any[] = [];

  await handleMessageEvent(
    {
      config: testConfig(),
      auth: { actorFor: () => ({ slackUserId: "UUSER", actorId: "slack:UUSER", displayName: "Jonathan" }) } as any,
      cerebro: {} as any,
      memory: {} as any,
      coordinator: {
        claimSlackEvent: async () => ({ claimed: true, reason: "claimed", eventKey: "triage-message" }),
        claimBotHandoff: () => ({ accepted: true, reason: "not_bot" }),
      } as any,
      notes: { record: async () => undefined } as any,
    },
    {
      triage: async () => ({
        classification: "likely_noise",
        severity: "info",
        confidence: 0.2,
        shouldRespond: false,
        summary: "No security action.",
        evidence: [],
        actionsTaken: [],
        recommendedActions: [],
        research: [],
        source: "pi",
      }),
    } as any,
    {
      enqueueSlackQuestion: (_client: any, input: any) => {
        queued.push(input);
        return { id: "work-1", position: 1, accepted: true, reason: "queued" };
      },
    } as any,
    fakeClient([], [], []),
    {
      channel: "CSEC",
      channel_type: "channel",
      user: "UUSER",
      ts: "1782511001.000000",
      event_ts: "1782511001.000000",
      team: "TSEC",
      text: "Thanks",
      thread_ts: "1782511000.000000",
    },
    fakeSpan(),
    { botUserId: "UCEREBRO" },
  );

  assert.equal(queued.length, 0);
});

test("an exact human reply to an open assistant initiative is queued through the Pi work loop", async () => {
  const config = testConfig({ slack: { triageChannelIds: new Set() } });
  const threadState = new SlackThreadSessionStateStore(config, { now: () => new Date("2026-07-16T12:00:00.000Z") });
  await threadState.bindAssistantInitiativeReceipt({
    deliveryId: "delivery-initiative",
    channelId: "CSEC",
    threadTs: "1784201000.000300",
    receiptContext: {
      kind: "assistant_initiative",
      refId: "initiative-source-loop",
      assistantInitiative: {
        intendedUserId: "UUSER",
        expiresAt: "2026-07-17T12:00:00.000Z",
        goalId: `improvement-${"a".repeat(24)}`,
      },
    },
  });
  const claims: any[] = [];
  const queued: any[] = [];
  const learned: any[] = [];
  const outcomes: any[] = [];

  await handleMessageEvent(
    {
      config,
      auth: { actorFor: () => ({ slackUserId: "UUSER", actorId: "slack:UUSER", displayName: "Jonathan" }) } as any,
      cerebro: {} as any,
      memory: {} as any,
      threadState,
      channelLearning: {
        observe: (input: any) => {
          learned.push(input);
          return { accepted: true, reason: "buffered", buffered: 1 };
        },
      },
      coordinator: {
        claimSlackEvent: async (input: any) => {
          claims.push(input);
          return { claimed: true, reason: "claimed", eventKey: "assistant-message" };
        },
        claimBotHandoff: () => ({ accepted: true, reason: "not_bot" }),
      } as any,
      notes: { record: async () => undefined } as any,
      improvement: {
        recordHumanAssistanceOutcome: async (input: any) => {
          outcomes.push(input);
          return { id: input.runId };
        },
      } as any,
    },
    {} as any,
    {
      enqueueSlackQuestion: (_client: any, input: any) => {
        queued.push(input);
        return { id: "work-initiative", position: 1, accepted: true, reason: "queued" };
      },
    } as any,
    fakeClient([], [], []),
    {
      channel: "CSEC",
      channel_type: "channel",
      user: "UUSER",
      ts: "1784201001.000300",
      event_ts: "1784201001.000300",
      team: "TSEC",
      text: "<@UCEREBRO> Prove the retry succeeds before opening the repair PR.",
      thread_ts: "1784201000.000300",
    },
    fakeSpan(),
    { botUserId: "UCEREBRO" },
  );

  assert.equal(claims[0]?.kind, "assistant_message");
  assert.equal(queued.length, 1);
  assert.equal(queued[0]?.question, "Prove the retry succeeds before opening the repair PR.");
  assert.equal(queued[0]?.replyThreadTs, "1784201000.000300");
  assert.deepEqual(learned, []);
  assert.deepEqual(outcomes, [{
    runId: `improvement-${"a".repeat(24)}`,
    channelId: "CSEC",
    intendedUserId: "UUSER",
    outcome: "Prove the retry succeeds before opening the repair PR.",
  }]);
  assert.equal((await threadState.getAssistantInitiativeBinding("CSEC", "1784201000.000300"))?.closeReason, "completed");
});

test("an exact human reply closes a generic one-shot assistant initiative", async () => {
  const config = testConfig({ slack: { triageChannelIds: new Set() } });
  const threadState = new SlackThreadSessionStateStore(config, { now: () => new Date("2026-07-16T12:00:00.000Z") });
  await threadState.bindAssistantInitiativeReceipt({
    deliveryId: "delivery-generic-initiative",
    channelId: "CSEC",
    threadTs: "1784201000.000350",
    receiptContext: {
      kind: "assistant_initiative",
      refId: "live-canary-prod-recheck",
      assistantInitiative: {
        intendedUserId: "UUSER",
        expiresAt: "2026-07-17T12:00:00.000Z",
      },
    },
  });
  const queued: any[] = [];
  const outcomes: any[] = [];

  await handleMessageEvent(
    {
      config,
      auth: { actorFor: () => ({ slackUserId: "UUSER", actorId: "slack:UUSER", displayName: "Jonathan" }) } as any,
      cerebro: {} as any,
      memory: {} as any,
      threadState,
      coordinator: {
        claimSlackEvent: async () => ({ claimed: true, reason: "claimed", eventKey: "assistant-message" }),
        claimBotHandoff: () => ({ accepted: true, reason: "not_bot" }),
      } as any,
      notes: { record: async () => undefined } as any,
      improvement: {
        recordHumanAssistanceOutcome: async (input: any) => {
          outcomes.push(input);
          return { id: input.runId };
        },
      } as any,
    },
    {} as any,
    {
      enqueueSlackQuestion: (_client: any, input: any) => {
        queued.push(input);
        return { id: "work-generic-initiative", position: 1, accepted: true, reason: "queued" };
      },
    } as any,
    fakeClient([], [], []),
    {
      channel: "CSEC",
      channel_type: "channel",
      user: "UUSER",
      ts: "1784201001.000350",
      event_ts: "1784201001.000350",
      team: "TSEC",
      text: "What do you see on the prod backend now?",
      thread_ts: "1784201000.000350",
    },
    fakeSpan(),
    { botUserId: "UCEREBRO" },
  );

  assert.equal(queued.length, 1);
  assert.equal(queued[0]?.question, "What do you see on the prod backend now?");
  assert.deepEqual(outcomes, []);
  assert.equal((await threadState.getAssistantInitiativeBinding("CSEC", "1784201000.000350"))?.closeReason, "completed");
});

test("bots, apps, and subtypes cannot claim an initiative binding", async () => {
  const config = testConfig({ slack: { triageChannelIds: new Set() } });
  let bindingLookups = 0;
  const queued: any[] = [];
  const variants = [
    { bot_id: "BOTHER" },
    { app_id: "AOTHER" },
    { subtype: "message_changed" },
  ];

  for (const [index, variant] of variants.entries()) {
    await handleMessageEvent(
      {
        config,
        auth: { actorFor: () => ({ slackUserId: "UUSER", actorId: "slack:UUSER", displayName: "Jonathan" }) } as any,
        cerebro: {} as any,
        memory: {} as any,
        threadState: {
          matchAssistantInitiativeReply: async () => {
            bindingLookups += 1;
            return { status: "open" };
          },
        } as any,
        coordinator: {
          claimSlackEvent: async () => ({ claimed: true, reason: "claimed", eventKey: "unexpected" }),
          claimBotHandoff: () => ({ accepted: true, reason: "not_bot" }),
        } as any,
        notes: { record: async () => undefined } as any,
      },
      {} as any,
      {
        enqueueSlackQuestion: (_client: any, input: any) => {
          queued.push(input);
          return { id: "unexpected", position: 1, accepted: true, reason: "queued" };
        },
      } as any,
      fakeClient([], [], []),
      {
        channel: "CSEC",
        channel_type: "channel",
        user: "UUSER",
        ts: `178420100${index}.000400`,
        event_ts: `178420100${index}.000400`,
        team: "TSEC",
        text: "take the next step",
        thread_ts: "1784201000.000400",
        ...variant,
      },
      fakeSpan(),
      { botUserId: "UCEREBRO" },
    );
  }

  assert.equal(bindingLookups, 0);
  assert.deepEqual(queued, []);
});

test("ordinary messages in joined non-triage channels are learned without a Slack response", async () => {
  const observations: any[] = [];
  const claims: any[] = [];
  const posts: any[] = [];
  const reactions: any[] = [];
  const queued: any[] = [];

  await handleMessageEvent(
    {
      config: testConfig({ slack: { triageChannelIds: new Set() } }),
      auth: { actorFor: () => ({ slackUserId: "UUSER", actorId: "slack:UUSER", displayName: "Teammate" }) } as any,
      cerebro: {} as any,
      memory: {} as any,
      channelLearning: {
        observe: (input: any) => {
          observations.push(input);
          return { accepted: true, reason: "buffered", buffered: 1 };
        },
      },
      coordinator: {
        claimSlackEvent: async (input: any) => {
          claims.push(input);
          return { claimed: true, reason: "claimed", eventKey: "channel-learning" };
        },
        claimBotHandoff: () => ({ accepted: true, reason: "not_bot" }),
      } as any,
      notes: { record: async () => undefined } as any,
    },
    { triage: async () => { throw new Error("triage must not run"); } } as any,
    {
      enqueueSlackQuestion: (_client: any, input: any) => {
        queued.push(input);
        return { id: "unexpected", position: 1, accepted: true, reason: "queued" };
      },
    } as any,
    fakeClient(posts, reactions, []),
    {
      channel: "CTEAM",
      channel_type: "channel",
      user: "UUSER",
      ts: "1782511005.000000",
      event_ts: "1782511005.000000",
      team: "TSEC",
      text: "<@UOWNER> confirmed the release check uses the running service task definition.",
    },
    fakeSpan(),
    { botUserId: "UCEREBRO" },
  );

  assert.equal(claims[0]?.kind, "channel_learning");
  assert.equal(observations.length, 1);
  assert.equal(observations[0].channelId, "CTEAM");
  assert.deepEqual(posts, []);
  assert.deepEqual(reactions, []);
  assert.deepEqual(queued, []);
});

test("machine digests do not enter joined channel learning", async () => {
  const observations: any[] = [];
  const claims: any[] = [];

  await handleMessageEvent(
    {
      config: testConfig({ slack: { triageChannelIds: new Set() } }),
      auth: { actorFor: () => ({ slackUserId: "UBOT", actorId: "slack:UBOT" }) } as any,
      cerebro: {} as any,
      memory: {} as any,
      channelLearning: {
        observe: (input: any) => {
          observations.push(input);
          return { accepted: true, reason: "buffered", buffered: 1 };
        },
      },
      coordinator: {
        claimSlackEvent: async (input: any) => {
          claims.push(input);
          return { claimed: true, reason: "claimed", eventKey: "unexpected" };
        },
        claimBotHandoff: () => ({ accepted: false, reason: "bot_not_allowed" }),
      } as any,
      notes: { record: async () => undefined } as any,
    },
    {} as any,
    { enqueueSlackQuestion: () => ({ id: "unexpected", position: 1, accepted: true, reason: "queued" }) } as any,
    fakeClient([], [], []),
    {
      channel: "CTEAM",
      channel_type: "channel",
      user: "UBOT",
      bot_id: "BAPP",
      app_id: "AAPP",
      subtype: "bot_message",
      ts: "1782511006.000000",
      event_ts: "1782511006.000000",
      team: "TSEC",
      text: "Automated daily digest",
    },
    fakeSpan(),
    { botUserId: "UCEREBRO" },
  );

  assert.deepEqual(observations, []);
  assert.deepEqual(claims, []);
});

function fakeClient(posts: any[], reactions: any[], apiCalls: any[]): any {
  return {
    chat: {
      postMessage: async (message: any) => {
        posts.push(message);
        return { ok: true };
      },
    },
    reactions: {
      add: async (reaction: any) => {
        reactions.push(reaction);
        return { ok: true };
      },
    },
    apiCall: async (method: string, args: any) => {
      apiCalls.push({ method, args });
      return { ok: true };
    },
  };
}

function fakeSpan(): TelemetrySpan {
  return {
    name: "slack.event.message",
    traceId: "trace",
    spanId: "span",
    startedAt: Date.now(),
    main: true,
    annotations: {},
  };
}
