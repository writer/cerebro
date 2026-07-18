import assert from "node:assert/strict";
import test from "node:test";
import { Authorization } from "../src/auth.js";
import { registerEventHandlers } from "../src/slack/events/index.js";
import { parseRememberCommand } from "../src/slack/remember-command.js";
import { testConfig } from "./fixtures.js";

test("parseRememberCommand handles textual and mention remember commands", () => {
  const textual = parseRememberCommand("Cerebro remember Sean says 90% of what he says on Slack is a dumb joke");
  assert.equal(textual?.topic, "Slack context: Sean");
  assert.equal(textual?.workingMemoryTarget, "team");
  assert.match(textual?.summary ?? "", /90%/);
  assert.deepEqual(textual?.tags.includes("tone"), true);

  const mention = parseRememberCommand("<@U0BOT> remember that Sean jokes a lot in Slack threads");
  assert.equal(mention?.topic, "Slack context: Sean");
  assert.equal(mention?.workingMemoryTarget, "team");

  assert.equal(parseRememberCommand('Actually that is a great idea. "Cerebro remember"'), undefined);
});

test("app mention remember command writes searchable and team memory", async () => {
  const events = fakeEventApp();
  const writes: any[] = [];
  const workingWrites: any[] = [];
  const posts: any[] = [];
  const reactions: any[] = [];
  const notes: any[] = [];

  registerEventHandlers(events.app, deps({
    memory: {
      remember: async (input: any) => {
        writes.push(input);
        return { id: "memory-1", ...input, tags: input.tags ?? [], createdAt: new Date().toISOString() };
      },
      writeWorkingMemory: (input: any) => {
        workingWrites.push(input);
        return { success: true, target: input.target, action: input.action, message: "Entry added.", entry_count: 1, usage: "1% - 100/1375" };
      },
    },
    notes: { record: async (input: any) => { notes.push(input); } },
  }));

  await events.handler("app_mention")({
    event: {
      channel: "CSEC",
      user: "UJON",
      ts: "1782500108.353089",
      event_ts: "1782500108.353089",
      team: "TWRITER",
      text: "<@U0BOT> remember Sean says 90% of what he says on Slack is a dumb joke",
    },
    client: fakeClient(posts, reactions),
    context: { botUserId: "U0BOT" },
    say: async (message: any) => posts.push(message),
  });

  assert.equal(writes.length, 2);
  assert.equal(writes[0].kind, "team_context");
  assert.equal(writes[0].topic, "Slack context: Sean");
  assert.match(writes[0].summary, /90%/);
  assert.deepEqual(writes[0].tags.includes("team-context"), true);
  assert.equal(writes[1].kind, "explicit_memory");
  assert.match(writes[1].summary, /explicitly told to remember/i);
  assert.match(writes[1].summary, /90%/);
  assert.deepEqual(writes[1].tags.includes("explicit-memory"), true);
  assert.equal(workingWrites.length, 1);
  assert.equal(workingWrites[0].target, "team");
  assert.match(workingWrites[0].content, /Slack context: Sean/);
  assert.equal(posts[0].text, "Remembered: Slack context: Sean.");
  assert.equal(reactions[0].name, "memo");
  assert.equal(notes[0].outcome, "remembered");
});

test("textual remember command is handled before passive triage", async () => {
  const events = fakeEventApp();
  const writes: any[] = [];
  const posts: any[] = [];
  const reactions: any[] = [];

  registerEventHandlers(events.app, deps({
    memory: {
      remember: async (input: any) => {
        writes.push(input);
        return { id: "memory-2", ...input, tags: input.tags ?? [], createdAt: new Date().toISOString() };
      },
      writeWorkingMemory: (input: any) => ({ success: true, target: input.target, action: input.action, message: "Entry added.", entry_count: 1, usage: "1% - 100/1375" }),
    },
  }));

  await events.handler("message")({
    event: {
      channel: "CSEC",
      user: "USEAN",
      ts: "1782500077.405889",
      event_ts: "1782500077.405889",
      team: "TWRITER",
      text: "Cerebro remember 90% of what I say on Slack is a dumb joke",
    },
    client: fakeClient(posts, reactions),
  });

  assert.equal(writes.length, 2);
  assert.equal(writes[0].topic, "Slack context: Sean");
  assert.match(writes[0].summary, /Sean: 90%/);
  assert.equal(writes[1].kind, "explicit_memory");
  assert.match(writes[1].summary, /90% of what I say/);
  assert.equal(posts[0].text, "Remembered: Slack context: Sean.");
});

test("app mention graph questions are queued behind the work loop", async () => {
  const events = fakeEventApp();
  const posts: any[] = [];
  const reactions: any[] = [];
  const queued: any[] = [];
  const notes: any[] = [];

  registerEventHandlers(events.app, deps({
    notes: { record: async (input: any) => { notes.push(input); } },
    workLoop: {
      enqueueSlackQuestion: (_client: any, input: any) => {
        queued.push(input);
        return { id: "work-1", position: 1, accepted: true, reason: "queued" };
      },
    },
  }));

  await events.handler("app_mention")({
    event: {
      channel: "CSEC",
      user: "UJON",
      ts: "1782509999.000000",
      event_ts: "1782509999.000000",
      team: "TWRITER",
      text: "<@U0BOT> what are the newest scariest findings today?",
    },
    client: fakeClient(posts, reactions),
    context: { botUserId: "U0BOT" },
    say: async (message: any) => posts.push(message),
  });

  assert.equal(queued.length, 1);
  assert.equal(queued[0].question, "what are the newest scariest findings today?");
  assert.equal(queued[0].threadTs, "1782509999.000000");
  assert.equal(queued[0].replyThreadTs, "1782509999.000000");
  assert.equal(posts.length, 0);
  assert.equal(reactions[0].name, "eyes");
  assert.equal(notes.some((note) => note.kind === "encounter_story" && note.outcome === "queued"), true);
});

test("app mention preserves helper mentions when stripping Cerebro addressing", async () => {
  const events = fakeEventApp();
  const posts: any[] = [];
  const reactions: any[] = [];
  const queued: any[] = [];

  registerEventHandlers(events.app, deps({
    workLoop: {
      enqueueSlackQuestion: (_client: any, input: any) => {
        queued.push(input);
        return { id: "work-helper", position: 1, accepted: true, reason: "queued" };
      },
    },
  }));

  await events.handler("app_mention")({
    event: {
      channel: "CSEC",
      user: "UJON",
      ts: "1782510001.000000",
      event_ts: "1782510001.000000",
      team: "TWRITER",
      text: "<@UALBERT> can you help <@U0BOT>?",
    },
    client: fakeClient(posts, reactions),
    context: { botUserId: "U0BOT" },
    say: async (message: any) => posts.push(message),
  });

  assert.equal(queued.length, 1);
  assert.equal(queued[0].question, "<@UALBERT> can you help?");
});

test("remember command refuses secrets", async () => {
  const events = fakeEventApp();
  const writes: any[] = [];
  const posts: any[] = [];
  const reactions: any[] = [];

  registerEventHandlers(events.app, deps({
    memory: {
      remember: async (input: any) => {
        writes.push(input);
        return { id: "memory-secret", ...input, tags: input.tags ?? [], createdAt: new Date().toISOString() };
      },
      writeWorkingMemory: () => ({ success: true, target: "memory", action: "add", message: "Entry added.", entry_count: 1, usage: "1% - 100/2200" }),
    },
  }));

  await events.handler("app_mention")({
    event: {
      channel: "CSEC",
      user: "UJON",
      ts: "1.1",
      event_ts: "1.1",
      team: "TWRITER",
      text: "<@U0BOT> remember token=xoxb-demo",
    },
    client: fakeClient(posts, reactions),
    say: async (message: any) => posts.push(message),
  });

  assert.equal(writes.length, 0);
  assert.match(posts[0].text, /did not save/i);
  assert.equal(reactions[0].name, "no_entry");
});

function fakeEventApp(): { app: { event(name: string, handler: any): void }; handler(name: string): any } {
  const handlers = new Map<string, any>();
  return {
    app: {
      event(name: string, handler: any): void {
        handlers.set(name, handler);
      },
    },
    handler(name: string): any {
      const handler = handlers.get(name);
      assert.ok(handler, `missing handler ${name}`);
      return handler;
    },
  };
}

function fakeClient(posts: any[], reactions: any[]): any {
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
    apiCall: async () => ({ ok: true }),
  };
}

function deps(overrides: { memory?: any; notes?: any; workLoop?: any; assistant?: any } = {}): any {
  const config = testConfig({
    cerebro: {
      slackUsers: new Map([
        ["USEAN", { actorId: "sean@writer.com", displayName: "Sean" }],
        ["UJON", { actorId: "jonathan.haas@writer.com", displayName: "Jonathan Haas" }],
      ]),
    },
  });
  return {
    config,
    auth: new Authorization(config),
    cerebro: {
      buildEvidencePacket: async () => ({}),
      reasonGraph: async () => ({ answer: "not used" }),
      recordInteraction: async () => undefined,
    },
    memory: overrides.memory ?? {
      remember: async () => undefined,
      writeWorkingMemory: () => ({ success: true, target: "memory", action: "add", message: "Entry added.", entry_count: 1, usage: "1% - 100/2200" }),
    },
    coordinator: {
      claimSlackEvent: async () => ({ claimed: true, reason: "claimed", eventKey: "test" }),
      claimBotHandoff: () => ({ accepted: true, reason: "not_bot" }),
    },
    notes: overrides.notes ?? { record: async () => undefined },
    assistant: overrides.assistant,
    workLoop: overrides.workLoop,
  };
}
