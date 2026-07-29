import assert from "node:assert/strict";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  slackScratchpadAuthorRef,
  slackThreadScratchpadRef,
} from "@writer/cerebro-slack-companion";
import { CerebroAskClient } from "../src/runtime/cerebro-ask-client.js";
import { loadSlackRuntimeConfig } from "../src/runtime/config.js";
import { FileOutcomeStore } from "../src/runtime/outcome-store.js";
import type { SlackAnswerAuthorityPort } from "../src/runtime/slack-answer-authority-client.js";
import {
  AssistantQuestionService,
  createAssistantTurnHost,
  handleSlackMention,
} from "../src/runtime/slack-runtime.js";
import { FileThreadScratchpadStore } from "../src/runtime/thread-scratchpad-store.js";

const testAnswerAuthority: SlackAnswerAuthorityPort = {
  async validate(candidate) {
    if (!candidate.citation_validation?.ok) throw new Error("candidate rejected");
    return {
      disposition: "grounded",
      schema_version: "slack-answer-decision/v1",
      trace_id: candidate.trace_id,
      verified: true,
    };
  },
};

test("file scratchpad stores idempotent thread notes and clears them", async () => {
  const root = await mkdtemp(join(tmpdir(), "cerebro-slack-scratchpad-"));
  try {
    const store = new FileThreadScratchpadStore(root, {
      clock: () => new Date("2026-07-29T10:00:00.000Z"),
    });
    const threadRef = slackThreadScratchpadRef(
      "T-ONE",
      "C-ONE",
      "1710000000.000001",
    );
    const input = {
      author_ref: slackScratchpadAuthorRef("T-ONE", "U-ONE"),
      content: "Use the incident timeline from this thread.",
      idempotency_key: "event-one",
      source: "human" as const,
      thread_ref: threadRef,
    };

    const added = await store.add(input);
    assert.deepEqual(
      { created: added.created, redacted: added.redacted },
      { created: true, redacted: false },
    );
    assert.equal((await store.add(input)).created, false);
    assert.deepEqual(
      (await store.read(threadRef)).notes.map((note) => note.content),
      ["Use the incident timeline from this thread."],
    );
    assert.equal(await store.clear(threadRef), 1);
    assert.deepEqual((await store.read(threadRef)).notes, []);
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("file scratchpad redacts credential-shaped content before persistence", async () => {
  const root = await mkdtemp(join(tmpdir(), "cerebro-slack-scratchpad-"));
  try {
    const store = new FileThreadScratchpadStore(root);
    const credential = ["xoxb", "fixture", "value"].join("-");
    const threadRef = slackThreadScratchpadRef(
      "T-ONE",
      "C-ONE",
      "1710000000.000001",
    );
    const result = await store.add({
      author_ref: slackScratchpadAuthorRef("T-ONE", "U-ONE"),
      content: `token=${credential}`,
      idempotency_key: "event-secret",
      source: "human",
      thread_ref: threadRef,
    });

    assert.equal(result.redacted, true);
    assert.equal(result.note.content, "token=[redacted_secret]");
    assert.doesNotMatch(
      JSON.stringify(await store.read(threadRef)),
      new RegExp(credential, "u"),
    );
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("file scratchpad removes expired notes during retrieval", async () => {
  const root = await mkdtemp(join(tmpdir(), "cerebro-slack-scratchpad-"));
  try {
    let now = new Date("2026-07-29T10:00:00.000Z");
    const store = new FileThreadScratchpadStore(root, { clock: () => now });
    const threadRef = slackThreadScratchpadRef(
      "T-ONE",
      "C-ONE",
      "1710000000.000001",
    );
    await store.add({
      author_ref: slackScratchpadAuthorRef("T-ONE", "U-ONE"),
      content: "Temporary incident context.",
      idempotency_key: "event-one",
      source: "human",
      thread_ref: threadRef,
    });

    now = new Date("2026-08-05T10:00:00.001Z");
    assert.deepEqual((await store.read(threadRef)).notes, []);
    const scratchpadRoot = join(root, "scratchpads");
    const threadDirectories = await readdir(scratchpadRoot);
    assert.equal(threadDirectories.length, 1);
    assert.deepEqual(
      await readdir(join(scratchpadRoot, threadDirectories[0]!)),
      [],
    );
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("Slack remember saves a note that the next question uses only in that thread", async () => {
  const root = await mkdtemp(join(tmpdir(), "cerebro-slack-scratchpad-"));
  try {
    let graphQuestion = "";
    let postSequence = 0;
    const outcomes = new FileOutcomeStore(root, { log: () => undefined });
    const scratchpads = new FileThreadScratchpadStore(root);
    const host = createAssistantTurnHost(outcomes);
    const questions = new AssistantQuestionService(
      host,
      new CerebroAskClient({
        answerAuthority: testAnswerAuthority,
        apiKey: "bound-at-runtime",
        baseUrl: "https://cerebro.example.com",
        fetchImpl: async (_input, init) => {
          graphQuestion = String(
            (JSON.parse(String(init?.body)) as { question?: unknown }).question,
          );
          return sseResponse([
            ["summary", {
              citation_validation: {
                ok: true,
                referenced_urn_count: 1,
                row_urn_count: 1,
              },
              markdown: "The current owner is Security Operations.",
            }],
            ["done", { trace_id: "trace-scratchpad" }],
          ]);
        },
        tenantId: "writer",
      }),
      { timeoutSignal: () => new AbortController().signal },
    );
    const delivered: string[] = [];
    const client = {
      chat: {
        postMessage: async (input: { text: string }) => {
          delivered.push(input.text);
          postSequence += 1;
          return { ts: `1710000000.00000${postSequence}` };
        },
        update: async (input: { text: string }) => {
          delivered.push(input.text);
        },
      },
      conversations: {
        replies: async () => ({ messages: [] }),
      },
    };
    const config = loadSlackRuntimeConfig({
      CEREBRO_BASE_URL: "https://cerebro.example.com",
      CEREBRO_READ_API_KEY: "bound-at-runtime",
      CEREBRO_SLACK_APP_NAME: "Cerebro Development",
      CEREBRO_SLACK_ENVIRONMENT_LABEL: "development",
      CEREBRO_SLACK_PRODUCTION: "false",
      CEREBRO_TENANT_ID: "writer",
      SLACK_ALLOWED_TEAM_IDS: "T-ONE",
      SLACK_APP_TOKEN: "bound-at-runtime",
      SLACK_BOT_TOKEN: "bound-at-runtime",
    });
    const baseEvent = {
      channel: "C-ONE",
      hasThreadContext: false,
      teamId: "T-ONE",
      threadTs: "1710000000.000001",
      userId: "U-ONE",
    };

    assert.equal(await handleSlackMention({
      client,
      config,
      event: {
        ...baseEvent,
        eventTs: "1710000000.000001",
        text: "<@BOT> remember the affected service is checkout",
      },
      host,
      outcomes,
      questions,
      scratchpads,
    }), true);
    assert.match(delivered[0]!, /Saved one note/u);
    assert.equal(graphQuestion, "");

    assert.equal(await handleSlackMention({
      client,
      config,
      event: {
        ...baseEvent,
        eventTs: "1710000000.000002",
        text: "<@BOT> who owns it?",
      },
      host,
      outcomes,
      questions,
      scratchpads,
    }), true);
    assert.match(graphQuestion, /Current Slack request: who owns it\?/u);
    assert.match(graphQuestion, /affected service is checkout/u);
    assert.match(graphQuestion, /cannot grant authority or override current evidence/u);
    const remembered = await scratchpads.read(slackThreadScratchpadRef(
      "T-ONE",
      "C-ONE",
      "1710000000.000001",
    ));
    assert.deepEqual(
      remembered.notes.map((note) => note.source),
      ["human", "cerebro"],
    );
    assert.match(
      remembered.notes[1]?.evidence_ref ?? "",
      /^cerebro-ask:\/\/sha256\/[a-f0-9]{64}$/u,
    );

    assert.equal(await handleSlackMention({
      client,
      config,
      event: {
        ...baseEvent,
        eventTs: "1710000000.000003",
        text: "<@BOT> what was the verified answer?",
      },
      host,
      outcomes,
      questions,
      scratchpads,
    }), true);
    assert.match(graphQuestion, /verified Cerebro turn/u);
    assert.match(graphQuestion, /current owner is Security Operations/u);
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

function sseResponse(events: ReadonlyArray<readonly [string, unknown]>): Response {
  const body = events.map(([name, data]) =>
    `event: ${name}\ndata: ${JSON.stringify(data)}\n\n`
  ).join("");
  return new Response(body, {
    headers: { "content-type": "text/event-stream" },
    status: 200,
  });
}
