import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { CerebroAskClient } from "../src/runtime/cerebro-ask-client.js";
import { loadSlackRuntimeConfig } from "../src/runtime/config.js";
import {
  OffSlackTransportAdapter,
  parseSlackTransportEnvelope,
  runOffSlackTransportJsonl,
  type SlackTransportResult,
} from "../src/runtime/off-slack-transport.js";
import { FileOutcomeStore } from "../src/runtime/outcome-store.js";
import { FileSlackIngressQueue } from "../src/runtime/slack-ingress-store.js";
import { FileSlackThreadRouteStore } from "../src/runtime/slack-thread-route-store.js";
import {
  AssistantQuestionService,
  createAssistantTurnHost,
} from "../src/runtime/slack-runtime.js";

test("JSONL Slack envelopes exercise mention and thread-reply transport boundaries", async () => {
  const root = await mkdtemp(join(tmpdir(), "cerebro-off-slack-transport-"));
  try {
    const candidateRequests: Array<Record<string, unknown>> = [];
    const answers = [
      "The first current answer is available.",
      "The follow-up uses the prior Slack thread context.",
    ];
    const askClient = new CerebroAskClient({
      agentRuntimeUrl: "http://127.0.0.1:8091",
      answerAuthority: rejectingLegacyAuthority(),
      apiKey: "unused",
      baseUrl: "https://legacy.example.com",
      fetchImpl: async (_input, init) => {
        candidateRequests.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
        const markdown = answers[candidateRequests.length - 1];
        assert.ok(markdown, "the fixture must have one answer per Slack turn");
        return Response.json({
          evidence_refs: [],
          final_state: "answered",
          lane: "converse",
          markdown,
          outcome: "delivered",
          schema_version: "agent-turn-result/v1",
          tool_call_count: 0,
        });
      },
      tenantId: "writer",
    });
    const outcomes = new FileOutcomeStore(root, { log: () => undefined });
    const adapter = new OffSlackTransportAdapter({
      config: transportConfig(root),
      host: createAssistantTurnHost(outcomes),
      ingressQueue: new FileSlackIngressQueue(root),
      outcomes,
      questions: new AssistantQuestionService(createAssistantTurnHost(outcomes), askClient),
      threadRoutes: new FileSlackThreadRouteStore(root),
    });
    const lines = [
      JSON.stringify(slackEnvelope({
        event: {
          channel: "C00000001",
          text: "<@U00000009> What changed?",
          ts: "1785000000.000001",
          type: "app_mention",
          user: "U00000001",
        },
        eventId: "Ev00000001",
      })),
      JSON.stringify(slackEnvelope({
        event: {
          channel: "C00000001",
          text: "What follows from that?",
          thread_ts: "1785000000.000001",
          ts: "1785000000.000010",
          type: "message",
          user: "U00000001",
        },
        eventId: "Ev00000002",
      })),
    ];
    const output: string[] = [];

    await runOffSlackTransportJsonl(asLines(lines), adapter, (line) => {
      output.push(line);
    });

    assert.equal(output.length, 2);
    assert.ok(output.every((line) => line.endsWith("\n")));
    const results = output.map((line) => JSON.parse(line) as SlackTransportResult);
    assert.deepEqual(results.map((result) => result.schema_version), [
      "slack-transport-result/v1",
      "slack-transport-result/v1",
    ]);
    assert.deepEqual(results.map((result) => result.handled), [true, true]);
    assert.deepEqual(results.map((result) => result.operations.map((operation) => operation.method)), [
      ["chat.postMessage", "chat.update"],
      ["chat.postMessage", "chat.update"],
    ]);
    assert.equal(results[0]?.messages.length, 2);
    assert.equal(results[1]?.messages.length, 4);
    assert.equal(results[1]?.messages[0]?.type, "message");
    assert.equal(results[1]?.messages[0]?.user, "U00000001");
    assert.equal(results[1]?.messages[1]?.user, "U00000009");
    assert.match(results[1]?.messages[1]?.text ?? "", /first current answer/u);
    assert.equal(candidateRequests.length, 2);
    assert.equal(candidateRequests[0]?.message, "What changed?");
    assert.equal(candidateRequests[1]?.message, "What follows from that?");
    assert.ok(Array.isArray(candidateRequests[1]?.history));
    assert.match(JSON.stringify(candidateRequests[1]?.history), /first current answer/u);
    assert.doesNotMatch(JSON.stringify(candidateRequests), /off.slack|holdout|evaluation/iu);
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("transport replay reuses the metadata-bound Slack message", async () => {
  const root = await mkdtemp(join(tmpdir(), "cerebro-off-slack-replay-"));
  try {
    let candidateCalls = 0;
    let progressCalls = 0;
    const askClient = new CerebroAskClient({
      agentRuntimeUrl: "http://127.0.0.1:8091",
      answerAuthority: rejectingLegacyAuthority(),
      apiKey: "unused",
      baseUrl: "https://legacy.example.com",
      fetchImpl: async (url, init) => {
        if (String(url).includes("/v1/turns/progress")) {
          progressCalls += 1;
          return Response.json({
            latest_sequence: 0,
            request_id: "slack-request-progress",
            schema_version: "agent-turn-progress/v1",
            updates: [],
          });
        }
        assert.equal(init?.method, "POST");
        candidateCalls += 1;
        return Response.json({
          evidence_refs: [],
          final_state: "answered",
          lane: "converse",
          markdown: "One transport-stable answer.",
          outcome: "delivered",
          schema_version: "agent-turn-result/v1",
          tool_call_count: 0,
        });
      },
      tenantId: "writer",
    });
    const outcomes = new FileOutcomeStore(root, { log: () => undefined });
    const host = createAssistantTurnHost(outcomes);
    const adapter = new OffSlackTransportAdapter({
      config: transportConfig(root),
      host,
      ingressQueue: new FileSlackIngressQueue(root),
      outcomes,
      questions: new AssistantQuestionService(host, askClient),
      threadRoutes: new FileSlackThreadRouteStore(root),
    });
    const envelope = slackEnvelope({
      event: {
        channel: "C00000001",
        text: "<@U00000009> Give me the current state.",
        ts: "1785000010.000001",
        type: "app_mention",
        user: "U00000001",
      },
      eventId: "Ev00000003",
    });

    const first = await adapter.dispatch(envelope);
    const replay = await adapter.dispatch(envelope);

    assert.equal(first.attempt, 1);
    assert.equal(replay.attempt, 2);
    assert.equal(first.messages.length, 2);
    assert.equal(replay.messages.length, 2);
    assert.deepEqual(first.operations.map((operation) => operation.method), [
      "chat.postMessage",
      "chat.update",
    ]);
    assert.deepEqual(replay.operations.map((operation) => operation.method), ["chat.update"]);
    assert.equal(candidateCalls, 2);
    assert.equal(progressCalls, 1);
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("transport input accepts only Slack-shaped human events", () => {
  assert.throws(
    () => parseSlackTransportEnvelope(slackEnvelope({
      event: {
        channel: "C00000001",
        text: "What changed?",
        ts: "1785000020.000001",
        type: "app_mention",
        user: "U00000001",
      },
      eventId: "Ev00000004",
    })),
    /must mention the authorized bot user/u,
  );
  assert.throws(
    () => parseSlackTransportEnvelope({
      ...slackEnvelope({
        event: {
          channel: "C00000001",
          text: "Keep going.",
          thread_ts: "not-a-slack-timestamp",
          ts: "1785000020.000002",
          type: "message",
          user: "U00000001",
        },
        eventId: "Ev00000005",
      }),
    }),
    /thread timestamp is invalid/u,
  );
});

function transportConfig(root: string) {
  return loadSlackRuntimeConfig({
    CEREBRO_BASE_URL: "https://cerebro.example.com",
    CEREBRO_READ_API_KEY: "bound-at-runtime",
    CEREBRO_SLACK_AGENT_ENABLED: "true",
    CEREBRO_SLACK_AGENT_RUNTIME_TOKEN: "test-runtime-token-1234567890-abcdef",
    CEREBRO_SLACK_APP_NAME: "Cerebro Development",
    CEREBRO_SLACK_ENVIRONMENT_LABEL: "development",
    CEREBRO_SLACK_PRODUCTION: "false",
    CEREBRO_SLACK_RUNTIME_MEMORY_DIR: root,
    CEREBRO_TENANT_ID: "writer",
    SLACK_ALLOWED_TEAM_IDS: "T00000001",
    SLACK_APP_TOKEN: "bound-at-runtime",
    SLACK_BOT_TOKEN: "bound-at-runtime",
  });
}

function slackEnvelope(input: {
  event: Record<string, unknown>;
  eventId: string;
}): Record<string, unknown> {
  return {
    authorizations: [{ user_id: "U00000009" }],
    event: input.event,
    event_id: input.eventId,
    schema_version: "slack-event-envelope/v1",
    team_id: "T00000001",
    type: "event_callback",
  };
}

async function* asLines(lines: readonly string[]): AsyncIterable<string> {
  for (const line of lines) yield line;
}

function rejectingLegacyAuthority() {
  return {
    async authorizeQuestion() {
      throw new Error("The transport adapter must use the Rust agent boundary.");
    },
    async validate() {
      throw new Error("The transport adapter must use the Rust agent boundary.");
    },
  };
}
