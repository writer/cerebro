import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, utimes, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { CerebroAskClient, CerebroAskError } from "../src/runtime/cerebro-ask-client.js";
import { loadSlackRuntimeConfig, SlackRuntimeConfigError } from "../src/runtime/config.js";
import { FileOutcomeStore } from "../src/runtime/outcome-store.js";
import {
  AssistantQuestionService,
  closeHealthServer,
  contextualQuestion,
  createAssistantTurnHost,
  environmentHomeView,
  formatEnvironmentMessage,
  formatSlackThreadContext,
  handleSlackMention,
  readSlackThreadContext,
  slackDeliveryReferences,
} from "../src/runtime/slack-runtime.js";

test("health server cleanup is safe before listen succeeds", async () => {
  const server = createServer();
  await closeHealthServer(server);
  assert.equal(server.listening, false);
});

test("runtime config accepts environment-held bindings and an allowlisted workspace", () => {
  const config = loadSlackRuntimeConfig({
    CEREBRO_BASE_URL: "https://cerebro.example.com/",
    CEREBRO_READ_API_KEY: "bound-at-runtime",
    CEREBRO_SLACK_APP_NAME: "Cerebro Development",
    CEREBRO_SLACK_ENVIRONMENT_LABEL: "development",
    CEREBRO_SLACK_PRODUCTION: "false",
    CEREBRO_TENANT_ID: "tenant-one",
    PORT: "3100",
    SLACK_ALLOWED_TEAM_IDS: "T-ONE,T-TWO",
    SLACK_APP_TOKEN: "bound-at-runtime",
    SLACK_BOT_TOKEN: "bound-at-runtime",
  });

  assert.equal(config.cerebroBaseUrl, "https://cerebro.example.com");
  assert.equal(config.environmentLabel, "development");
  assert.equal(config.production, false);
  assert.equal(config.port, 3100);
  assert.equal(config.lifecycleNoticesEnabled, false);
  assert.deepEqual([...config.allowedTeamIds], ["T-ONE", "T-TWO"]);
});

test("runtime config requires durable destinations for enabled lifecycle notices", () => {
  const base = {
    CEREBRO_BASE_URL: "https://cerebro.example.com",
    CEREBRO_READ_API_KEY: "bound-at-runtime",
    CEREBRO_SLACK_APP_NAME: "Cerebro Development",
    CEREBRO_SLACK_ENVIRONMENT_LABEL: "development",
    CEREBRO_SLACK_PRODUCTION: "false",
    CEREBRO_TENANT_ID: "tenant-one",
    SLACK_ALLOWED_TEAM_IDS: "T-ONE",
    SLACK_APP_TOKEN: "bound-at-runtime",
    SLACK_BOT_TOKEN: "bound-at-runtime",
    SLACK_LIFECYCLE_NOTICES_ENABLED: "true",
  };
  assert.throws(() => loadSlackRuntimeConfig(base), SlackRuntimeConfigError);
  const config = loadSlackRuntimeConfig({
    ...base,
    SECURITY_LEARNING_TABLE_NAME: "companion-learning",
    SLACK_LIFECYCLE_CHANNEL_IDS: "C-ONE,C-TWO",
  });
  assert.equal(config.learningTableName, "companion-learning");
  assert.deepEqual([...config.lifecycleChannelIds], ["C-ONE", "C-TWO"]);
});

test("runtime config rejects a missing workspace allowlist", () => {
  assert.throws(() => loadSlackRuntimeConfig({
    CEREBRO_BASE_URL: "https://cerebro.example.com",
    CEREBRO_READ_API_KEY: "bound-at-runtime",
    CEREBRO_SLACK_APP_NAME: "Cerebro Development",
    CEREBRO_SLACK_ENVIRONMENT_LABEL: "development",
    CEREBRO_SLACK_PRODUCTION: "false",
    CEREBRO_TENANT_ID: "tenant-one",
    SLACK_ALLOWED_TEAM_IDS: "",
    SLACK_APP_TOKEN: "bound-at-runtime",
    SLACK_BOT_TOKEN: "bound-at-runtime",
  }), SlackRuntimeConfigError);
});

test("runtime config rejects an invalid production binding", () => {
  assert.throws(() => loadSlackRuntimeConfig({
    CEREBRO_BASE_URL: "https://cerebro.example.com",
    CEREBRO_READ_API_KEY: "bound-at-runtime",
    CEREBRO_SLACK_APP_NAME: "Cerebro Development",
    CEREBRO_SLACK_ENVIRONMENT_LABEL: "development",
    CEREBRO_SLACK_PRODUCTION: "sometimes",
    CEREBRO_TENANT_ID: "tenant-one",
    SLACK_ALLOWED_TEAM_IDS: "T-ONE",
    SLACK_APP_TOKEN: "bound-at-runtime",
    SLACK_BOT_TOKEN: "bound-at-runtime",
  }), SlackRuntimeConfigError);
});

test("non-production messages and App Home keep the configured environment visible", () => {
  const development = {
    appName: "Cerebro Development",
    environmentLabel: "development",
    production: false,
  };
  const production = {
    appName: "Cerebro",
    environmentLabel: "production",
    production: true,
  };
  const message = formatEnvironmentMessage(development, "One current finding is open.");
  assert.match(message, /^🧪 \*Cerebro Development · development\*/u);
  assert.match(message, /One current finding is open/u);
  assert.equal(formatEnvironmentMessage(production, "Production answer."), "Production answer.");
  assert.ok(Array.from(formatEnvironmentMessage(development, "x".repeat(4_000))).length <= 3_500);

  const home = environmentHomeView(development);
  assert.equal(home.type, "home");
  assert.match(JSON.stringify(home.blocks), /Cerebro Development/u);
  assert.match(JSON.stringify(home.blocks), /development/u);
  assert.match(JSON.stringify(home.blocks), /Production is separate/u);
});

test("question service preflights one governed graph lookup and returns its verified summary", async () => {
  const root = await mkdtemp(join(tmpdir(), "cerebro-slack-runtime-"));
  try {
    let request: Request | undefined;
    let timeoutMs: number | undefined;
    const askClient = new CerebroAskClient({
      apiKey: "bound-at-runtime",
      baseUrl: "https://cerebro.example.com",
      fetchImpl: async (input, init) => {
        request = new Request(input, init);
        return sseResponse([
          ["summary", {
            citation_validation: { ok: true },
            markdown: "One current finding is open.",
          }],
          ["done", { trace_id: "trace-one" }],
        ]);
      },
      tenantId: "writer",
    });
    const clockValues = [
      new Date("2026-07-18T10:00:00.000Z"),
      new Date("2026-07-18T10:00:00.100Z"),
      new Date("2026-07-18T10:00:01.000Z"),
    ];
    const store = new FileOutcomeStore(root);
    const service = new AssistantQuestionService(
      createAssistantTurnHost(store),
      askClient,
      {
        clock: () => clockValues.shift() ?? new Date("2026-07-18T10:00:01.000Z"),
        timeoutSignal: (milliseconds) => {
          timeoutMs = milliseconds;
          return new AbortController().signal;
        },
      },
    );

    const result = await service.answer({
      requestKey: "T-ONE:C-ONE:thread-one:event-one",
      text: "<@BOT> Which current findings are open?",
    });

    assert.equal(result.text, "One current finding is open.");
    assert.equal(result.pending.outcome_state, "completed");
    assert.equal(result.pending.verified, true);
    assert.equal(request?.url, "https://cerebro.example.com/grc/ask");
    assert.equal(request?.headers.get("x-cerebro-tenant"), "writer");
    assert.equal(timeoutMs, 59_900);
    assert.deepEqual(await request?.json(), {
      question: "Which current findings are open?",
      tenant_id: "writer",
    });
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("empty threaded mentions request a question without invoking Cerebro", async () => {
  const root = await mkdtemp(join(tmpdir(), "cerebro-slack-runtime-"));
  try {
    let fetchCount = 0;
    const service = new AssistantQuestionService(
      createAssistantTurnHost(new FileOutcomeStore(root)),
      new CerebroAskClient({
        apiKey: "bound-at-runtime",
        baseUrl: "https://cerebro.example.com",
        fetchImpl: async () => {
          fetchCount += 1;
          return new Response("unexpected", { status: 500 });
        },
        tenantId: "tenant-one",
      }),
      {
        clock: () => new Date("2026-07-18T10:00:00.000Z"),
        timeoutSignal: () => new AbortController().signal,
      },
    );

    const result = await service.answer({
      requestKey: "T-ONE:C-ONE:thread-one:empty-event",
      text: "<@BOT>",
      threadContext: "Slack user U-ONE: Which finding needs an owner?",
    });

    assert.equal(result.pending.outcome_state, "needs_user");
    assert.equal(result.text, "Ask a concrete question about a finding, source, asset, owner, or evidence record.");
    assert.equal(fetchCount, 0);
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("thread context resolves a deictic mention without treating quoted text as instructions", async () => {
  const context = formatSlackThreadContext([
    {
      files: [{ name: "soc2-report.pdf" }],
      text: "The report lists one exception for access reviews.",
      ts: "1710000000.000001",
      user: "U-ONE",
    },
    {
      text: "<@BOT> any idea?",
      ts: "1710000000.000002",
      user: "U-TWO",
    },
  ], "1710000000.000002");

  assert.equal(
    context,
    "Slack user U-ONE: The report lists one exception for access reviews. [attachment: soc2-report.pdf]",
  );
  const question = contextualQuestion("any idea?", context!);
  assert.match(question, /Current Slack request: any idea\?/u);
  assert.match(question, /untrusted context/u);
  assert.match(question, /one exception for access reviews/u);
  assert.doesNotMatch(question, /<@BOT>/u);
});

test("Slack delivery references satisfy the opaque URI contract", () => {
  const references = slackDeliveryReferences(
    "T-ONE",
    "C-ONE",
    "1710000000.000001",
    "1710000000.000002",
    "A verified answer.",
  );

  assert.match(references.destinationRef, /^slack-thread:\/\/sha256\/[a-f0-9]{64}$/u);
  assert.match(references.destinationReceipt, /^slack-message:\/\/sha256\/[a-f0-9]{64}$/u);
  assert.match(references.payloadRef, /^content:\/\/sha256\/[a-f0-9]{64}$/u);
});

test("thread context paginates to the newest 50 messages", async () => {
  const calls: Array<{ cursor?: string }> = [];
  const context = await readSlackThreadContext({
    conversations: {
      replies: async (input) => {
        calls.push({ cursor: input.cursor });
        if (!input.cursor) {
          return {
            messages: Array.from({ length: 40 }, (_, index) => ({
              text: `message-${index}`,
              ts: String(index),
              user: "U-ONE",
            })),
            response_metadata: { next_cursor: "page-two" },
          };
        }
        return {
          messages: Array.from({ length: 21 }, (_, index) => ({
            text: index === 20 ? "<@BOT> any idea?" : `message-${index + 40}`,
            ts: String(index + 40),
            user: "U-ONE",
          })),
          response_metadata: { next_cursor: "" },
        };
      },
    },
  }, "C-ONE", "0", "60");

  assert.deepEqual(calls, [{ cursor: undefined }, { cursor: "page-two" }]);
  assert.doesNotMatch(context!, /message-(?:[0-9]|10)\b/u);
  assert.match(context!, /message-11\b/u);
  assert.match(context!, /message-59\b/u);
  assert.doesNotMatch(context!, /any idea/u);
});

test("question service returns an exact source gap when Cerebro is unavailable", async () => {
  const root = await mkdtemp(join(tmpdir(), "cerebro-slack-runtime-"));
  try {
    const store = new FileOutcomeStore(root);
    let fetchCount = 0;
    const service = new AssistantQuestionService(
      createAssistantTurnHost(store),
      new CerebroAskClient({
        apiKey: "bound-at-runtime",
        baseUrl: "https://cerebro.example.com",
        fetchImpl: async () => {
          fetchCount += 1;
          return new Response("unavailable", { status: 503 });
        },
        tenantId: "writer",
      }),
      {
        clock: () => new Date("2026-07-18T10:00:00.000Z"),
        timeoutSignal: () => new AbortController().signal,
      },
    );

    const result = await service.answer({ requestKey: "request-two", text: "What changed?" });

    assert.equal(result.pending.outcome_state, "blocked");
    assert.match(result.text, /Cerebro: current graph evidence \(unavailable\)/);
    assert.match(result.text, /Retry after the Cerebro source health check passes/);
    const retry = await service.answer({ requestKey: "request-three", text: "What changed now?" });
    assert.match(retry.text, /approved graph lookup \(unavailable\)/);
    assert.equal(fetchCount, 1);
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("Cerebro ask cancels and unlocks an unfinished SSE response after an error event", async () => {
  let cancelCount = 0;
  const body = new ReadableStream<Uint8Array>({
    cancel() {
      cancelCount += 1;
    },
    start(controller) {
      controller.enqueue(new TextEncoder().encode(
        'event: error\ndata: {"message":"source failed"}\n\n',
      ));
    },
  });
  const client = new CerebroAskClient({
    apiKey: "bound-at-runtime",
    baseUrl: "https://cerebro.example.com",
    fetchImpl: async () => new Response(body, {
      headers: { "content-type": "text/event-stream" },
      status: 200,
    }),
    tenantId: "writer",
  });

  await assert.rejects(
    client.ask("What changed?", new AbortController().signal),
    (error: unknown) => error instanceof CerebroAskError
      && error.sourceState === "unavailable"
      && error.message === "source failed",
  );
  assert.equal(cancelCount, 1);
  const reader = body.getReader();
  reader.releaseLock();
});

test("Cerebro ask returns after done without waiting for the SSE response to close", async () => {
  let cancelCount = 0;
  const body = new ReadableStream<Uint8Array>({
    cancel() {
      cancelCount += 1;
    },
    start(controller) {
      controller.enqueue(new TextEncoder().encode(
        'event: summary\ndata: {"citation_validation":{"ok":true},"markdown":"Current evidence is verified."}\n\n'
          + 'event: done\ndata: {"trace_id":"trace-complete"}\n\n',
      ));
    },
  });
  const client = new CerebroAskClient({
    apiKey: "bound-at-runtime",
    baseUrl: "https://cerebro.example.com",
    fetchImpl: async () => new Response(body, {
      headers: { "content-type": "text/event-stream" },
      status: 200,
    }),
    tenantId: "writer",
  });

  const result = await client.ask("What changed?", new AbortController().signal);

  assert.deepEqual(result, {
    citationValidationPassed: true,
    markdown: "Current evidence is verified.",
    traceId: "trace-complete",
  });
  assert.equal(cancelCount, 1);
  const reader = body.getReader();
  reader.releaseLock();
});

test("Cerebro ask ignores an error event sent after done", async () => {
  let cancelCount = 0;
  const body = new ReadableStream<Uint8Array>({
    cancel() {
      cancelCount += 1;
    },
    start(controller) {
      controller.enqueue(new TextEncoder().encode(
        'event: summary\ndata: {"citation_validation":{"ok":true},"markdown":"Current evidence is verified."}\n\n'
          + 'event: done\ndata: {"trace_id":"trace-complete"}\n\n'
          + 'event: error\ndata: {"message":"post-completion cleanup failed"}\n\n',
      ));
    },
  });
  const client = new CerebroAskClient({
    apiKey: "bound-at-runtime",
    baseUrl: "https://cerebro.example.com",
    fetchImpl: async () => new Response(body, {
      headers: { "content-type": "text/event-stream" },
      status: 200,
    }),
    tenantId: "writer",
  });

  const result = await client.ask("What changed?", new AbortController().signal);

  assert.deepEqual(result, {
    citationValidationPassed: true,
    markdown: "Current evidence is verified.",
    traceId: "trace-complete",
  });
  assert.equal(cancelCount, 1);
  const reader = body.getReader();
  reader.releaseLock();
});

test("Cerebro ask classifies a mid-stream deadline as timed out", async () => {
  const controller = new AbortController();
  const body = new ReadableStream<Uint8Array>({
    async pull(streamController) {
      if (!controller.signal.aborted) {
        await new Promise<void>((resolve) => {
          controller.signal.addEventListener("abort", () => resolve(), { once: true });
        });
      }
      streamController.error(controller.signal.reason);
    },
  });
  const client = new CerebroAskClient({
    apiKey: "bound-at-runtime",
    baseUrl: "https://cerebro.example.com",
    fetchImpl: async () => new Response(body, {
      headers: { "content-type": "text/event-stream" },
      status: 200,
    }),
    tenantId: "writer",
  });

  const result = client.ask("What changed?", controller.signal);
  controller.abort(new DOMException("deadline", "TimeoutError"));
  await assert.rejects(
    result,
    (error: unknown) => error instanceof CerebroAskError && error.sourceState === "timed_out",
  );
  const reader = body.getReader();
  reader.releaseLock();
});

test("Cerebro ask rejects a summary whose citations did not validate", async () => {
  const client = new CerebroAskClient({
    apiKey: "bound-at-runtime",
    baseUrl: "https://cerebro.example.com",
    fetchImpl: async () => sseResponse([
      ["summary", {
        citation_validation: { ok: false },
        markdown: "No current findings are open.",
      }],
      ["done", { trace_id: "trace-unverified" }],
    ]),
    tenantId: "writer",
  });

  await assert.rejects(
    client.ask("Are we clear?", new AbortController().signal),
    (error: unknown) => error instanceof CerebroAskError
      && error.sourceState === "unavailable"
      && /without validated citations/u.test(error.message),
  );
});

test("question service gives a bounded recovery action after a source timeout", async () => {
  const root = await mkdtemp(join(tmpdir(), "cerebro-slack-runtime-"));
  try {
    const controller = new AbortController();
    controller.abort(new DOMException("deadline", "TimeoutError"));
    const service = new AssistantQuestionService(
      createAssistantTurnHost(new FileOutcomeStore(root)),
      new CerebroAskClient({
        apiKey: "bound-at-runtime",
        baseUrl: "https://cerebro.example.com",
        fetchImpl: async (_input, init) => {
          assert.equal(init?.signal?.aborted, true);
          throw init?.signal?.reason;
        },
        tenantId: "writer",
      }),
      {
        clock: () => new Date("2026-07-18T10:00:00.000Z"),
        timeoutSignal: () => controller.signal,
      },
    );

    const result = await service.answer({ requestKey: "request-timeout", text: "What changed?" });
    assert.equal(result.pending.outcome_state, "blocked");
    assert.match(result.text, /current graph evidence \(timed out\)/u);
    assert.match(result.text, /one asset, identity, finding, or source/u);
    assert.doesNotMatch(result.text, /all clear|nothing urgent/iu);
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("failed claimed mentions persist a blocked outcome before retries are suppressed", async () => {
  const root = await mkdtemp(join(tmpdir(), "cerebro-slack-runtime-"));
  try {
    const store = new FileOutcomeStore(root, { log: () => undefined });
    const host = createAssistantTurnHost(store);
    const questions = new AssistantQuestionService(
      host,
      new CerebroAskClient({
        apiKey: "bound-at-runtime",
        baseUrl: "https://cerebro.example.com",
        fetchImpl: async () => sseResponse([]),
        tenantId: "writer",
      }),
    );
    const event = {
      channel: "C-ONE",
      eventTs: "1710000000.000001",
      hasThreadContext: false,
      teamId: "T-ONE",
      text: "<@BOT> What changed?",
      threadTs: "1710000000.000001",
      userId: "U-ONE",
    };
    const client = {
      chat: {
        postMessage: async () => {
          throw new Error("Slack unavailable");
        },
        update: async () => undefined,
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

    await assert.rejects(
      handleSlackMention({ client, config, event, host, outcomes: store, questions }),
      /Slack unavailable/,
    );
    assert.equal(
      await handleSlackMention({ client, config, event, host, outcomes: store, questions }),
      false,
    );
    const pendingFiles = await readdir(join(root, "pending"));
    assert.equal(pendingFiles.length, 1);
    const pending = JSON.parse(await readFile(join(root, "pending", pendingFiles[0]!), "utf8"));
    assert.equal(pending.outcome_state, "blocked");
    assert.equal(pending.verified, false);
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("outcome store applies negative feedback before the durable 24-hour assessment", async () => {
  const root = await mkdtemp(join(tmpdir(), "cerebro-slack-runtime-"));
  const telemetry: unknown[] = [];
  try {
    const store = new FileOutcomeStore(root, {
      clock: () => new Date("2026-07-19T10:00:01.000Z"),
      log: (event) => telemetry.push(event),
    });
    await store.initialize();
    assert.equal(await store.claimRequest("slack-event-one"), true);
    assert.equal(await store.claimRequest("slack-event-one"), false);
    await store.recordPending({
      delivered_message_ts: "1710000000.000001",
      execution_lane: "lookup",
      latency_budget_ms: 30_000,
      negative_feedback_count: 0,
      opened_at: "2026-07-18T10:00:00.000Z",
      outcome_state: "completed",
      request_id: "request-three",
      schema_version: "assistant-turn-pending-outcome/v1",
      user_correction_count: 0,
      useful_answer_at: "2026-07-18T10:00:10.000Z",
      verified: true,
    });
    assert.equal(await store.recordNegativeFeedback("1710000000.000001"), true);

    assert.equal(await store.assessDue(createAssistantTurnHost(store)), 1);
    assert.equal(await store.assessDue(createAssistantTurnHost(store)), 0);
    assert.equal(telemetry.length, 1);
    assert.match(JSON.stringify(telemetry), /eligible_failure/);
    const assessmentFiles = await readdir(join(root, "assessments"));
    assert.equal(assessmentFiles.length, 1);
    const assessment = JSON.parse(await readFile(join(root, "assessments", assessmentFiles[0]!), "utf8"));
    assert.equal(assessment.negative_feedback_count, 1);
    assert.equal(assessment.verified_outcome_within_slo, false);
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("outcome maintenance removes expired admission and telemetry receipts", async () => {
  const root = await mkdtemp(join(tmpdir(), "cerebro-slack-runtime-"));
  try {
    const now = new Date("2026-07-19T10:00:00.000Z");
    const store = new FileOutcomeStore(root, {
      clock: () => now,
      log: () => undefined,
    });
    await store.initialize();
    const admission = join(root, "admissions", "expired.json");
    const telemetry = join(root, "telemetry", "expired.json");
    await writeFile(admission, "claimed\n");
    await writeFile(telemetry, "{}\n");
    const old = new Date("2026-07-01T00:00:00.000Z");
    await Promise.all([utimes(admission, old, old), utimes(telemetry, old, old)]);

    assert.equal(await store.assessDue(createAssistantTurnHost(store)), 0);
    assert.deepEqual(await readdir(join(root, "admissions")), []);
    assert.deepEqual(await readdir(join(root, "telemetry")), []);
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
