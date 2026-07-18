import assert from "node:assert/strict";
import test from "node:test";
import { SlackDeliveryOutbox } from "../src/slack/delivery-outbox.js";
import {
  createSlackDeliveryRecord,
  DynamoSlackDeliveryOutboxStore,
  InMemorySlackDeliveryOutboxStore,
  slackDeliveryDueIndexName,
} from "../src/slack/delivery-outbox-store.js";
import { testConfig } from "./fixtures.js";

test("enqueue is deterministic and rejects an idempotency key with different content", async () => {
  const store = new InMemorySlackDeliveryOutboxStore();
  const now = new Date("2026-07-16T12:00:00.000Z");
  const outbox = new SlackDeliveryOutbox(testConfig(), { store, now: () => now, workerId: "worker-a" });
  const input = {
    idempotencyKey: "finding:f-123:owner-request",
    channelId: "CSEC",
    threadTs: "1784200000.000100",
    text: "Finding f-123 needs an owner. Reply in this thread with the owner or the next check.",
    receiptContext: { kind: "assistant_initiative", refId: "initiative-123" },
  };

  const first = await outbox.enqueue(input);
  const repeated = await outbox.enqueue(input);

  assert.equal(repeated.id, first.id);
  assert.equal(repeated.clientMessageId, first.clientMessageId);
  assert.deepEqual(repeated.receiptContext, input.receiptContext);
  assert.match(first.clientMessageId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  await assert.rejects(
    outbox.enqueue({ ...input, text: "This is different content." }),
    /idempotency key conflict/,
  );
});

test("worker persists the actual Slack timestamp after posting", async () => {
  const store = new InMemorySlackDeliveryOutboxStore();
  const now = new Date("2026-07-16T12:00:00.000Z");
  let postedHookTs: string | undefined;
  let statusWhenHookRan: string | undefined;
  const outbox = new SlackDeliveryOutbox(testConfig(), {
    store,
    now: () => now,
    workerId: "worker-a",
    beforeCompletePosted: async ({ delivery, postedTs }) => {
      postedHookTs = postedTs;
      statusWhenHookRan = (await store.get(delivery.id))?.status;
    },
  });
  const queued = await outbox.enqueue({
    idempotencyKey: "delivery:posted",
    channelId: "CSEC",
    text: "Deployment evidence is ready for review.",
  });
  const postedMessages: Array<{ client_msg_id: string; unfurl_links: boolean }> = [];

  const results = await outbox.tick({
    chat: {
      postMessage: async (message) => {
        postedMessages.push(message);
        return { ts: "1784200001.000200" };
      },
    },
  });

  assert.deepEqual(results, [{
    deliveryId: queued.id,
    status: "posted",
    attempts: 1,
    postedTs: "1784200001.000200",
  }]);
  assert.ok(postedMessages[0]);
  assert.equal(postedMessages[0].client_msg_id, queued.clientMessageId);
  assert.equal(postedMessages[0].unfurl_links, false);
  assert.equal((await store.get(queued.id))?.status, "posted");
  assert.equal((await store.get(queued.id))?.postedTs, "1784200001.000200");
  assert.equal(postedHookTs, "1784200001.000200");
  assert.equal(statusWhenHookRan, "leased");
});

test("receipt hook failure retries the binding without posting to Slack again", async () => {
  const store = new InMemorySlackDeliveryOutboxStore();
  let now = new Date("2026-07-16T12:00:00.000Z");
  let hookAttempts = 0;
  const outbox = new SlackDeliveryOutbox(testConfig(), {
    store,
    now: () => now,
    workerId: "worker-a",
    retryBaseMs: 100,
    maxRetryMs: 100,
    maxAttempts: 2,
    beforeCompletePosted: async () => {
      hookAttempts += 1;
      if (hookAttempts === 1) throw new Error("initiative binding unavailable");
    },
  });
  const queued = await outbox.enqueue({
    idempotencyKey: "delivery:receipt-hook-retry",
    channelId: "CSEC",
    text: "Cerebro needs one owner decision to continue this investigation.",
  });
  const clientMessageIds: string[] = [];
  const client = {
    chat: {
      postMessage: async (message: { client_msg_id: string }) => {
        clientMessageIds.push(message.client_msg_id);
        return { ts: "1784200001.000250" };
      },
    },
  };

  assert.equal((await outbox.tick(client))[0]?.status, "retry");
  assert.equal((await store.get(queued.id))?.status, "retry");
  assert.equal((await store.get(queued.id))?.postedTs, "1784200001.000250");

  now = new Date(now.getTime() + 100);
  assert.equal((await outbox.tick(client))[0]?.status, "posted");
  assert.equal((await store.get(queued.id))?.postedTs, "1784200001.000250");
  assert.equal(hookAttempts, 2);
  assert.deepEqual(clientMessageIds, [queued.clientMessageId]);
});

test("Dynamo store uses the sparse due index and removes due attributes at completion", async () => {
  const now = new Date("2026-07-16T12:00:00.000Z");
  const record = createSlackDeliveryRecord("writer", {
    idempotencyKey: "delivery:dynamo-shape",
    channelId: "CSEC",
    text: "Cerebro has a concrete next action.",
    receiptContext: { kind: "assistant_initiative", refId: "initiative-dynamo" },
  }, now);
  const dynamo = new RecordingDynamo(record);
  const store = new DynamoSlackDeliveryOutboxStore("learning", "writer", { dynamo });

  await store.enqueue(record);
  await store.listDue(now.toISOString(), 3);
  await store.tryLease(record.id, {
    workerId: "worker-a",
    now: now.toISOString(),
    leaseExpiresAt: "2026-07-16T12:01:00.000Z",
  });
  await store.markSlackAccepted(record.id, "worker-a", now.toISOString(), "1784200003.000400");
  await store.completePosted(record.id, "worker-a", now.toISOString());

  const put = dynamo.commands.find((command) => command.name === "PutCommand")!.input;
  assert.equal(put.Item.delivery_due_scope, "tenant#writer#slack-delivery-outbox#due");
  assert.equal(put.Item.receiptContext.refId, "initiative-dynamo");

  const query = dynamo.commands.find((command) => command.name === "QueryCommand")!.input;
  assert.equal(query.IndexName, slackDeliveryDueIndexName);
  assert.equal(query.Limit, 3);
  assert.match(query.KeyConditionExpression, /delivery_due_at <= :dueAt/);

  const updates = dynamo.commands.filter((command) => command.name === "UpdateCommand");
  assert.match(updates[0]!.input.UpdateExpression, /delivery_due_at = :dueAt/);
  assert.match(updates[1]!.input.ConditionExpression, /attribute_not_exists\(postedTs\)/);
  assert.match(updates[2]!.input.UpdateExpression, /REMOVE .*delivery_due_scope, delivery_due_at/);
});

test("stop waits for an active poll and prevents it from claiming new work", async () => {
  const now = new Date("2026-07-16T12:00:00.000Z");
  const store = new BlockingListStore();
  const outbox = new SlackDeliveryOutbox(testConfig(), { store, now: () => now, workerId: "worker-a" });
  let posts = 0;
  const tick = outbox.tick({
    chat: {
      postMessage: async () => {
        posts += 1;
        return { ts: "1784200004.000500" };
      },
    },
  });
  await store.started;

  const stopping = outbox.stop();
  store.release([]);
  await stopping;

  assert.deepEqual(await tick, []);
  assert.equal(posts, 0);
});

test("expired lease is reclaimed by a second worker", async () => {
  const store = new InMemorySlackDeliveryOutboxStore();
  let now = new Date("2026-07-16T12:00:00.000Z");
  const workerA = new SlackDeliveryOutbox(testConfig(), { store, now: () => now, workerId: "ecs-worker-a", leaseMs: 1_000 });
  const workerB = new SlackDeliveryOutbox(testConfig(), { store, now: () => now, workerId: "ecs-worker-b", leaseMs: 1_000 });
  const queued = await workerA.enqueue({
    idempotencyKey: "delivery:lease-reclaim",
    channelId: "CSEC",
    text: "An investigation checkpoint is waiting for a teammate response.",
  });
  const leased = await store.tryLease(queued.id, {
    workerId: "ecs-worker-a",
    now: now.toISOString(),
    leaseExpiresAt: new Date(now.getTime() + 1_000).toISOString(),
  });
  assert.equal(leased?.status, "leased");

  let posts = 0;
  const client = {
    chat: {
      postMessage: async () => {
        posts += 1;
        return { ts: "1784200002.000300" };
      },
    },
  };
  assert.deepEqual(await workerB.tick(client), []);
  assert.equal(posts, 0);

  now = new Date(now.getTime() + 1_001);
  const results = await workerB.tick(client);
  assert.equal(results[0]?.status, "posted");
  assert.equal(posts, 1);
  assert.equal((await store.get(queued.id))?.attempts, 2);
  assert.equal((await store.get(queued.id))?.postedTs, "1784200002.000300");
});

test("post failures keep one client message id and become terminal after bounded retries", async () => {
  const store = new InMemorySlackDeliveryOutboxStore();
  let now = new Date("2026-07-16T12:00:00.000Z");
  const outbox = new SlackDeliveryOutbox(testConfig(), {
    store,
    now: () => now,
    workerId: "worker-a",
    retryBaseMs: 100,
    maxRetryMs: 100,
    maxAttempts: 2,
  });
  const queued = await outbox.enqueue({
    idempotencyKey: "delivery:failure",
    channelId: "CSEC",
    text: "The release check needs another attempt.",
  });
  const clientMessageIds: string[] = [];
  const client = {
    chat: {
      postMessage: async (message: { client_msg_id: string }) => {
        clientMessageIds.push(message.client_msg_id);
        throw new Error("Slack unavailable");
      },
    },
  };

  assert.equal((await outbox.tick(client))[0]?.status, "retry");
  assert.equal((await store.get(queued.id))?.status, "retry");

  now = new Date(now.getTime() + 100);
  assert.equal((await outbox.tick(client))[0]?.status, "failed");
  const failed = await store.get(queued.id);
  assert.equal(failed?.status, "failed");
  assert.equal(failed?.attempts, 2);
  assert.equal(failed?.nextAttemptAt, undefined);
  assert.deepEqual(clientMessageIds, [queued.clientMessageId, queued.clientMessageId]);
});

class RecordingDynamo {
  readonly commands: Array<{ name: string; input: any }> = [];

  constructor(private readonly record: ReturnType<typeof createSlackDeliveryRecord>) {}

  async send(command: any): Promise<unknown> {
    this.commands.push({ name: command.constructor.name, input: command.input });
    if (command.constructor.name === "PutCommand") return {};
    if (command.constructor.name === "QueryCommand") return { Items: [this.record] };
    if (command.constructor.name === "UpdateCommand") {
      return {
        Attributes: {
          ...this.record,
          status: "leased",
          leaseOwner: "worker-a",
          leaseExpiresAt: "2026-07-16T12:01:00.000Z",
          postedAt: "2026-07-16T12:00:00.000Z",
          postedTs: "1784200003.000400",
        },
      };
    }
    throw new Error(`Unexpected command ${command.constructor.name}`);
  }
}

class BlockingListStore extends InMemorySlackDeliveryOutboxStore {
  private resolveStarted!: () => void;
  private resolveList!: (records: Awaited<ReturnType<InMemorySlackDeliveryOutboxStore["listDue"]>>) => void;
  readonly started = new Promise<void>((resolve) => { this.resolveStarted = resolve; });
  private readonly result = new Promise<Awaited<ReturnType<InMemorySlackDeliveryOutboxStore["listDue"]>>>((resolve) => {
    this.resolveList = resolve;
  });

  override async listDue(): Promise<Awaited<ReturnType<InMemorySlackDeliveryOutboxStore["listDue"]>>> {
    this.resolveStarted();
    return this.result;
  }

  release(records: Awaited<ReturnType<InMemorySlackDeliveryOutboxStore["listDue"]>>): void {
    this.resolveList(records);
  }
}
