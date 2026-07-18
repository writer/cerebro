import assert from "node:assert/strict";
import test from "node:test";
import { DynamoSlackQuestionWorkStore, SlackQuestionWorkScheduler, SqsSlackQuestionWorkQueue, slackQuestionPublisherBackoffMs, type SlackQuestionClaimResult, type SlackQuestionWorkDelivery, type SlackQuestionWorkQueue, type SlackQuestionWorkRunner, type SlackQuestionWorkStore } from "../src/work/slack-question-work.js";
import { createSlackQuestionWorkItems, slackQuestionWorkOutboxFromItem, type SlackQuestionTaskEnvelope, type SlackQuestionWorkOutboxRecord, type SlackQuestionWorkRecord } from "../src/work/slack-question-work-model.js";
import type { SlackQuestionWorkInput } from "../src/work/companion-work-loop.js";
import { testConfig } from "./fixtures.js";

const NOW = "2026-07-16T12:00:00.000Z";

test("Slack question work creates state and outbox records with a bounded dispatch delay", () => {
  const created = workItems();
  assert.equal(created.record.status, "queued");
  assert.equal(created.record.revision, 1);
  assert.equal(created.record.availableAt, "2026-07-16T12:00:02.000Z");
  assert.equal(created.state.recordType, "slack_question_work");
  assert.equal(created.outbox.recordType, "slack_question_work_outbox");
  assert.match(String(created.outbox.slack_work_scope), /tenant#writer#slack-question-work/);
  assert.match(String(created.outbox.slack_work_available_at), /^2026-07-16T12:00:02\.000Z#/);
  assert.equal(Number(created.state.expires_at) - Date.parse(NOW) / 1_000, 7 * 86_400);
});

test("Slack question publisher claims the outbox before FIFO publication and records the receipt", async () => {
  const { outbox } = parsedWorkItems();
  const store = new FakeStore([outbox]);
  const queue = new FakeQueue();
  const scheduler = createScheduler(store, queue, new FakeRunner());

  assert.equal(await scheduler.publishOnce(), 1);
  assert.equal(store.publicationClaims.length, 1);
  assert.deepEqual(queue.sent, [outbox.task]);
  assert.equal(store.published[0]?.messageId, "message-1");
});

test("Slack question publisher uses bounded exponential backoff for control-plane failures", () => {
  assert.deepEqual(
    Array.from({ length: 8 }, (_, index) => slackQuestionPublisherBackoffMs(index + 1, 1_000)),
    [1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000],
  );
  assert.equal(slackQuestionPublisherBackoffMs(1, 250), 1_000);
});

test("Slack question consumer completes and acknowledges recovered work", async () => {
  const { record, outbox } = parsedWorkItems();
  const store = new FakeStore([], { reason: "claimed", record });
  const queue = new FakeQueue(delivery(outbox.task, 2));
  const runner = new FakeRunner({ completed: true });
  const scheduler = createScheduler(store, queue, runner);

  assert.equal(await scheduler.consumeOnce(), true);
  assert.equal(runner.records[0]?.workId, record.workId);
  assert.equal(store.completed[0]?.task.revision, 1);
  assert.deepEqual(queue.deleted, ["receipt-1"]);
  assert.deepEqual(queue.visibilityChanges, []);
});

test("a replacement task reclaims an expired lease and finishes the original Slack work", async () => {
  const { record, outbox } = parsedWorkItems();
  const store = new ExpiredLeaseStore({
    ...record,
    status: "leased",
    leaseOwner: "terminated-task",
    leaseExpiresAt: "2026-07-16T12:01:30.000Z",
  });
  const queue = new FakeQueue(delivery(outbox.task, 2));
  const runner = new FakeRunner({ completed: true });
  const scheduler = new SlackQuestionWorkScheduler(config(), runner, {
    store,
    queue,
    now: () => new Date("2026-07-16T12:01:31.000Z"),
    workerId: "replacement-task",
  });

  assert.equal(await scheduler.consumeOnce(), true);
  assert.deepEqual(store.claims, [{ workerId: "replacement-task", now: "2026-07-16T12:01:31.000Z" }]);
  assert.equal(runner.records[0]?.workId, record.workId);
  assert.deepEqual(queue.deleted, ["receipt-1"]);
});

test("Slack question consumer schedules bounded retry after an incomplete run", async () => {
  const { record, outbox } = parsedWorkItems();
  const store = new FakeStore([], { reason: "claimed", record });
  const queue = new FakeQueue(delivery(outbox.task, 2));
  const scheduler = createScheduler(store, queue, new FakeRunner({ completed: false, error: "provider timeout" }));

  assert.equal(await scheduler.consumeOnce(), false);
  assert.equal(store.retried[0]?.error, "provider timeout");
  assert.equal(store.retried[0]?.availableAt, "2026-07-16T12:00:10.000Z");
  assert.deepEqual(queue.visibilityChanges, [{ receiptHandle: "receipt-1", seconds: 10 }]);
  assert.deepEqual(queue.deleted, []);
});

test("Slack question consumer acknowledges completed revisions and leaves active leases alone", async () => {
  const { outbox } = parsedWorkItems();
  const completedQueue = new FakeQueue(delivery(outbox.task, 1));
  const completed = createScheduler(new FakeStore([], { reason: "completed" }), completedQueue, new FakeRunner());
  assert.equal(await completed.consumeOnce(), true);
  assert.deepEqual(completedQueue.deleted, ["receipt-1"]);

  const busyQueue = new FakeQueue(delivery(outbox.task, 1));
  const busy = createScheduler(new FakeStore([], { reason: "busy" }), busyQueue, new FakeRunner());
  assert.equal(await busy.consumeOnce(), false);
  assert.deepEqual(busyQueue.deleted, []);
});

test("SQS Slack question work hashes the thread group and deduplicates the exact revision", async () => {
  const commands: any[] = [];
  const queue = new SqsSlackQuestionWorkQueue("https://sqs.us-east-1.amazonaws.com/123/slack-question-work.fifo", {
    async send(command: any): Promise<unknown> {
      commands.push(command);
      return { MessageId: "message-22" };
    },
  });
  const { outbox } = parsedWorkItems();

  assert.deepEqual(await queue.send(outbox.task), { messageId: "message-22" });
  assert.match(commands[0].input.MessageGroupId, /^slack-thread-[a-f0-9]{64}$/);
  assert.notEqual(commands[0].input.MessageGroupId, outbox.task.threadKey);
  assert.equal(commands[0].input.MessageDeduplicationId, outbox.task.taskId);
  assert.deepEqual(JSON.parse(commands[0].input.MessageBody), outbox.task);
});

test("Dynamo Slack question work uses an atomic outbox write and an exact-revision reclaim condition", async () => {
  const commands: any[] = [];
  const created = workItems();
  const dynamo = {
    async send(command: any): Promise<unknown> {
      commands.push(command);
      if (command.constructor.name === "UpdateCommand") {
        return {
          Attributes: {
            ...created.state,
            status: "leased",
            leaseOwner: "worker-a",
            leaseExpiresAt: "2026-07-16T12:01:30.000Z",
            attempts: 1,
          },
        };
      }
      return {};
    },
  };
  const store = new DynamoSlackQuestionWorkStore(config(), "learning", dynamo);
  await store.enqueue("CSEC:1782510000.000000", "CSEC:1782510000.000000", input(), new Date(NOW));
  const transaction = commands[0].input.TransactItems;
  assert.equal(transaction.length, 2);
  assert.equal(transaction[0].Put.ConditionExpression, "attribute_not_exists(pk)");
  assert.equal(transaction[1].Put.Item.recordType, "slack_question_work_outbox");

  const { outbox } = parsedWorkItems();
  const claim = await store.claim(outbox.task, "worker-a", new Date(NOW), 90_000);
  assert.equal(claim.reason, "claimed");
  assert.match(commands[1].input.ConditionExpression, /revision = :revision/);
  assert.match(commands[1].input.ConditionExpression, /leaseExpiresAt <= :now/);
  assert.equal(commands[1].input.ExpressionAttributeValues[":revision"], 1);
  assert.equal(commands[1].input.ExpressionAttributeValues[":leaseExpiresAt"], "2026-07-16T12:01:30.000Z");
});

function config() {
  return testConfig({
    triage: {
      workQueueEnabled: true,
      workQueueUrl: "https://sqs.us-east-1.amazonaws.com/123/slack-question-work.fifo",
      workQueuePublisherBatchSize: 50,
      workQueueVisibilityTimeoutSeconds: 90,
    },
    learning: { tableName: "learning" },
  });
}

function input(): SlackQuestionWorkInput {
  return {
    channelId: "CSEC",
    userId: "UUSER",
    senderKind: "human",
    question: "Run the read-only offboarding preflight.",
    ts: "1782510000.000000",
    threadTs: "1782510000.000000",
    replyThreadTs: "1782510000.000000",
  };
}

function workItems() {
  return createSlackQuestionWorkItems(
    config(),
    "CSEC:1782510000.000000",
    "CSEC:1782510000.000000",
    input(),
    new Date(NOW),
  );
}

function parsedWorkItems(): { record: SlackQuestionWorkRecord; outbox: SlackQuestionWorkOutboxRecord } {
  const created = workItems();
  const outbox = slackQuestionWorkOutboxFromItem(created.outbox);
  assert(outbox);
  return { record: created.record, outbox };
}

function delivery(task: SlackQuestionTaskEnvelope, receiveCount: number): SlackQuestionWorkDelivery {
  return { body: JSON.stringify(task), receiptHandle: "receipt-1", messageId: "message-1", receiveCount };
}

function createScheduler(store: FakeStore, queue: FakeQueue, runner: FakeRunner): SlackQuestionWorkScheduler {
  return new SlackQuestionWorkScheduler(config(), runner, { store, queue, now: () => new Date(NOW), workerId: "worker-a" });
}

class FakeStore implements SlackQuestionWorkStore {
  readonly publicationClaims: Array<{ record: SlackQuestionWorkOutboxRecord; leaseId: string }> = [];
  readonly published: Array<{ record: SlackQuestionWorkOutboxRecord; leaseId: string; messageId?: string }> = [];
  readonly completed: Array<{ task: SlackQuestionTaskEnvelope; workerId: string; completedAt: string }> = [];
  readonly retried: Array<{ task: SlackQuestionTaskEnvelope; workerId: string; availableAt: string; error: string }> = [];

  constructor(private readonly due: SlackQuestionWorkOutboxRecord[] = [], private readonly claimResult?: SlackQuestionClaimResult) {}

  async enqueue(): Promise<{ created: boolean; record: SlackQuestionWorkRecord }> {
    return { created: true, record: parsedWorkItems().record };
  }

  async listDue(): Promise<SlackQuestionWorkOutboxRecord[]> {
    return structuredClone(this.due);
  }

  async claimPublication(record: SlackQuestionWorkOutboxRecord, leaseId: string): Promise<boolean> {
    this.publicationClaims.push({ record: structuredClone(record), leaseId });
    return true;
  }

  async markPublished(record: SlackQuestionWorkOutboxRecord, leaseId: string, _publishedAt: string, messageId?: string): Promise<void> {
    this.published.push({ record: structuredClone(record), leaseId, messageId });
  }

  async claim(_task: SlackQuestionTaskEnvelope, _workerId: string, _now: Date, _leaseMs: number): Promise<SlackQuestionClaimResult> {
    return this.claimResult ?? { reason: "claimed", record: parsedWorkItems().record };
  }

  async renew(): Promise<boolean> {
    return true;
  }

  async complete(task: SlackQuestionTaskEnvelope, workerId: string, completedAt: string): Promise<void> {
    this.completed.push({ task: structuredClone(task), workerId, completedAt });
  }

  async retry(task: SlackQuestionTaskEnvelope, workerId: string, _now: Date, availableAt: string, error: string): Promise<void> {
    this.retried.push({ task: structuredClone(task), workerId, availableAt, error });
  }
}

class FakeQueue implements SlackQuestionWorkQueue {
  readonly sent: SlackQuestionTaskEnvelope[] = [];
  readonly deleted: string[] = [];
  readonly visibilityChanges: Array<{ receiptHandle: string; seconds: number }> = [];

  constructor(private nextDelivery?: SlackQuestionWorkDelivery) {}

  async send(task: SlackQuestionTaskEnvelope): Promise<{ messageId?: string }> {
    this.sent.push(structuredClone(task));
    return { messageId: `message-${this.sent.length}` };
  }

  async receive(): Promise<SlackQuestionWorkDelivery | undefined> {
    const result = this.nextDelivery;
    this.nextDelivery = undefined;
    return result ? structuredClone(result) : undefined;
  }

  async delete(receiptHandle: string): Promise<void> {
    this.deleted.push(receiptHandle);
  }

  async changeVisibility(receiptHandle: string, seconds: number): Promise<void> {
    this.visibilityChanges.push({ receiptHandle, seconds });
  }
}

class ExpiredLeaseStore extends FakeStore {
  readonly claims: Array<{ workerId: string; now: string }> = [];

  constructor(private readonly leasedRecord: SlackQuestionWorkRecord) {
    super();
  }

  override async claim(_task: SlackQuestionTaskEnvelope, workerId: string, now: Date): Promise<SlackQuestionClaimResult> {
    this.claims.push({ workerId, now: now.toISOString() });
    if (Date.parse(this.leasedRecord.leaseExpiresAt ?? "") > now.getTime()) return { reason: "busy" };
    return {
      reason: "claimed",
      record: {
        ...this.leasedRecord,
        leaseOwner: workerId,
        leaseExpiresAt: new Date(now.getTime() + 90_000).toISOString(),
      },
    };
  }
}

class FakeRunner implements SlackQuestionWorkRunner {
  readonly records: SlackQuestionWorkRecord[] = [];

  constructor(private readonly result: { completed: boolean; error?: string } = { completed: true }) {}

  async run(record: SlackQuestionWorkRecord): Promise<{ completed: boolean; error?: string }> {
    this.records.push(structuredClone(record));
    return this.result;
  }
}
