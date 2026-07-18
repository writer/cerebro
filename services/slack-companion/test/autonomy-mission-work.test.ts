import assert from "node:assert/strict";
import test from "node:test";
import { MissionWorkScheduler, SqsMissionWorkQueue, type MissionWorkDelivery, type MissionWorkOutbox, type MissionWorkQueue } from "../src/autonomy/mission-work.js";
import { MISSION_TASK_SCHEMA_VERSION, type MissionTaskEnvelope, type MissionWorkOutboxRecord } from "../src/autonomy/mission-work-model.js";
import type { AutonomyRunnerAdvanceResult } from "../src/autonomy/runner-types.js";
import { testConfig } from "./fixtures.js";

const NOW = "2026-07-16T12:00:00.000Z";

test("mission work publisher claims an outbox record before FIFO publication and records the receipt", async () => {
  const task = missionTask(7);
  const outbox = new FakeOutbox([workRecord(task)]);
  const queue = new FakeQueue();
  const scheduler = createScheduler(outbox, queue, new FakeRunner());

  assert.equal(await scheduler.publishOnce(), 1);
  assert.deepEqual(queue.sent, [task]);
  assert.equal(outbox.claims.length, 1);
  assert.equal(outbox.published[0]?.record.task.taskId, task.taskId);
  assert.equal(outbox.published[0]?.messageId, "message-1");
});

test("mission work consumer acknowledges a stale revision without executing newer work", async () => {
  const task = missionTask(4);
  const outbox = new FakeOutbox();
  const queue = new FakeQueue({
    body: JSON.stringify(task),
    receiptHandle: "receipt-stale",
    messageId: "message-stale",
    receiveCount: 2,
  });
  const runner = new FakeRunner({ goalId: task.goalId, status: "stale", summary: "Revision 4 is no longer current." });
  const scheduler = createScheduler(outbox, queue, runner);

  assert.equal(await scheduler.consumeOnce(), true);
  assert.deepEqual(runner.advances, [{ goalId: task.goalId, expectedRevision: 4, leaseMs: 900_000 }]);
  assert.equal(outbox.consumed[0]?.result.status, "stale");
  assert.deepEqual(queue.deleted, ["receipt-stale"]);
});

test("mission work consumer leaves a concurrently claimed revision for retry", async () => {
  const task = missionTask(9);
  const outbox = new FakeOutbox();
  const queue = new FakeQueue({
    body: JSON.stringify(task),
    receiptHandle: "receipt-claimed",
    receiveCount: 1,
  });
  const runner = new FakeRunner({ goalId: task.goalId, status: "claimed_elsewhere", summary: "Goal is leased by another worker." });
  const scheduler = createScheduler(outbox, queue, runner);

  assert.equal(await scheduler.consumeOnce(), false);
  assert.equal(outbox.consumed.length, 0);
  assert.equal(queue.deleted.length, 0);
});

test("SQS mission work queue preserves per-mission ordering and revision deduplication", async () => {
  const commands: any[] = [];
  const queue = new SqsMissionWorkQueue("https://sqs.us-west-2.amazonaws.com/123/mission-work.fifo", {
    async send(command: any): Promise<unknown> {
      commands.push(command);
      return { MessageId: "message-22" };
    },
  });
  const task = missionTask(22);

  assert.deepEqual(await queue.send(task), { messageId: "message-22" });
  assert.equal(commands[0].input.MessageGroupId, task.goalId);
  assert.equal(commands[0].input.MessageDeduplicationId, task.taskId);
  assert.deepEqual(JSON.parse(commands[0].input.MessageBody), task);
});

function createScheduler(outbox: FakeOutbox, queue: FakeQueue, runner: FakeRunner): MissionWorkScheduler {
  return new MissionWorkScheduler(testConfig({
    autonomy: {
      goalsTableName: "goals",
      queueEnabled: true,
      queueUrl: "https://sqs.us-west-2.amazonaws.com/123/mission-work.fifo",
      queuePublisherBatchSize: 50,
      queueVisibilityTimeoutSeconds: 900,
    },
  }), runner, { outbox, queue, now: () => new Date(NOW) });
}

function missionTask(revision: number): MissionTaskEnvelope {
  return {
    schemaVersion: MISSION_TASK_SCHEMA_VERSION,
    taskId: `goal-00000000-0000-4000-8000-000000000001:${revision}`,
    tenantId: "writer",
    goalId: "goal-00000000-0000-4000-8000-000000000001",
    revision,
    capabilityId: "investigation",
    stepId: "collect-evidence",
    availableAt: NOW,
    enqueuedAt: NOW,
    execution: { contractVersion: "2026-07-16.1", profileId: "investigation-read" },
  };
}

function workRecord(task: MissionTaskEnvelope): MissionWorkOutboxRecord {
  return {
    pk: `tenant#writer#mission#${task.goalId}`,
    sk: `work#${String(task.revision).padStart(16, "0")}`,
    task,
  };
}

class FakeOutbox implements MissionWorkOutbox {
  readonly claims: Array<{ record: MissionWorkOutboxRecord; leaseId: string }> = [];
  readonly published: Array<{ record: MissionWorkOutboxRecord; leaseId: string; messageId?: string }> = [];
  readonly consumed: Array<{ task: MissionTaskEnvelope; result: AutonomyRunnerAdvanceResult }> = [];

  constructor(private readonly due: MissionWorkOutboxRecord[] = []) {}

  async listDue(): Promise<MissionWorkOutboxRecord[]> {
    return structuredClone(this.due);
  }

  async claimPublication(record: MissionWorkOutboxRecord, leaseId: string): Promise<boolean> {
    this.claims.push({ record: structuredClone(record), leaseId });
    return true;
  }

  async markPublished(record: MissionWorkOutboxRecord, leaseId: string, _publishedAt: string, messageId?: string): Promise<void> {
    this.published.push({ record: structuredClone(record), leaseId, messageId });
  }

  async recordConsumed(task: MissionTaskEnvelope, result: AutonomyRunnerAdvanceResult): Promise<void> {
    this.consumed.push({ task: structuredClone(task), result: structuredClone(result) });
  }

  async reconcileDue(): Promise<number> {
    return 0;
  }
}

class FakeQueue implements MissionWorkQueue {
  readonly sent: MissionTaskEnvelope[] = [];
  readonly deleted: string[] = [];

  constructor(private delivery?: MissionWorkDelivery) {}

  async send(task: MissionTaskEnvelope): Promise<{ messageId?: string }> {
    this.sent.push(structuredClone(task));
    return { messageId: `message-${this.sent.length}` };
  }

  async receive(): Promise<MissionWorkDelivery | undefined> {
    const delivery = this.delivery;
    this.delivery = undefined;
    return delivery ? structuredClone(delivery) : undefined;
  }

  async delete(receiptHandle: string): Promise<void> {
    this.deleted.push(receiptHandle);
  }
}

class FakeRunner {
  readonly advances: Array<{ goalId: string; expectedRevision?: number; leaseMs?: number }> = [];

  constructor(private readonly result?: AutonomyRunnerAdvanceResult) {}

  setSlackClient(): void {}

  async advance(goalId: string, expectedRevision?: number, leaseMs?: number): Promise<AutonomyRunnerAdvanceResult> {
    this.advances.push({ goalId, expectedRevision, leaseMs });
    return this.result ?? { goalId, status: "advanced", summary: "Advanced one step." };
  }
}
