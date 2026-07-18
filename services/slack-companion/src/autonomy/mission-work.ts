import { randomUUID } from "node:crypto";
import {
  DeleteMessageCommand,
  ReceiveMessageCommand,
  SendMessageCommand,
  SQSClient,
} from "@aws-sdk/client-sqs";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  BatchGetCommand,
  DynamoDBDocumentClient,
  PutCommand,
  QueryCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";
import type { AppConfig } from "../config/index.js";
import { logger } from "../logger.js";
import { recordMetric } from "../telemetry.js";
import {
  MISSION_DUE_INDEX,
  MISSION_INDEX_SHARDS,
  storedGoalFromItem,
} from "./goal-store-dynamo-model.js";
import {
  MISSION_WORK_INDEX,
  missionTaskEnvelopeSchema,
  missionWorkOutboxFromItem,
  missionWorkOutboxItem,
  missionWorkScope,
  missionWorkSortKey,
  type MissionTaskEnvelope,
  type MissionWorkOutboxRecord,
} from "./mission-work-model.js";
import type { AutonomyRunnerAdvanceResult } from "./runner-types.js";

interface DynamoCommandSender {
  send(command: unknown): Promise<unknown>;
}

interface SqsCommandSender {
  send(command: unknown, options?: { abortSignal?: AbortSignal }): Promise<unknown>;
}

export interface MissionWorkDelivery {
  body: string;
  receiptHandle: string;
  messageId?: string;
  receiveCount: number;
}

export interface MissionWorkQueue {
  send(task: MissionTaskEnvelope): Promise<{ messageId?: string }>;
  receive(visibilityTimeoutSeconds: number, abortSignal?: AbortSignal): Promise<MissionWorkDelivery | undefined>;
  delete(receiptHandle: string): Promise<void>;
}

export interface MissionWorkOutbox {
  listDue(now: Date, limit: number): Promise<MissionWorkOutboxRecord[]>;
  claimPublication(record: MissionWorkOutboxRecord, leaseId: string, now: Date, leaseMs: number): Promise<boolean>;
  markPublished(record: MissionWorkOutboxRecord, leaseId: string, publishedAt: string, messageId?: string): Promise<void>;
  recordConsumed(task: MissionTaskEnvelope, result: AutonomyRunnerAdvanceResult, consumedAt: string): Promise<void>;
  reconcileDue(now: Date, limit: number): Promise<number>;
}

interface MissionWorkRunner {
  setSlackClient(client: any): void;
  advance(goalId: string, expectedRevision?: number, leaseMs?: number): Promise<AutonomyRunnerAdvanceResult>;
}

export class SqsMissionWorkQueue implements MissionWorkQueue {
  private readonly client: SqsCommandSender;

  constructor(private readonly queueUrl: string, client?: SqsCommandSender) {
    this.client = client ?? new SQSClient({});
  }

  async send(task: MissionTaskEnvelope): Promise<{ messageId?: string }> {
    const parsed = missionTaskEnvelopeSchema.parse(task);
    const response = await this.client.send(new SendMessageCommand({
      QueueUrl: this.queueUrl,
      MessageBody: JSON.stringify(parsed),
      MessageGroupId: parsed.goalId,
      MessageDeduplicationId: parsed.taskId,
      MessageAttributes: {
        schema_version: { DataType: "String", StringValue: parsed.schemaVersion },
        tenant_id: { DataType: "String", StringValue: parsed.tenantId },
        capability_id: { DataType: "String", StringValue: parsed.capabilityId },
      },
    })) as { MessageId?: string };
    return { messageId: response.MessageId };
  }

  async receive(visibilityTimeoutSeconds: number, abortSignal?: AbortSignal): Promise<MissionWorkDelivery | undefined> {
    const response = await this.client.send(new ReceiveMessageCommand({
      QueueUrl: this.queueUrl,
      MaxNumberOfMessages: 1,
      WaitTimeSeconds: 20,
      VisibilityTimeout: visibilityTimeoutSeconds,
      MessageSystemAttributeNames: ["ApproximateReceiveCount"],
    }), { abortSignal }) as {
      Messages?: Array<{
        Body?: string;
        ReceiptHandle?: string;
        MessageId?: string;
        Attributes?: Record<string, string>;
      }>;
    };
    const message = response.Messages?.[0];
    if (!message?.Body || !message.ReceiptHandle) return undefined;
    return {
      body: message.Body,
      receiptHandle: message.ReceiptHandle,
      messageId: message.MessageId,
      receiveCount: Math.max(1, Number(message.Attributes?.ApproximateReceiveCount ?? 1)),
    };
  }

  async delete(receiptHandle: string): Promise<void> {
    await this.client.send(new DeleteMessageCommand({ QueueUrl: this.queueUrl, ReceiptHandle: receiptHandle }));
  }
}

export class DynamoMissionWorkOutbox implements MissionWorkOutbox {
  private readonly dynamo: DynamoCommandSender;

  constructor(
    private readonly config: AppConfig,
    private readonly tableName: string,
    dynamo?: DynamoCommandSender,
  ) {
    this.dynamo = dynamo ?? DynamoDBDocumentClient.from(new DynamoDBClient({}), {
      marshallOptions: { removeUndefinedValues: true },
    });
  }

  async listDue(now: Date, limit: number): Promise<MissionWorkOutboxRecord[]> {
    const keys = await this.queryIndexKeys(
      MISSION_WORK_INDEX,
      "mission_work_scope",
      "mission_work_available_at",
      (shard) => missionWorkScope(this.config, shard),
      `${now.toISOString()}#\uffff`,
      limit,
    );
    const items = await this.batchGet(keys);
    return items
      .map(missionWorkOutboxFromItem)
      .filter(isWorkRecord)
      .sort((left, right) => left.task.availableAt.localeCompare(right.task.availableAt))
      .slice(0, Math.max(1, limit));
  }

  async claimPublication(record: MissionWorkOutboxRecord, leaseId: string, now: Date, leaseMs: number): Promise<boolean> {
    const leaseExpiresAt = new Date(now.getTime() + leaseMs).toISOString();
    try {
      await this.dynamo.send(new UpdateCommand({
        TableName: this.tableName,
        Key: { pk: record.pk, sk: record.sk },
        ConditionExpression: "attribute_not_exists(published_at) AND (attribute_not_exists(publish_lease_expires_at) OR publish_lease_expires_at <= :now)",
        UpdateExpression: "SET publish_lease_id = :leaseId, publish_lease_expires_at = :leaseExpiresAt, mission_work_available_at = :deferred, publication_attempts = if_not_exists(publication_attempts, :zero) + :one",
        ExpressionAttributeValues: {
          ":now": now.toISOString(),
          ":leaseId": leaseId,
          ":leaseExpiresAt": leaseExpiresAt,
          ":deferred": missionWorkSortKey(record.task, leaseExpiresAt),
          ":zero": 0,
          ":one": 1,
        },
      }));
      return true;
    } catch (error) {
      if (conditionalCheckFailed(error)) return false;
      throw error;
    }
  }

  async markPublished(
    record: MissionWorkOutboxRecord,
    leaseId: string,
    publishedAt: string,
    messageId?: string,
  ): Promise<void> {
    await this.dynamo.send(new UpdateCommand({
      TableName: this.tableName,
      Key: { pk: record.pk, sk: record.sk },
      ConditionExpression: "publish_lease_id = :leaseId AND attribute_not_exists(published_at)",
      UpdateExpression: "SET published_at = :publishedAt, queue_message_id = :messageId REMOVE mission_work_scope, mission_work_available_at, publish_lease_id, publish_lease_expires_at",
      ExpressionAttributeValues: {
        ":leaseId": leaseId,
        ":publishedAt": publishedAt,
        ":messageId": messageId ?? "unavailable",
      },
    }));
  }

  async recordConsumed(task: MissionTaskEnvelope, result: AutonomyRunnerAdvanceResult, consumedAt: string): Promise<void> {
    try {
      await this.dynamo.send(new UpdateCommand({
        TableName: this.tableName,
        Key: {
          pk: `tenant#${this.config.cerebro.tenantId}#mission#${task.goalId}`,
          sk: `work#${String(task.revision).padStart(16, "0")}`,
        },
        ConditionExpression: "attribute_exists(pk) AND attribute_not_exists(consumed_at)",
        UpdateExpression: "SET consumed_at = :consumedAt, consumer_outcome = :outcome, consumer_summary = :summary",
        ExpressionAttributeValues: {
          ":consumedAt": consumedAt,
          ":outcome": result.status,
          ":summary": result.summary.slice(0, 1_000),
        },
      }));
    } catch (error) {
      if (!conditionalCheckFailed(error)) throw error;
    }
  }

  async reconcileDue(now: Date, limit: number): Promise<number> {
    const keys = await this.queryIndexKeys(
      MISSION_DUE_INDEX,
      "mission_due_scope",
      "mission_due_at",
      (shard) => `tenant#${this.config.cerebro.tenantId}#shard#${String(shard).padStart(2, "0")}`,
      `${now.toISOString()}#\uffff`,
      limit,
    );
    const snapshots = await this.batchGet(keys);
    let created = 0;
    for (const snapshot of snapshots) {
      const stored = storedGoalFromItem(snapshot, "mission_v2");
      if (!stored || stored.goal.status !== "active" || stored.revision < 1) continue;
      const item = missionWorkOutboxItem(this.config, stored.goal, {
        id: `reconcile-${stored.goal.id}-${stored.revision}`,
        goalId: stored.goal.id,
        type: "goal_updated",
        occurredAt: now.toISOString(),
        revision: stored.revision,
        previousRevision: Math.max(0, stored.revision - 1),
        changedFields: ["nextWakeAt"],
      }, stored.revision);
      if (!item) continue;
      try {
        await this.dynamo.send(new PutCommand({
          TableName: this.tableName,
          Item: item,
          ConditionExpression: "attribute_not_exists(pk)",
        }));
        created += 1;
      } catch (error) {
        if (!conditionalCheckFailed(error)) throw error;
      }
    }
    return created;
  }

  private async queryIndexKeys(
    indexName: string,
    scopeName: string,
    sortName: string,
    scope: (shard: number) => string,
    upperBound: string,
    limit: number,
  ): Promise<Array<{ pk: string; sk: string }>> {
    const shardLimit = Math.max(1, Math.ceil(limit / MISSION_INDEX_SHARDS));
    const responses = await Promise.all(Array.from({ length: MISSION_INDEX_SHARDS }, async (_, shard) => this.dynamo.send(new QueryCommand({
      TableName: this.tableName,
      IndexName: indexName,
      KeyConditionExpression: "#scope = :scope AND #sort <= :upperBound",
      ExpressionAttributeNames: { "#scope": scopeName, "#sort": sortName },
      ExpressionAttributeValues: { ":scope": scope(shard), ":upperBound": upperBound },
      ScanIndexForward: true,
      Limit: shardLimit,
    })) as Promise<{ Items?: Record<string, unknown>[] }>));
    const unique = new Map<string, { pk: string; sk: string }>();
    for (const item of responses.flatMap((response) => response.Items ?? [])) {
      if (typeof item.pk === "string" && typeof item.sk === "string") unique.set(`${item.pk}\0${item.sk}`, { pk: item.pk, sk: item.sk });
    }
    return [...unique.values()];
  }

  private async batchGet(keys: Array<{ pk: string; sk: string }>): Promise<Record<string, unknown>[]> {
    const items: Record<string, unknown>[] = [];
    const batches = chunk(keys, 100);
    for (const batch of batches) {
      let pending = batch;
      for (let attempt = 0; pending.length > 0 && attempt < 3; attempt += 1) {
        const response = await this.dynamo.send(new BatchGetCommand({
          RequestItems: { [this.tableName]: { Keys: pending, ConsistentRead: true } },
        })) as {
          Responses?: Record<string, Record<string, unknown>[]>;
          UnprocessedKeys?: Record<string, { Keys?: Array<{ pk: string; sk: string }> }>;
        };
        items.push(...(response.Responses?.[this.tableName] ?? []));
        pending = response.UnprocessedKeys?.[this.tableName]?.Keys ?? [];
      }
      if (pending.length > 0) throw new Error(`Mission work read left ${pending.length} unprocessed key(s).`);
    }
    return items;
  }
}

export class MissionWorkScheduler {
  private readonly outbox: MissionWorkOutbox;
  private readonly queue: MissionWorkQueue;
  private readonly now: () => Date;
  private running = false;
  private publisherInterval?: NodeJS.Timeout;
  private reconcileInterval?: NodeJS.Timeout;
  private abortController?: AbortController;
  private consumers: Array<Promise<void>> = [];
  private publishing = false;
  private reconciling = false;

  constructor(
    private readonly config: AppConfig,
    private readonly runner: MissionWorkRunner,
    options: {
      outbox?: MissionWorkOutbox;
      queue?: MissionWorkQueue;
      now?: () => Date;
    } = {},
  ) {
    if (!config.autonomy.goalsTableName) throw new Error("Mission work queue requires a mission table.");
    if (!config.autonomy.queueUrl) throw new Error("Mission work queue requires an SQS queue URL.");
    this.outbox = options.outbox ?? new DynamoMissionWorkOutbox(config, config.autonomy.goalsTableName);
    this.queue = options.queue ?? new SqsMissionWorkQueue(config.autonomy.queueUrl);
    this.now = options.now ?? (() => new Date());
  }

  start(client?: any): void {
    if (this.running || !this.config.autonomy.runnerEnabled || !this.config.autonomy.queueEnabled) return;
    if (client) this.runner.setSlackClient(client);
    this.running = true;
    this.abortController = new AbortController();
    this.publisherInterval = setInterval(() => void this.publishSafely(), this.config.autonomy.queuePublisherIntervalMs);
    this.reconcileInterval = setInterval(() => void this.reconcileSafely(), this.config.autonomy.queueReconcileIntervalMs);
    this.publisherInterval.unref?.();
    this.reconcileInterval.unref?.();
    void this.reconcileSafely().then(() => this.publishSafely());
    this.consumers = Array.from({ length: this.config.autonomy.queueConsumerCount }, (_, index) => this.consumeLoop(index));
  }

  async stop(): Promise<void> {
    this.running = false;
    if (this.publisherInterval) clearInterval(this.publisherInterval);
    if (this.reconcileInterval) clearInterval(this.reconcileInterval);
    this.publisherInterval = undefined;
    this.reconcileInterval = undefined;
    this.abortController?.abort();
    await Promise.allSettled(this.consumers);
    this.consumers = [];
    this.abortController = undefined;
  }

  async publishOnce(): Promise<number> {
    const due = await this.outbox.listDue(this.now(), this.config.autonomy.queuePublisherBatchSize);
    const outcomes = await Promise.all(due.map((record) => this.publishRecord(record)));
    const published = outcomes.filter(Boolean).length;
    recordMetric("cerebro_slack_companion_mission_work_publications_total", { outcome: "published" }, published);
    return published;
  }

  async reconcileOnce(): Promise<number> {
    const created = await this.outbox.reconcileDue(this.now(), this.config.autonomy.queuePublisherBatchSize);
    recordMetric("cerebro_slack_companion_mission_work_reconciled_total", {}, created);
    return created;
  }

  async consumeOnce(abortSignal?: AbortSignal): Promise<boolean> {
    const delivery = await this.queue.receive(this.config.autonomy.queueVisibilityTimeoutSeconds, abortSignal);
    if (!delivery) return false;
    const parsed = parseTask(delivery.body);
    if (!parsed.success) {
      logger.error("mission work envelope rejected", {
        event: "autonomy.mission_work.envelope_rejected",
        messageId: delivery.messageId,
        receiveCount: delivery.receiveCount,
        error: parsed.error,
      });
      recordMetric("cerebro_slack_companion_mission_work_consumptions_total", { outcome: "invalid" }, 1);
      return false;
    }
    const task = parsed.task;
    if (task.tenantId !== this.config.cerebro.tenantId) {
      logger.error("mission work tenant rejected", {
        event: "autonomy.mission_work.tenant_rejected",
        taskId: task.taskId,
        tenantId: task.tenantId,
      });
      recordMetric("cerebro_slack_companion_mission_work_consumptions_total", { outcome: "wrong_tenant" }, 1);
      return false;
    }
    const result = await this.runner.advance(
      task.goalId,
      task.revision,
      this.config.autonomy.queueVisibilityTimeoutSeconds * 1_000,
    );
    if (result.status === "claimed_elsewhere" || result.status === "failed") {
      recordMetric("cerebro_slack_companion_mission_work_consumptions_total", { outcome: result.status }, 1);
      return false;
    }
    const consumedAt = this.now().toISOString();
    await this.outbox.recordConsumed(task, result, consumedAt);
    await this.queue.delete(delivery.receiptHandle);
    recordMetric("cerebro_slack_companion_mission_work_consumptions_total", { outcome: result.status }, 1);
    logger.info("mission work consumed", {
      event: "autonomy.mission_work.consumed",
      taskId: task.taskId,
      goalId: task.goalId,
      revision: task.revision,
      outcome: result.status,
      receiveCount: delivery.receiveCount,
    });
    return true;
  }

  private async publishRecord(record: MissionWorkOutboxRecord): Promise<boolean> {
    const leaseId = randomUUID();
    const claimed = await this.outbox.claimPublication(record, leaseId, this.now(), 30_000);
    if (!claimed) return false;
    const receipt = await this.queue.send(record.task);
    await this.outbox.markPublished(record, leaseId, this.now().toISOString(), receipt.messageId);
    return true;
  }

  private async publishSafely(): Promise<void> {
    if (this.publishing || !this.running) return;
    this.publishing = true;
    try {
      await this.publishOnce();
    } catch (error) {
      logger.warn("mission work publication failed", { event: "autonomy.mission_work.publish_failed", error: String(error) });
      recordMetric("cerebro_slack_companion_mission_work_publications_total", { outcome: "failed" }, 1);
    } finally {
      this.publishing = false;
    }
  }

  private async reconcileSafely(): Promise<void> {
    if (this.reconciling || !this.running) return;
    this.reconciling = true;
    try {
      await this.reconcileOnce();
    } catch (error) {
      logger.warn("mission work reconciliation failed", { event: "autonomy.mission_work.reconcile_failed", error: String(error) });
    } finally {
      this.reconciling = false;
    }
  }

  private async consumeLoop(index: number): Promise<void> {
    while (this.running && !this.abortController?.signal.aborted) {
      try {
        await this.consumeOnce(this.abortController?.signal);
      } catch (error) {
        if (isAbortError(error) || !this.running) return;
        logger.warn("mission work consumption failed", {
          event: "autonomy.mission_work.consume_failed",
          consumer: index,
          error: String(error),
        });
        recordMetric("cerebro_slack_companion_mission_work_consumptions_total", { outcome: "failed" }, 1);
        await delay(1_000);
      }
    }
  }
}

function parseTask(body: string): { success: true; task: MissionTaskEnvelope } | { success: false; error: string } {
  try {
    const parsed = missionTaskEnvelopeSchema.safeParse(JSON.parse(body) as unknown);
    return parsed.success
      ? { success: true, task: parsed.data }
      : { success: false, error: parsed.error.issues.map((issue) => issue.message).join("; ").slice(0, 1_000) };
  } catch (error) {
    return { success: false, error: String(error).slice(0, 1_000) };
  }
}

function conditionalCheckFailed(error: unknown): boolean {
  return error instanceof Error && error.name === "ConditionalCheckFailedException";
}

function isWorkRecord(value: MissionWorkOutboxRecord | undefined): value is MissionWorkOutboxRecord {
  return Boolean(value);
}

function isAbortError(error: unknown): boolean {
  return error instanceof Error && (error.name === "AbortError" || error.name === "TimeoutError");
}

function chunk<T>(items: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let index = 0; index < items.length; index += size) chunks.push(items.slice(index, index + size));
  return chunks;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const timeout = setTimeout(resolve, ms);
    timeout.unref?.();
  });
}
