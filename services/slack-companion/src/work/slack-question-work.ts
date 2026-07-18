import { createHash, randomUUID } from "node:crypto";
import { hostname } from "node:os";
import {
  ChangeMessageVisibilityCommand,
  DeleteMessageCommand,
  ReceiveMessageCommand,
  SendMessageCommand,
  SQSClient,
} from "@aws-sdk/client-sqs";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  QueryCommand,
  TransactWriteCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";
import type { AppConfig } from "../config/index.js";
import { logger } from "../logger.js";
import { recordMetric, telemetryEvent } from "../telemetry.js";
import type { SlackQuestionWorkInput } from "./companion-work-loop.js";
import {
  SLACK_QUESTION_WORK_INDEX,
  createSlackQuestionWorkItems,
  slackQuestionTaskEnvelopeSchema,
  slackQuestionWorkOutboxFromItem,
  slackQuestionWorkPartitionKey,
  slackQuestionWorkRecordFromItem,
  slackQuestionWorkScope,
  type SlackQuestionTaskEnvelope,
  type SlackQuestionWorkOutboxRecord,
  type SlackQuestionWorkRecord,
} from "./slack-question-work-model.js";

interface CommandSender {
  send(command: unknown, options?: { abortSignal?: AbortSignal }): Promise<unknown>;
}

export interface SlackQuestionWorkDelivery {
  body: string;
  receiptHandle: string;
  messageId?: string;
  receiveCount: number;
}

export interface SlackQuestionWorkQueue {
  send(task: SlackQuestionTaskEnvelope): Promise<{ messageId?: string }>;
  receive(visibilityTimeoutSeconds: number, abortSignal?: AbortSignal): Promise<SlackQuestionWorkDelivery | undefined>;
  delete(receiptHandle: string): Promise<void>;
  changeVisibility(receiptHandle: string, visibilityTimeoutSeconds: number): Promise<void>;
}

export type SlackQuestionClaimResult =
  | { reason: "claimed"; record: SlackQuestionWorkRecord }
  | { reason: "completed" | "stale" | "busy" | "missing" };

export interface SlackQuestionWorkStore {
  enqueue(workId: string, threadKey: string, input: SlackQuestionWorkInput, now: Date): Promise<{ created: boolean; record: SlackQuestionWorkRecord }>;
  listDue(now: Date, limit: number): Promise<SlackQuestionWorkOutboxRecord[]>;
  claimPublication(record: SlackQuestionWorkOutboxRecord, leaseId: string, now: Date, leaseMs: number): Promise<boolean>;
  markPublished(record: SlackQuestionWorkOutboxRecord, leaseId: string, publishedAt: string, messageId?: string): Promise<void>;
  claim(task: SlackQuestionTaskEnvelope, workerId: string, now: Date, leaseMs: number): Promise<SlackQuestionClaimResult>;
  renew(task: SlackQuestionTaskEnvelope, workerId: string, now: Date, leaseMs: number): Promise<boolean>;
  complete(task: SlackQuestionTaskEnvelope, workerId: string, completedAt: string): Promise<void>;
  retry(task: SlackQuestionTaskEnvelope, workerId: string, now: Date, availableAt: string, error: string): Promise<void>;
}

export interface SlackQuestionWorkRunner {
  run(record: SlackQuestionWorkRecord): Promise<{ completed: boolean; error?: string }>;
}

export class SqsSlackQuestionWorkQueue implements SlackQuestionWorkQueue {
  private readonly client: CommandSender;

  constructor(private readonly queueUrl: string, client?: CommandSender) {
    this.client = client ?? new SQSClient({});
  }

  async send(task: SlackQuestionTaskEnvelope): Promise<{ messageId?: string }> {
    const parsed = slackQuestionTaskEnvelopeSchema.parse(task);
    const response = await this.client.send(new SendMessageCommand({
      QueueUrl: this.queueUrl,
      MessageBody: JSON.stringify(parsed),
      MessageGroupId: queueGroupId(parsed.threadKey),
      MessageDeduplicationId: parsed.taskId,
      MessageAttributes: {
        schema_version: { DataType: "String", StringValue: parsed.schemaVersion },
        tenant_id: { DataType: "String", StringValue: parsed.tenantId },
      },
    })) as { MessageId?: string };
    return { messageId: response.MessageId };
  }

  async receive(visibilityTimeoutSeconds: number, abortSignal?: AbortSignal): Promise<SlackQuestionWorkDelivery | undefined> {
    const response = await this.client.send(new ReceiveMessageCommand({
      QueueUrl: this.queueUrl,
      MaxNumberOfMessages: 1,
      WaitTimeSeconds: 20,
      VisibilityTimeout: visibilityTimeoutSeconds,
      MessageSystemAttributeNames: ["ApproximateReceiveCount"],
    }), { abortSignal }) as {
      Messages?: Array<{ Body?: string; ReceiptHandle?: string; MessageId?: string; Attributes?: Record<string, string> }>;
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

  async changeVisibility(receiptHandle: string, visibilityTimeoutSeconds: number): Promise<void> {
    await this.client.send(new ChangeMessageVisibilityCommand({
      QueueUrl: this.queueUrl,
      ReceiptHandle: receiptHandle,
      VisibilityTimeout: visibilityTimeoutSeconds,
    }));
  }
}

export class DynamoSlackQuestionWorkStore implements SlackQuestionWorkStore {
  private readonly dynamo: CommandSender;

  constructor(private readonly config: AppConfig, private readonly tableName: string, dynamo?: CommandSender) {
    this.dynamo = dynamo ?? DynamoDBDocumentClient.from(new DynamoDBClient({}), {
      marshallOptions: { removeUndefinedValues: true },
    });
  }

  async enqueue(workId: string, threadKey: string, input: SlackQuestionWorkInput, now: Date): Promise<{ created: boolean; record: SlackQuestionWorkRecord }> {
    const items = createSlackQuestionWorkItems(this.config, workId, threadKey, input, now);
    try {
      await this.dynamo.send(new TransactWriteCommand({
        TransactItems: [
          { Put: { TableName: this.tableName, Item: items.state, ConditionExpression: "attribute_not_exists(pk)" } },
          { Put: { TableName: this.tableName, Item: items.outbox, ConditionExpression: "attribute_not_exists(pk)" } },
        ],
      }));
      return { created: true, record: items.record };
    } catch (error) {
      if (!conditionalCheckFailed(error)) throw error;
      const existing = await this.get(workId);
      if (!existing) throw new Error("Slack question work transaction was cancelled without an existing state record.");
      if (JSON.stringify(existing.input) !== JSON.stringify(items.record.input)) {
        throw new Error("Slack question work idempotency conflict: the same work id has different input.");
      }
      return { created: false, record: existing };
    }
  }

  async listDue(now: Date, limit: number): Promise<SlackQuestionWorkOutboxRecord[]> {
    const response = await this.dynamo.send(new QueryCommand({
      TableName: this.tableName,
      IndexName: SLACK_QUESTION_WORK_INDEX,
      KeyConditionExpression: "slack_work_scope = :scope AND slack_work_available_at <= :upper",
      ExpressionAttributeValues: {
        ":scope": slackQuestionWorkScope(this.config.cerebro.tenantId),
        ":upper": `${now.toISOString()}#\uffff`,
      },
      ScanIndexForward: true,
      Limit: Math.max(1, limit),
    })) as { Items?: Record<string, unknown>[] };
    return (response.Items ?? []).map(slackQuestionWorkOutboxFromItem).filter(isOutboxRecord);
  }

  async claimPublication(record: SlackQuestionWorkOutboxRecord, leaseId: string, now: Date, leaseMs: number): Promise<boolean> {
    const leaseExpiresAt = new Date(now.getTime() + leaseMs).toISOString();
    try {
      await this.dynamo.send(new UpdateCommand({
        TableName: this.tableName,
        Key: { pk: record.pk, sk: record.sk },
        ConditionExpression: "attribute_not_exists(published_at) AND (attribute_not_exists(publish_lease_expires_at) OR publish_lease_expires_at <= :now)",
        UpdateExpression: "SET publish_lease_id = :leaseId, publish_lease_expires_at = :leaseExpiresAt, slack_work_available_at = :deferred, publication_attempts = if_not_exists(publication_attempts, :zero) + :one",
        ExpressionAttributeValues: {
          ":now": now.toISOString(),
          ":leaseId": leaseId,
          ":leaseExpiresAt": leaseExpiresAt,
          ":deferred": `${leaseExpiresAt}#${record.task.taskId}`,
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

  async markPublished(record: SlackQuestionWorkOutboxRecord, leaseId: string, publishedAt: string, messageId?: string): Promise<void> {
    await this.dynamo.send(new UpdateCommand({
      TableName: this.tableName,
      Key: { pk: record.pk, sk: record.sk },
      ConditionExpression: "publish_lease_id = :leaseId AND attribute_not_exists(published_at)",
      UpdateExpression: "SET published_at = :publishedAt, queue_message_id = :messageId REMOVE slack_work_scope, slack_work_available_at, publish_lease_id, publish_lease_expires_at",
      ExpressionAttributeValues: {
        ":leaseId": leaseId,
        ":publishedAt": publishedAt,
        ":messageId": messageId ?? "unavailable",
      },
    }));
  }

  async claim(task: SlackQuestionTaskEnvelope, workerId: string, now: Date, leaseMs: number): Promise<SlackQuestionClaimResult> {
    const leaseExpiresAt = new Date(now.getTime() + leaseMs).toISOString();
    try {
      const response = await this.dynamo.send(new UpdateCommand({
        TableName: this.tableName,
        Key: { pk: slackQuestionWorkPartitionKey(task.tenantId, task.workId), sk: "state" },
        ConditionExpression: "revision = :revision AND (((#status = :queued OR #status = :retry) AND availableAt <= :now) OR (#status = :leased AND leaseExpiresAt <= :now))",
        UpdateExpression: "SET #status = :leased, leaseOwner = :workerId, leaseExpiresAt = :leaseExpiresAt, updatedAt = :now, attempts = if_not_exists(attempts, :zero) + :one REMOVE lastError",
        ExpressionAttributeNames: { "#status": "status" },
        ExpressionAttributeValues: {
          ":revision": task.revision,
          ":queued": "queued",
          ":retry": "retry",
          ":leased": "leased",
          ":workerId": workerId,
          ":leaseExpiresAt": leaseExpiresAt,
          ":now": now.toISOString(),
          ":zero": 0,
          ":one": 1,
        },
        ReturnValues: "ALL_NEW",
      })) as { Attributes?: Record<string, unknown> };
      const record = slackQuestionWorkRecordFromItem(response.Attributes);
      if (!record) throw new Error("Slack question work claim returned an invalid record.");
      return { reason: "claimed", record };
    } catch (error) {
      if (!conditionalCheckFailed(error)) throw error;
      const existing = await this.get(task.workId);
      if (!existing) return { reason: "missing" };
      if (existing.revision !== task.revision) return { reason: "stale" };
      if (existing.status === "completed") return { reason: "completed" };
      return { reason: "busy" };
    }
  }

  async renew(task: SlackQuestionTaskEnvelope, workerId: string, now: Date, leaseMs: number): Promise<boolean> {
    try {
      await this.dynamo.send(new UpdateCommand({
        TableName: this.tableName,
        Key: { pk: slackQuestionWorkPartitionKey(task.tenantId, task.workId), sk: "state" },
        ConditionExpression: "revision = :revision AND #status = :leased AND leaseOwner = :workerId",
        UpdateExpression: "SET leaseExpiresAt = :leaseExpiresAt, updatedAt = :now",
        ExpressionAttributeNames: { "#status": "status" },
        ExpressionAttributeValues: {
          ":revision": task.revision,
          ":leased": "leased",
          ":workerId": workerId,
          ":leaseExpiresAt": new Date(now.getTime() + leaseMs).toISOString(),
          ":now": now.toISOString(),
        },
      }));
      return true;
    } catch (error) {
      if (conditionalCheckFailed(error)) return false;
      throw error;
    }
  }

  async complete(task: SlackQuestionTaskEnvelope, workerId: string, completedAt: string): Promise<void> {
    await this.dynamo.send(new UpdateCommand({
      TableName: this.tableName,
      Key: { pk: slackQuestionWorkPartitionKey(task.tenantId, task.workId), sk: "state" },
      ConditionExpression: "revision = :revision AND #status = :leased AND leaseOwner = :workerId",
      UpdateExpression: "SET #status = :completed, completedAt = :completedAt, updatedAt = :completedAt REMOVE leaseOwner, leaseExpiresAt, lastError",
      ExpressionAttributeNames: { "#status": "status" },
      ExpressionAttributeValues: {
        ":revision": task.revision,
        ":leased": "leased",
        ":completed": "completed",
        ":workerId": workerId,
        ":completedAt": completedAt,
      },
    }));
  }

  async retry(task: SlackQuestionTaskEnvelope, workerId: string, now: Date, availableAt: string, error: string): Promise<void> {
    await this.dynamo.send(new UpdateCommand({
      TableName: this.tableName,
      Key: { pk: slackQuestionWorkPartitionKey(task.tenantId, task.workId), sk: "state" },
      ConditionExpression: "revision = :revision AND #status = :leased AND leaseOwner = :workerId",
      UpdateExpression: "SET #status = :retry, availableAt = :availableAt, updatedAt = :now, lastError = :error REMOVE leaseOwner, leaseExpiresAt",
      ExpressionAttributeNames: { "#status": "status" },
      ExpressionAttributeValues: {
        ":revision": task.revision,
        ":leased": "leased",
        ":retry": "retry",
        ":workerId": workerId,
        ":availableAt": availableAt,
        ":now": now.toISOString(),
        ":error": boundedError(error),
      },
    }));
  }

  private async get(workId: string): Promise<SlackQuestionWorkRecord | undefined> {
    const response = await this.dynamo.send(new GetCommand({
      TableName: this.tableName,
      Key: { pk: slackQuestionWorkPartitionKey(this.config.cerebro.tenantId, workId), sk: "state" },
      ConsistentRead: true,
    })) as { Item?: Record<string, unknown> };
    return slackQuestionWorkRecordFromItem(response.Item);
  }
}

export class SlackQuestionWorkScheduler {
  private readonly store: SlackQuestionWorkStore;
  private readonly queue: SlackQuestionWorkQueue;
  private readonly now: () => Date;
  private readonly workerId: string;
  private running = false;
  private publisherInterval?: NodeJS.Timeout;
  private abortController?: AbortController;
  private publishing = false;
  private publishFailureCount = 0;
  private nextPublishAttemptAt = 0;

  constructor(private readonly config: AppConfig, private readonly runner: SlackQuestionWorkRunner, options: {
    store?: SlackQuestionWorkStore;
    queue?: SlackQuestionWorkQueue;
    now?: () => Date;
    workerId?: string;
  } = {}) {
    if (!config.learning.tableName) throw new Error("Durable Slack question work requires the learning table.");
    if (!config.triage.workQueueUrl) throw new Error("Durable Slack question work requires an SQS queue URL.");
    this.store = options.store ?? new DynamoSlackQuestionWorkStore(config, config.learning.tableName);
    this.queue = options.queue ?? new SqsSlackQuestionWorkQueue(config.triage.workQueueUrl);
    this.now = options.now ?? (() => new Date());
    this.workerId = options.workerId ?? `slack-question-${process.pid}@${hostname()}`;
  }

  start(): void {
    if (this.running || !this.config.triage.workQueueEnabled) return;
    this.running = true;
    this.publishFailureCount = 0;
    this.nextPublishAttemptAt = 0;
    this.abortController = new AbortController();
    this.publisherInterval = setInterval(() => void this.publishSafely(), this.config.triage.workQueuePublisherIntervalMs);
    this.publisherInterval.unref?.();
    void this.publishSafely();
    for (let index = 0; index < this.config.triage.workQueueConsumerCount; index += 1) {
      void this.consumeLoop(index);
    }
  }

  stop(): void {
    this.running = false;
    if (this.publisherInterval) clearInterval(this.publisherInterval);
    this.publisherInterval = undefined;
    this.abortController?.abort();
    this.abortController = undefined;
  }

  async enqueue(workId: string, threadKey: string, input: SlackQuestionWorkInput): Promise<{ created: boolean; record: SlackQuestionWorkRecord }> {
    const result = await this.store.enqueue(workId, threadKey, input, this.now());
    if (result.created) void this.publishSafely();
    return result;
  }

  async publishOnce(): Promise<number> {
    const due = await this.store.listDue(this.now(), this.config.triage.workQueuePublisherBatchSize);
    const results = await Promise.all(due.map((record) => this.publishRecord(record)));
    const published = results.filter(Boolean).length;
    recordMetric("cerebro_slack_companion_question_work_publications_total", { outcome: "published" }, published);
    return published;
  }

  async consumeOnce(abortSignal?: AbortSignal): Promise<boolean> {
    const visibilitySeconds = this.config.triage.workQueueVisibilityTimeoutSeconds;
    const delivery = await this.queue.receive(visibilitySeconds, abortSignal);
    if (!delivery) return false;
    const parsed = slackQuestionTaskEnvelopeSchema.safeParse(parseJson(delivery.body));
    if (!parsed.success || parsed.data.tenantId !== this.config.cerebro.tenantId) {
      telemetryEvent("companion.question_work.invalid_delivery", {
        component: "work-loop",
        operation: "consume_durable_question",
        "work.delivery.receive_count": delivery.receiveCount,
      });
      return false;
    }
    const task = parsed.data;
    const leaseMs = visibilitySeconds * 1_000;
    const claim = await this.store.claim(task, this.workerId, this.now(), leaseMs);
    if (claim.reason === "completed" || claim.reason === "stale") {
      await this.queue.delete(delivery.receiptHandle);
      return true;
    }
    if (claim.reason !== "claimed") return false;

    const heartbeatMs = Math.max(5_000, Math.floor(leaseMs / 3));
    const heartbeat = setInterval(() => {
      void Promise.all([
        this.store.renew(task, this.workerId, this.now(), leaseMs),
        this.queue.changeVisibility(delivery.receiptHandle, visibilitySeconds),
      ]).catch((error) => logger.warn("slack.question_work.heartbeat_failed", {
        event: "slack.question_work.heartbeat_failed",
        workIdHash: task.taskId.split(":", 1)[0],
        error: boundedError(error),
      }));
    }, heartbeatMs);
    heartbeat.unref?.();
    try {
      const result = await this.runner.run(claim.record);
      if (!result.completed) {
        await this.retry(task, delivery, result.error ?? "Slack question work did not complete.");
        return false;
      }
      const completedAt = this.now().toISOString();
      await this.store.complete(task, this.workerId, completedAt);
      await this.queue.delete(delivery.receiptHandle);
      telemetryEvent("companion.question_work.completed", {
        component: "work-loop",
        operation: "consume_durable_question",
        "work.delivery.receive_count": delivery.receiveCount,
        "work.recovered": delivery.receiveCount > 1,
      });
      return true;
    } catch (error) {
      await this.retry(task, delivery, boundedError(error));
      return false;
    } finally {
      clearInterval(heartbeat);
    }
  }

  private async retry(task: SlackQuestionTaskEnvelope, delivery: SlackQuestionWorkDelivery, error: string): Promise<void> {
    const delaySeconds = Math.min(300, 5 * (2 ** Math.max(0, delivery.receiveCount - 1)));
    const now = this.now();
    await this.store.retry(task, this.workerId, now, new Date(now.getTime() + delaySeconds * 1_000).toISOString(), error);
    await this.queue.changeVisibility(delivery.receiptHandle, delaySeconds);
    recordMetric("cerebro_slack_companion_question_work_retries_total", { outcome: "retry" }, 1);
  }

  private async publishRecord(record: SlackQuestionWorkOutboxRecord): Promise<boolean> {
    const leaseId = randomUUID();
    const now = this.now();
    const claimed = await this.store.claimPublication(record, leaseId, now, Math.max(5_000, this.config.triage.workQueuePublisherIntervalMs * 5));
    if (!claimed) return false;
    const receipt = await this.queue.send(record.task);
    await this.store.markPublished(record, leaseId, this.now().toISOString(), receipt.messageId);
    return true;
  }

  private async publishSafely(): Promise<void> {
    if (!this.running || this.publishing || this.now().getTime() < this.nextPublishAttemptAt) return;
    this.publishing = true;
    try {
      await this.publishOnce();
      this.publishFailureCount = 0;
      this.nextPublishAttemptAt = 0;
    } catch (error) {
      this.publishFailureCount += 1;
      const retryInMs = slackQuestionPublisherBackoffMs(
        this.publishFailureCount,
        this.config.triage.workQueuePublisherIntervalMs,
      );
      this.nextPublishAttemptAt = this.now().getTime() + retryInMs;
      recordMetric("cerebro_slack_companion_question_work_publications_total", { outcome: "failed" }, 1);
      logger.warn("slack.question_work.publish_failed", {
        event: "slack.question_work.publish_failed",
        error: boundedError(error),
        failureCount: this.publishFailureCount,
        retryInMs,
      });
    } finally {
      this.publishing = false;
    }
  }

  private async consumeLoop(index: number): Promise<void> {
    while (this.running) {
      try {
        await this.consumeOnce(this.abortController?.signal);
      } catch (error) {
        if (!this.running || isAbortError(error)) return;
        logger.warn("slack.question_work.consume_failed", {
          event: "slack.question_work.consume_failed",
          workerIndex: index,
          error: boundedError(error),
        });
      }
    }
  }
}

export function slackQuestionPublisherBackoffMs(failureCount: number, publisherIntervalMs: number): number {
  const baseMs = Math.max(1_000, Math.floor(publisherIntervalMs));
  const exponent = Math.min(6, Math.max(0, Math.floor(failureCount) - 1));
  return Math.min(60_000, baseMs * (2 ** exponent));
}

function parseJson(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return undefined;
  }
}

function boundedError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.replace(/\s+/g, " ").trim().slice(0, 500) || "Slack question work failed.";
}

function conditionalCheckFailed(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const name = "name" in error ? String((error as { name?: unknown }).name ?? "") : "";
  const message = "message" in error ? String((error as { message?: unknown }).message ?? "") : "";
  return /ConditionalCheckFailed|TransactionCanceled/i.test(`${name} ${message}`);
}

function isAbortError(error: unknown): boolean {
  const name = error && typeof error === "object" && "name" in error ? String((error as { name?: unknown }).name ?? "") : "";
  return name === "AbortError";
}

function isOutboxRecord(value: SlackQuestionWorkOutboxRecord | undefined): value is SlackQuestionWorkOutboxRecord {
  return Boolean(value);
}

function queueGroupId(threadKey: string): string {
  return `slack-thread-${createHash("sha256").update(threadKey).digest("hex")}`;
}
