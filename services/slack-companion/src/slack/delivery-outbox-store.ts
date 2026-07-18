import { createHash } from "node:crypto";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";

export type SlackDeliveryStatus = "queued" | "leased" | "retry" | "posted" | "failed";

export interface SlackDeliveryReceiptContext {
  kind: string;
  refId: string;
  assistantInitiative?: {
    intendedUserId: string;
    expiresAt?: string;
    goalId?: string;
  };
}

export interface EnqueueSlackDeliveryInput {
  idempotencyKey: string;
  channelId: string;
  threadTs?: string;
  text: string;
  receiptContext?: SlackDeliveryReceiptContext;
}

export interface SlackDeliveryRecord {
  id: string;
  inputFingerprint: string;
  clientMessageId: string;
  channelId: string;
  threadTs?: string;
  text: string;
  receiptContext?: SlackDeliveryReceiptContext;
  status: SlackDeliveryStatus;
  attempts: number;
  createdAt: string;
  updatedAt: string;
  nextAttemptAt?: string;
  leaseOwner?: string;
  leaseExpiresAt?: string;
  leasedAt?: string;
  postedAt?: string;
  postedTs?: string;
  lastError?: string;
}

export interface SlackDeliveryLeaseInput {
  workerId: string;
  now: string;
  leaseExpiresAt: string;
}

export interface SlackDeliveryFailureInput {
  workerId: string;
  status: "retry" | "failed";
  failedAt: string;
  nextAttemptAt?: string;
  error: string;
}

export interface SlackDeliveryOutboxStore {
  enqueue(record: SlackDeliveryRecord): Promise<SlackDeliveryRecord>;
  get(id: string): Promise<SlackDeliveryRecord | undefined>;
  listDue(now: string, limit: number): Promise<SlackDeliveryRecord[]>;
  tryLease(id: string, input: SlackDeliveryLeaseInput): Promise<SlackDeliveryRecord | undefined>;
  markSlackAccepted(id: string, workerId: string, postedAt: string, postedTs: string): Promise<SlackDeliveryRecord>;
  completePosted(id: string, workerId: string, completedAt: string): Promise<SlackDeliveryRecord>;
  completeFailure(id: string, input: SlackDeliveryFailureInput): Promise<SlackDeliveryRecord>;
}

interface CommandSender {
  send(command: unknown): Promise<unknown>;
}

interface DynamoSlackDeliveryOutboxStoreOptions {
  dynamo?: CommandSender;
}

const deliveryRetentionSeconds = 30 * 24 * 60 * 60;
export const slackDeliveryDueIndexName = "slack-delivery-due-index";

export class DynamoSlackDeliveryOutboxStore implements SlackDeliveryOutboxStore {
  private readonly dynamo: CommandSender;
  private readonly partitionKey: string;
  private readonly dueScope: string;

  constructor(
    private readonly tableName: string,
    tenantId: string,
    options: DynamoSlackDeliveryOutboxStoreOptions = {},
  ) {
    this.partitionKey = slackDeliveryPartitionKey(tenantId);
    this.dueScope = `${this.partitionKey}#due`;
    this.dynamo = options.dynamo ?? DynamoDBDocumentClient.from(new DynamoDBClient({}), {
      marshallOptions: { removeUndefinedValues: true },
    });
  }

  async enqueue(record: SlackDeliveryRecord): Promise<SlackDeliveryRecord> {
    try {
      await this.dynamo.send(new PutCommand({
        TableName: this.tableName,
        Item: this.item(record),
        ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)",
      }));
      return cloneDelivery(record);
    } catch (error) {
      if (!conditionalCheckFailed(error)) throw error;
      const existing = await this.get(record.id);
      if (!existing) throw new Error(`Slack delivery ${record.id} exists but could not be read.`);
      assertMatchingEnqueue(existing, record);
      return existing;
    }
  }

  async get(id: string): Promise<SlackDeliveryRecord | undefined> {
    const response = await this.dynamo.send(new GetCommand({
      TableName: this.tableName,
      Key: this.key(id),
      ConsistentRead: true,
    })) as { Item?: unknown };
    return deliveryFromItem(response.Item);
  }

  async listDue(now: string, limit: number): Promise<SlackDeliveryRecord[]> {
    const boundedLimit = Math.max(0, limit);
    if (boundedLimit === 0) return [];
    const response = await this.dynamo.send(new QueryCommand({
      TableName: this.tableName,
      IndexName: slackDeliveryDueIndexName,
      KeyConditionExpression: "delivery_due_scope = :scope AND delivery_due_at <= :dueAt",
      ExpressionAttributeValues: {
        ":scope": this.dueScope,
        ":dueAt": dueIndexUpperBound(now),
      },
      Limit: boundedLimit,
      ScanIndexForward: true,
    })) as { Items?: unknown[] };
    return (response.Items ?? [])
      .map(deliveryFromItem)
      .filter(isDeliveryRecord)
      .filter((record) => deliveryIsDue(record, now))
      .map(cloneDelivery);
  }

  async tryLease(id: string, input: SlackDeliveryLeaseInput): Promise<SlackDeliveryRecord | undefined> {
    try {
      const response = await this.dynamo.send(new UpdateCommand({
        TableName: this.tableName,
        Key: this.key(id),
        UpdateExpression: "SET #status = :leased, leaseOwner = :workerId, leaseExpiresAt = :leaseExpiresAt, leasedAt = :now, attempts = if_not_exists(attempts, :zero) + :one, updatedAt = :now, delivery_due_scope = :dueScope, delivery_due_at = :dueAt",
        ConditionExpression: "((#status IN (:queued, :retry)) AND nextAttemptAt <= :now) OR (#status = :leased AND leaseExpiresAt <= :now)",
        ExpressionAttributeNames: { "#status": "status" },
        ExpressionAttributeValues: {
          ":queued": "queued",
          ":retry": "retry",
          ":leased": "leased",
          ":workerId": input.workerId,
          ":leaseExpiresAt": input.leaseExpiresAt,
          ":dueScope": this.dueScope,
          ":dueAt": dueIndexValue(input.leaseExpiresAt, id),
          ":now": input.now,
          ":zero": 0,
          ":one": 1,
        },
        ReturnValues: "ALL_NEW",
      })) as { Attributes?: unknown };
      return deliveryFromItem(response.Attributes);
    } catch (error) {
      if (conditionalCheckFailed(error)) return undefined;
      throw error;
    }
  }

  async markSlackAccepted(id: string, workerId: string, postedAt: string, postedTs: string): Promise<SlackDeliveryRecord> {
    const response = await this.dynamo.send(new UpdateCommand({
      TableName: this.tableName,
      Key: this.key(id),
      UpdateExpression: "SET postedAt = :postedAt, postedTs = :postedTs, updatedAt = :postedAt",
      ConditionExpression: "#status = :leased AND leaseOwner = :workerId AND attribute_not_exists(postedTs)",
      ExpressionAttributeNames: { "#status": "status" },
      ExpressionAttributeValues: {
        ":leased": "leased",
        ":workerId": workerId,
        ":postedAt": postedAt,
        ":postedTs": postedTs,
      },
      ReturnValues: "ALL_NEW",
    })) as { Attributes?: unknown };
    return requiredDelivery(response.Attributes, id);
  }

  async completePosted(id: string, workerId: string, completedAt: string): Promise<SlackDeliveryRecord> {
    const response = await this.dynamo.send(new UpdateCommand({
      TableName: this.tableName,
      Key: this.key(id),
      UpdateExpression: "SET #status = :posted, updatedAt = :completedAt, expires_at = :expiresAt REMOVE leaseOwner, leaseExpiresAt, leasedAt, nextAttemptAt, lastError, delivery_due_scope, delivery_due_at",
      ConditionExpression: "#status = :leased AND leaseOwner = :workerId AND attribute_exists(postedTs)",
      ExpressionAttributeNames: { "#status": "status" },
      ExpressionAttributeValues: {
        ":leased": "leased",
        ":posted": "posted",
        ":workerId": workerId,
        ":completedAt": completedAt,
        ":expiresAt": expiresAt(completedAt),
      },
      ReturnValues: "ALL_NEW",
    })) as { Attributes?: unknown };
    return requiredDelivery(response.Attributes, id);
  }

  async completeFailure(id: string, input: SlackDeliveryFailureInput): Promise<SlackDeliveryRecord> {
    const terminal = input.status === "failed";
    const response = await this.dynamo.send(new UpdateCommand({
      TableName: this.tableName,
      Key: this.key(id),
      UpdateExpression: terminal
        ? "SET #status = :status, updatedAt = :failedAt, lastError = :error, expires_at = :expiresAt REMOVE leaseOwner, leaseExpiresAt, leasedAt, nextAttemptAt, delivery_due_scope, delivery_due_at"
        : "SET #status = :status, updatedAt = :failedAt, lastError = :error, nextAttemptAt = :nextAttemptAt, delivery_due_scope = :dueScope, delivery_due_at = :dueAt REMOVE leaseOwner, leaseExpiresAt, leasedAt",
      ConditionExpression: "#status = :leased AND leaseOwner = :workerId",
      ExpressionAttributeNames: { "#status": "status" },
      ExpressionAttributeValues: {
        ":leased": "leased",
        ":status": input.status,
        ":workerId": input.workerId,
        ":failedAt": input.failedAt,
        ":error": cleanError(input.error),
        ...(terminal
          ? { ":expiresAt": expiresAt(input.failedAt) }
          : {
              ":nextAttemptAt": requiredNextAttemptAt(input),
              ":dueScope": this.dueScope,
              ":dueAt": dueIndexValue(requiredNextAttemptAt(input), id),
            }),
      },
      ReturnValues: "ALL_NEW",
    })) as { Attributes?: unknown };
    return requiredDelivery(response.Attributes, id);
  }

  private item(record: SlackDeliveryRecord): Record<string, unknown> {
    return {
      pk: this.partitionKey,
      sk: `delivery#${record.id}`,
      ...cloneDelivery(record),
      delivery_due_scope: this.dueScope,
      delivery_due_at: dueIndexValue(requiredRecordNextAttemptAt(record), record.id),
    };
  }

  private key(id: string): Record<string, string> {
    return { pk: this.partitionKey, sk: `delivery#${id}` };
  }
}

export class InMemorySlackDeliveryOutboxStore implements SlackDeliveryOutboxStore {
  private readonly records = new Map<string, SlackDeliveryRecord>();

  async enqueue(record: SlackDeliveryRecord): Promise<SlackDeliveryRecord> {
    const existing = this.records.get(record.id);
    if (existing) {
      assertMatchingEnqueue(existing, record);
      return cloneDelivery(existing);
    }
    this.records.set(record.id, cloneDelivery(record));
    return cloneDelivery(record);
  }

  async get(id: string): Promise<SlackDeliveryRecord | undefined> {
    const record = this.records.get(id);
    return record ? cloneDelivery(record) : undefined;
  }

  async listDue(now: string, limit: number): Promise<SlackDeliveryRecord[]> {
    return [...this.records.values()]
      .filter((record) => deliveryIsDue(record, now))
      .sort(compareDueDeliveries)
      .slice(0, Math.max(0, limit))
      .map(cloneDelivery);
  }

  async tryLease(id: string, input: SlackDeliveryLeaseInput): Promise<SlackDeliveryRecord | undefined> {
    const current = this.records.get(id);
    if (!current || !deliveryIsDue(current, input.now)) return undefined;
    const leased: SlackDeliveryRecord = {
      ...current,
      status: "leased",
      attempts: current.attempts + 1,
      leaseOwner: input.workerId,
      leaseExpiresAt: input.leaseExpiresAt,
      leasedAt: input.now,
      updatedAt: input.now,
    };
    this.records.set(id, leased);
    return cloneDelivery(leased);
  }

  async markSlackAccepted(id: string, workerId: string, postedAt: string, postedTs: string): Promise<SlackDeliveryRecord> {
    const current = this.requiredLease(id, workerId);
    if (current.postedTs) throw new Error(`Slack delivery ${id} already has an accepted Slack timestamp.`);
    const accepted: SlackDeliveryRecord = {
      ...current,
      postedAt,
      postedTs,
      updatedAt: postedAt,
    };
    this.records.set(id, accepted);
    return cloneDelivery(accepted);
  }

  async completePosted(id: string, workerId: string, completedAt: string): Promise<SlackDeliveryRecord> {
    const current = this.requiredLease(id, workerId);
    if (!current.postedTs) throw new Error(`Slack delivery ${id} has no accepted Slack timestamp.`);
    const posted: SlackDeliveryRecord = {
      ...withoutLease(current),
      status: "posted",
      updatedAt: completedAt,
    };
    delete posted.nextAttemptAt;
    delete posted.lastError;
    this.records.set(id, posted);
    return cloneDelivery(posted);
  }

  async completeFailure(id: string, input: SlackDeliveryFailureInput): Promise<SlackDeliveryRecord> {
    const current = this.requiredLease(id, input.workerId);
    const failed: SlackDeliveryRecord = {
      ...withoutLease(current),
      status: input.status,
      updatedAt: input.failedAt,
      lastError: cleanError(input.error),
      nextAttemptAt: input.status === "retry" ? requiredNextAttemptAt(input) : current.nextAttemptAt,
    };
    if (input.status === "failed") delete failed.nextAttemptAt;
    this.records.set(id, failed);
    return cloneDelivery(failed);
  }

  private requiredLease(id: string, workerId: string): SlackDeliveryRecord {
    const current = this.records.get(id);
    if (!current || current.status !== "leased" || current.leaseOwner !== workerId) {
      throw new Error(`Slack delivery ${id} is not leased by ${workerId}.`);
    }
    return current;
  }
}

export function createSlackDeliveryRecord(
  tenantId: string,
  input: EnqueueSlackDeliveryInput,
  now: Date,
): SlackDeliveryRecord {
  const normalized = normalizeInput(input);
  const id = createHash("sha256")
    .update(`slack-delivery-v1\0${tenantId.trim()}\0${normalized.idempotencyKey}`)
    .digest("hex")
    .slice(0, 32);
  const timestamp = now.toISOString();
  return {
    id,
    inputFingerprint: createHash("sha256")
      .update(JSON.stringify([
        normalized.channelId,
        normalized.threadTs ?? "",
        normalized.text,
        normalized.receiptContext?.kind ?? "",
        normalized.receiptContext?.refId ?? "",
        normalized.receiptContext?.assistantInitiative?.intendedUserId ?? "",
        normalized.receiptContext?.assistantInitiative?.expiresAt ?? "",
        normalized.receiptContext?.assistantInitiative?.goalId ?? "",
      ]))
      .digest("hex"),
    clientMessageId: deterministicClientMessageId(id),
    channelId: normalized.channelId,
    threadTs: normalized.threadTs,
    text: normalized.text,
    receiptContext: normalized.receiptContext,
    status: "queued",
    attempts: 0,
    createdAt: timestamp,
    updatedAt: timestamp,
    nextAttemptAt: timestamp,
  };
}

function normalizeInput(input: EnqueueSlackDeliveryInput): EnqueueSlackDeliveryInput {
  const idempotencyKey = requiredText(input.idempotencyKey, "idempotency key", 500);
  const channelId = requiredText(input.channelId, "channel id", 120);
  const text = requiredText(input.text, "Slack delivery text", 40_000);
  const threadTs = input.threadTs ? requiredText(input.threadTs, "thread timestamp", 80) : undefined;
  const receiptContext = input.receiptContext ? normalizeReceiptContext(input.receiptContext) : undefined;
  return { idempotencyKey, channelId, text, threadTs, receiptContext };
}

function requiredText(value: string, label: string, maxLength: number): string {
  const cleaned = value.trim();
  if (!cleaned) throw new Error(`${label} is required.`);
  if (cleaned.length > maxLength) throw new Error(`${label} exceeds ${maxLength} characters.`);
  return cleaned;
}

function deterministicClientMessageId(id: string): string {
  const bytes = Buffer.from(createHash("sha256").update(`slack-client-message-v1\0${id}`).digest("hex").slice(0, 32), "hex");
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function slackDeliveryPartitionKey(tenantId: string): string {
  return `tenant#${tenantId.trim()}#slack-delivery-outbox`;
}

function deliveryIsDue(record: SlackDeliveryRecord, now: string): boolean {
  if ((record.status === "queued" || record.status === "retry") && Boolean(record.nextAttemptAt && record.nextAttemptAt <= now)) return true;
  return record.status === "leased" && Boolean(record.leaseExpiresAt && record.leaseExpiresAt <= now);
}

function compareDueDeliveries(left: SlackDeliveryRecord, right: SlackDeliveryRecord): number {
  return (left.nextAttemptAt ?? left.updatedAt).localeCompare(right.nextAttemptAt ?? right.updatedAt)
    || left.createdAt.localeCompare(right.createdAt)
    || left.id.localeCompare(right.id);
}

function deliveryFromItem(item: unknown): SlackDeliveryRecord | undefined {
  if (!item || typeof item !== "object") return undefined;
  const value = item as Record<string, unknown>;
  if (
    typeof value.id !== "string"
    || typeof value.inputFingerprint !== "string"
    || typeof value.clientMessageId !== "string"
    || typeof value.channelId !== "string"
    || typeof value.text !== "string"
    || !deliveryStatus(value.status)
    || typeof value.attempts !== "number"
    || typeof value.createdAt !== "string"
    || typeof value.updatedAt !== "string"
  ) return undefined;
  return {
    id: value.id,
    inputFingerprint: value.inputFingerprint,
    clientMessageId: value.clientMessageId,
    channelId: value.channelId,
    threadTs: optionalString(value.threadTs),
    text: value.text,
    receiptContext: receiptContextFromItem(value.receiptContext),
    status: value.status,
    attempts: value.attempts,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
    nextAttemptAt: optionalString(value.nextAttemptAt),
    leaseOwner: optionalString(value.leaseOwner),
    leaseExpiresAt: optionalString(value.leaseExpiresAt),
    leasedAt: optionalString(value.leasedAt),
    postedAt: optionalString(value.postedAt),
    postedTs: optionalString(value.postedTs),
    lastError: optionalString(value.lastError),
  };
}

function deliveryStatus(value: unknown): value is SlackDeliveryStatus {
  return value === "queued" || value === "leased" || value === "retry" || value === "posted" || value === "failed";
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function receiptContextFromItem(value: unknown): SlackDeliveryReceiptContext | undefined {
  if (!value || typeof value !== "object") return undefined;
  const context = value as Record<string, unknown>;
  if (typeof context.kind !== "string" || typeof context.refId !== "string") return undefined;
  const assistantInitiative = assistantInitiativeContextFromItem(context.assistantInitiative);
  return {
    kind: context.kind,
    refId: context.refId,
    ...(assistantInitiative ? { assistantInitiative } : {}),
  };
}

function normalizeReceiptContext(context: SlackDeliveryReceiptContext): SlackDeliveryReceiptContext {
  const expiresAt = context.assistantInitiative?.expiresAt
    ? requiredText(context.assistantInitiative.expiresAt, "assistant initiative expiry", 80)
    : undefined;
  const goalId = context.assistantInitiative?.goalId
    ? requiredText(context.assistantInitiative.goalId, "assistant initiative goal id", 300)
    : undefined;
  const assistantInitiative = context.assistantInitiative ? {
    intendedUserId: requiredText(context.assistantInitiative.intendedUserId, "assistant initiative user id", 120),
    ...(expiresAt ? { expiresAt } : {}),
    ...(goalId ? { goalId } : {}),
  } : undefined;
  return {
    kind: requiredText(context.kind, "receipt context kind", 80),
    refId: requiredText(context.refId, "receipt context reference", 300),
    ...(assistantInitiative ? { assistantInitiative } : {}),
  };
}

function assistantInitiativeContextFromItem(value: unknown): SlackDeliveryReceiptContext["assistantInitiative"] {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const context = value as Record<string, unknown>;
  if (typeof context.intendedUserId !== "string") return undefined;
  const expiresAt = optionalString(context.expiresAt);
  const goalId = optionalString(context.goalId);
  return {
    intendedUserId: context.intendedUserId,
    ...(expiresAt ? { expiresAt } : {}),
    ...(goalId ? { goalId } : {}),
  };
}

function isDeliveryRecord(record: SlackDeliveryRecord | undefined): record is SlackDeliveryRecord {
  return Boolean(record);
}

function requiredDelivery(item: unknown, id: string): SlackDeliveryRecord {
  const record = deliveryFromItem(item);
  if (!record) throw new Error(`Slack delivery ${id} update returned no record.`);
  return record;
}

function assertMatchingEnqueue(existing: SlackDeliveryRecord, proposed: SlackDeliveryRecord): void {
  if (existing.inputFingerprint !== proposed.inputFingerprint) {
    throw new Error(`Slack delivery idempotency key conflict for ${proposed.id}.`);
  }
}

function requiredNextAttemptAt(input: SlackDeliveryFailureInput): string {
  if (!input.nextAttemptAt) throw new Error("Retry delivery requires a next attempt timestamp.");
  return input.nextAttemptAt;
}

function requiredRecordNextAttemptAt(record: SlackDeliveryRecord): string {
  if (!record.nextAttemptAt) throw new Error(`Slack delivery ${record.id} requires a next attempt timestamp.`);
  return record.nextAttemptAt;
}

function cleanError(error: string): string {
  return error.replace(/\s+/g, " ").trim().slice(0, 500) || "Slack delivery failed.";
}

function expiresAt(timestamp: string): number {
  return Math.floor(Date.parse(timestamp) / 1_000) + deliveryRetentionSeconds;
}

function dueIndexValue(timestamp: string, id: string): string {
  return `${timestamp}#${id}`;
}

function dueIndexUpperBound(timestamp: string): string {
  return `${timestamp}#\uffff`;
}

function conditionalCheckFailed(error: unknown): boolean {
  return typeof error === "object" && error !== null && (error as { name?: string }).name === "ConditionalCheckFailedException";
}

function withoutLease(record: SlackDeliveryRecord): SlackDeliveryRecord {
  const cloned = cloneDelivery(record);
  delete cloned.leaseOwner;
  delete cloned.leaseExpiresAt;
  delete cloned.leasedAt;
  return cloned;
}

function cloneDelivery(record: SlackDeliveryRecord): SlackDeliveryRecord {
  return { ...record };
}
