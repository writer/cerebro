import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, PutCommand } from "@aws-sdk/lib-dynamodb";
import type { AppConfig } from "../config/index.js";
import type { CuratedMemoryBatchRejectionCategory } from "./security-memory-curator.js";

export type SlackChannelBackfillStatus = "running" | "completed" | "capped" | "failed";

export interface SlackChannelBackfillCounts {
  rootsScanned: number;
  threadMessagesScanned: number;
  threadErrors: number;
  humanMessages: number;
  machineMessages: number;
  subtypeMessages: number;
  missingUserMessages: number;
  missingTimestampMessages: number;
  emptyMessages: number;
  directMentions: number;
  batchesProcessed: number;
  batchesSkipped: number;
  recordsStored: number;
  recordsRejected: number;
}

export interface SlackChannelBackfillCheckpoint extends SlackChannelBackfillCounts {
  channelId: string;
  status: SlackChannelBackfillStatus;
  targetOldestTs: string;
  snapshotTs: string;
  nextLatestTs: string;
  runId: string;
  updatedAt: string;
  curationVersion?: string;
}

export interface SlackChannelBackfillRunReceipt extends SlackChannelBackfillCounts {
  runId: string;
  status: "completed" | "failed";
  startedAt: string;
  completedAt: string;
  targetOldestTs: string;
  snapshotTs: string;
  channelsDiscovered: number;
  channelsProcessed: number;
  channelsSkipped: number;
  channelsCapped: number;
  curationVersion: string;
  errorType?: string;
}

export interface SlackChannelBackfillBatchMarker {
  fingerprint: string;
  channelId: string;
  messageCount: number;
  result: "stored" | "rejected";
  recordsStored?: number;
  rejectionCategory?: CuratedMemoryBatchRejectionCategory;
  curationVersion?: string;
  processedAt: string;
}

export interface SlackChannelBackfillProgressStore {
  checkpoint(channelId: string): Promise<SlackChannelBackfillCheckpoint | undefined>;
  saveCheckpoint(checkpoint: SlackChannelBackfillCheckpoint): Promise<void>;
  batchMarker(channelId: string, fingerprint: string): Promise<SlackChannelBackfillBatchMarker | undefined>;
  markBatch(marker: SlackChannelBackfillBatchMarker): Promise<void>;
  saveRun(receipt: SlackChannelBackfillRunReceipt): Promise<void>;
}

type DocumentClient = Pick<DynamoDBDocumentClient, "send">;

export class SlackChannelBackfillStore implements SlackChannelBackfillProgressStore {
  private readonly client?: DocumentClient;
  private readonly tableName?: string;
  private readonly partitionKey: string;
  private readonly checkpoints = new Map<string, SlackChannelBackfillCheckpoint>();
  private readonly batches = new Map<string, SlackChannelBackfillBatchMarker>();
  private readonly runs = new Map<string, SlackChannelBackfillRunReceipt>();

  constructor(config: AppConfig, options: { client?: DocumentClient } = {}) {
    this.tableName = config.learning.tableName;
    this.partitionKey = `tenant#${config.cerebro.tenantId}#slack-channel-backfill`;
    if (this.tableName) {
      this.client = options.client ?? DynamoDBDocumentClient.from(new DynamoDBClient({}), {
        marshallOptions: { removeUndefinedValues: true },
      });
    }
  }

  async checkpoint(channelId: string): Promise<SlackChannelBackfillCheckpoint | undefined> {
    if (!this.client || !this.tableName) return this.checkpoints.get(channelId);
    const response = await this.client.send(new GetCommand({
      TableName: this.tableName,
      Key: { pk: this.partitionKey, sk: channelKey(channelId) },
    }));
    return decodeCheckpoint(response.Item);
  }

  async saveCheckpoint(checkpoint: SlackChannelBackfillCheckpoint): Promise<void> {
    if (!this.client || !this.tableName) {
      this.checkpoints.set(checkpoint.channelId, structuredClone(checkpoint));
      return;
    }
    await this.client.send(new PutCommand({
      TableName: this.tableName,
      Item: {
        pk: this.partitionKey,
        sk: channelKey(checkpoint.channelId),
        recordType: "slack_channel_backfill_checkpoint",
        ...checkpoint,
      },
    }));
  }

  async batchMarker(channelId: string, fingerprint: string): Promise<SlackChannelBackfillBatchMarker | undefined> {
    const key = batchKey(channelId, fingerprint);
    if (!this.client || !this.tableName) return this.batches.get(key);
    const response = await this.client.send(new GetCommand({
      TableName: this.tableName,
      Key: { pk: this.partitionKey, sk: key },
    }));
    return decodeBatchMarker(response.Item);
  }

  async markBatch(marker: SlackChannelBackfillBatchMarker): Promise<void> {
    const key = batchKey(marker.channelId, marker.fingerprint);
    if (!this.client || !this.tableName) {
      this.batches.set(key, structuredClone(marker));
      return;
    }
    await this.client.send(new PutCommand({
      TableName: this.tableName,
      Item: {
        pk: this.partitionKey,
        sk: key,
        recordType: "slack_channel_backfill_batch",
        ...marker,
        expires_at: Math.floor(Date.now() / 1_000) + 400 * 86_400,
      },
    }));
  }

  async saveRun(receipt: SlackChannelBackfillRunReceipt): Promise<void> {
    if (!this.client || !this.tableName) {
      this.runs.set(receipt.runId, structuredClone(receipt));
      return;
    }
    await this.client.send(new PutCommand({
      TableName: this.tableName,
      Item: {
        pk: this.partitionKey,
        sk: `run#${receipt.runId}`,
        recordType: "slack_channel_backfill_run",
        ...receipt,
      },
    }));
  }
}

function channelKey(channelId: string): string {
  return `channel#${channelId}`;
}

function batchKey(channelId: string, fingerprint: string): string {
  return `batch#${channelId}#${fingerprint}`;
}

function decodeCheckpoint(item: Record<string, unknown> | undefined): SlackChannelBackfillCheckpoint | undefined {
  if (!item || typeof item.channelId !== "string" || !isStatus(item.status)) return undefined;
  if (typeof item.targetOldestTs !== "string" || typeof item.snapshotTs !== "string" || typeof item.nextLatestTs !== "string") return undefined;
  if (typeof item.runId !== "string" || typeof item.updatedAt !== "string") return undefined;
  const counts = decodeCounts(item);
  return {
    channelId: item.channelId,
    status: item.status,
    targetOldestTs: item.targetOldestTs,
    snapshotTs: item.snapshotTs,
    nextLatestTs: item.nextLatestTs,
    runId: item.runId,
    updatedAt: item.updatedAt,
    ...(typeof item.curationVersion === "string" && item.curationVersion ? { curationVersion: item.curationVersion } : {}),
    ...counts,
  };
}

function decodeBatchMarker(item: Record<string, unknown> | undefined): SlackChannelBackfillBatchMarker | undefined {
  if (!item || typeof item.fingerprint !== "string" || typeof item.channelId !== "string") return undefined;
  if (typeof item.messageCount !== "number" || (item.result !== "stored" && item.result !== "rejected") || typeof item.processedAt !== "string") return undefined;
  const recordsStored = typeof item.recordsStored === "number" ? count(item.recordsStored) : undefined;
  const rejectionCategory = isRejectionCategory(item.rejectionCategory) ? item.rejectionCategory : undefined;
  const curationVersion = typeof item.curationVersion === "string" && item.curationVersion ? item.curationVersion : undefined;
  return {
    fingerprint: item.fingerprint,
    channelId: item.channelId,
    messageCount: count(item.messageCount),
    result: item.result,
    ...(recordsStored === undefined ? {} : { recordsStored }),
    ...(rejectionCategory ? { rejectionCategory } : {}),
    ...(curationVersion ? { curationVersion } : {}),
    processedAt: item.processedAt,
  };
}

function decodeCounts(item: Record<string, unknown>): SlackChannelBackfillCounts {
  return {
    rootsScanned: count(item.rootsScanned),
    threadMessagesScanned: count(item.threadMessagesScanned),
    threadErrors: count(item.threadErrors),
    humanMessages: count(item.humanMessages),
    machineMessages: count(item.machineMessages),
    subtypeMessages: count(item.subtypeMessages),
    missingUserMessages: count(item.missingUserMessages),
    missingTimestampMessages: count(item.missingTimestampMessages),
    emptyMessages: count(item.emptyMessages),
    directMentions: count(item.directMentions),
    batchesProcessed: count(item.batchesProcessed),
    batchesSkipped: count(item.batchesSkipped),
    recordsStored: count(item.recordsStored),
    recordsRejected: count(item.recordsRejected),
  };
}

function count(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? Math.floor(value) : 0;
}

function isStatus(value: unknown): value is SlackChannelBackfillStatus {
  return value === "running" || value === "completed" || value === "capped" || value === "failed";
}

function isRejectionCategory(value: unknown): value is CuratedMemoryBatchRejectionCategory {
  return value === "social_chatter"
    || value === "transient_status"
    || value === "unsupported_or_speculative"
    || value === "no_reusable_knowledge"
    || value === "duplicate_only"
    || value === "other";
}
