import { randomUUID } from "node:crypto";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand, QueryCommand } from "@aws-sdk/lib-dynamodb";
import type { SlackActor } from "../../auth.js";
import type { AppConfig } from "../../config/index.js";
import {
  normalizeContextProviderIds,
  type ScheduleCadence,
  type ScheduledJobDraft,
  type ScheduleTrigger,
} from "../schedule-parser.js";
import type { CommandSender, ScheduledJobRecord, ScheduledJobServiceOptions } from "./types.js";

export class ScheduledJobStore {
  private readonly dynamo?: CommandSender;
  private readonly tableName?: string;
  private readonly now: () => Date;
  private readonly inMemoryJobs = new Map<string, ScheduledJobRecord>();

  constructor(
    private readonly config: AppConfig,
    options: ScheduledJobServiceOptions = {},
  ) {
    this.now = options.now ?? (() => new Date());
    this.tableName = config.schedules.tableName;
    if (config.schedules.enabled && this.tableName) {
      this.dynamo = options.dynamo ?? DynamoDBDocumentClient.from(new DynamoDBClient({}));
    }
  }

  async create(draft: ScheduledJobDraft, actor: SlackActor): Promise<ScheduledJobRecord> {
    const now = this.now().toISOString();
    const record: ScheduledJobRecord = {
      ...draft,
      id: `sched-${randomUUID().slice(0, 8)}`,
      status: "active",
      createdAt: now,
      updatedAt: now,
      createdBy: actor,
    };
    await this.put(record);
    return record;
  }

  async get(jobId: string): Promise<ScheduledJobRecord | undefined> {
    return (await this.list()).find((job) => job.id === jobId || job.id.endsWith(jobId));
  }

  async list(): Promise<ScheduledJobRecord[]> {
    if (this.dynamo && this.tableName) {
      const response = await this.dynamo.send(new QueryCommand({
        TableName: this.tableName,
        KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues: {
          ":pk": partitionKey(this.config),
          ":prefix": "schedule#",
        },
      })) as { Items?: Record<string, unknown>[] };
      return (response.Items ?? []).map(toScheduledJobRecord).filter(isScheduledJobRecord).sort(compareJobs);
    }
    return [...this.inMemoryJobs.values()].sort(compareJobs);
  }

  async put(record: ScheduledJobRecord): Promise<void> {
    const normalized = { ...record, updatedAt: this.now().toISOString() };
    if (this.dynamo && this.tableName) {
      await this.dynamo.send(new PutCommand({
        TableName: this.tableName,
        Item: {
          pk: partitionKey(this.config),
          sk: `schedule#${record.id}`,
          ...normalized,
        },
      }));
      return;
    }
    this.inMemoryJobs.set(normalized.id, normalized);
  }
}

function partitionKey(config: AppConfig): string {
  return `tenant#${config.cerebro.tenantId}#schedules`;
}

function toScheduledJobRecord(item: Record<string, unknown>): ScheduledJobRecord | undefined {
  if (typeof item.id !== "string" || typeof item.description !== "string" || typeof item.status !== "string" || typeof item.createdAt !== "string" || typeof item.updatedAt !== "string") {
    return undefined;
  }
  if (item.status !== "active" && item.status !== "paused" && item.status !== "completed" && item.status !== "blocked") {
    return undefined;
  }
  if (!Array.isArray(item.steps)) return undefined;
  const createdBy = objectValue(item.createdBy);
  if (!createdBy || typeof createdBy.slackUserId !== "string" || typeof createdBy.actorId !== "string") {
    return undefined;
  }
  return {
    id: item.id,
    description: item.description,
    status: item.status,
    schedule: objectValue(item.schedule) as ScheduleCadence | undefined,
    trigger: objectValue(item.trigger) as ScheduleTrigger | undefined,
    steps: item.steps as ScheduledJobRecord["steps"],
    contextProviders: normalizeContextProviderIds(item.contextProviders),
    channelId: typeof item.channelId === "string" ? item.channelId : undefined,
    nextRunAt: typeof item.nextRunAt === "string" ? item.nextRunAt : undefined,
    warnings: Array.isArray(item.warnings) ? item.warnings.map(String) : [],
    createdAt: item.createdAt,
    updatedAt: item.updatedAt,
    createdBy: {
      slackUserId: createdBy.slackUserId,
      actorId: createdBy.actorId,
      displayName: typeof createdBy.displayName === "string" ? createdBy.displayName : undefined,
    },
    lastRunAt: typeof item.lastRunAt === "string" ? item.lastRunAt : undefined,
    lastStatus: item.lastStatus === "completed" || item.lastStatus === "failed" ? item.lastStatus : undefined,
    lastSummary: typeof item.lastSummary === "string" ? item.lastSummary : undefined,
    consecutiveFailures: typeof item.consecutiveFailures === "number" ? item.consecutiveFailures : undefined,
    lastFailureAt: typeof item.lastFailureAt === "string" ? item.lastFailureAt : undefined,
    lastError: typeof item.lastError === "string" ? item.lastError : undefined,
  };
}

function isScheduledJobRecord(value: ScheduledJobRecord | undefined): value is ScheduledJobRecord {
  return Boolean(value);
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function compareJobs(left: ScheduledJobRecord, right: ScheduledJobRecord): number {
  return (left.nextRunAt ?? left.createdAt).localeCompare(right.nextRunAt ?? right.createdAt);
}
