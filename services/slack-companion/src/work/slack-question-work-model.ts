import { createHash } from "node:crypto";
import { z } from "zod";
import type { AppConfig } from "../config/index.js";
import type { SlackQuestionWorkInput } from "./companion-work-loop.js";

export const SLACK_QUESTION_WORK_SCHEMA_VERSION = "cerebro.slack-question-work/v1" as const;
export const SLACK_QUESTION_WORK_INDEX = "slack-question-work-index";
const WORK_DISPATCH_DELAY_MS = 2_000;

export const slackQuestionWorkInputSchema = z.object({
  interactionId: z.string().min(1).max(200).optional(),
  channelId: z.string().min(1).max(120),
  userId: z.string().min(1).max(120).optional(),
  senderKind: z.enum(["human", "bot"]).optional(),
  question: z.string().min(1).max(40_000),
  ts: z.string().min(1).max(80),
  threadTs: z.string().min(1).max(80).optional(),
  replyThreadTs: z.string().min(1).max(80),
}).strict();

export const slackQuestionTaskEnvelopeSchema = z.object({
  schemaVersion: z.literal(SLACK_QUESTION_WORK_SCHEMA_VERSION),
  taskId: z.string().min(1).max(200),
  tenantId: z.string().min(1).max(120),
  workId: z.string().min(1).max(300),
  revision: z.number().int().positive(),
  threadKey: z.string().min(1).max(300),
  availableAt: z.string().datetime(),
  enqueuedAt: z.string().datetime(),
}).strict();

export type SlackQuestionTaskEnvelope = z.infer<typeof slackQuestionTaskEnvelopeSchema>;
export type SlackQuestionWorkStatus = "queued" | "leased" | "retry" | "completed";

export interface SlackQuestionWorkRecord {
  pk: string;
  sk: "state";
  workId: string;
  revision: number;
  threadKey: string;
  status: SlackQuestionWorkStatus;
  input: SlackQuestionWorkInput;
  enqueuedAt: string;
  updatedAt: string;
  availableAt: string;
  attempts: number;
  leaseOwner?: string;
  leaseExpiresAt?: string;
  completedAt?: string;
  lastError?: string;
}

export interface SlackQuestionWorkOutboxRecord {
  pk: string;
  sk: string;
  task: SlackQuestionTaskEnvelope;
}

export function createSlackQuestionWorkItems(
  config: AppConfig,
  workId: string,
  threadKey: string,
  input: SlackQuestionWorkInput,
  now: Date,
): { state: Record<string, unknown>; outbox: Record<string, unknown>; record: SlackQuestionWorkRecord } {
  const parsedInput = slackQuestionWorkInputSchema.parse(input);
  const revision = 1;
  const enqueuedAt = now.toISOString();
  const availableAt = new Date(now.getTime() + WORK_DISPATCH_DELAY_MS).toISOString();
  const pk = slackQuestionWorkPartitionKey(config.cerebro.tenantId, workId);
  const task: SlackQuestionTaskEnvelope = {
    schemaVersion: SLACK_QUESTION_WORK_SCHEMA_VERSION,
    taskId: `${workIdHash(workId)}:${revision}`,
    tenantId: config.cerebro.tenantId,
    workId,
    revision,
    threadKey,
    availableAt,
    enqueuedAt,
  };
  const record: SlackQuestionWorkRecord = {
    pk,
    sk: "state",
    workId,
    revision,
    threadKey,
    status: "queued",
    input: parsedInput,
    enqueuedAt,
    updatedAt: enqueuedAt,
    availableAt,
    attempts: 0,
  };
  return {
    record,
    state: {
      ...record,
      recordType: "slack_question_work",
      expires_at: Math.floor(now.getTime() / 1_000) + 7 * 86_400,
    },
    outbox: {
      pk,
      sk: slackQuestionWorkSortKey(revision),
      recordType: "slack_question_work_outbox",
      task,
      slack_work_scope: slackQuestionWorkScope(config.cerebro.tenantId),
      slack_work_available_at: `${availableAt}#${task.taskId}`,
      publication_attempts: 0,
      expires_at: Math.floor(now.getTime() / 1_000) + 7 * 86_400,
    },
  };
}

export function slackQuestionWorkRecordFromItem(value: unknown): SlackQuestionWorkRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const item = value as Record<string, unknown>;
  if (item.sk !== "state" || item.recordType !== "slack_question_work") return undefined;
  const input = slackQuestionWorkInputSchema.safeParse(item.input);
  const status = item.status;
  if (!input.success || !isWorkStatus(status)) return undefined;
  const required = [item.pk, item.workId, item.threadKey, item.enqueuedAt, item.updatedAt, item.availableAt];
  if (required.some((entry) => typeof entry !== "string")) return undefined;
  if (typeof item.revision !== "number" || !Number.isInteger(item.revision) || item.revision < 1) return undefined;
  return {
    pk: item.pk as string,
    sk: "state",
    workId: item.workId as string,
    revision: item.revision,
    threadKey: item.threadKey as string,
    status,
    input: input.data,
    enqueuedAt: item.enqueuedAt as string,
    updatedAt: item.updatedAt as string,
    availableAt: item.availableAt as string,
    attempts: typeof item.attempts === "number" ? item.attempts : 0,
    leaseOwner: optionalString(item.leaseOwner),
    leaseExpiresAt: optionalString(item.leaseExpiresAt),
    completedAt: optionalString(item.completedAt),
    lastError: optionalString(item.lastError),
  };
}

export function slackQuestionWorkOutboxFromItem(value: unknown): SlackQuestionWorkOutboxRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const item = value as Record<string, unknown>;
  const task = slackQuestionTaskEnvelopeSchema.safeParse(item.task);
  if (!task.success || typeof item.pk !== "string" || typeof item.sk !== "string") return undefined;
  return { pk: item.pk, sk: item.sk, task: task.data };
}

export function slackQuestionWorkPartitionKey(tenantId: string, workId: string): string {
  return `tenant#${tenantId}#slack-question#${workIdHash(workId)}`;
}

export function slackQuestionWorkSortKey(revision: number): string {
  return `work#${String(revision).padStart(16, "0")}`;
}

export function slackQuestionWorkScope(tenantId: string): string {
  return `tenant#${tenantId}#slack-question-work`;
}

function workIdHash(workId: string): string {
  return createHash("sha256").update(workId).digest("hex").slice(0, 40);
}

function isWorkStatus(value: unknown): value is SlackQuestionWorkStatus {
  return value === "queued" || value === "leased" || value === "retry" || value === "completed";
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}
