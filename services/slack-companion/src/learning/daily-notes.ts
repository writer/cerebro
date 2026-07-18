import { createHash } from "node:crypto";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand, QueryCommand } from "@aws-sdk/lib-dynamodb";
import type { AppConfig } from "../config/index.js";
import { logger } from "../logger.js";
import { redactSecurityText } from "../security/redaction.js";
import type { SecurityMemoryStore } from "./security-memory/index.js";

export type DailyNoteKind =
  | "assistant_answer"
  | "triage_outcome"
  | "slash_command"
  | "finding_action"
  | "runtime_action"
  | "safety_refusal"
  | "encounter_story"
  | "lifecycle"
  | "maintenance"
  | "failure";

export interface DailyNoteInput {
  kind: DailyNoteKind;
  title: string;
  summary: string;
  details?: string;
  tags?: string[];
  channelId?: string;
  sourceTs?: string;
  outcome?: string;
  senderKind?: "human" | "bot";
  trafficKind?: "human_request" | "machine_handoff";
}

export interface DailyNoteRecord extends DailyNoteInput {
  id: string;
  localDate: string;
  createdAt: string;
}

export interface DailyConsolidationResult {
  status: "disabled" | "outside_window" | "already_done" | "no_notes" | "consolidated";
  targetDate?: string;
  noteCount?: number;
  summary?: string;
}

interface CommandSender {
  send(command: unknown): Promise<unknown>;
}

interface DailyNotesOptions {
  dynamo?: CommandSender;
  now?: () => Date;
}

export class DailyNotesService {
  private readonly dynamo?: CommandSender;
  private readonly now: () => Date;
  private readonly notesByDate = new Map<string, DailyNoteRecord[]>();
  private readonly consolidationClaims = new Set<string>();
  private interval?: NodeJS.Timeout;

  constructor(
    private readonly config: AppConfig,
    private readonly memory: SecurityMemoryStore,
    options: DailyNotesOptions = {},
  ) {
    this.now = options.now ?? (() => new Date());
    if (config.learning.dailyNotesEnabled && config.learning.tableName) {
      this.dynamo = options.dynamo ?? DynamoDBDocumentClient.from(new DynamoDBClient({}), {
        marshallOptions: { removeUndefinedValues: true },
      });
    }
  }

  start(): void {
    if (!this.config.learning.dailyNotesEnabled || this.interval) return;
    this.interval = setInterval(() => {
      void this.consolidateIfDue().catch((error) => logger.warn("daily note consolidation failed", { error: String(error) }));
    }, this.config.learning.dailyNotesCheckIntervalMs);
    this.interval.unref?.();
    void this.consolidateIfDue().catch((error) => logger.warn("daily note consolidation failed", { error: String(error) }));
  }

  stop(): void {
    if (this.interval) clearInterval(this.interval);
    this.interval = undefined;
  }

  async record(input: DailyNoteInput): Promise<DailyNoteRecord | undefined> {
    if (!this.config.learning.dailyNotesEnabled) return undefined;

    const now = this.now();
    const localDate = localDateFor(now, this.config.learning.dailyNotesTimeZone);
    const record: DailyNoteRecord = {
      id: stableId([input.kind, input.title, input.channelId ?? "", input.sourceTs ?? "", now.toISOString()]),
      kind: input.kind,
      title: clean(input.title, 180),
      summary: clean(input.summary, 1200),
      details: input.details ? clean(input.details, 2200) : undefined,
      tags: (input.tags ?? []).map((tag) => clean(tag, 48)).filter(Boolean).slice(0, 12),
      channelId: input.channelId,
      sourceTs: input.sourceTs,
      outcome: input.outcome ? clean(input.outcome, 120) : undefined,
      senderKind: input.senderKind,
      trafficKind: input.trafficKind,
      localDate,
      createdAt: now.toISOString(),
    };

    if (this.dynamo && this.config.learning.tableName) {
      await this.dynamo.send(new PutCommand({
        TableName: this.config.learning.tableName,
        Item: {
          pk: notesPartitionKey(this.config, localDate),
          sk: `note#${record.createdAt}#${record.id}`,
          ...record,
          expires_at: Math.floor(now.getTime() / 1000) + this.config.learning.dailyNotesRetentionDays * 86_400,
        },
      }));
      return record;
    }

    const notes = this.notesByDate.get(localDate) ?? [];
    notes.push(record);
    this.notesByDate.set(localDate, notes);
    return record;
  }

  async consolidateIfDue(): Promise<DailyConsolidationResult> {
    if (!this.config.learning.dailyNotesEnabled) return { status: "disabled" };

    const now = this.now();
    if (!isConsolidationWindow(now, this.config)) {
      return { status: "outside_window" };
    }

    const targetDate = localDateFor(new Date(now.getTime() - 86_400_000), this.config.learning.dailyNotesTimeZone);
    const claimed = await this.claimConsolidation(targetDate);
    if (!claimed) {
      return { status: "already_done", targetDate };
    }

    const notes = await this.notesForDate(targetDate);
    if (notes.length === 0) {
      await this.runMemoryHygiene();
      return { status: "no_notes", targetDate, noteCount: 0 };
    }

    const digest = buildDigest(targetDate, notes);
    await this.memory.remember({
      kind: "investigation_note",
      topic: `Cerebro daily notes ${targetDate}`,
      summary: digest.summary,
      details: digest.details,
      tags: ["daily-notes", "nightly-consolidation", ...digest.tags],
      sourceKind: "daily_notes",
    });

    if (digest.safetyCount > 0 || digest.failureCount > 0) {
      await this.memory.remember({
        kind: "runbook_note",
        topic: `Cerebro operating follow-ups ${targetDate}`,
        summary: digest.followUpSummary,
        details: digest.followUpDetails,
        tags: ["daily-follow-up", "cerebro-operations"],
        sourceKind: "daily_notes",
      });
    }

    await this.runMemoryHygiene();

    return {
      status: "consolidated",
      targetDate,
      noteCount: notes.length,
      summary: digest.summary,
    };
  }

  private async notesForDate(localDate: string): Promise<DailyNoteRecord[]> {
    if (this.dynamo && this.config.learning.tableName) {
      const response = await this.dynamo.send(new QueryCommand({
        TableName: this.config.learning.tableName,
        KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues: {
          ":pk": notesPartitionKey(this.config, localDate),
          ":prefix": "note#",
        },
        ScanIndexForward: true,
        Limit: 500,
      })) as { Items?: Record<string, unknown>[] };
      return (response.Items ?? []).map(toDailyNote).filter(Boolean) as DailyNoteRecord[];
    }
    return [...(this.notesByDate.get(localDate) ?? [])];
  }

  private async claimConsolidation(localDate: string): Promise<boolean> {
    const key = `consolidate#${localDate}`;
    if (this.consolidationClaims.has(key)) return false;
    this.consolidationClaims.add(key);

    if (!this.dynamo || !this.config.learning.tableName) return true;

    try {
      const now = this.now();
      await this.dynamo.send(new PutCommand({
        TableName: this.config.learning.tableName,
        Item: {
          pk: `tenant#${this.config.cerebro.tenantId}#daily-note-consolidations`,
          sk: key,
          targetDate: localDate,
          claimedAt: now.toISOString(),
          expires_at: Math.floor(now.getTime() / 1000) + 7 * 86_400,
        },
        ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)",
      }));
      return true;
    } catch (error) {
      if (typeof error === "object" && error !== null && (error as { name?: string }).name === "ConditionalCheckFailedException") {
        return false;
      }
      this.consolidationClaims.delete(key);
      throw error;
    }
  }

  private async runMemoryHygiene(): Promise<void> {
    await this.memory.runHygiene().catch((error) => logger.warn("memory hygiene failed", { error: String(error) }));
  }
}

function buildDigest(localDate: string, notes: DailyNoteRecord[]) {
  const counts = countBy(notes.map((note) => note.kind));
  const outcomes = countBy(notes.map((note) => note.outcome).filter(Boolean) as string[]);
  const traffic = countBy(notes.map((note) => note.trafficKind ?? "unclassified"));
  const topTags = topCounts(notes.flatMap((note) => note.tags ?? []), 8);
  const notable = notes
    .filter((note) => note.kind === "safety_refusal" || note.kind === "failure" || note.kind === "assistant_answer" || note.kind === "triage_outcome" || note.kind === "encounter_story")
    .slice(0, 12);
  const safetyCount = counts.safety_refusal ?? 0;
  const failureCount = counts.failure ?? 0;
  const summary = [
    `Cerebro processed ${notes.length} noted event(s) on ${localDate}.`,
    Object.entries(counts).map(([kind, count]) => `${kind}=${count}`).join(", "),
    topTags.length > 0 ? `Common tags: ${topTags.map(([tag, count]) => `${tag} (${count})`).join(", ")}.` : "",
  ].filter(Boolean).join(" ");
  const details = [
    `Outcomes: ${Object.entries(outcomes).map(([outcome, count]) => `${outcome}=${count}`).join(", ") || "none recorded"}.`,
    `Traffic: ${Object.entries(traffic).map(([kind, count]) => `${kind}=${count}`).join(", ") || "none recorded"}.`,
    "Notable notes:",
    ...notable.map((note) => `- ${note.kind}: ${note.title} - ${note.summary}`),
  ].join("\n");
  const followUpSummary = [
    safetyCount > 0 ? `${safetyCount} dangerous or unsafe request(s) were refused.` : "",
    failureCount > 0 ? `${failureCount} failure note(s) need review.` : "",
  ].filter(Boolean).join(" ");
  const followUpDetails = notes
    .filter((note) => note.kind === "safety_refusal" || note.kind === "failure")
    .slice(0, 12)
    .map((note) => `- ${note.kind}: ${note.title} - ${note.summary}`)
    .join("\n");

  return {
    summary,
    details,
    followUpSummary,
    followUpDetails,
    safetyCount,
    failureCount,
    tags: topTags.map(([tag]) => tag).slice(0, 4),
  };
}

function toDailyNote(item: Record<string, unknown>): DailyNoteRecord | undefined {
  if (typeof item.id !== "string" || typeof item.kind !== "string" || typeof item.title !== "string" || typeof item.summary !== "string" || typeof item.localDate !== "string" || typeof item.createdAt !== "string") {
    return undefined;
  }
  return {
    id: item.id,
    kind: item.kind as DailyNoteKind,
    title: item.title,
    summary: item.summary,
    details: typeof item.details === "string" ? item.details : undefined,
    tags: Array.isArray(item.tags) ? item.tags.map(String) : [],
    channelId: typeof item.channelId === "string" ? item.channelId : undefined,
    sourceTs: typeof item.sourceTs === "string" ? item.sourceTs : undefined,
    outcome: typeof item.outcome === "string" ? item.outcome : undefined,
    senderKind: item.senderKind === "human" || item.senderKind === "bot" ? item.senderKind : undefined,
    trafficKind: item.trafficKind === "human_request" || item.trafficKind === "machine_handoff" ? item.trafficKind : undefined,
    localDate: item.localDate,
    createdAt: item.createdAt,
  };
}

function notesPartitionKey(config: AppConfig, localDate: string): string {
  return `tenant#${config.cerebro.tenantId}#daily-notes#${localDate}`;
}

function isConsolidationWindow(now: Date, config: AppConfig): boolean {
  const parts = localParts(now, config.learning.dailyNotesTimeZone);
  const currentMinutes = parts.hour * 60 + parts.minute;
  const startMinutes = config.learning.dailyNotesNightStartHour * 60;
  const endMinutes = config.learning.dailyNotesNightEndHour * 60;
  const consolidationMinutes = config.learning.dailyNotesConsolidationHour * 60 + config.learning.dailyNotesConsolidationMinute;
  return currentMinutes >= startMinutes && currentMinutes < endMinutes && currentMinutes >= consolidationMinutes;
}

function localDateFor(date: Date, timeZone: string): string {
  const parts = localParts(date, timeZone);
  return `${parts.year}-${pad(parts.month)}-${pad(parts.day)}`;
}

function localParts(date: Date, timeZone: string): { year: number; month: number; day: number; hour: number; minute: number } {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).formatToParts(date);
  const value = (type: string) => Number(parts.find((part) => part.type === type)?.value);
  return {
    year: value("year"),
    month: value("month"),
    day: value("day"),
    hour: value("hour") % 24,
    minute: value("minute"),
  };
}

function clean(value: string, max: number): string {
  return redactSecurityText(value).replace(/\s+/g, " ").trim().slice(0, max);
}

function stableId(parts: string[]): string {
  return createHash("sha256").update(parts.join("\u0000")).digest("hex").slice(0, 32);
}

function countBy(values: string[]): Record<string, number> {
  return values.reduce<Record<string, number>>((acc, value) => {
    acc[value] = (acc[value] ?? 0) + 1;
    return acc;
  }, {});
}

function topCounts(values: string[], limit: number): Array<[string, number]> {
  return Object.entries(countBy(values))
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .slice(0, limit);
}

function pad(value: number): string {
  return String(value).padStart(2, "0");
}
