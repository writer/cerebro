import { createHash, randomUUID } from "node:crypto";
import type { Logger } from "../logger.js";
import { logger as defaultLogger } from "../logger.js";
import { telemetryEvent } from "../telemetry.js";
import type { SlackChannelHistoryReader } from "../slack/channel-history.js";
import { slackLearningCandidateRejection } from "../slack/channel-history.js";
import type { SlackMessage } from "../slack/research/types.js";
import { SLACK_CHANNEL_CURATION_VERSION } from "./slack-channel-learning.js";
import type { SlackChannelLearningInput, SlackChannelLearningService } from "./slack-channel-learning.js";
import type {
  SlackChannelBackfillCheckpoint,
  SlackChannelBackfillCounts,
  SlackChannelBackfillProgressStore,
  SlackChannelBackfillRunReceipt,
} from "./slack-channel-backfill-store.js";

const MAX_PAGE_ATTEMPTS = 3;
const PAGE_RETRY_BASE_MS = 2_000;

export interface SlackChannelBackfillOptions {
  targetOldestTs: string;
  snapshotTs: string;
  batchSize: number;
  maxChannels: number;
  maxRootsPerChannel: number;
  pageSize?: number;
  maxThreadMessages?: number;
}

interface SlackChannelBackfillDependencies {
  history: SlackChannelHistoryReader;
  learning: Pick<SlackChannelLearningService, "learnBatch">;
  store: SlackChannelBackfillProgressStore;
  excludedChannelIds?: Set<string>;
  logger?: Logger;
  sleep?: (milliseconds: number) => Promise<void>;
}

interface ChannelOutcome {
  checkpoint: SlackChannelBackfillCheckpoint;
  skipped: boolean;
}

export class SlackChannelBackfillService {
  private readonly logger: Logger;
  private readonly sleep: (milliseconds: number) => Promise<void>;

  constructor(private readonly deps: SlackChannelBackfillDependencies) {
    this.logger = deps.logger ?? defaultLogger;
    this.sleep = deps.sleep ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
  }

  async run(options: SlackChannelBackfillOptions): Promise<SlackChannelBackfillRunReceipt> {
    validateOptions(options);
    const runId = randomUUID();
    const startedAt = new Date().toISOString();
    const receipt = emptyReceipt(runId, startedAt, options);
    this.log("info", "slack channel backfill started", "slack.channel_backfill.started", {
      runId,
      targetOldestTs: options.targetOldestTs,
      snapshotTs: options.snapshotTs,
      batchSize: options.batchSize,
      maxChannels: options.maxChannels,
      maxRootsPerChannel: options.maxRootsPerChannel,
      curationVersion: SLACK_CHANNEL_CURATION_VERSION,
    });

    try {
      const [botUserId, channels] = await Promise.all([
        this.deps.history.botUserId(),
        this.deps.history.joinedChannels(options.maxChannels),
      ]);
      receipt.channelsDiscovered = channels.length;
      for (const channel of channels) {
        if (this.deps.excludedChannelIds?.has(channel.id)) {
          receipt.channelsSkipped += 1;
          continue;
        }
        try {
          const outcome = await this.processChannel(channel.id, botUserId, runId, options);
          addCounts(receipt, outcome.checkpoint);
          if (outcome.skipped) receipt.channelsSkipped += 1;
          else receipt.channelsProcessed += 1;
          if (outcome.checkpoint.status === "capped") receipt.channelsCapped += 1;
        } catch (error) {
          const failed = await this.deps.store.checkpoint(channel.id).catch(() => undefined);
          if (failed) addCounts(receipt, failed);
          throw error;
        }
      }
      receipt.completedAt = new Date().toISOString();
      await this.deps.store.saveRun(receipt);
      this.log("info", "slack channel backfill completed", "slack.channel_backfill.completed", receiptFields(receipt));
      telemetryEvent("slack.channel_backfill.completed", telemetryFields(receipt));
      return receipt;
    } catch (error) {
      const failed: SlackChannelBackfillRunReceipt = {
        ...receipt,
        status: "failed",
        completedAt: new Date().toISOString(),
        errorType: errorType(error),
      };
      await this.deps.store.saveRun(failed).catch(() => undefined);
      this.log("error", "slack channel backfill failed", "slack.channel_backfill.failed", receiptFields(failed));
      telemetryEvent("slack.channel_backfill.failed", telemetryFields(failed));
      throw error;
    }
  }

  private async processChannel(
    channelId: string,
    botUserId: string,
    runId: string,
    options: SlackChannelBackfillOptions,
  ): Promise<ChannelOutcome> {
    const saved = await this.deps.store.checkpoint(channelId);
    const currentCuration = saved?.curationVersion === SLACK_CHANNEL_CURATION_VERSION;
    if (currentCuration && saved?.status === "completed" && tsAtOrBefore(saved.targetOldestTs, options.targetOldestTs)) {
      return { checkpoint: saved, skipped: true };
    }

    const continuing = Boolean(currentCuration && saved && Number(saved.nextLatestTs) > Number(options.targetOldestTs));
    const checkpoint: SlackChannelBackfillCheckpoint = {
      ...(continuing ? countsFrom(saved!) : emptyCounts()),
      channelId,
      status: "running",
      targetOldestTs: options.targetOldestTs,
      snapshotTs: continuing ? saved!.snapshotTs : options.snapshotTs,
      nextLatestTs: continuing ? saved!.nextLatestTs : options.snapshotTs,
      runId,
      updatedAt: new Date().toISOString(),
      curationVersion: SLACK_CHANNEL_CURATION_VERSION,
    };
    await this.deps.store.saveCheckpoint(checkpoint);

    try {
      while (Number(checkpoint.nextLatestTs) > Number(options.targetOldestTs)) {
        const page = await this.deps.history.historyPage(channelId, {
          oldestTs: options.targetOldestTs,
          latestTs: checkpoint.nextLatestTs,
          limit: options.pageSize ?? 100,
        });
        if (page.messages.length === 0) {
          checkpoint.status = "completed";
          break;
        }

        await this.processPageWithRetries(page.messages, channelId, botUserId, runId, checkpoint, options);

        const oldestRootTs = oldestTimestamp(page.messages);
        if (!oldestRootTs) throw new Error("Slack history page did not contain a valid timestamp.");
        checkpoint.nextLatestTs = oldestRootTs;
        checkpoint.updatedAt = new Date().toISOString();
        if (checkpoint.rootsScanned >= options.maxRootsPerChannel) {
          checkpoint.status = "capped";
        } else if (!page.hasMore) {
          checkpoint.status = "completed";
        }
        await this.deps.store.saveCheckpoint(checkpoint);
        this.log("info", "slack channel backfill page completed", "slack.channel_backfill.page_completed", {
          runId,
          channelId,
          status: checkpoint.status,
          rootsScanned: checkpoint.rootsScanned,
          humanMessages: checkpoint.humanMessages,
          batchesProcessed: checkpoint.batchesProcessed,
          recordsStored: checkpoint.recordsStored,
          nextLatestTs: checkpoint.nextLatestTs,
        });
        if (checkpoint.status !== "running") break;
      }
      if (checkpoint.status === "running") checkpoint.status = "completed";
      checkpoint.updatedAt = new Date().toISOString();
      await this.deps.store.saveCheckpoint(checkpoint);
      return { checkpoint, skipped: false };
    } catch (error) {
      checkpoint.status = "failed";
      checkpoint.updatedAt = new Date().toISOString();
      await this.deps.store.saveCheckpoint(checkpoint).catch(() => undefined);
      throw error;
    }
  }

  private async processPageWithRetries(
    roots: SlackMessage[],
    channelId: string,
    botUserId: string,
    runId: string,
    checkpoint: SlackChannelBackfillCheckpoint,
    options: SlackChannelBackfillOptions,
  ): Promise<void> {
    const pageBaseline = countsFrom(checkpoint);
    let lastError: unknown;
    for (let attempt = 1; attempt <= MAX_PAGE_ATTEMPTS; attempt += 1) {
      assignCounts(checkpoint, pageBaseline);
      try {
        checkpoint.rootsScanned += roots.length;
        const batches = await this.learningBatches(roots, channelId, botUserId, checkpoint, options);
        for (const batch of batches) await this.processBatch(channelId, batch, checkpoint);
        return;
      } catch (error) {
        lastError = error;
        assignCounts(checkpoint, pageBaseline);
        const retrying = attempt < MAX_PAGE_ATTEMPTS;
        this.log("warn", "slack channel backfill page attempt failed", "slack.channel_backfill.page_attempt_failed", {
          runId,
          channelId,
          attempt,
          retrying,
          pageRoots: roots.length,
          nextLatestTs: checkpoint.nextLatestTs,
          errorType: errorType(error),
        });
        if (retrying) await this.sleep(PAGE_RETRY_BASE_MS * attempt);
      }
    }
    throw lastError;
  }

  private async learningBatches(
    roots: SlackMessage[],
    channelId: string,
    botUserId: string,
    counts: SlackChannelBackfillCounts,
    options: SlackChannelBackfillOptions,
  ): Promise<SlackChannelLearningInput[][]> {
    const batches: SlackChannelLearningInput[][] = [];
    const ambient: SlackChannelLearningInput[] = [];
    for (const root of roots) {
      let conversation = [root];
      if ((root.reply_count ?? 0) > 0 && root.ts) {
        try {
          conversation = dedupeMessages([root, ...await this.deps.history.threadReplies(channelId, root.ts, options.maxThreadMessages)]);
          counts.threadMessagesScanned += Math.max(0, conversation.length - 1);
        } catch (error) {
          counts.threadErrors += 1;
          this.log("warn", "slack channel backfill thread read failed", "slack.channel_backfill.thread_failed", {
            channelId,
            threadTs: root.ts,
            errorType: errorType(error),
          });
        }
      }
      const candidates = conversation
        .filter((message) => timestampInRange(message.ts, options.targetOldestTs, options.snapshotTs))
        .flatMap((message) => this.learningInput(message, channelId, botUserId, counts))
        .sort((left, right) => Number(left.ts) - Number(right.ts));
      if (candidates.length > 1) {
        flushAmbient(ambient, batches, options.batchSize, true);
        batches.push(...chunks(candidates, options.batchSize));
      } else {
        ambient.push(...candidates);
        flushAmbient(ambient, batches, options.batchSize, false);
      }
    }
    flushAmbient(ambient, batches, options.batchSize, true);
    return batches;
  }

  private learningInput(
    message: SlackMessage,
    channelId: string,
    botUserId: string,
    counts: SlackChannelBackfillCounts,
  ): SlackChannelLearningInput[] {
    const rejection = slackLearningCandidateRejection(message, botUserId);
    if (rejection) {
      incrementRejection(counts, rejection);
      return [];
    }
    counts.humanMessages += 1;
    return [{ channelId, ts: message.ts!, text: message.text! }];
  }

  private async processBatch(
    channelId: string,
    batch: SlackChannelLearningInput[],
    counts: SlackChannelBackfillCounts,
  ): Promise<void> {
    const orderedBatch = [...batch].sort((left, right) => Number(left.ts) - Number(right.ts));
    const fingerprint = batchFingerprint(channelId, orderedBatch);
    const existing = await this.deps.store.batchMarker(channelId, fingerprint);
    if (existing?.curationVersion === SLACK_CHANNEL_CURATION_VERSION) {
      counts.batchesSkipped += 1;
      counts.batchesProcessed += 1;
      if (existing.result === "stored") counts.recordsStored += existing.recordsStored ?? 1;
      else counts.recordsRejected += 1;
      return;
    }
    const result = await this.learnWithRetries(channelId, orderedBatch);
    if (!result.accepted || (result.reason !== "stored" && result.reason !== "rejected")) {
      throw new Error(`Channel learning rejected a valid backfill batch: ${result.reason}`);
    }
    counts.batchesProcessed += 1;
    const recordsStored = result.recordsStored ?? (result.reason === "stored" ? 1 : 0);
    if (result.reason === "stored") counts.recordsStored += recordsStored;
    else counts.recordsRejected += 1;
    await this.deps.store.markBatch({
      fingerprint,
      channelId,
      messageCount: orderedBatch.length,
      result: result.reason,
      recordsStored,
      rejectionCategory: result.rejectionCategory,
      curationVersion: SLACK_CHANNEL_CURATION_VERSION,
      processedAt: new Date().toISOString(),
    });
  }

  private async learnWithRetries(channelId: string, batch: SlackChannelLearningInput[]) {
    let lastError: unknown;
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      try {
        return await this.deps.learning.learnBatch(channelId, batch);
      } catch (error) {
        lastError = error;
        if (attempt < 3) await this.sleep(1_000 * 2 ** (attempt - 1));
      }
    }
    throw lastError;
  }

  private log(level: "info" | "warn" | "error", message: string, event: string, fields: Record<string, unknown>): void {
    this.logger[level](message, { event, ...fields });
  }
}

function validateOptions(options: SlackChannelBackfillOptions): void {
  if (!(Number(options.targetOldestTs) > 0) || !(Number(options.snapshotTs) > Number(options.targetOldestTs))) throw new Error("Backfill timestamps are invalid.");
  if (!Number.isInteger(options.batchSize) || options.batchSize < 2 || options.batchSize > 50) throw new Error("Backfill batch size must be between 2 and 50.");
  if (!Number.isInteger(options.maxChannels) || options.maxChannels < 1) throw new Error("Backfill max channels must be positive.");
  if (!Number.isInteger(options.maxRootsPerChannel) || options.maxRootsPerChannel < 1) throw new Error("Backfill max roots per channel must be positive.");
}

function emptyCounts(): SlackChannelBackfillCounts {
  return { rootsScanned: 0, threadMessagesScanned: 0, threadErrors: 0, humanMessages: 0, machineMessages: 0, subtypeMessages: 0, missingUserMessages: 0, missingTimestampMessages: 0, emptyMessages: 0, directMentions: 0, batchesProcessed: 0, batchesSkipped: 0, recordsStored: 0, recordsRejected: 0 };
}

function countsFrom(value: SlackChannelBackfillCounts): SlackChannelBackfillCounts {
  return Object.fromEntries(Object.keys(emptyCounts()).map((key) => [key, value[key as keyof SlackChannelBackfillCounts]])) as unknown as SlackChannelBackfillCounts;
}

function emptyReceipt(runId: string, startedAt: string, options: SlackChannelBackfillOptions): SlackChannelBackfillRunReceipt {
  return { ...emptyCounts(), runId, status: "completed", startedAt, completedAt: startedAt, targetOldestTs: options.targetOldestTs, snapshotTs: options.snapshotTs, channelsDiscovered: 0, channelsProcessed: 0, channelsSkipped: 0, channelsCapped: 0, curationVersion: SLACK_CHANNEL_CURATION_VERSION };
}

function addCounts(target: SlackChannelBackfillCounts, source: SlackChannelBackfillCounts): void {
  for (const key of Object.keys(emptyCounts()) as Array<keyof SlackChannelBackfillCounts>) target[key] += source[key];
}

function assignCounts(target: SlackChannelBackfillCounts, source: SlackChannelBackfillCounts): void {
  for (const key of Object.keys(emptyCounts()) as Array<keyof SlackChannelBackfillCounts>) target[key] = source[key];
}

function incrementRejection(counts: SlackChannelBackfillCounts, reason: ReturnType<typeof slackLearningCandidateRejection>): void {
  if (reason === "machine") counts.machineMessages += 1;
  else if (reason === "subtype") counts.subtypeMessages += 1;
  else if (reason === "missing_user") counts.missingUserMessages += 1;
  else if (reason === "missing_timestamp") counts.missingTimestampMessages += 1;
  else if (reason === "empty") counts.emptyMessages += 1;
  else if (reason === "cerebro_mention") counts.directMentions += 1;
}

function flushAmbient(ambient: SlackChannelLearningInput[], batches: SlackChannelLearningInput[][], batchSize: number, flushPartial: boolean): void {
  while (ambient.length >= batchSize || (flushPartial && ambient.length > 0)) batches.push(ambient.splice(0, batchSize));
}

function chunks<T>(values: T[], size: number): T[][] {
  const result: T[][] = [];
  for (let index = 0; index < values.length; index += size) result.push(values.slice(index, index + size));
  return result;
}

function dedupeMessages(messages: SlackMessage[]): SlackMessage[] {
  const seen = new Set<string>();
  return messages.filter((message) => {
    const key = message.ts?.trim();
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function oldestTimestamp(messages: SlackMessage[]): string | undefined {
  return messages.map((message) => message.ts).filter((value): value is string => Boolean(value)).sort((left, right) => Number(left) - Number(right))[0];
}

function timestampInRange(ts: string | undefined, oldestTs: string, snapshotTs: string): boolean {
  const value = Number(ts);
  return Number.isFinite(value) && value >= Number(oldestTs) && value <= Number(snapshotTs);
}

function tsAtOrBefore(left: string, right: string): boolean {
  return Number(left) <= Number(right);
}

function batchFingerprint(channelId: string, batch: SlackChannelLearningInput[]): string {
  const timestamps = batch.map((message) => message.ts).sort((left, right) => Number(left) - Number(right));
  return createHash("sha256").update([channelId, ...timestamps].join("|")).digest("hex").slice(0, 24);
}

function errorType(error: unknown): string {
  return error instanceof Error ? error.name : "unknown";
}

function receiptFields(receipt: SlackChannelBackfillRunReceipt): Record<string, unknown> {
  return { ...receipt, errorType: receipt.errorType };
}

function telemetryFields(receipt: SlackChannelBackfillRunReceipt): Record<string, string | number | boolean | undefined> {
  return { component: "channel-backfill", operation: "backfill", status: receipt.status, run_id: receipt.runId, curation_version: receipt.curationVersion, channels_discovered: receipt.channelsDiscovered, channels_processed: receipt.channelsProcessed, human_messages: receipt.humanMessages, machine_messages: receipt.machineMessages, batches_processed: receipt.batchesProcessed, records_stored: receipt.recordsStored, records_rejected: receipt.recordsRejected, error_kind: receipt.errorType };
}
