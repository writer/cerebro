import type { AppConfig } from "../config/index.js";
import { SlotQueue } from "../agent/slot-queue.js";
import { logger } from "../logger.js";
import { redactSecurityText } from "../security/redaction.js";
import { recordMetric, telemetryEvent } from "../telemetry.js";
import type { CuratedMemoryBatchRejectionCategory } from "./security-memory-curator.js";
import type { SecurityMemoryStore, SecurityMemoryWriteInput } from "./security-memory/index.js";

const MAX_BUFFERED_CHANNELS = 80;
const MAX_MESSAGE_CHARS = 1_200;
export const SLACK_CHANNEL_CURATION_VERSION = "multi-facet-v2";

export interface SlackChannelLearningInput {
  channelId: string;
  ts: string;
  text: string;
}

export interface SlackChannelLearningResult {
  accepted: boolean;
  reason: "buffered" | "disabled" | "excluded_channel" | "unsupported_conversation" | "empty" | "buffer_full";
  buffered: number;
}

export interface SlackChannelLearningBatchResult {
  accepted: boolean;
  reason: "stored" | "rejected" | "disabled" | "excluded_channel" | "unsupported_conversation" | "empty" | "batch_too_large";
  messageCount: number;
  recordId?: string;
  recordIds?: string[];
  recordsStored?: number;
  rejectionCategory?: CuratedMemoryBatchRejectionCategory;
  curationVersion?: string;
}

interface BufferedChannelMessage {
  ts: string;
  text: string;
}

type ChannelLearningMemory = Pick<SecurityMemoryStore, "rememberWithRequiredCuration">
  & Partial<Pick<SecurityMemoryStore, "rememberManyWithRequiredCuration">>;

export class SlackChannelLearningService {
  private readonly buffers = new Map<string, BufferedChannelMessage[]>();
  private readonly inFlight = new Map<string, Promise<void>>();
  private readonly curationSlots = new SlotQueue(() => 1);
  private interval?: NodeJS.Timeout;
  private accepting = true;

  constructor(
    private readonly config: AppConfig,
    private readonly memory: ChannelLearningMemory,
  ) {}

  start(): void {
    if (!this.isEnabled() || this.interval) return;
    this.accepting = true;
    this.interval = setInterval(() => {
      void this.flushAll().catch((error) => this.recordFlushError(undefined, error));
    }, this.config.learning.channelLearningFlushIntervalMs);
    this.interval.unref?.();
  }

  async stop(): Promise<void> {
    this.accepting = false;
    if (this.interval) clearInterval(this.interval);
    this.interval = undefined;
    await this.flushAll();
  }

  observe(input: SlackChannelLearningInput): SlackChannelLearningResult {
    if (!this.accepting || !this.isEnabled()) return rejected("disabled");
    const channelId = input.channelId.trim();
    if (!isJoinedChannelId(channelId)) return rejected("unsupported_conversation");
    if (this.config.learning.channelLearningExcludedChannelIds.has(channelId)) return rejected("excluded_channel");
    const text = sanitizeChannelMessage(input.text);
    if (!text) return rejected("empty");
    const knownChannels = new Set([...this.buffers.keys(), ...this.inFlight.keys()]);
    if (!knownChannels.has(channelId) && knownChannels.size >= MAX_BUFFERED_CHANNELS) return rejected("buffer_full");

    const buffer = this.buffers.get(channelId) ?? [];
    buffer.push({ ts: input.ts, text });
    const maxBuffered = Math.max(this.config.learning.channelLearningBatchSize * 2, 24);
    if (buffer.length > maxBuffered) {
      const dropped = buffer.length - maxBuffered;
      buffer.splice(0, dropped);
      recordMetric("cerebro_slack_companion_channel_learning_observed_total", { result: "buffer_trimmed" }, dropped);
    }
    this.buffers.set(channelId, buffer);

    recordMetric("cerebro_slack_companion_channel_learning_observed_total", { result: "buffered" }, 1);
    if (buffer.length >= this.config.learning.channelLearningBatchSize) {
      void this.flushChannel(channelId);
    }
    return { accepted: true, reason: "buffered", buffered: buffer.length };
  }

  async learnBatch(channelIdValue: string, inputs: SlackChannelLearningInput[]): Promise<SlackChannelLearningBatchResult> {
    if (!this.isEnabled()) return rejectedBatch("disabled");
    const channelId = channelIdValue.trim();
    if (!isJoinedChannelId(channelId)) return rejectedBatch("unsupported_conversation");
    if (this.config.learning.channelLearningExcludedChannelIds.has(channelId)) return rejectedBatch("excluded_channel");
    if (inputs.length > this.config.learning.channelLearningBatchSize) return rejectedBatch("batch_too_large");
    const messages = inputs.flatMap((input) => {
      const text = sanitizeChannelMessage(input.text);
      return text ? [{ ts: input.ts, text }] : [];
    });
    if (messages.length === 0) return rejectedBatch("empty");
    return this.curationSlots.run(() => this.persistBatch(channelId, messages));
  }

  async flushAll(): Promise<void> {
    while (this.buffers.size > 0 || this.inFlight.size > 0) {
      const channelIds = new Set([...this.buffers.keys(), ...this.inFlight.keys()]);
      await Promise.all([...channelIds].map((channelId) => this.flushChannel(channelId)));
    }
  }

  private flushChannel(channelId: string): Promise<void> {
    const active = this.inFlight.get(channelId);
    if (active) return active;
    const messages = this.buffers.get(channelId);
    if (!messages?.length) return Promise.resolve();
    this.buffers.delete(channelId);

    const task = this.curationSlots.run(() => this.persistBatch(channelId, messages))
      .then(() => undefined)
      .catch((error) => this.recordFlushError(channelId, error))
      .finally(() => this.inFlight.delete(channelId));
    this.inFlight.set(channelId, task);
    return task;
  }

  private async persistBatch(channelId: string, messages: BufferedChannelMessage[]): Promise<SlackChannelLearningBatchResult> {
    const latest = messages.at(-1)!;
    const candidate: SecurityMemoryWriteInput = {
      kind: "team_context",
      topic: `Joined Slack channel context from ${channelId}`,
      summary: "Review this passive human channel batch for reusable company operating context.",
      details: messages.map((message, index) => `Message ${index + 1}: ${message.text}`).join("\n"),
      tags: ["slack-channel-learning", "passive-context"],
      channelId,
      sourceTs: latest.ts,
      sourceKind: "slack_channel",
      classification: "passive_channel_candidate",
      sourceArtifacts: messages.slice(-16).map((message) => `slack:${channelId}:${message.ts}`),
      stalenessPolicy: "until_reverified",
      promotionState: "candidate",
    };
    const curated = this.memory.rememberManyWithRequiredCuration
      ? await this.memory.rememberManyWithRequiredCuration(candidate)
      : await this.memory.rememberWithRequiredCuration(candidate).then((record) => ({
        records: record ? [record] : [],
        storedCount: record ? 1 : 0,
        reason: record ? "Stored one curated memory." : "No reusable operating knowledge.",
        rejectionCategory: record ? undefined : "no_reusable_knowledge" as const,
      }));
    const result = curated.storedCount > 0 ? "stored" : "rejected";
    recordMetric("cerebro_slack_companion_channel_learning_batch_total", { result }, 1);
    recordMetric("cerebro_slack_companion_channel_learning_records_stored_total", {}, curated.storedCount);
    telemetryEvent("slack.channel_learning.batch_completed", {
      component: "channel-learning",
      operation: "curate_batch",
      "slack.channel_id": channelId,
      "learning.message_count": messages.length,
      "learning.result": result,
      "learning.records_stored": curated.storedCount,
      "learning.rejection_category": curated.rejectionCategory ?? "none",
      "learning.curation_version": SLACK_CHANNEL_CURATION_VERSION,
    });
    logger.info("slack channel learning batch completed", {
      event: "slack.channel_learning.batch_completed",
      channelId,
      messageCount: messages.length,
      result,
      recordsStored: curated.storedCount,
      rejectionCategory: curated.rejectionCategory,
      curationVersion: SLACK_CHANNEL_CURATION_VERSION,
    });
    return {
      accepted: true,
      reason: result,
      messageCount: messages.length,
      recordId: curated.records[0]?.id,
      recordIds: curated.records.map((record) => record.id),
      recordsStored: curated.storedCount,
      rejectionCategory: curated.rejectionCategory,
      curationVersion: SLACK_CHANNEL_CURATION_VERSION,
    };
  }

  private recordFlushError(channelId: string | undefined, error: unknown): void {
    recordMetric("cerebro_slack_companion_channel_learning_batch_total", { result: "failed" }, 1);
    logger.warn("slack channel learning batch failed", {
      event: "slack.channel_learning.batch_failed",
      channelId,
      errorType: error instanceof Error ? error.name : "unknown",
    });
  }

  private isEnabled(): boolean {
    return this.config.learning.enabled && this.config.learning.channelLearningEnabled;
  }
}

function sanitizeChannelMessage(value: string): string {
  return redactSecurityText(value)
    .replace(/<@[A-Z0-9]+>/gi, "@participant")
    .replace(/<mailto:[^>]+>/gi, "[email]")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, MAX_MESSAGE_CHARS);
}

function isJoinedChannelId(value: string): boolean {
  return /^[CG][A-Z0-9]+$/i.test(value);
}

function rejected(reason: SlackChannelLearningResult["reason"]): SlackChannelLearningResult {
  recordMetric("cerebro_slack_companion_channel_learning_observed_total", { result: reason }, 1);
  return { accepted: false, reason, buffered: 0 };
}

function rejectedBatch(reason: SlackChannelLearningBatchResult["reason"]): SlackChannelLearningBatchResult {
  recordMetric("cerebro_slack_companion_channel_learning_batch_total", { result: reason }, 1);
  return { accepted: false, reason, messageCount: 0, curationVersion: SLACK_CHANNEL_CURATION_VERSION };
}
