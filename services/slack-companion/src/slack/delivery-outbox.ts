import { hostname } from "node:os";
import type { AppConfig } from "../config/index.js";
import { logger } from "../logger.js";
import {
  createSlackDeliveryRecord,
  DynamoSlackDeliveryOutboxStore,
  type EnqueueSlackDeliveryInput,
  type SlackDeliveryOutboxStore,
  type SlackDeliveryRecord,
} from "./delivery-outbox-store.js";

interface SlackDeliveryClient {
  chat: {
    postMessage(input: {
      channel: string;
      text: string;
      thread_ts?: string;
      client_msg_id: string;
      unfurl_links: false;
      unfurl_media: false;
    }): Promise<{ ts?: string }>;
  };
}

export interface SlackDeliveryOutboxOptions {
  store?: SlackDeliveryOutboxStore;
  beforeCompletePosted?: (receipt: {
    delivery: SlackDeliveryRecord;
    postedAt: string;
    postedTs: string;
  }) => Promise<void> | void;
  now?: () => Date;
  workerId?: string;
  pollIntervalMs?: number;
  leaseMs?: number;
  retryBaseMs?: number;
  maxRetryMs?: number;
  maxAttempts?: number;
  maxPerTick?: number;
}

export interface SlackDeliveryTickResult {
  deliveryId: string;
  status: "posted" | "retry" | "failed" | "lease_retained";
  attempts: number;
  postedTs?: string;
}

export class SlackDeliveryOutbox {
  private readonly store?: SlackDeliveryOutboxStore;
  private readonly now: () => Date;
  private readonly workerId: string;
  private readonly beforeCompletePosted?: SlackDeliveryOutboxOptions["beforeCompletePosted"];
  private readonly pollIntervalMs: number;
  private readonly leaseMs: number;
  private readonly retryBaseMs: number;
  private readonly maxRetryMs: number;
  private readonly maxAttempts: number;
  private readonly maxPerTick: number;
  private interval?: NodeJS.Timeout;
  private client?: SlackDeliveryClient;
  private inFlight?: Promise<SlackDeliveryTickResult[]>;
  private stopping = false;

  constructor(private readonly config: AppConfig, options: SlackDeliveryOutboxOptions = {}) {
    this.store = options.store ?? (config.learning.tableName
      ? new DynamoSlackDeliveryOutboxStore(config.learning.tableName, config.cerebro.tenantId)
      : undefined);
    this.now = options.now ?? (() => new Date());
    this.workerId = options.workerId ?? `slack-delivery-${process.pid}@${hostname()}`;
    this.beforeCompletePosted = options.beforeCompletePosted;
    this.pollIntervalMs = Math.max(1_000, options.pollIntervalMs ?? 5_000);
    this.leaseMs = Math.max(1_000, options.leaseMs ?? 60_000);
    this.retryBaseMs = Math.max(100, options.retryBaseMs ?? 5_000);
    this.maxRetryMs = Math.max(this.retryBaseMs, options.maxRetryMs ?? 5 * 60_000);
    this.maxAttempts = Math.max(1, options.maxAttempts ?? 5);
    this.maxPerTick = Math.max(1, options.maxPerTick ?? 10);
  }

  async enqueue(input: EnqueueSlackDeliveryInput): Promise<SlackDeliveryRecord> {
    if (!this.store) throw new Error("Slack delivery outbox requires a configured learning table.");
    return this.store.enqueue(createSlackDeliveryRecord(this.config.cerebro.tenantId, input, this.now()));
  }

  start(client: SlackDeliveryClient): void {
    this.client = client;
    this.stopping = false;
    if (!this.store || this.interval) return;
    this.interval = setInterval(() => {
      void this.tick().catch((error) => logger.warn("slack.delivery_outbox.tick_failed", { error: shortError(error) }));
    }, this.pollIntervalMs);
    this.interval.unref?.();
    void this.tick().catch((error) => logger.warn("slack.delivery_outbox.initial_tick_failed", { error: shortError(error) }));
  }

  async stop(): Promise<void> {
    this.stopping = true;
    if (this.interval) clearInterval(this.interval);
    this.interval = undefined;
    await this.inFlight;
    this.client = undefined;
  }

  async tick(client?: SlackDeliveryClient): Promise<SlackDeliveryTickResult[]> {
    if (client) this.client = client;
    if (!this.store || !this.client || this.inFlight || this.stopping) return [];
    const run = this.runTick(this.client);
    this.inFlight = run;
    try {
      return await run;
    } finally {
      if (this.inFlight === run) this.inFlight = undefined;
    }
  }

  private async runTick(client: SlackDeliveryClient): Promise<SlackDeliveryTickResult[]> {
    const now = this.now();
    const due = await this.store!.listDue(now.toISOString(), this.maxPerTick);
    const results: SlackDeliveryTickResult[] = [];
    for (const record of due) {
      if (this.stopping) break;
      const claimedAt = this.now();
      const leased = await this.store!.tryLease(record.id, {
        workerId: this.workerId,
        now: claimedAt.toISOString(),
        leaseExpiresAt: new Date(claimedAt.getTime() + this.leaseMs).toISOString(),
      });
      if (!leased) continue;
      results.push(await this.deliver(leased, client));
    }
    return results;
  }

  private async deliver(record: SlackDeliveryRecord, client: SlackDeliveryClient): Promise<SlackDeliveryTickResult> {
    let accepted = record;
    if (!accepted.postedTs) {
      let postedTs: string;
      try {
        const response = await client.chat.postMessage({
          channel: record.channelId,
          text: record.text,
          ...(record.threadTs ? { thread_ts: record.threadTs } : {}),
          client_msg_id: record.clientMessageId,
          unfurl_links: false,
          unfurl_media: false,
        });
        postedTs = response.ts?.trim() ?? "";
        if (!postedTs) throw new Error("Slack postMessage returned no message timestamp.");
      } catch (error) {
        return this.recordFailure(record, error);
      }

      const postedAt = this.now().toISOString();
      try {
        accepted = await this.store!.markSlackAccepted(record.id, this.workerId, postedAt, postedTs);
      } catch (error) {
        logger.warn("slack.delivery_outbox.acceptance_write_failed", {
          deliveryId: record.id,
          status: "leased",
          attempts: record.attempts,
          error: shortError(error),
        });
        return { deliveryId: record.id, status: "lease_retained", attempts: record.attempts, postedTs };
      }
    }

    const postedTs = accepted.postedTs!;
    const postedAt = accepted.postedAt!;
    try {
      if (this.beforeCompletePosted) {
        await this.beforeCompletePosted({ delivery: accepted, postedAt, postedTs });
      }
      const posted = await this.store!.completePosted(record.id, this.workerId, this.now().toISOString());
      logger.info("slack.delivery_outbox.posted", {
        deliveryId: record.id,
        status: posted.status,
        attempts: posted.attempts,
      });
      return { deliveryId: record.id, status: "posted", attempts: posted.attempts, postedTs: posted.postedTs };
    } catch (error) {
      return this.recordFailure(accepted, error);
    }
  }

  private async recordFailure(record: SlackDeliveryRecord, error: unknown): Promise<SlackDeliveryTickResult> {
    const failedAt = this.now();
    const status = record.attempts >= this.maxAttempts ? "failed" : "retry";
    try {
      const completed = await this.store!.completeFailure(record.id, {
        workerId: this.workerId,
        status,
        failedAt: failedAt.toISOString(),
        nextAttemptAt: status === "retry"
          ? new Date(failedAt.getTime() + retryDelayMs(record.attempts, this.retryBaseMs, this.maxRetryMs)).toISOString()
          : undefined,
        error: shortError(error),
      });
      const phase = record.postedTs ? "receipt" : "post";
      logger.warn(`slack.delivery_outbox.${phase}_failed`, {
        deliveryId: record.id,
        phase,
        status: completed.status,
        attempts: completed.attempts,
        error: shortError(error),
      });
      return { deliveryId: record.id, status, attempts: completed.attempts };
    } catch (storeError) {
      logger.warn("slack.delivery_outbox.failure_write_failed", {
        deliveryId: record.id,
        status: "leased",
        attempts: record.attempts,
        error: shortError(storeError),
      });
      return { deliveryId: record.id, status: "lease_retained", attempts: record.attempts };
    }
  }
}

function retryDelayMs(attempt: number, baseMs: number, maxMs: number): number {
  return Math.min(maxMs, baseMs * (2 ** Math.max(0, attempt - 1)));
}

function shortError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.replace(/\s+/g, " ").trim().slice(0, 500) || "Slack delivery failed.";
}
