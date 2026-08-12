import { createHash } from "node:crypto";
import {
  planSlackNotification,
  type SlackNotificationPreferencesV1,
} from "@writer/cerebro-slack-companion";
import type {
  CerebroAskClient,
  RustPendingWakeDelivery,
} from "./cerebro-ask-client.js";
import type { FileSlackThreadRouteStore, SlackThreadRoute } from "./slack-thread-route-store.js";
import {
  FileWakeDeliveryOutbox,
  type WakeDeliveryOutboxRecord,
} from "./wake-delivery-outbox.js";

const WAKE_METADATA_EVENT_TYPE = "cerebro_wake_delivery";

interface SlackWakeMessage {
  metadata?: {
    event_payload?: Record<string, unknown>;
    event_type?: string;
  };
  text?: string;
  ts?: string;
  user?: string;
}

export interface SlackWakeDeliveryClient {
  chat: {
    postMessage(input: {
      channel: string;
      client_msg_id: string;
      metadata: {
        event_payload: Record<string, string>;
        event_type: typeof WAKE_METADATA_EVENT_TYPE;
      };
      text: string;
      thread_ts: string;
      unfurl_links: false;
      unfurl_media: false;
    }): Promise<{ ts?: string }>;
  };
  conversations: {
    replies(input: {
      channel: string;
      inclusive: true;
      include_all_metadata: true;
      limit: 100;
      ts: string;
      cursor?: string;
    }): Promise<{
      messages?: SlackWakeMessage[];
      response_metadata?: { next_cursor?: string };
    }>;
  };
}

export interface WakeDeliveryWorkerOptions {
  clock?: () => Date;
  notificationPreferences?: SlackNotificationPreferencesV1;
  signal?: (milliseconds: number) => AbortSignal;
  workerRef: string;
}

export class WakeDeliveryWorker {
  private readonly clock: () => Date;
  private running = false;
  private readonly signal: (milliseconds: number) => AbortSignal;

  constructor(
    private readonly rust: CerebroAskClient,
    private readonly slack: SlackWakeDeliveryClient,
    private readonly routes: FileSlackThreadRouteStore,
    private readonly outbox: FileWakeDeliveryOutbox,
    private readonly options: WakeDeliveryWorkerOptions,
  ) {
    this.clock = options.clock ?? (() => new Date());
    this.signal = options.signal ?? ((milliseconds) => AbortSignal.timeout(milliseconds));
  }

  async tick(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      await this.flush();
      if (this.options.notificationPreferences) {
        const decision = planSlackNotification(this.options.notificationPreferences, {
          class: "followup",
          observed_at: this.clock().toISOString(),
          severity: "medium",
        });
        if (decision.disposition !== "deliver") return;
      }
      await this.rust.runDueWake({
        signal: this.signal(950_000),
        workerRef: this.options.workerRef,
      });
      const delivery = await this.rust.claimPendingWakeDelivery({
        signal: this.signal(20_000),
        workerRef: this.options.workerRef,
      });
      if (!delivery) return;
      const route = await this.routes.read(delivery.thread_ref);
      if (!route) {
        throw new Error("The pending wake delivery has no private Slack thread route.");
      }
      if (delivery.mode === "send") {
        await this.outbox.prepare({
          channelId: route.channelId,
          delivery,
          threadTs: route.threadTs,
        });
      } else {
        await this.outbox.trackOutcomeUnknown({
          channelId: route.channelId,
          delivery,
          threadTs: route.threadTs,
        });
      }
      await this.flush();
    } finally {
      this.running = false;
    }
  }

  async flush(): Promise<void> {
    for (const record of await this.outbox.list()) {
      await this.flushRecord(record);
    }
  }

  private async flushRecord(input: WakeDeliveryOutboxRecord): Promise<void> {
    let record = input;
    const route = await this.routes.read(record.delivery.thread_ref);
    if (!route || route.channelId !== record.channelId || route.threadTs !== record.threadTs) {
      throw new Error("The Slack wake outbox route no longer matches its private binding.");
    }
    if (record.state === "prepared") {
      record = await this.outbox.markOutcomeUnknown(record.recordRef);
      const posted = await this.slack.chat.postMessage(deliveryMessage(record));
      if (!posted.ts) {
        throw new Error("Slack did not return a receipt for the wake delivery attempt.");
      }
      record = await this.markDelivered(record, route, posted.ts);
    } else if (record.state === "outcome_unknown") {
      let messageTs = await this.reconcile(record, route);
      if (!messageTs) {
        const posted = await this.slack.chat.postMessage(deliveryMessage(record));
        messageTs = posted.ts;
      }
      if (!messageTs) {
        throw new Error("Slack did not return a receipt for the idempotent wake delivery attempt.");
      }
      record = await this.markDelivered(record, route, messageTs);
    }
    if (record.state !== "slack_delivered") return;
    await this.rust.recordWakeDelivery({
      deliveredAt: record.deliveredAt!,
      delivery: record.delivery,
      destinationReceipt: record.destinationReceipt!,
      signal: this.signal(20_000),
    });
    await this.outbox.complete(record.recordRef);
  }

  private async reconcile(
    record: WakeDeliveryOutboxRecord,
    route: SlackThreadRoute,
  ): Promise<string | undefined> {
    const expected = deliveryMetadata(record.delivery);
    const matches: SlackWakeMessage[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 100; page += 1) {
      const response = await this.slack.conversations.replies({
        channel: record.channelId,
        inclusive: true,
        include_all_metadata: true,
        limit: 100,
        ts: record.threadTs,
        ...(cursor ? { cursor } : {}),
      });
      matches.push(...(response.messages ?? []).filter((message) =>
        message.text === record.delivery.markdown
        && message.user === route.botUserId
        && message.metadata?.event_type === expected.event_type
        && message.metadata.event_payload?.delivery_attempt_ref
          === expected.event_payload.delivery_attempt_ref
        && message.metadata.event_payload?.delivery_ref === expected.event_payload.delivery_ref
        && message.metadata.event_payload?.payload_digest === expected.event_payload.payload_digest
        && Boolean(message.ts)
      ));
      cursor = response.response_metadata?.next_cursor?.trim() || undefined;
      if (!cursor) break;
      if (page === 99) {
        throw new Error("Slack wake reconciliation exceeded the bounded thread history.");
      }
    }
    if (matches.length > 1) {
      throw new Error("Slack contains multiple messages for one wake delivery attempt.");
    }
    return matches[0]?.ts;
  }

  private async markDelivered(
    record: WakeDeliveryOutboxRecord,
    route: SlackThreadRoute,
    messageTs: string,
  ): Promise<WakeDeliveryOutboxRecord> {
    return this.outbox.markSlackDelivered(record.recordRef, {
      deliveredAt: this.clock().toISOString(),
      destinationReceipt: `slack-message://sha256/${digest(
        `${route.channelId}:${messageTs}`,
      )}`,
      messageTs,
    });
  }
}

function deliveryMessage(record: WakeDeliveryOutboxRecord): {
  channel: string;
  client_msg_id: string;
  metadata: ReturnType<typeof deliveryMetadata>;
  text: string;
  thread_ts: string;
  unfurl_links: false;
  unfurl_media: false;
} {
  return {
    channel: record.channelId,
    client_msg_id: clientMessageId(record.delivery.lease.delivery_attempt_ref),
    metadata: deliveryMetadata(record.delivery),
    text: record.delivery.markdown,
    thread_ts: record.threadTs,
    unfurl_links: false,
    unfurl_media: false,
  };
}

function clientMessageId(deliveryAttemptRef: string): string {
  const hex = digest(deliveryAttemptRef).slice(0, 32);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-a${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

function deliveryMetadata(delivery: RustPendingWakeDelivery): {
  event_payload: Record<string, string>;
  event_type: typeof WAKE_METADATA_EVENT_TYPE;
} {
  return {
    event_payload: {
      delivery_attempt_ref: delivery.lease.delivery_attempt_ref,
      delivery_ref: delivery.lease.delivery_ref,
      payload_digest: delivery.lease.payload_digest,
    },
    event_type: WAKE_METADATA_EVENT_TYPE,
  };
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}
