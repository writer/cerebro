import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { RustPendingWakeDelivery } from "./cerebro-ask-client.js";

const WAKE_OUTBOX_SCHEMA_VERSION = "slack-wake-delivery-outbox/v1";

export interface WakeDeliveryOutboxRecord {
  channelId: string;
  deliveredAt: string | null;
  delivery: RustPendingWakeDelivery;
  destinationReceipt: string | null;
  messageTs: string | null;
  recordRef: string;
  schemaVersion: typeof WAKE_OUTBOX_SCHEMA_VERSION;
  state: "outcome_unknown" | "prepared" | "slack_delivered";
  threadTs: string;
}

export class FileWakeDeliveryOutbox {
  private mutationQueue: Promise<void> = Promise.resolve();

  constructor(private readonly root: string) {}

  async prepare(input: {
    channelId: string;
    delivery: RustPendingWakeDelivery;
    threadTs: string;
  }): Promise<WakeDeliveryOutboxRecord> {
    return this.serialize(async () => {
      const recordRef = `slack-wake-outbox://sha256/${digest(
        input.delivery.lease.delivery_ref,
      )}`;
      const record = validateRecord({
        ...input,
        deliveredAt: null,
        destinationReceipt: null,
        messageTs: null,
        recordRef,
        schemaVersion: WAKE_OUTBOX_SCHEMA_VERSION,
        state: "prepared",
      });
      const current = await this.readRecord(recordRef);
      if (current) {
        if (!samePreparedIdentity(current, record)) {
          throw new Error("The Slack wake delivery changed for an existing identity.");
        }
        return current;
      }
      await atomicWrite(this.path(recordRef), record);
      return record;
    });
  }

  async trackOutcomeUnknown(input: {
    channelId: string;
    delivery: RustPendingWakeDelivery;
    threadTs: string;
  }): Promise<WakeDeliveryOutboxRecord> {
    return this.serialize(async () => {
      const recordRef = `slack-wake-outbox://sha256/${digest(
        input.delivery.lease.delivery_ref,
      )}`;
      const record = validateRecord({
        ...input,
        deliveredAt: null,
        destinationReceipt: null,
        messageTs: null,
        recordRef,
        schemaVersion: WAKE_OUTBOX_SCHEMA_VERSION,
        state: "outcome_unknown",
      });
      const current = await this.readRecord(recordRef);
      if (current) {
        if (!samePreparedIdentity(current, record)) {
          throw new Error("The Slack wake delivery changed for an existing identity.");
        }
        return current;
      }
      await atomicWrite(this.path(recordRef), record);
      return record;
    });
  }

  async markOutcomeUnknown(recordRef: string): Promise<WakeDeliveryOutboxRecord> {
    return this.serialize(async () => {
      const current = await this.requiredRecord(recordRef);
      if (current.state !== "prepared") return current;
      const unknown = validateRecord({ ...current, state: "outcome_unknown" });
      await atomicWrite(this.path(recordRef), unknown);
      return unknown;
    });
  }

  async markSlackDelivered(
    recordRef: string,
    receipt: { deliveredAt: string; destinationReceipt: string; messageTs: string },
  ): Promise<WakeDeliveryOutboxRecord> {
    return this.serialize(async () => {
      const current = await this.requiredRecord(recordRef);
      const delivered = validateRecord({
        ...current,
        ...receipt,
        state: "slack_delivered",
      });
      if (current.state === "slack_delivered") {
        if (JSON.stringify(current) !== JSON.stringify(delivered)) {
          throw new Error("The Slack wake receipt changed after delivery.");
        }
        return current;
      }
      if (current.state !== "outcome_unknown") {
        throw new Error("The Slack wake send was not durably started.");
      }
      await atomicWrite(this.path(recordRef), delivered);
      return delivered;
    });
  }

  async complete(recordRef: string): Promise<void> {
    await this.serialize(async () => {
      const current = await this.requiredRecord(recordRef);
      if (current.state !== "slack_delivered") {
        throw new Error("The Slack wake delivery is not acknowledged as delivered.");
      }
      await rm(this.path(recordRef), { force: true });
    });
  }

  async list(): Promise<WakeDeliveryOutboxRecord[]> {
    let files: string[];
    try {
      files = (await readdir(this.directory())).filter((file) => file.endsWith(".json"));
    } catch (error) {
      if (errorCode(error) === "ENOENT") return [];
      throw error;
    }
    const records = await Promise.all(files.sort().map(async (file) =>
      validateRecord(JSON.parse(await readFile(join(this.directory(), file), "utf8")))
    ));
    return records.sort((left, right) => left.recordRef.localeCompare(right.recordRef));
  }

  private async requiredRecord(recordRef: string): Promise<WakeDeliveryOutboxRecord> {
    const record = await this.readRecord(recordRef);
    if (!record) throw new Error("The Slack wake delivery record does not exist.");
    return record;
  }

  private async readRecord(recordRef: string): Promise<WakeDeliveryOutboxRecord | undefined> {
    try {
      return validateRecord(JSON.parse(await readFile(this.path(recordRef), "utf8")));
    } catch (error) {
      if (errorCode(error) === "ENOENT") return undefined;
      throw error;
    }
  }

  private directory(): string {
    return join(this.root, "wake-delivery-outbox");
  }

  private path(recordRef: string): string {
    return join(this.directory(), `${digest(recordRef)}.json`);
  }

  private async serialize<T>(operation: () => Promise<T>): Promise<T> {
    const prior = this.mutationQueue;
    let release!: () => void;
    this.mutationQueue = new Promise<void>((resolve) => {
      release = resolve;
    });
    await prior;
    try {
      return await operation();
    } finally {
      release();
    }
  }
}

function samePreparedIdentity(
  current: WakeDeliveryOutboxRecord,
  prepared: WakeDeliveryOutboxRecord,
): boolean {
  return current.channelId === prepared.channelId
    && current.recordRef === prepared.recordRef
    && current.threadTs === prepared.threadTs
    && current.delivery.markdown === prepared.delivery.markdown
    && current.delivery.tenant_id === prepared.delivery.tenant_id
    && current.delivery.thread_ref === prepared.delivery.thread_ref
    && current.delivery.lease.commitment_ref === prepared.delivery.lease.commitment_ref
    && current.delivery.lease.delivery_attempt_ref
      === prepared.delivery.lease.delivery_attempt_ref
    && current.delivery.lease.delivery_ref === prepared.delivery.lease.delivery_ref
    && current.delivery.lease.payload_digest === prepared.delivery.lease.payload_digest
    && current.delivery.lease.request_id === prepared.delivery.lease.request_id
    && current.delivery.lease.schedule_generation
      === prepared.delivery.lease.schedule_generation
    && current.delivery.lease.session_ref === prepared.delivery.lease.session_ref;
}

function validateRecord(value: unknown): WakeDeliveryOutboxRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The Slack wake delivery record is invalid.");
  }
  const record = value as Record<string, unknown>;
  const state = record.state;
  const delivered = state === "slack_delivered";
  if (
    JSON.stringify(Object.keys(record).sort()) !== JSON.stringify([
      "channelId",
      "deliveredAt",
      "delivery",
      "destinationReceipt",
      "messageTs",
      "recordRef",
      "schemaVersion",
      "state",
      "threadTs",
    ])
    || record.schemaVersion !== WAKE_OUTBOX_SCHEMA_VERSION
    || (state !== "prepared" && state !== "outcome_unknown" && !delivered)
    || !requiredText(record.channelId)
    || !/^\d+(?:\.\d+)?$/u.test(requiredText(record.threadTs))
    || !/^slack-wake-outbox:\/\/sha256\/[a-f0-9]{64}$/u.test(requiredText(record.recordRef))
    || !validDelivery(record.delivery)
    || (delivered && (
      !canonicalTimestamp(record.deliveredAt)
      || !requiredText(record.destinationReceipt)
      || !/^\d+(?:\.\d+)?$/u.test(requiredText(record.messageTs))
    ))
    || (!delivered && (
      record.deliveredAt !== null
      || record.destinationReceipt !== null
      || record.messageTs !== null
    ))
  ) {
    throw new Error("The Slack wake delivery record is invalid.");
  }
  return record as unknown as WakeDeliveryOutboxRecord;
}

function validDelivery(value: unknown): value is RustPendingWakeDelivery {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const delivery = value as Record<string, unknown>;
  if (delivery.lease === null || typeof delivery.lease !== "object") return false;
  const lease = delivery.lease as Record<string, unknown>;
  return (delivery.mode === "send" || delivery.mode === "reconcile")
    && /^slack-scratchpad:\/\/sha256\/[a-f0-9]{64}$/u.test(requiredText(delivery.thread_ref))
    && /^wake-delivery:\/\/sha256\/[a-f0-9]{64}$/u.test(requiredText(lease.delivery_ref))
    && /^wake-delivery-attempt:\/\/sha256\/[a-f0-9]{64}$/u.test(
      requiredText(lease.delivery_attempt_ref),
    )
    && /^sha256:[a-f0-9]{64}$/u.test(requiredText(lease.payload_digest))
    && requiredText(delivery.markdown).length > 0;
}

async function atomicWrite(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${randomUUID()}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  await rename(temporary, path);
}

function requiredText(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function canonicalTimestamp(value: unknown): boolean {
  return typeof value === "string"
    && Number.isFinite(Date.parse(value))
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(value);
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function errorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code?: unknown }).code)
    : undefined;
}
