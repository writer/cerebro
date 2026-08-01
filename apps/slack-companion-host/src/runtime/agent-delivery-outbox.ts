import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

const DELIVERY_SCHEMA_VERSION = "slack-agent-delivery-outbox/v1";

export interface AgentDeliveryOutboxRecord {
  channel: string;
  deliveredAt: string;
  deliveryRef: string;
  messageTs: string;
  payloadDigest: string;
  recordRef: string;
  requestId: string;
  schemaVersion: typeof DELIVERY_SCHEMA_VERSION;
  state: "prepared" | "slack_delivered";
  text: string;
  threadRef: string;
}

export class FileAgentDeliveryOutbox {
  private mutationQueue: Promise<void> = Promise.resolve();

  constructor(private readonly root: string) {}

  async prepare(
    input: Omit<AgentDeliveryOutboxRecord, "recordRef" | "schemaVersion" | "state">,
  ): Promise<AgentDeliveryOutboxRecord> {
    return this.serialize(async () => {
      const recordRef = `slack-agent-delivery://sha256/${digest([
        input.threadRef,
        input.requestId,
        input.deliveryRef,
      ].join("\n"))}`;
      const record: AgentDeliveryOutboxRecord = {
        ...input,
        recordRef,
        schemaVersion: DELIVERY_SCHEMA_VERSION,
        state: "prepared",
      };
      validateRecord(record);
      const current = await this.readRecord(recordRef);
      if (current) {
        const expected = { ...record, state: current.state };
        if (JSON.stringify(current) !== JSON.stringify(expected)) {
          throw new Error("The Slack agent delivery changed for an existing identity.");
        }
        return current;
      }
      await atomicWrite(this.path(recordRef), record);
      return record;
    });
  }

  async markSlackDelivered(recordRef: string): Promise<AgentDeliveryOutboxRecord> {
    return this.serialize(async () => {
      const current = await this.readRecord(recordRef);
      if (!current) throw new Error("The Slack agent delivery record does not exist.");
      if (current.state === "slack_delivered") return current;
      const delivered: AgentDeliveryOutboxRecord = {
        ...current,
        state: "slack_delivered",
      };
      await atomicWrite(this.path(recordRef), delivered);
      return delivered;
    });
  }

  async complete(recordRef: string): Promise<void> {
    await this.serialize(async () => {
      await rm(this.path(recordRef), { force: true });
    });
  }

  async list(): Promise<AgentDeliveryOutboxRecord[]> {
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

  private async readRecord(recordRef: string): Promise<AgentDeliveryOutboxRecord | undefined> {
    try {
      return validateRecord(JSON.parse(await readFile(this.path(recordRef), "utf8")));
    } catch (error) {
      if (errorCode(error) === "ENOENT") return undefined;
      throw error;
    }
  }

  private directory(): string {
    return join(this.root, "agent-delivery-outbox");
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

function validateRecord(value: unknown): AgentDeliveryOutboxRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The Slack agent delivery record is invalid.");
  }
  const record = value as Record<string, unknown>;
  if (
    record.schemaVersion !== DELIVERY_SCHEMA_VERSION
    || (record.state !== "prepared" && record.state !== "slack_delivered")
    || !requiredText(record.channel)
    || !requiredText(record.deliveryRef)
    || !requiredText(record.messageTs)
    || !/^sha256:[a-f0-9]{64}$/u.test(requiredText(record.payloadDigest))
    || !/^slack-agent-delivery:\/\/sha256\/[a-f0-9]{64}$/u.test(
      requiredText(record.recordRef),
    )
    || !requiredText(record.requestId)
    || !requiredText(record.text)
    || !requiredText(record.threadRef)
    || !canonicalTimestamp(record.deliveredAt)
  ) {
    throw new Error("The Slack agent delivery record is invalid.");
  }
  return record as unknown as AgentDeliveryOutboxRecord;
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
    && new Date(value).toISOString() === value;
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function errorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code?: unknown }).code)
    : undefined;
}
