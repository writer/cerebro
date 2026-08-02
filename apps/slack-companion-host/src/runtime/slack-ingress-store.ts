import { createHash, randomUUID } from "node:crypto";
import {
  link,
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  stat,
  unlink,
} from "node:fs/promises";
import { join } from "node:path";

const INGRESS_LEASE_MS = 20 * 60 * 1_000;
const MESSAGE_BINDING_RETENTION_MS = 7 * 24 * 60 * 60 * 1_000;
const MAX_MESSAGE_BINDINGS = 50_000;
const MAX_INGRESS_TEXT_BYTES = 64 * 1024;

export interface SlackIngressEvent {
  botUserId?: string;
  channel: string;
  eventTs: string;
  hasThreadContext: boolean;
  kind: "app_mention" | "message";
  teamId: string;
  text: string;
  threadTs: string;
  userId: string;
}

interface SlackIngressRecord {
  admittedAt: string;
  event: SlackIngressEvent;
  recordRef: string;
  requestKey: string;
  schemaVersion: "cerebro-slack-ingress/v1";
}

interface SlackIngressLease {
  expiresAt: string;
  leaseToken: string;
  workerRef: string;
}

interface SlackMessageBinding {
  boundAt: string;
  clientMessageId: string;
  messageTs: string;
  requestKey: string;
  schemaVersion: "cerebro-slack-message-binding/v1";
}

export interface SlackIngressClaim {
  event: SlackIngressEvent;
  leaseToken: string;
  recordRef: string;
  requestKey: string;
  workerRef: string;
}

export class FileSlackIngressQueue {
  constructor(
    private readonly root: string,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  async initialize(): Promise<void> {
    await Promise.all([
      mkdir(this.eventsDirectory(), { recursive: true }),
      mkdir(this.leasesDirectory(), { recursive: true }),
      mkdir(this.bindingsDirectory(), { recursive: true }),
    ]);
  }

  async maintain(): Promise<void> {
    await this.initialize();
    const bindings = await Promise.all(
      (await readdir(this.bindingsDirectory()))
        .filter((file) => file.endsWith(".json"))
        .map(async (file) => {
          const path = join(this.bindingsDirectory(), file);
          return { path, modifiedAt: (await stat(path)).mtimeMs };
        }),
    );
    bindings.sort((left, right) => right.modifiedAt - left.modifiedAt);
    const cutoff = this.clock().getTime() - MESSAGE_BINDING_RETENTION_MS;
    const expired = bindings.filter((binding) => binding.modifiedAt < cutoff);
    const retained = bindings.filter((binding) => binding.modifiedAt >= cutoff);
    const overLimit = retained.slice(MAX_MESSAGE_BINDINGS);
    await Promise.all([...expired, ...overLimit].map(({ path }) => unlink(path)));
    if (expired.length > 0 || overLimit.length > 0) {
      await syncDirectory(this.bindingsDirectory());
    }
  }

  async readMessageBinding(
    requestKey: string,
    clientMessageId: string,
  ): Promise<string | undefined> {
    await this.initialize();
    try {
      const binding = JSON.parse(
        await readFile(this.bindingPath(requestKey), "utf8"),
      ) as SlackMessageBinding;
      validateMessageBinding(binding, requestKey, clientMessageId);
      return binding.messageTs;
    } catch (error) {
      if (errorCode(error) === "ENOENT") return undefined;
      throw error;
    }
  }

  async bindMessage(
    requestKey: string,
    clientMessageId: string,
    messageTs: string,
  ): Promise<void> {
    if (
      !matchesRequestKey(requestKey)
      || !matchesText(clientMessageId)
      || !matchesText(messageTs)
    ) {
      throw new Error("Slack message binding is invalid.");
    }
    await this.initialize();
    const binding: SlackMessageBinding = {
      boundAt: this.clock().toISOString(),
      clientMessageId,
      messageTs,
      requestKey,
      schemaVersion: "cerebro-slack-message-binding/v1",
    };
    const finalPath = this.bindingPath(requestKey);
    const temporaryPath = join(
      this.bindingsDirectory(),
      `.${digest(requestKey)}.${randomUUID()}.tmp`,
    );
    const handle = await open(temporaryPath, "wx", 0o600);
    try {
      await handle.writeFile(`${JSON.stringify(binding)}\n`, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      await link(temporaryPath, finalPath);
      await syncDirectory(this.bindingsDirectory());
    } catch (error) {
      if (errorCode(error) !== "EEXIST") throw error;
      const existing = JSON.parse(await readFile(finalPath, "utf8")) as SlackMessageBinding;
      validateMessageBinding(existing, requestKey, clientMessageId);
      if (existing.messageTs !== messageTs) {
        throw new Error("Slack message binding changed for an exact request.");
      }
    } finally {
      await unlink(temporaryPath).catch((error: unknown) => {
        if (errorCode(error) !== "ENOENT") throw error;
      });
    }
  }

  async admitEnvelope(body: unknown): Promise<boolean> {
    const event = slackIngressEvent(body);
    if (!event) return false;
    await this.admit(event);
    return true;
  }

  async admit(event: SlackIngressEvent): Promise<string> {
    validateIngressEvent(event);
    await this.initialize();
    const requestKey = slackIngressRequestKey(event);
    const recordRef = `slack-ingress-${digest(requestKey)}`;
    const record: SlackIngressRecord = {
      admittedAt: this.clock().toISOString(),
      event,
      recordRef,
      requestKey,
      schemaVersion: "cerebro-slack-ingress/v1",
    };
    const finalPath = this.eventPath(recordRef);
    const temporaryPath = join(this.eventsDirectory(), `.${recordRef}.${randomUUID()}.tmp`);
    const handle = await open(temporaryPath, "wx", 0o600);
    try {
      await handle.writeFile(`${JSON.stringify(record)}\n`, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      await link(temporaryPath, finalPath);
      await syncDirectory(this.eventsDirectory());
    } catch (error) {
      if (errorCode(error) !== "EEXIST") throw error;
      const existing = await this.readRecord(finalPath);
      if (JSON.stringify(existing.event) !== JSON.stringify(event)) {
        throw new Error("Slack ingress request identity changed after durable admission.");
      }
    } finally {
      await unlink(temporaryPath).catch((error: unknown) => {
        if (errorCode(error) !== "ENOENT") throw error;
      });
    }
    return recordRef;
  }

  async claimNext(workerRef: string): Promise<SlackIngressClaim | undefined> {
    if (!workerRef.trim()) throw new Error("Slack ingress worker reference is required.");
    await this.initialize();
    const files = (await readdir(this.eventsDirectory()))
      .filter((file) => file.endsWith(".json"))
      .sort();
    for (const file of files) {
      const record = await this.readRecord(join(this.eventsDirectory(), file));
      const leaseToken = await this.acquireLease(record.recordRef, workerRef);
      if (!leaseToken) continue;
      return {
        event: record.event,
        leaseToken,
        recordRef: record.recordRef,
        requestKey: record.requestKey,
        workerRef,
      };
    }
    return undefined;
  }

  async complete(claim: SlackIngressClaim): Promise<void> {
    await this.verifyLease(claim);
    await unlink(this.eventPath(claim.recordRef)).catch((error: unknown) => {
      if (errorCode(error) !== "ENOENT") throw error;
    });
    await syncDirectory(this.eventsDirectory());
    await this.release(claim);
  }

  async release(claim: SlackIngressClaim): Promise<void> {
    const path = this.leasePath(claim.recordRef);
    let lease: SlackIngressLease;
    try {
      lease = JSON.parse(await readFile(path, "utf8")) as SlackIngressLease;
    } catch (error) {
      if (errorCode(error) === "ENOENT") return;
      throw error;
    }
    if (lease.leaseToken !== claim.leaseToken || lease.workerRef !== claim.workerRef) {
      throw new Error("Slack ingress lease changed before release.");
    }
    await unlink(path);
    await syncDirectory(this.leasesDirectory());
  }

  private async acquireLease(recordRef: string, workerRef: string): Promise<string | undefined> {
    const path = this.leasePath(recordRef);
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const leaseToken = randomUUID();
      const lease: SlackIngressLease = {
        expiresAt: new Date(this.clock().getTime() + INGRESS_LEASE_MS).toISOString(),
        leaseToken,
        workerRef,
      };
      try {
        const handle = await open(path, "wx", 0o600);
        try {
          await handle.writeFile(`${JSON.stringify(lease)}\n`, "utf8");
          await handle.sync();
        } finally {
          await handle.close();
        }
        await syncDirectory(this.leasesDirectory());
        return leaseToken;
      } catch (error) {
        if (errorCode(error) !== "EEXIST") throw error;
      }
      let existing: SlackIngressLease | undefined;
      try {
        existing = JSON.parse(await readFile(path, "utf8")) as SlackIngressLease;
      } catch (error) {
        if (errorCode(error) === "ENOENT") continue;
      }
      if (existing && Date.parse(existing.expiresAt) > this.clock().getTime()) return undefined;
      const stalePath = `${path}.stale.${randomUUID()}`;
      try {
        await rename(path, stalePath);
        await unlink(stalePath);
      } catch (error) {
        if (errorCode(error) !== "ENOENT") throw error;
      }
    }
    return undefined;
  }

  private async verifyLease(claim: SlackIngressClaim): Promise<void> {
    const lease = JSON.parse(
      await readFile(this.leasePath(claim.recordRef), "utf8"),
    ) as SlackIngressLease;
    if (
      lease.leaseToken !== claim.leaseToken
      || lease.workerRef !== claim.workerRef
      || Date.parse(lease.expiresAt) <= this.clock().getTime()
    ) {
      throw new Error("Slack ingress completion requires the exact live lease.");
    }
  }

  private async readRecord(path: string): Promise<SlackIngressRecord> {
    const record = JSON.parse(await readFile(path, "utf8")) as SlackIngressRecord;
    if (
      record.schemaVersion !== "cerebro-slack-ingress/v1"
      || !record.recordRef
      || !record.requestKey
    ) throw new Error("Slack ingress record is invalid.");
    validateIngressEvent(record.event);
    if (
      record.requestKey !== slackIngressRequestKey(record.event)
      || record.recordRef !== `slack-ingress-${digest(record.requestKey)}`
    ) throw new Error("Slack ingress record identity is invalid.");
    return record;
  }

  private eventsDirectory(): string {
    return join(this.root, "slack-ingress", "events");
  }

  private bindingsDirectory(): string {
    return join(this.root, "slack-ingress", "bindings");
  }

  private bindingPath(requestKey: string): string {
    return join(this.bindingsDirectory(), `${digest(requestKey)}.json`);
  }

  private leasesDirectory(): string {
    return join(this.root, "slack-ingress", "leases");
  }

  private eventPath(recordRef: string): string {
    return join(this.eventsDirectory(), `${recordRef}.json`);
  }

  private leasePath(recordRef: string): string {
    return join(this.leasesDirectory(), `${recordRef}.json`);
  }
}

export function slackIngressRequestKey(event: SlackIngressEvent): string {
  return [event.teamId, event.channel, event.threadTs, event.eventTs].join(":");
}

function slackIngressEvent(body: unknown): SlackIngressEvent | undefined {
  if (!isRecord(body) || body.type !== "events_api" || !isRecord(body.event)) return undefined;
  const event = body.event;
  if (event.type !== "app_mention" && event.type !== "message") return undefined;
  const authorization = Array.isArray(body.authorizations)
    ? body.authorizations.find(isRecord)
    : undefined;
  const teamId = typeof body.team_id === "string"
    ? body.team_id
    : authorization && typeof authorization.team_id === "string"
      ? authorization.team_id
      : undefined;
  if (
    !teamId
    || typeof event.channel !== "string"
    || typeof event.ts !== "string"
    || typeof event.user !== "string"
    || typeof event.text !== "string"
  ) return undefined;
  if (event.type === "message" && typeof event.thread_ts !== "string") return undefined;
  const threadTs = typeof event.thread_ts === "string" ? event.thread_ts : event.ts;
  const botUserId = authorization && typeof authorization.user_id === "string"
    ? authorization.user_id
    : undefined;
  if (
    event.type === "message"
    && (
      event.subtype !== undefined
      || event.bot_id !== undefined
      || event.app_id !== undefined
      || event.user === botUserId
      || (botUserId && event.text.includes(`<@${botUserId}>`))
    )
  ) return undefined;
  return {
    ...(botUserId ? { botUserId } : {}),
    channel: event.channel,
    eventTs: event.ts,
    hasThreadContext: typeof event.thread_ts === "string",
    kind: event.type,
    teamId,
    text: event.text,
    threadTs,
    userId: event.user,
  };
}

function validateIngressEvent(event: SlackIngressEvent): void {
  if (
    !isRecord(event)
    || !matchesText(event.teamId)
    || !matchesText(event.channel)
    || !matchesText(event.threadTs)
    || !matchesText(event.eventTs)
    || !matchesText(event.userId)
    || (event.botUserId !== undefined && !matchesText(event.botUserId))
    || (event.kind !== "app_mention" && event.kind !== "message")
    || typeof event.hasThreadContext !== "boolean"
    || typeof event.text !== "string"
    || !event.text.trim()
    || Buffer.byteLength(event.text, "utf8") > MAX_INGRESS_TEXT_BYTES
  ) throw new Error("Slack ingress event is invalid or exceeds its durable bound.");
}

function validateMessageBinding(
  binding: SlackMessageBinding,
  requestKey: string,
  clientMessageId: string,
): void {
  if (
    binding.schemaVersion !== "cerebro-slack-message-binding/v1"
    || binding.requestKey !== requestKey
    || binding.clientMessageId !== clientMessageId
    || !matchesText(binding.messageTs)
    || !Number.isFinite(Date.parse(binding.boundAt))
  ) throw new Error("Slack message binding is invalid.");
}

function matchesText(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 256;
}

function matchesRequestKey(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 2_048;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function errorCode(error: unknown): string | undefined {
  return isRecord(error) && typeof error.code === "string" ? error.code : undefined;
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(path, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}
