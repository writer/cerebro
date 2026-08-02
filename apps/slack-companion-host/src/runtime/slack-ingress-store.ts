import { createHash, randomUUID } from "node:crypto";
import { chmod, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

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
  private databaseInstance?: DatabaseSync;
  private initializeTask?: Promise<void>;

  constructor(
    private readonly root: string,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  async initialize(): Promise<void> {
    this.initializeTask ??= this.initializeOnce();
    await this.initializeTask;
  }

  async maintain(): Promise<void> {
    await this.initialize();
    const cutoff = this.clock().getTime() - MESSAGE_BINDING_RETENTION_MS;
    this.transaction((database) => {
      database.prepare("DELETE FROM slack_message_bindings WHERE bound_at_ms < ?").run(cutoff);
      database.prepare(`
        DELETE FROM slack_message_bindings
        WHERE request_key IN (
          SELECT request_key
          FROM slack_message_bindings
          ORDER BY bound_at_ms DESC, request_key DESC
          LIMIT -1 OFFSET ?
        )
      `).run(MAX_MESSAGE_BINDINGS);
    });
  }

  async readMessageBinding(
    requestKey: string,
    clientMessageId: string,
  ): Promise<string | undefined> {
    await this.initialize();
    const row = this.database().prepare(`
      SELECT binding_json
      FROM slack_message_bindings
      WHERE request_key = ?
    `).get(requestKey) as { binding_json: string } | undefined;
    if (!row) return undefined;
    const binding = JSON.parse(row.binding_json) as SlackMessageBinding;
    validateMessageBinding(binding, requestKey, clientMessageId);
    return binding.messageTs;
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
    this.transaction((database) => {
      const row = database.prepare(`
        SELECT binding_json
        FROM slack_message_bindings
        WHERE request_key = ?
      `).get(requestKey) as { binding_json: string } | undefined;
      if (row) {
        const existing = JSON.parse(row.binding_json) as SlackMessageBinding;
        validateMessageBinding(existing, requestKey, clientMessageId);
        if (existing.messageTs !== messageTs) {
          throw new Error("Slack message binding changed for an exact request.");
        }
        return;
      }
      database.prepare(`
        INSERT INTO slack_message_bindings (
          request_key,
          client_message_id,
          message_ts,
          bound_at_ms,
          binding_json
        ) VALUES (?, ?, ?, ?, ?)
      `).run(
        requestKey,
        clientMessageId,
        messageTs,
        this.clock().getTime(),
        JSON.stringify(binding),
      );
    });
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
    this.transaction((database) => {
      database.prepare(`
        INSERT OR IGNORE INTO slack_ingress_events (
          record_ref,
          request_key,
          admitted_at_ms,
          record_json
        ) VALUES (?, ?, ?, ?)
      `).run(recordRef, requestKey, this.clock().getTime(), JSON.stringify(record));
      const row = database.prepare(`
        SELECT record_json
        FROM slack_ingress_events
        WHERE record_ref = ?
      `).get(recordRef) as { record_json: string } | undefined;
      if (!row) throw new Error("Slack ingress durable admission did not commit.");
      const existing = this.parseRecord(row.record_json);
      if (JSON.stringify(existing.event) !== JSON.stringify(event)) {
        throw new Error("Slack ingress request identity changed after durable admission.");
      }
    });
    return recordRef;
  }

  async claimNext(workerRef: string): Promise<SlackIngressClaim | undefined> {
    if (!workerRef.trim()) throw new Error("Slack ingress worker reference is required.");
    await this.initialize();
    return this.transaction((database) => {
      const now = this.clock().getTime();
      database.prepare("DELETE FROM slack_ingress_leases WHERE expires_at_ms <= ?").run(now);
      const row = database.prepare(`
        SELECT event.record_json
        FROM slack_ingress_events AS event
        LEFT JOIN slack_ingress_leases AS lease
          ON lease.record_ref = event.record_ref
        WHERE lease.record_ref IS NULL
        ORDER BY event.admitted_at_ms ASC, event.record_ref ASC
        LIMIT 1
      `).get() as { record_json: string } | undefined;
      if (!row) return undefined;
      const record = this.parseRecord(row.record_json);
      const leaseToken = randomUUID();
      database.prepare(`
        INSERT INTO slack_ingress_leases (
          record_ref,
          worker_ref,
          lease_token,
          expires_at_ms
        ) VALUES (?, ?, ?, ?)
      `).run(record.recordRef, workerRef, leaseToken, now + INGRESS_LEASE_MS);
      return {
        event: record.event,
        leaseToken,
        recordRef: record.recordRef,
        requestKey: record.requestKey,
        workerRef,
      };
    });
  }

  async complete(claim: SlackIngressClaim): Promise<void> {
    await this.initialize();
    this.transaction((database) => {
      this.verifyLease(database, claim);
      const result = database.prepare(`
        DELETE FROM slack_ingress_events
        WHERE record_ref = ?
      `).run(claim.recordRef);
      if (result.changes !== 1) {
        throw new Error("Slack ingress completion requires one admitted event.");
      }
    });
  }

  async release(claim: SlackIngressClaim): Promise<void> {
    await this.initialize();
    this.transaction((database) => {
      const row = this.lease(database, claim.recordRef);
      if (!row) return;
      if (row.lease_token !== claim.leaseToken || row.worker_ref !== claim.workerRef) {
        throw new Error("Slack ingress lease changed before release.");
      }
      database.prepare(`
        DELETE FROM slack_ingress_leases
        WHERE record_ref = ? AND worker_ref = ? AND lease_token = ?
      `).run(claim.recordRef, claim.workerRef, claim.leaseToken);
    });
  }

  async renew(claim: SlackIngressClaim): Promise<void> {
    await this.initialize();
    this.transaction((database) => {
      this.verifyLease(database, claim);
      const result = database.prepare(`
        UPDATE slack_ingress_leases
        SET expires_at_ms = ?
        WHERE record_ref = ? AND worker_ref = ? AND lease_token = ?
      `).run(
        this.clock().getTime() + INGRESS_LEASE_MS,
        claim.recordRef,
        claim.workerRef,
        claim.leaseToken,
      );
      if (result.changes !== 1) {
        throw new Error("Slack ingress lease changed before renewal.");
      }
    });
  }

  private parseRecord(serialized: string): SlackIngressRecord {
    const record = JSON.parse(serialized) as SlackIngressRecord;
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

  private async initializeOnce(): Promise<void> {
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    const database = this.database();
    database.exec(`
      PRAGMA busy_timeout = 5000;
      PRAGMA foreign_keys = ON;
      PRAGMA journal_mode = DELETE;
      PRAGMA synchronous = FULL;
      CREATE TABLE IF NOT EXISTS slack_ingress_events (
        record_ref TEXT PRIMARY KEY,
        request_key TEXT NOT NULL UNIQUE,
        admitted_at_ms INTEGER NOT NULL,
        record_json TEXT NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS slack_ingress_leases (
        record_ref TEXT PRIMARY KEY REFERENCES slack_ingress_events(record_ref) ON DELETE CASCADE,
        worker_ref TEXT NOT NULL,
        lease_token TEXT NOT NULL,
        expires_at_ms INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS slack_message_bindings (
        request_key TEXT PRIMARY KEY,
        client_message_id TEXT NOT NULL,
        message_ts TEXT NOT NULL,
        bound_at_ms INTEGER NOT NULL,
        binding_json TEXT NOT NULL
      ) STRICT;
    `);
    await chmod(this.databasePath(), 0o600);
  }

  private database(): DatabaseSync {
    this.databaseInstance ??= new DatabaseSync(this.databasePath());
    return this.databaseInstance;
  }

  private databasePath(): string {
    return join(this.root, "slack-ingress.sqlite3");
  }

  private lease(
    database: DatabaseSync,
    recordRef: string,
  ): { lease_token: string; worker_ref: string; expires_at_ms: number } | undefined {
    return database.prepare(`
      SELECT lease_token, worker_ref, expires_at_ms
      FROM slack_ingress_leases
      WHERE record_ref = ?
    `).get(recordRef) as {
      lease_token: string;
      worker_ref: string;
      expires_at_ms: number;
    } | undefined;
  }

  private transaction<T>(operation: (database: DatabaseSync) => T): T {
    const database = this.database();
    database.exec("BEGIN IMMEDIATE");
    try {
      const result = operation(database);
      database.exec("COMMIT");
      return result;
    } catch (error) {
      database.exec("ROLLBACK");
      throw error;
    }
  }

  private verifyLease(database: DatabaseSync, claim: SlackIngressClaim): void {
    const lease = this.lease(database, claim.recordRef);
    if (
      !lease
      || lease.lease_token !== claim.leaseToken
      || lease.worker_ref !== claim.workerRef
      || lease.expires_at_ms <= this.clock().getTime()
    ) {
      throw new Error("Slack ingress completion requires the exact live lease.");
    }
  }
}

export function slackIngressRequestKey(event: SlackIngressEvent): string {
  return [event.teamId, event.channel, event.threadTs, event.eventTs].join(":");
}

function slackIngressEvent(body: unknown): SlackIngressEvent | undefined {
  if (!isRecord(body) || body.type !== "event_callback" || !isRecord(body.event)) {
    return undefined;
  }
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
