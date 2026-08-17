import { createHash, randomUUID } from "node:crypto";
import { chmod, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

const INGRESS_LEASE_MS = 20 * 60 * 1_000;
const INGRESS_MAX_ATTEMPTS = 5;
const INGRESS_RETRY_BACKOFF_MS = [5_000, 30_000, 2 * 60_000, 10 * 60_000] as const;
const EXECUTION_GATE_BUSY_TIMEOUT_MS = 0;
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
  attempt: number;
  event: SlackIngressEvent;
  leaseToken: string;
  recordRef: string;
  requestKey: string;
  workerRef: string;
}

export interface SlackIngressDeadLetter {
  attemptCount: number;
  deadLetteredAt: string;
  event: SlackIngressEvent;
  lastErrorKind: string;
  recordRef: string;
  requestKey: string;
  schemaVersion: "cerebro-slack-ingress-dead-letter/v1";
}

export type SlackIngressFailureDisposition = "dead_lettered" | "retry_scheduled";

const executionPermitBrand: unique symbol = Symbol("SlackIngressExecutionPermit");

export interface SlackIngressExecutionPermit {
  readonly workerRef: string;
  readonly [executionPermitBrand]: true;
}

export type SlackIngressExecutionAttempt<T> =
  | { acquired: false }
  | { acquired: true; value: T };

export class SlackIngressLeaseLostError extends Error {
  constructor(message = "Slack ingress completion requires the exact live lease.") {
    super(message);
    this.name = "SlackIngressLeaseLostError";
  }
}

export class FileSlackIngressQueue {
  private readonly activeExecutionPermits = new WeakSet<object>();
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
      // Bindings are keyed by (request_key, client_message_id) so one Slack
      // request can bind multiple delivered parts. Evict the oldest individual
      // rows beyond the cap rather than whole request keys.
      database.prepare(`
        DELETE FROM slack_message_bindings
        WHERE rowid IN (
          SELECT rowid
          FROM slack_message_bindings
          ORDER BY bound_at_ms DESC, request_key DESC, client_message_id DESC
          LIMIT -1 OFFSET ?
        )
      `).run(MAX_MESSAGE_BINDINGS);
    });
  }

  async tryWithExclusiveExecution<T>(
    workerRef: string,
    operation: (permit: SlackIngressExecutionPermit) => Promise<T>,
  ): Promise<SlackIngressExecutionAttempt<T>> {
    if (!workerRef.trim()) throw new Error("Slack ingress worker reference is required.");
    await this.initialize();
    const gate = new DatabaseSync(this.executionGatePath());
    gate.exec(`PRAGMA busy_timeout = ${EXECUTION_GATE_BUSY_TIMEOUT_MS}`);
    try {
      gate.exec("BEGIN IMMEDIATE");
    } catch (error) {
      gate.close();
      if (errorCode(error) === "ERR_SQLITE_ERROR" && /database is locked/u.test(errorMessage(error))) {
        return { acquired: false };
      }
      throw error;
    }
    const permit = Object.freeze({
      workerRef,
      [executionPermitBrand]: true as const,
    });
    this.activeExecutionPermits.add(permit);
    try {
      return { acquired: true, value: await operation(permit) };
    } finally {
      this.activeExecutionPermits.delete(permit);
      try {
        gate.exec("ROLLBACK");
      } finally {
        gate.close();
      }
    }
  }

  async readMessageBinding(
    requestKey: string,
    clientMessageId: string,
  ): Promise<string | undefined> {
    await this.initialize();
    const row = this.database().prepare(`
      SELECT binding_json
      FROM slack_message_bindings
      WHERE request_key = ? AND client_message_id = ?
    `).get(requestKey, clientMessageId) as { binding_json: string } | undefined;
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
        WHERE request_key = ? AND client_message_id = ?
      `).get(requestKey, clientMessageId) as { binding_json: string } | undefined;
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
      const terminalRow = database.prepare(`
        SELECT dead_letter_json
        FROM slack_ingress_dead_letters
        WHERE record_ref = ?
      `).get(recordRef) as { dead_letter_json: string } | undefined;
      if (terminalRow) {
        const terminal = this.parseDeadLetter(terminalRow.dead_letter_json);
        if (JSON.stringify(terminal.event) !== JSON.stringify(event)) {
          throw new Error("Slack ingress request identity changed after dead-lettering.");
        }
        return;
      }
      database.prepare(`
        INSERT OR IGNORE INTO slack_ingress_events (
          record_ref,
          request_key,
          admitted_at_ms,
          record_json
        ) VALUES (?, ?, ?, ?)
      `).run(recordRef, requestKey, this.clock().getTime(), JSON.stringify(record));
      database.prepare(`
        INSERT OR IGNORE INTO slack_ingress_order (record_ref)
        VALUES (?)
      `).run(recordRef);
      database.prepare(`
        INSERT OR IGNORE INTO slack_ingress_attempts (
          record_ref,
          attempt_count,
          next_attempt_at_ms,
          last_error_kind
        ) VALUES (?, 0, 0, NULL)
      `).run(recordRef);
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

  async claimNext(permit: SlackIngressExecutionPermit): Promise<SlackIngressClaim | undefined> {
    this.verifyPermit(permit);
    await this.initialize();
    return this.transaction((database) => {
      const now = this.clock().getTime();
      database.prepare(`
        UPDATE slack_ingress_attempts
        SET last_error_kind = 'SlackIngressLeaseExpired'
        WHERE record_ref IN (
          SELECT record_ref
          FROM slack_ingress_leases
          WHERE expires_at_ms <= ?
        )
      `).run(now);
      database.prepare("DELETE FROM slack_ingress_leases WHERE expires_at_ms <= ?").run(now);
      while (true) {
        const row = database.prepare(`
          SELECT
            event.record_json,
            attempt.attempt_count,
            attempt.last_error_kind,
            attempt.next_attempt_at_ms,
            lease.record_ref AS leased_record_ref
          FROM slack_ingress_events AS event
          INNER JOIN slack_ingress_order AS admitted
            ON admitted.record_ref = event.record_ref
          INNER JOIN slack_ingress_attempts AS attempt
            ON attempt.record_ref = event.record_ref
          LEFT JOIN slack_ingress_leases AS lease
            ON lease.record_ref = event.record_ref
          ORDER BY admitted.admission_sequence ASC
          LIMIT 1
        `).get() as {
          attempt_count: number;
          last_error_kind: string | null;
          leased_record_ref: string | null;
          next_attempt_at_ms: number;
          record_json: string;
        } | undefined;
        if (!row || row.leased_record_ref) return undefined;
        const record = this.parseRecord(row.record_json);
        if (row.attempt_count >= INGRESS_MAX_ATTEMPTS) {
          this.deadLetter(
            database,
            record,
            row.attempt_count,
            row.last_error_kind ?? "SlackIngressAttemptsExhausted",
          );
          continue;
        }
        if (row.next_attempt_at_ms > now) return undefined;
        const attempt = row.attempt_count + 1;
        const leaseToken = randomUUID();
        const updated = database.prepare(`
          UPDATE slack_ingress_attempts
          SET attempt_count = ?, next_attempt_at_ms = 0
          WHERE record_ref = ? AND attempt_count = ?
        `).run(attempt, record.recordRef, row.attempt_count);
        if (updated.changes !== 1) {
          throw new Error("Slack ingress attempt changed before claim.");
        }
        database.prepare(`
          INSERT INTO slack_ingress_leases (
            record_ref,
            worker_ref,
            lease_token,
            expires_at_ms
          ) VALUES (?, ?, ?, ?)
        `).run(record.recordRef, permit.workerRef, leaseToken, now + INGRESS_LEASE_MS);
        return {
          attempt,
          event: record.event,
          leaseToken,
          recordRef: record.recordRef,
          requestKey: record.requestKey,
          workerRef: permit.workerRef,
        };
      }
    });
  }

  async fail(
    permit: SlackIngressExecutionPermit,
    claim: SlackIngressClaim,
    error: unknown,
  ): Promise<SlackIngressFailureDisposition> {
    this.verifyPermit(permit, claim);
    await this.initialize();
    return this.transaction((database) => {
      this.verifyLeaseOwnership(database, claim);
      const recordRow = database.prepare(`
        SELECT event.record_json, attempt.attempt_count
        FROM slack_ingress_events AS event
        INNER JOIN slack_ingress_attempts AS attempt
          ON attempt.record_ref = event.record_ref
        WHERE event.record_ref = ?
      `).get(claim.recordRef) as {
        attempt_count: number;
        record_json: string;
      } | undefined;
      if (!recordRow) {
        throw new Error("Slack ingress failure requires one admitted event.");
      }
      if (recordRow.attempt_count !== claim.attempt) {
        throw new SlackIngressLeaseLostError(
          "Slack ingress failure requires the exact claimed attempt.",
        );
      }
      const errorKind = ingressErrorKind(error);
      if (recordRow.attempt_count >= INGRESS_MAX_ATTEMPTS) {
        this.deadLetter(
          database,
          this.parseRecord(recordRow.record_json),
          recordRow.attempt_count,
          errorKind,
        );
        return "dead_lettered";
      }
      const nextAttemptAt = this.clock().getTime() + ingressRetryBackoffMs(claim.attempt);
      const updated = database.prepare(`
        UPDATE slack_ingress_attempts
        SET next_attempt_at_ms = ?, last_error_kind = ?
        WHERE record_ref = ? AND attempt_count = ?
      `).run(nextAttemptAt, errorKind, claim.recordRef, claim.attempt);
      if (updated.changes !== 1) {
        throw new Error("Slack ingress attempt changed before failure recording.");
      }
      database.prepare(`
        DELETE FROM slack_ingress_leases
        WHERE record_ref = ? AND worker_ref = ? AND lease_token = ?
      `).run(claim.recordRef, claim.workerRef, claim.leaseToken);
      return "retry_scheduled";
    });
  }

  async readDeadLetter(recordRef: string): Promise<SlackIngressDeadLetter | undefined> {
    await this.initialize();
    const row = this.database().prepare(`
      SELECT dead_letter_json
      FROM slack_ingress_dead_letters
      WHERE record_ref = ?
    `).get(recordRef) as { dead_letter_json: string } | undefined;
    if (!row) return undefined;
    return this.parseDeadLetter(row.dead_letter_json);
  }

  async complete(
    permit: SlackIngressExecutionPermit,
    claim: SlackIngressClaim,
  ): Promise<void> {
    this.verifyPermit(permit, claim);
    await this.initialize();
    this.transaction((database) => {
      this.verifyLeaseOwnership(database, claim);
      const result = database.prepare(`
        DELETE FROM slack_ingress_events
        WHERE record_ref = ?
      `).run(claim.recordRef);
      if (result.changes !== 1) {
        throw new Error("Slack ingress completion requires one admitted event.");
      }
    });
  }

  async release(
    permit: SlackIngressExecutionPermit,
    claim: SlackIngressClaim,
  ): Promise<void> {
    this.verifyPermit(permit, claim);
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

  async renew(
    permit: SlackIngressExecutionPermit,
    claim: SlackIngressClaim,
  ): Promise<void> {
    this.verifyPermit(permit, claim);
    await this.initialize();
    this.transaction((database) => {
      this.verifyLeaseOwnership(database, claim);
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
      CREATE TABLE IF NOT EXISTS slack_ingress_order (
        admission_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        record_ref TEXT NOT NULL UNIQUE REFERENCES slack_ingress_events(record_ref) ON DELETE CASCADE
      ) STRICT;
      CREATE TABLE IF NOT EXISTS slack_ingress_attempts (
        record_ref TEXT PRIMARY KEY REFERENCES slack_ingress_events(record_ref) ON DELETE CASCADE,
        attempt_count INTEGER NOT NULL CHECK (attempt_count >= 0),
        next_attempt_at_ms INTEGER NOT NULL CHECK (next_attempt_at_ms >= 0),
        last_error_kind TEXT
      ) STRICT;
      CREATE TABLE IF NOT EXISTS slack_ingress_dead_letters (
        record_ref TEXT PRIMARY KEY,
        request_key TEXT NOT NULL UNIQUE,
        dead_lettered_at_ms INTEGER NOT NULL,
        attempt_count INTEGER NOT NULL CHECK (attempt_count > 0),
        last_error_kind TEXT NOT NULL,
        dead_letter_json TEXT NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS slack_message_bindings (
        request_key TEXT NOT NULL,
        client_message_id TEXT NOT NULL,
        message_ts TEXT NOT NULL,
        bound_at_ms INTEGER NOT NULL,
        binding_json TEXT NOT NULL,
        PRIMARY KEY (request_key, client_message_id)
      ) STRICT;
      INSERT OR IGNORE INTO slack_ingress_order (record_ref)
      SELECT record_ref
      FROM slack_ingress_events
      ORDER BY admitted_at_ms ASC, record_ref ASC;
      INSERT OR IGNORE INTO slack_ingress_attempts (
        record_ref,
        attempt_count,
        next_attempt_at_ms,
        last_error_kind
      )
      SELECT record_ref, 0, 0, NULL
      FROM slack_ingress_events;
    `);
    this.migrateMessageBindings(database);
    await chmod(this.databasePath(), 0o600);
    const gate = new DatabaseSync(this.executionGatePath());
    try {
      gate.exec(`
        PRAGMA busy_timeout = 5000;
        PRAGMA journal_mode = DELETE;
        PRAGMA synchronous = FULL;
        CREATE TABLE IF NOT EXISTS slack_ingress_execution_gate (
          singleton INTEGER PRIMARY KEY CHECK (singleton = 1)
        ) STRICT;
        INSERT OR IGNORE INTO slack_ingress_execution_gate (singleton) VALUES (1);
      `);
    } finally {
      gate.close();
    }
    await chmod(this.executionGatePath(), 0o600);
  }

  // The v1 message binding table keyed rows on request_key alone, so a single
  // Slack request could only bind one delivered message and the multipart
  // delivery threw when it tried to bind a second part. v2 keys on
  // (request_key, client_message_id) so each delivered part gets its own
  // binding. Recreate the table in place when the legacy single-column primary
  // key is present; existing bindings are preserved.
  private migrateMessageBindings(database: DatabaseSync): void {
    const columns = database.prepare(
      "PRAGMA table_info(slack_message_bindings)",
    ).all() as Array<{ name: string; pk: number }>;
    const clientIdColumn = columns.find((column) => column.name === "client_message_id");
    if (clientIdColumn === undefined || clientIdColumn.pk > 0) return;
    database.exec(`
      ALTER TABLE slack_message_bindings RENAME TO slack_message_bindings_v1_legacy;
      CREATE TABLE slack_message_bindings (
        request_key TEXT NOT NULL,
        client_message_id TEXT NOT NULL,
        message_ts TEXT NOT NULL,
        bound_at_ms INTEGER NOT NULL,
        binding_json TEXT NOT NULL,
        PRIMARY KEY (request_key, client_message_id)
      ) STRICT;
      INSERT INTO slack_message_bindings (
        request_key,
        client_message_id,
        message_ts,
        bound_at_ms,
        binding_json
      )
      SELECT request_key, client_message_id, message_ts, bound_at_ms, binding_json
      FROM slack_message_bindings_v1_legacy;
      DROP TABLE slack_message_bindings_v1_legacy;
    `);
  }

  private database(): DatabaseSync {
    this.databaseInstance ??= new DatabaseSync(this.databasePath());
    return this.databaseInstance;
  }

  private databasePath(): string {
    return join(this.root, "slack-ingress.sqlite3");
  }

  private executionGatePath(): string {
    return join(this.root, "slack-ingress-execution.sqlite3");
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

  private deadLetter(
    database: DatabaseSync,
    record: SlackIngressRecord,
    attemptCount: number,
    lastErrorKind: string,
  ): void {
    const deadLetteredAt = this.clock();
    const deadLetter: SlackIngressDeadLetter = {
      attemptCount,
      deadLetteredAt: deadLetteredAt.toISOString(),
      event: record.event,
      lastErrorKind,
      recordRef: record.recordRef,
      requestKey: record.requestKey,
      schemaVersion: "cerebro-slack-ingress-dead-letter/v1",
    };
    database.prepare(`
      INSERT INTO slack_ingress_dead_letters (
        record_ref,
        request_key,
        dead_lettered_at_ms,
        attempt_count,
        last_error_kind,
        dead_letter_json
      ) VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      deadLetter.recordRef,
      deadLetter.requestKey,
      deadLetteredAt.getTime(),
      deadLetter.attemptCount,
      deadLetter.lastErrorKind,
      JSON.stringify(deadLetter),
    );
    const removed = database.prepare(`
      DELETE FROM slack_ingress_events
      WHERE record_ref = ?
    `).run(record.recordRef);
    if (removed.changes !== 1) {
      throw new Error("Slack ingress dead-letter requires one admitted event.");
    }
  }

  private parseDeadLetter(serialized: string): SlackIngressDeadLetter {
    const deadLetter = JSON.parse(serialized) as SlackIngressDeadLetter;
    if (
      deadLetter.schemaVersion !== "cerebro-slack-ingress-dead-letter/v1"
      || !matchesText(deadLetter.recordRef)
      || !matchesRequestKey(deadLetter.requestKey)
      || !Number.isInteger(deadLetter.attemptCount)
      || deadLetter.attemptCount < 1
      || !Number.isFinite(Date.parse(deadLetter.deadLetteredAt))
      || !matchesText(deadLetter.lastErrorKind)
    ) throw new Error("Slack ingress dead-letter record is invalid.");
    validateIngressEvent(deadLetter.event);
    if (
      deadLetter.requestKey !== slackIngressRequestKey(deadLetter.event)
      || deadLetter.recordRef !== `slack-ingress-${digest(deadLetter.requestKey)}`
    ) throw new Error("Slack ingress dead-letter identity is invalid.");
    return deadLetter;
  }

  private verifyLeaseOwnership(database: DatabaseSync, claim: SlackIngressClaim): void {
    const lease = this.lease(database, claim.recordRef);
    if (
      !lease
      || lease.lease_token !== claim.leaseToken
      || lease.worker_ref !== claim.workerRef
    ) {
      throw new SlackIngressLeaseLostError();
    }
  }

  private verifyPermit(
    permit: SlackIngressExecutionPermit,
    claim?: SlackIngressClaim,
  ): void {
    if (
      !this.activeExecutionPermits.has(permit)
      || permit[executionPermitBrand] !== true
      || (claim !== undefined && claim.workerRef !== permit.workerRef)
    ) {
      throw new SlackIngressLeaseLostError(
        "Slack ingress work requires the active exclusive execution permit.",
      );
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

function errorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code?: unknown }).code)
    : undefined;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function ingressErrorKind(error: unknown): string {
  const kind = error instanceof Error && error.name.trim()
    ? error.name.trim()
    : "unknown";
  return kind.slice(0, 256);
}

function ingressRetryBackoffMs(attempt: number): number {
  const delay = INGRESS_RETRY_BACKOFF_MS[attempt - 1];
  if (delay === undefined) {
    throw new Error("Slack ingress retry backoff requires a retryable attempt.");
  }
  return delay;
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
