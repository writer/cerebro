import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, rename, stat, unlink, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
  ASSISTANT_EXECUTION_LANES,
  AssistantTurnHostAdapter,
  type AssistantExecutionLane,
  type AssistantTurnHostTelemetryEvent,
  type AssistantTurnOutcomeAssessment,
  type AssistantTurnReceiptPort,
  type AssistantTurnTelemetryPort,
  type SlackMultipartProjection,
  type SlackStatusProjection,
} from "../assistant-turn.js";

export const OUTCOME_OBSERVATION_WINDOW_MS = 24 * 60 * 60 * 1_000;
export const ADMISSION_RETENTION_MS = 24 * 60 * 60 * 1_000;
export const TELEMETRY_RETENTION_MS = 7 * 24 * 60 * 60 * 1_000;
const MAX_ADMISSION_RECEIPTS = 50_000;
const MAX_TELEMETRY_RECEIPTS = 100_000;

export interface PendingAssistantOutcome {
  delivered_message_ts: string;
  execution_lane: AssistantExecutionLane;
  latency_budget_ms: number;
  negative_feedback_count: number;
  opened_at: string;
  outcome_state: "blocked" | "completed" | "needs_user" | "owned" | "unknown";
  request_id: string;
  schema_version: "assistant-turn-pending-outcome/v1";
  user_correction_count: number;
  useful_answer_at?: string;
  verified: boolean;
}

export interface OutcomeStoreOptions {
  clock?: () => Date;
  log?: (event: AssistantTurnHostTelemetryEvent) => void;
}

export class FileOutcomeStore
  implements AssistantTurnReceiptPort, AssistantTurnTelemetryPort {
  private readonly clock: () => Date;
  private readonly log: (event: AssistantTurnHostTelemetryEvent) => void;
  private mutationQueue: Promise<void> = Promise.resolve();

  constructor(
    private readonly root: string,
    options: OutcomeStoreOptions = {},
  ) {
    this.clock = options.clock ?? (() => new Date());
    this.log = options.log ?? ((event) => {
      process.stdout.write(`${JSON.stringify({ component: "slack-outcomes", ...event })}\n`);
    });
  }

  async initialize(): Promise<void> {
    await Promise.all([
      mkdir(this.directory("pending"), { recursive: true }),
      mkdir(this.directory("assessments"), { recursive: true }),
      mkdir(this.directory("delivery"), { recursive: true }),
      mkdir(this.directory("status"), { recursive: true }),
      mkdir(this.directory("admissions"), { recursive: true }),
      mkdir(this.directory("telemetry"), { recursive: true }),
    ]);
  }

  async recordPending(outcome: PendingAssistantOutcome): Promise<void> {
    validatePending(outcome);
    await this.serialize(async () => {
      await this.atomicWrite(this.path("pending", outcome.request_id), outcome);
    });
  }

  async claimRequest(requestKey: string): Promise<boolean> {
    await this.initialize();
    try {
      await writeFile(this.path("admissions", requestKey), "claimed\n", {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600,
      });
      return true;
    } catch (error) {
      if (errorCode(error) === "EEXIST") return false;
      throw error;
    }
  }

  async recordNegativeFeedback(deliveredMessageTs: string): Promise<boolean> {
    let recorded = false;
    await this.serialize(async () => {
      for (const file of await this.pendingFiles()) {
        const pending = await this.readPending(file);
        if (pending.delivered_message_ts !== deliveredMessageTs) continue;
        await this.atomicWrite(this.path("pending", pending.request_id), {
          ...pending,
          negative_feedback_count: pending.negative_feedback_count + 1,
        });
        recorded = true;
        return;
      }
    });
    return recorded;
  }

  async assessDue(host: AssistantTurnHostAdapter): Promise<number> {
    let assessed = 0;
    await this.initialize();
    await this.serialize(async () => {
      await Promise.all([
        this.pruneReceiptDirectory("admissions", ADMISSION_RETENTION_MS, MAX_ADMISSION_RECEIPTS),
        this.pruneReceiptDirectory("telemetry", TELEMETRY_RETENTION_MS, MAX_TELEMETRY_RECEIPTS),
      ]);
      for (const file of await this.pendingFiles()) {
        const pending = await this.readPending(file);
        const openedAt = Date.parse(pending.opened_at);
        if (this.clock().getTime() - openedAt < OUTCOME_OBSERVATION_WINDOW_MS) continue;
        await host.recordOutcome({
          assessment_at: this.clock().toISOString(),
          evaluation_blockers: pending.verified ? [] : ["outcome_unknown"],
          execution_lane: pending.execution_lane,
          latency_budget_ms: pending.latency_budget_ms,
          negative_feedback_count: pending.negative_feedback_count,
          opened_at: pending.opened_at,
          outcome_state: pending.outcome_state,
          request_id: pending.request_id,
          request_kind: "human",
          user_correction_count: pending.user_correction_count,
          useful_answer_at: pending.useful_answer_at,
          verified: pending.verified,
        });
        await unlink(file);
        assessed += 1;
      }
    });
    return assessed;
  }

  async persistOutcome(
    assessment: AssistantTurnOutcomeAssessment,
  ): Promise<{ receipt_ref: string }> {
    await this.atomicWrite(
      this.path("assessments", assessment.assessment_digest),
      assessment,
    );
    return { receipt_ref: `receipt://assistant-outcome/${digest(assessment.assessment_digest)}` };
  }

  async persistMultipartDelivery(
    projection: SlackMultipartProjection,
  ): Promise<{ receipt_ref: string }> {
    await this.atomicWrite(this.path("delivery", projection.projection_id), projection);
    return { receipt_ref: `receipt://slack-delivery/${digest(projection.projection_id)}` };
  }

  async persistStatus(
    projection: SlackStatusProjection,
  ): Promise<{ receipt_ref: string }> {
    await this.atomicWrite(this.path("status", projection.projection_id), projection);
    return { receipt_ref: `receipt://slack-status/${digest(projection.projection_id)}` };
  }

  async recordIdempotent(event: AssistantTurnHostTelemetryEvent): Promise<void> {
    await this.initialize();
    try {
      await writeFile(this.path("telemetry", event.event_id), `${JSON.stringify(event)}\n`, {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600,
      });
    } catch (error) {
      if (errorCode(error) === "EEXIST") return;
      throw error;
    }
    this.log(event);
  }

  private async pendingFiles(): Promise<string[]> {
    await this.initialize();
    return (await readdir(this.directory("pending")))
      .filter((file) => file.endsWith(".json"))
      .sort()
      .map((file) => join(this.directory("pending"), file));
  }

  private async readPending(file: string): Promise<PendingAssistantOutcome> {
    const decoded: unknown = JSON.parse(await readFile(file, "utf8"));
    validatePending(decoded);
    return decoded;
  }

  private async atomicWrite(path: string, value: unknown): Promise<void> {
    await mkdir(dirname(path), { recursive: true });
    const temporary = `${path}.${randomUUID()}.tmp`;
    await writeFile(temporary, `${JSON.stringify(value)}\n`, { encoding: "utf8", mode: 0o600 });
    await rename(temporary, path);
  }

  private async pruneReceiptDirectory(
    name: "admissions" | "telemetry",
    retentionMs: number,
    maximumReceipts: number,
  ): Promise<void> {
    const directory = this.directory(name);
    const receipts = await Promise.all(
      (await readdir(directory))
        .filter((file) => file.endsWith(".json"))
        .map(async (file) => {
          const path = join(directory, file);
          return { path, modifiedAt: (await stat(path)).mtimeMs };
        }),
    );
    receipts.sort((left, right) => right.modifiedAt - left.modifiedAt);
    const cutoff = this.clock().getTime() - retentionMs;
    const expired = receipts.filter((receipt) => receipt.modifiedAt < cutoff);
    const retained = receipts.filter((receipt) => receipt.modifiedAt >= cutoff);
    const overLimit = retained.slice(maximumReceipts);
    await Promise.all([...expired, ...overLimit].map(async ({ path }) => {
      await unlink(path).catch((error: unknown) => {
        if (errorCode(error) !== "ENOENT") throw error;
      });
    }));
  }

  private directory(name: string): string {
    return join(this.root, name);
  }

  private path(directory: string, key: string): string {
    return join(this.directory(directory), `${digest(key)}.json`);
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

function validatePending(value: unknown): asserts value is PendingAssistantOutcome {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Pending assistant outcome is invalid.");
  }
  const pending = value as Partial<PendingAssistantOutcome>;
  if (
    pending.schema_version !== "assistant-turn-pending-outcome/v1"
    || typeof pending.request_id !== "string"
    || pending.request_id.length === 0
    || typeof pending.delivered_message_ts !== "string"
    || !ASSISTANT_EXECUTION_LANES.includes(pending.execution_lane as AssistantExecutionLane)
    || !Number.isSafeInteger(pending.latency_budget_ms)
    || !Number.isSafeInteger(pending.negative_feedback_count)
    || !Number.isSafeInteger(pending.user_correction_count)
    || typeof pending.opened_at !== "string"
    || !Number.isFinite(Date.parse(pending.opened_at))
    || typeof pending.verified !== "boolean"
  ) {
    throw new Error("Pending assistant outcome is invalid.");
  }
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function errorCode(value: unknown): string | undefined {
  return value !== null && typeof value === "object" && "code" in value
    ? String((value as { code?: unknown }).code)
    : undefined;
}
