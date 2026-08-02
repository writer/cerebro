import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { AgentApprovalRequest } from "./cerebro-ask-client.js";

const APPROVAL_LIFETIME_MS = 30 * 60 * 1_000;
const APPROVAL_SCHEMA_VERSION = "slack-agent-approval/v1";

export interface PendingAgentApproval extends AgentApprovalRequest {
  actorRef: string;
  createdAt: string;
  expiresAt: string;
  question: string;
  requestId: string;
  schemaVersion: typeof APPROVAL_SCHEMA_VERSION;
  threadRef: string;
}

export class FileAgentApprovalStore {
  private mutationQueue: Promise<void> = Promise.resolve();

  constructor(
    private readonly root: string,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  async record(input: {
    actorRef: string;
    approval: AgentApprovalRequest;
    question: string;
    requestId: string;
    threadRef: string;
  }): Promise<PendingAgentApproval> {
    return this.serialize(async () => {
      const now = this.clock();
      const approval: PendingAgentApproval = {
        approvalRef: input.approval.approvalRef,
        inputDigest: input.approval.inputDigest,
        purpose: input.approval.purpose,
        toolId: input.approval.toolId,
        actorRef: requiredText(input.actorRef, "actorRef"),
        createdAt: now.toISOString(),
        expiresAt: new Date(now.getTime() + APPROVAL_LIFETIME_MS).toISOString(),
        question: requiredText(input.question, "question"),
        requestId: requiredText(input.requestId, "requestId"),
        schemaVersion: APPROVAL_SCHEMA_VERSION,
        threadRef: requiredText(input.threadRef, "threadRef"),
      };
      validateApproval(approval);
      await atomicWrite(this.path(input.threadRef), approval);
      return approval;
    });
  }

  async read(threadRef: string): Promise<PendingAgentApproval | undefined> {
    const path = this.path(threadRef);
    let decoded: unknown;
    try {
      decoded = JSON.parse(await readFile(path, "utf8"));
    } catch (error) {
      if (errorCode(error) === "ENOENT") return undefined;
      throw error;
    }
    const approval = validateApproval(decoded);
    if (approval.threadRef !== threadRef) {
      throw new Error("The saved Slack approval belongs to another thread.");
    }
    if (Date.parse(approval.expiresAt) <= this.clock().getTime()) {
      await rm(path, { force: true });
      return undefined;
    }
    return approval;
  }

  async clear(threadRef: string, approvalRef?: string): Promise<boolean> {
    return this.serialize(async () => {
      const current = await this.read(threadRef);
      if (!current || (approvalRef !== undefined && current.approvalRef !== approvalRef)) {
        return false;
      }
      await rm(this.path(threadRef), { force: true });
      return true;
    });
  }

  private path(threadRef: string): string {
    return join(this.root, "agent-approvals", `${digest(threadRef)}.json`);
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

function validateApproval(value: unknown): PendingAgentApproval {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The saved Slack approval is invalid.");
  }
  const approval = value as Record<string, unknown>;
  const exactKeys = [
    "actorRef",
    "approvalRef",
    "createdAt",
    "expiresAt",
    "inputDigest",
    "purpose",
    "question",
    "requestId",
    "schemaVersion",
    "threadRef",
    "toolId",
  ];
  if (
    Object.keys(approval).sort().join("\n") !== exactKeys.sort().join("\n")
    || approval.schemaVersion !== APPROVAL_SCHEMA_VERSION
    || !text(approval.actorRef)
    || !/^approval:\/\/agent-effect\/[a-f0-9]{64}$/u.test(text(approval.approvalRef))
    || !/^sha256:[a-f0-9]{64}$/u.test(text(approval.inputDigest))
    || !text(approval.purpose)
    || !text(approval.question)
    || !text(approval.requestId)
    || !text(approval.threadRef)
    || !text(approval.toolId)
    || !canonicalTimestamp(approval.createdAt)
    || !canonicalTimestamp(approval.expiresAt)
    || Date.parse(text(approval.expiresAt)) <= Date.parse(text(approval.createdAt))
  ) {
    throw new Error("The saved Slack approval is invalid.");
  }
  return approval as unknown as PendingAgentApproval;
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

function requiredText(value: string, field: string): string {
  const normalized = value.trim();
  if (!normalized) throw new Error(`The Slack approval ${field} is empty.`);
  return normalized;
}

function canonicalTimestamp(value: unknown): boolean {
  return typeof value === "string"
    && Number.isFinite(Date.parse(value))
    && new Date(value).toISOString() === value;
}

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function errorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code?: unknown }).code)
    : undefined;
}
