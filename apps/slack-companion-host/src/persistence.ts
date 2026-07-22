import { createHash } from "node:crypto";
import type {
  CanonicalWorkCaseCommit,
  CanonicalWorkCaseCommitResult,
  CanonicalWorkCaseSync,
  CanonicalWorkCaseV1,
  CanonicalWorkCommandIntentCommit,
  CanonicalWorkCommandIntentCommitResult,
  CanonicalWorkCommandIntentV1,
  CanonicalWorkIntentBegin,
  CanonicalWorkIntentBeginResult,
  CanonicalWorkIntentFinish,
  DurableCanonicalWorkCasePort,
} from "@writer/cerebro-slack-companion";
import type { AtomicDocument, AtomicDocumentStore } from "./types.js";

interface StoredCase {
  payload_fingerprint: string;
  record: CanonicalWorkCaseV1;
  schema_version: "private-canonical-work-case/v1";
}

interface StoredIntent {
  payload_fingerprint: string;
  record: CanonicalWorkCommandIntentV1;
  schema_version: "private-canonical-work-intent/v1";
}

export class AtomicCanonicalWorkCaseStore implements DurableCanonicalWorkCasePort {
  constructor(private readonly documents: AtomicDocumentStore) {}

  async putCaseIfAbsent(input: CanonicalWorkCaseCommit): Promise<CanonicalWorkCaseCommitResult> {
    const key = caseKey(input.case.case_id);
    const stored: StoredCase = {
      payload_fingerprint: input.payload_fingerprint,
      record: clone(input.case),
      schema_version: "private-canonical-work-case/v1",
    };
    if (await this.documents.putIfAbsent(key, stored)) return { case: clone(input.case), created: true };
    const current = parseCase(await this.requireDocument(key));
    if (current.payload_fingerprint !== input.payload_fingerprint) {
      throw new Error("Canonical work case changed intent for an existing identity.");
    }
    return { case: clone(current.record), created: false };
  }

  async putIntentIfAbsent(
    input: CanonicalWorkCommandIntentCommit,
  ): Promise<CanonicalWorkCommandIntentCommitResult> {
    const key = intentKey(input.intent.intent_id);
    const stored: StoredIntent = {
      payload_fingerprint: input.payload_fingerprint,
      record: clone(input.intent),
      schema_version: "private-canonical-work-intent/v1",
    };
    if (await this.documents.putIfAbsent(key, stored)) return { created: true, intent: clone(input.intent) };
    const current = parseIntent(await this.requireDocument(key));
    if (current.payload_fingerprint !== input.payload_fingerprint) {
      throw new Error("Canonical work command intent changed for an existing identity.");
    }
    return { created: false, intent: clone(current.record) };
  }

  async readCase(caseId: string): Promise<CanonicalWorkCaseV1 | undefined> {
    const document = await this.documents.read(caseKey(caseId));
    return document === undefined ? undefined : clone(parseCase(document).record);
  }

  async readIntent(intentId: string): Promise<CanonicalWorkCommandIntentV1 | undefined> {
    const document = await this.documents.read(intentKey(intentId));
    return document === undefined ? undefined : clone(parseIntent(document).record);
  }

  async syncCase(input: CanonicalWorkCaseSync): Promise<CanonicalWorkCaseV1> {
    const key = caseKey(input.case_id);
    const document = await this.requireDocument(key);
    const stored = parseCase(document);
    if (stored.record.revision !== input.expected_revision) throw staleRevision("case");
    const next: StoredCase = { ...stored, record: clone(input.next) };
    if (!(await this.documents.compareAndSwap(key, document.token, next))) throw staleRevision("case");
    return clone(next.record);
  }

  async beginIntent(input: CanonicalWorkIntentBegin): Promise<CanonicalWorkIntentBeginResult> {
    const key = intentKey(input.intent_id);
    const document = await this.requireDocument(key);
    const stored = parseIntent(document);
    const current = stored.record;
    if (current.revision !== input.expected_revision) throw staleRevision("intent");
    if (current.command_digest !== input.approval.command_digest || current.intent_id !== input.approval.intent_id) {
      throw new Error("Approval does not match the exact command intent.");
    }
    if (current.status === "executing" || current.status === "applied" || current.status === "conflicted") {
      assertSameApproval(current, input.approval.approval_digest, input.approval.approval_ref);
      return { created: false, intent: clone(current) };
    }
    const next: CanonicalWorkCommandIntentV1 = {
      ...current,
      approval_digest: input.approval.approval_digest,
      approval_ref: input.approval.approval_ref,
      approved_at: input.approval.approved_at,
      approved_by_ref: input.approval.approved_by_ref,
      reason_code: undefined,
      revision: current.revision + 1,
      status: "executing",
      updated_at: input.updated_at,
    };
    if (!(await this.documents.compareAndSwap(key, document.token, { ...stored, record: next }))) {
      throw staleRevision("intent");
    }
    return { created: true, intent: clone(next) };
  }

  async finishIntent(input: CanonicalWorkIntentFinish): Promise<CanonicalWorkCommandIntentV1> {
    const key = intentKey(input.intent_id);
    const document = await this.requireDocument(key);
    const stored = parseIntent(document);
    const current = stored.record;
    if (current.revision !== input.expected_revision || current.status !== "executing") {
      throw staleRevision("intent");
    }
    if ((input.status === "applied" || input.status === "conflicted") && input.record === undefined) {
      throw new Error("Terminal canonical command results require the current work-item record.");
    }
    const next: CanonicalWorkCommandIntentV1 = {
      ...current,
      reason_code: input.reason_code,
      result_digest: input.record === undefined ? undefined : digest(input.record),
      result_state: input.record?.item.state,
      result_version: input.record?.item.version,
      revision: current.revision + 1,
      status: input.status,
      updated_at: input.updated_at,
    };
    if (!(await this.documents.compareAndSwap(key, document.token, { ...stored, record: next }))) {
      throw staleRevision("intent");
    }
    return clone(next);
  }

  private async requireDocument(key: string): Promise<AtomicDocument> {
    const document = await this.documents.read(key);
    if (document === undefined) throw new Error("Canonical work record does not exist.");
    return document;
  }
}

function caseKey(caseId: string): string {
  return `canonical-work/cases/${encodeURIComponent(caseId)}`;
}

function intentKey(intentId: string): string {
  return `canonical-work/intents/${encodeURIComponent(intentId)}`;
}

function parseCase(document: AtomicDocument): StoredCase {
  const value = document.value as Partial<StoredCase>;
  if (value.schema_version !== "private-canonical-work-case/v1" || value.record === undefined) {
    throw new Error("Canonical work case document is invalid.");
  }
  return value as StoredCase;
}

function parseIntent(document: AtomicDocument): StoredIntent {
  const value = document.value as Partial<StoredIntent>;
  if (value.schema_version !== "private-canonical-work-intent/v1" || value.record === undefined) {
    throw new Error("Canonical work intent document is invalid.");
  }
  return value as StoredIntent;
}

function assertSameApproval(
  intent: CanonicalWorkCommandIntentV1,
  approvalDigest: string,
  approvalRef: string,
): void {
  if (intent.approval_digest !== approvalDigest || intent.approval_ref !== approvalRef) {
    throw new Error("Approval does not match the recorded command execution.");
  }
}

function staleRevision(kind: "case" | "intent"): Error {
  return new Error(`Canonical work ${kind} revision is stale.`);
}

function digest(value: unknown): string {
  return `sha256:${createHash("sha256").update(stableJson(value)).digest("hex")}`;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${stableJson(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function clone<T>(value: T): T {
  return structuredClone(value);
}
