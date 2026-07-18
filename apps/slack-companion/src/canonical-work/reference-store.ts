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
} from "./contracts.js";
import type { DurableCanonicalWorkCasePort } from "./ports.js";

interface Stored<T> {
  fingerprint: string;
  value: T;
}

/** In-memory conformance store for tests and local portable development. */
export class ReferenceMemoryCanonicalWorkCaseStore implements DurableCanonicalWorkCasePort {
  private readonly cases = new Map<string, Stored<CanonicalWorkCaseV1>>();
  private readonly intents = new Map<string, Stored<CanonicalWorkCommandIntentV1>>();

  async putCaseIfAbsent(input: CanonicalWorkCaseCommit): Promise<CanonicalWorkCaseCommitResult> {
    const current = this.cases.get(input.case.case_id);
    if (current !== undefined) {
      requireFingerprint(current.fingerprint, input.payload_fingerprint, "case");
      return { case: clone(current.value), created: false };
    }
    this.cases.set(input.case.case_id, {
      fingerprint: input.payload_fingerprint,
      value: clone(input.case),
    });
    return { case: clone(input.case), created: true };
  }

  async readCase(caseId: string): Promise<CanonicalWorkCaseV1 | undefined> {
    return cloneOptional(this.cases.get(caseId)?.value);
  }

  async syncCase(input: CanonicalWorkCaseSync): Promise<CanonicalWorkCaseV1> {
    const current = this.cases.get(input.case_id);
    if (current === undefined) throw new Error("Canonical work case does not exist.");
    if (current.value.revision !== input.expected_revision) {
      if (
        current.value.work_item_version === input.next.work_item_version &&
        current.value.work_item_updated_at === input.next.work_item_updated_at
      ) return clone(current.value);
      throw new Error("Canonical work case revision is stale.");
    }
    current.value = clone(input.next);
    return clone(current.value);
  }

  async putIntentIfAbsent(
    input: CanonicalWorkCommandIntentCommit,
  ): Promise<CanonicalWorkCommandIntentCommitResult> {
    const current = this.intents.get(input.intent.intent_id);
    if (current !== undefined) {
      requireFingerprint(current.fingerprint, input.payload_fingerprint, "command intent");
      return { created: false, intent: clone(current.value) };
    }
    this.intents.set(input.intent.intent_id, {
      fingerprint: input.payload_fingerprint,
      value: clone(input.intent),
    });
    return { created: true, intent: clone(input.intent) };
  }

  async readIntent(intentId: string): Promise<CanonicalWorkCommandIntentV1 | undefined> {
    return cloneOptional(this.intents.get(intentId)?.value);
  }

  async beginIntent(input: CanonicalWorkIntentBegin): Promise<CanonicalWorkIntentBeginResult> {
    const stored = this.requireIntent(input.intent_id);
    const current = stored.value;
    if (current.status === "applied" || current.status === "conflicted" || current.status === "executing") {
      return { created: false, intent: clone(current) };
    }
    if (current.revision !== input.expected_revision) throw new Error("Canonical work intent revision is stale.");
    stored.value = {
      ...current,
      approval_digest: input.approval.approval_digest,
      approval_ref: input.approval.approval_ref,
      approved_at: input.approval.approved_at,
      approved_by_ref: input.approval.approved_by_ref,
      revision: current.revision + 1,
      status: "executing",
      updated_at: input.updated_at,
    };
    return { created: true, intent: clone(stored.value) };
  }

  async finishIntent(input: CanonicalWorkIntentFinish): Promise<CanonicalWorkCommandIntentV1> {
    const stored = this.requireIntent(input.intent_id);
    const current = stored.value;
    const candidateDigest = input.record === undefined ? undefined : resultDigest(input.record);
    if (
      current.status === input.status &&
      current.reason_code === input.reason_code &&
      current.result_digest === candidateDigest &&
      current.result_state === input.record?.item.state &&
      current.result_version === input.record?.item.version
    ) return clone(current);
    if (current.revision !== input.expected_revision) throw new Error("Canonical work intent revision is stale.");
    stored.value = {
      ...current,
      reason_code: input.reason_code,
      result_digest: candidateDigest,
      result_state: input.record?.item.state,
      result_version: input.record?.item.version,
      revision: current.revision + 1,
      status: input.status,
      updated_at: input.updated_at,
    };
    return clone(stored.value);
  }

  private requireIntent(intentId: string): Stored<CanonicalWorkCommandIntentV1> {
    const stored = this.intents.get(intentId);
    if (stored === undefined) throw new Error("Canonical work intent does not exist.");
    return stored;
  }
}

function requireFingerprint(current: string, candidate: string, label: string): void {
  if (current !== candidate) throw new Error(`Canonical work ${label} changed intent.`);
}

function resultDigest(value: unknown): string {
  return `sha256:${createHash("sha256").update(stableJson(value)).digest("hex")}`;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .sort(([left], [right]) => left.localeCompare(right));
    return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${stableJson(entry)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

function cloneOptional<T>(value: T | undefined): T | undefined {
  return value === undefined ? undefined : clone(value);
}
