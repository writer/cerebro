import type {
  ComplianceWorkCommand,
  ComplianceWorkItemPage,
  ComplianceWorkItemRecord,
  ComplianceWorkItemState,
} from "@writer/cerebro-sdk";
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

export interface CanonicalWorkClockPort {
  now(): Date;
}

/** Implemented by a host with the public Cerebro SDK. */
export interface CanonicalWorkItemPort {
  command(
    workItemId: string,
    command: ComplianceWorkCommand,
    context: { idempotency_key: string },
  ): Promise<ComplianceWorkItemRecord>;
  get(workItemId: string): Promise<ComplianceWorkItemRecord>;
  list(options?: {
    cursor?: string;
    limit?: number;
    owner_id?: string;
    state?: ComplianceWorkItemState;
  }): Promise<ComplianceWorkItemPage>;
}

/**
 * Production hosts make each mutation durable and atomic. Exact retries return
 * the prior value; changed intent and stale revisions are rejected.
 */
export interface DurableCanonicalWorkCasePort {
  beginIntent(input: CanonicalWorkIntentBegin): Promise<CanonicalWorkIntentBeginResult>;
  finishIntent(input: CanonicalWorkIntentFinish): Promise<CanonicalWorkCommandIntentV1>;
  putCaseIfAbsent(input: CanonicalWorkCaseCommit): Promise<CanonicalWorkCaseCommitResult>;
  putIntentIfAbsent(
    input: CanonicalWorkCommandIntentCommit,
  ): Promise<CanonicalWorkCommandIntentCommitResult>;
  readCase(caseId: string): Promise<CanonicalWorkCaseV1 | undefined>;
  readIntent(intentId: string): Promise<CanonicalWorkCommandIntentV1 | undefined>;
  syncCase(input: CanonicalWorkCaseSync): Promise<CanonicalWorkCaseV1>;
}
