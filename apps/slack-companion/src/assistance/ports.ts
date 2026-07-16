import type { RunReceiptV1 } from "@writer/cerebro-sdk";
import type {
  AssistanceDeliveryAttachment,
  AssistanceOutcomeCommit,
  AssistanceRefinementAdmission,
  AssistanceRefinementAttachment,
  AssistanceRefinementReceipt,
  AssistanceRequestCommit,
  AssistanceRequestCommitResult,
  AssistanceRequestV1,
  AssistanceThreadAttachment,
} from "./contracts.js";

export interface AssistanceClockPort {
  now(): Date;
}

/** Reads receipts from the existing durable run lifecycle. */
export interface AssistanceRunReceiptPort {
  readRun(runId: string): RunReceiptV1 | undefined | Promise<RunReceiptV1 | undefined>;
}

/**
 * Admits refinement work under the already admitted reply run. Implementations
 * must use idempotency_key and must not create a second run lifecycle.
 */
export interface AssistanceRefinementPort {
  admit(
    admission: AssistanceRefinementAdmission,
  ): Promise<AssistanceRefinementReceipt>;
}

/**
 * Production implementations make every operation durable and atomic. CAS
 * methods return the prior value for an exact retry and reject changed intent.
 */
export interface DurableAssistancePort {
  attachDelivery(
    attachment: AssistanceDeliveryAttachment,
  ): Promise<AssistanceRequestV1>;
  attachRefinement(
    attachment: AssistanceRefinementAttachment,
  ): Promise<AssistanceRequestV1>;
  attachThreadBinding(
    attachment: AssistanceThreadAttachment,
  ): Promise<AssistanceRequestV1>;
  expire(
    assistanceId: string,
    expectedRevision: number,
    expiredAt: string,
  ): Promise<AssistanceRequestV1>;
  putIfAbsent(
    commit: AssistanceRequestCommit,
  ): Promise<AssistanceRequestCommitResult>;
  read(assistanceId: string): Promise<AssistanceRequestV1 | undefined>;
  recordOutcome(commit: AssistanceOutcomeCommit): Promise<AssistanceRequestV1>;
}
