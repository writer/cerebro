import type { RunReceiptV1 } from "../execution/model.js";
import type {
  QuestionWorkAdmissionCommit,
  QuestionWorkAdmissionCommitResult,
  QuestionWorkClaim,
  QuestionWorkClaimResult,
  QuestionWorkOutcomeInput,
  QuestionWorkOutcomeResult,
  QuestionWorkProgressInput,
  QuestionWorkProgressResult,
  QuestionWorkRetryInput,
  QuestionWorkRetryResult,
  QuestionWorkRunnableCommit,
  QuestionWorkRunnableResult,
  QuestionWorkV1,
} from "./contracts.js";

export interface QuestionWorkClockPort {
  now(): Date;
}

/** Reads the existing durable admission receipt for the Slack request. */
export interface QuestionWorkRunReceiptPort {
  readRun(runId: string): RunReceiptV1 | undefined | Promise<RunReceiptV1 | undefined>;
}

/**
 * Production adapters make every operation durable and atomic. Admission must
 * commit the work snapshot, immutable preflight receipt, and optional runnable
 * outbox item before returning. Every later mutation must verify the supplied
 * WorkLeaseV1 against the current durable run lease, including its generation
 * and fencing token.
 */
export interface DurableQuestionWorkPort {
  admitAndQueue(
    commit: QuestionWorkAdmissionCommit,
  ): Promise<QuestionWorkAdmissionCommitResult>;
  appendProgress(
    input: QuestionWorkProgressInput,
    recordedAt: string,
  ): Promise<QuestionWorkProgressResult>;
  claim(input: QuestionWorkClaim): Promise<QuestionWorkClaimResult | undefined>;
  makeRunnable(
    commit: QuestionWorkRunnableCommit,
  ): Promise<QuestionWorkRunnableResult>;
  read(workId: string): Promise<QuestionWorkV1 | undefined>;
  recordOutcome(
    input: QuestionWorkOutcomeInput,
    recordedAt: string,
  ): Promise<QuestionWorkOutcomeResult>;
  scheduleRetry(
    input: QuestionWorkRetryInput,
    recordedAt: string,
  ): Promise<QuestionWorkRetryResult>;
}
