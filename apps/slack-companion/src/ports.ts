import type {
  AdmissionCommit,
  AdmissionCommitResult,
  AdmissionContext,
  InstallationTransition,
  InstallationTransitionResult,
} from "./contracts.js";

export interface ClockPort {
  now(): Date;
}

export interface IdentityPort {
  nextReceiptId(): string;
  nextRunId(): string;
}

/**
 * Commits the idempotency mapping, run receipt, admission events, and runnable
 * queue entry as one durable unit. A production adapter must never implement
 * this as a durable claim followed by process-local enqueue.
 */
export interface DurableAdmissionPort {
  admitAndEnqueue(commit: AdmissionCommit): Promise<AdmissionCommitResult>;
}

export interface AdmissionContextPort {
  read(bindingId: string): Promise<AdmissionContext>;
}

export interface InstallationLifecyclePort {
  compareAndSet(
    transition: InstallationTransition,
  ): Promise<InstallationTransitionResult>;
}
