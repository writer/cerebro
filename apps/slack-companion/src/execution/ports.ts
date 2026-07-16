import type {
  CheckpointDraft,
  CheckpointV1,
  EffectDraft,
  EffectReceiptV1,
  EffectResolution,
  ExternalEffectIntentCommit,
  ExternalEffectIntentDraft,
  ExternalEffectIntentV1,
  LeaseAcquisition,
  LeaseClaim,
  RecoveredRun,
  RunReceiptV1,
  WorkLeaseV1,
} from "./model.js";

export interface ExecutionClockPort {
  now(): Date;
}

/**
 * Durable execution operations. Production adapters must make each method's
 * documented state change atomic and reject an outdated lease proof.
 */
export interface DurableExecutionPort {
  /** Atomically advances the run to leased and installs one fenced lease. */
  acquireLease(
    claim: LeaseClaim,
    heartbeatAt: string,
    leaseExpiresAt: string,
  ): Promise<LeaseAcquisition | undefined>;

  /** Returns the lease only when every ownership and fencing field is current. */
  renewLease(
    lease: WorkLeaseV1,
    heartbeatAt: string,
    leaseExpiresAt: string,
  ): Promise<WorkLeaseV1>;

  /** Atomically releases ownership and returns a non-terminal run to queued. */
  releaseLease(
    lease: WorkLeaseV1,
    releasedAt: string,
  ): Promise<RunReceiptV1>;

  /** Atomically advances a leased run to running under the same lease proof. */
  markRunning(lease: WorkLeaseV1, updatedAt: string): Promise<RunReceiptV1>;

  latestCheckpoint(runId: string): Promise<CheckpointV1 | undefined>;

  appendCheckpoint(
    lease: WorkLeaseV1,
    draft: CheckpointDraft,
    createdAt: string,
  ): Promise<CheckpointV1>;

  /** Atomically appends the checkpoint, pauses the run, and releases the lease. */
  pauseWithCheckpoint(
    lease: WorkLeaseV1,
    draft: CheckpointDraft,
    createdAt: string,
  ): Promise<{ checkpoint: CheckpointV1; run: RunReceiptV1 }>;

  /**
   * Atomically finishes execution, advances the run to durable delivery, and
   * releases its lease. An external intent without a succeeded, independently
   * verified effect must block this transition. Delivery reconciliation alone
   * may complete the run.
   */
  finishExecution(
    lease: WorkLeaseV1,
    finishedAt: string,
  ): Promise<RunReceiptV1>;

  /**
   * Persists the exact external write intent under the active lease. Repeating
   * the same logical intent is idempotent; changing it is a conflict.
   */
  persistEffectIntent(
    lease: WorkLeaseV1,
    draft: ExternalEffectIntentDraft,
    persistedAt: string,
  ): Promise<ExternalEffectIntentCommit>;

  getEffectIntent(
    runId: string,
    idempotencyKey: string,
  ): Promise<ExternalEffectIntentV1 | undefined>;

  beginEffect(
    lease: WorkLeaseV1,
    draft: EffectDraft,
    recordedAt: string,
  ): Promise<EffectReceiptV1>;

  markEffectExecuting(
    lease: WorkLeaseV1,
    idempotencyKey: string,
    recordedAt: string,
  ): Promise<EffectReceiptV1>;

  resolveEffect(
    lease: WorkLeaseV1,
    idempotencyKey: string,
    resolution: EffectResolution,
    recordedAt: string,
  ): Promise<EffectReceiptV1>;

  getEffect(
    runId: string,
    idempotencyKey: string,
  ): Promise<EffectReceiptV1 | undefined>;

  listExpiredLeases(observedAt: string): Promise<WorkLeaseV1[]>;

  /**
   * Atomically removes the expired lease, returns the run to queued, and marks
   * effects left executing by that lease as unknown.
   */
  recoverExpiredLease(
    lease: WorkLeaseV1,
    recoveredAt: string,
  ): Promise<RecoveredRun>;
}
