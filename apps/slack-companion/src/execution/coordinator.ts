import type {
  CheckpointDraft,
  CheckpointV1,
  EffectDraft,
  EffectReceiptV1,
  EffectResolution,
  ExecutionSession,
  ExecutionStartResult,
  LeaseClaim,
  RecoveredRun,
  RunReceiptV1,
  ServiceAvailabilityState,
  WorkLeaseV1,
} from "./model.js";
import { mayAcquireNewLease } from "./model.js";
import type {
  DurableExecutionPort,
  ExecutionClockPort,
} from "./ports.js";

export interface ExecutionCoordinatorOptions {
  clock: ExecutionClockPort;
  lease_duration_ms: number;
  store: DurableExecutionPort;
}

export interface StartExecutionInput extends LeaseClaim {
  service_state: ServiceAvailabilityState;
}

export class ExecutionCoordinator {
  private readonly clock: ExecutionClockPort;
  private readonly leaseDurationMs: number;
  private readonly store: DurableExecutionPort;

  constructor(options: ExecutionCoordinatorOptions) {
    if (!Number.isSafeInteger(options.lease_duration_ms) || options.lease_duration_ms <= 0) {
      throw new Error("lease_duration_ms must be a positive integer");
    }
    this.clock = options.clock;
    this.leaseDurationMs = options.lease_duration_ms;
    this.store = options.store;
  }

  async start(input: StartExecutionInput): Promise<ExecutionStartResult> {
    if (!mayAcquireNewLease(input.service_state)) {
      return { status: "not_runnable" };
    }

    const now = this.clock.now();
    const acquired = await this.store.acquireLease(
      input,
      now.toISOString(),
      this.expiresAt(now),
    );
    if (acquired === undefined) {
      return { status: "not_runnable" };
    }

    const run =
      acquired.run.state === "leased"
        ? await this.store.markRunning(acquired.lease, now.toISOString())
        : acquired.run;
    const checkpoint = await this.store.latestCheckpoint(input.run_id);

    return {
      session: { checkpoint, lease: acquired.lease, run },
      status: checkpoint === undefined ? "started" : "resumed",
    };
  }

  renew(lease: WorkLeaseV1): Promise<WorkLeaseV1> {
    const now = this.clock.now();
    return this.store.renewLease(lease, now.toISOString(), this.expiresAt(now));
  }

  release(session: ExecutionSession): Promise<RunReceiptV1> {
    return this.store.releaseLease(
      session.lease,
      this.clock.now().toISOString(),
    );
  }

  checkpoint(
    session: ExecutionSession,
    draft: CheckpointDraft,
  ): Promise<CheckpointV1> {
    return this.store.appendCheckpoint(
      session.lease,
      draft,
      this.clock.now().toISOString(),
    );
  }

  pauseForDrain(
    session: ExecutionSession,
    draft: CheckpointDraft,
  ): Promise<{ checkpoint: CheckpointV1; run: RunReceiptV1 }> {
    return this.store.pauseWithCheckpoint(
      session.lease,
      draft,
      this.clock.now().toISOString(),
    );
  }

  finishExecution(session: ExecutionSession): Promise<RunReceiptV1> {
    return this.store.finishExecution(
      session.lease,
      this.clock.now().toISOString(),
    );
  }

  beginEffect(
    session: ExecutionSession,
    draft: EffectDraft,
  ): Promise<EffectReceiptV1> {
    if (draft.approval_required && draft.approval_ref === undefined) {
      return Promise.reject(
        new ExecutionInvariantError("required effect approval is missing"),
      );
    }
    return this.store.beginEffect(
      session.lease,
      draft,
      this.clock.now().toISOString(),
    );
  }

  markEffectExecuting(
    session: ExecutionSession,
    idempotencyKey: string,
  ): Promise<EffectReceiptV1> {
    return this.store.markEffectExecuting(
      session.lease,
      idempotencyKey,
      this.clock.now().toISOString(),
    );
  }

  resolveEffect(
    session: ExecutionSession,
    idempotencyKey: string,
    resolution: EffectResolution,
  ): Promise<EffectReceiptV1> {
    if (
      resolution.state === "succeeded" &&
      resolution.verification_state !== "verified"
    ) {
      return Promise.reject(
        new ExecutionInvariantError(
          "a successful effect requires successful independent verification",
        ),
      );
    }
    if (resolution.verification_receipt_ref === resolution.result_ref) {
      return Promise.reject(
        new ExecutionInvariantError(
          "effect result and verification must use different receipts",
        ),
      );
    }
    return this.store.resolveEffect(
      session.lease,
      idempotencyKey,
      resolution,
      this.clock.now().toISOString(),
    );
  }

  async reconcileExpired(): Promise<RecoveredRun[]> {
    const now = this.clock.now().toISOString();
    const expired = await this.store.listExpiredLeases(now);
    const recovered: RecoveredRun[] = [];
    for (const lease of expired) {
      const result = await this.store.recoverExpiredLease(lease, now);
      if (result.recovered) {
        recovered.push(result);
      }
    }
    return recovered;
  }

  private expiresAt(now: Date): string {
    return new Date(now.getTime() + this.leaseDurationMs).toISOString();
  }
}

export class ExecutionInvariantError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ExecutionInvariantError";
  }
}
