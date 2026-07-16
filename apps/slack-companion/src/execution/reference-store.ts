import { ExecutionInvariantError } from "./coordinator.js";
import {
  effectIntentDigest,
  normalizeEffectIntentValue,
  sameExternalEffectIntent,
} from "./effect-intent.js";
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
import type { DurableExecutionPort } from "./ports.js";

/** Conformance fixture only. Production adapters must use durable storage. */
export class ReferenceMemoryExecutionStore implements DurableExecutionPort {
  private readonly checkpoints = new Map<string, CheckpointV1[]>();
  private readonly effects = new Map<string, EffectReceiptV1>();
  private readonly effectIntents = new Map<string, ExternalEffectIntentV1>();
  private readonly fencingTokens = new Map<string, number>();
  private readonly highestGenerations = new Map<string, number>();
  private readonly leases = new Map<string, WorkLeaseV1>();
  private readonly runs = new Map<string, RunReceiptV1>();

  seedRun(run: RunReceiptV1): void {
    this.runs.set(run.run_id, structuredClone(run));
  }

  acquireLease(
    claim: LeaseClaim,
    heartbeatAt: string,
    leaseExpiresAt: string,
  ): Promise<LeaseAcquisition | undefined> {
    validateLeaseClaim(claim);
    const run = this.runs.get(claim.run_id);
    if (run === undefined) {
      throw new ExecutionInvariantError("run does not exist");
    }
    const highestGeneration = this.highestGenerations.get(claim.run_id) ?? 0;
    if (claim.generation < highestGeneration) {
      throw new ExecutionInvariantError("lease generation regressed");
    }

    const current = this.leases.get(claim.run_id);
    if (current !== undefined) {
      if (sameLeaseClaim(current, claim)) {
        return Promise.resolve({
          created: false,
          lease: structuredClone(current),
          run: structuredClone(run),
        });
      }
      return Promise.resolve(undefined);
    }
    if (run.state !== "queued" && run.state !== "paused") {
      return Promise.resolve(undefined);
    }

    const fencingToken = (this.fencingTokens.get(claim.run_id) ?? 0) + 1;
    this.fencingTokens.set(claim.run_id, fencingToken);
    this.highestGenerations.set(claim.run_id, claim.generation);
    const lease: WorkLeaseV1 = {
      fencing_token: fencingToken,
      generation: claim.generation,
      heartbeat_at: heartbeatAt,
      lease_expires_at: leaseExpiresAt,
      lease_token: claim.lease_token,
      owner_id: claim.owner_id,
      run_id: claim.run_id,
      schema_version: "work-lease/v1",
    };
    const leasedRun = updateRun(run, "leased", heartbeatAt);
    this.leases.set(claim.run_id, lease);
    this.runs.set(claim.run_id, leasedRun);
    return Promise.resolve({
      created: true,
      lease: structuredClone(lease),
      run: structuredClone(leasedRun),
    });
  }

  renewLease(
    lease: WorkLeaseV1,
    heartbeatAt: string,
    leaseExpiresAt: string,
  ): Promise<WorkLeaseV1> {
    this.assertLease(lease, heartbeatAt);
    const renewed = {
      ...lease,
      heartbeat_at: heartbeatAt,
      lease_expires_at: leaseExpiresAt,
    };
    this.leases.set(lease.run_id, renewed);
    return Promise.resolve(structuredClone(renewed));
  }

  releaseLease(
    lease: WorkLeaseV1,
    releasedAt: string,
  ): Promise<RunReceiptV1> {
    this.assertLease(lease, releasedAt);
    const queued = updateRun(this.requireRun(lease.run_id), "queued", releasedAt);
    this.runs.set(lease.run_id, queued);
    this.leases.delete(lease.run_id);
    return Promise.resolve(structuredClone(queued));
  }

  markRunning(lease: WorkLeaseV1, updatedAt: string): Promise<RunReceiptV1> {
    this.assertLease(lease, updatedAt);
    const run = this.requireRun(lease.run_id);
    if (run.state === "running") {
      return Promise.resolve(structuredClone(run));
    }
    if (run.state !== "leased") {
      throw new ExecutionInvariantError("only a leased run can start");
    }
    const running = updateRun(run, "running", updatedAt);
    this.runs.set(run.run_id, running);
    return Promise.resolve(structuredClone(running));
  }

  latestCheckpoint(runId: string): Promise<CheckpointV1 | undefined> {
    const records = this.checkpoints.get(runId) ?? [];
    const checkpoint = records.at(-1);
    return Promise.resolve(
      checkpoint === undefined ? undefined : structuredClone(checkpoint),
    );
  }

  appendCheckpoint(
    lease: WorkLeaseV1,
    draft: CheckpointDraft,
    createdAt: string,
  ): Promise<CheckpointV1> {
    this.assertLease(lease, createdAt);
    const checkpoint = this.buildCheckpoint(lease, draft, createdAt);
    const stored = this.storeCheckpoint(checkpoint);
    return Promise.resolve(structuredClone(stored));
  }

  pauseWithCheckpoint(
    lease: WorkLeaseV1,
    draft: CheckpointDraft,
    createdAt: string,
  ): Promise<{ checkpoint: CheckpointV1; run: RunReceiptV1 }> {
    this.assertLease(lease, createdAt);
    const checkpoint = this.buildCheckpoint(lease, draft, createdAt);
    const paused = updateRun(this.requireRun(lease.run_id), "paused", createdAt);

    // This block models one transaction: checkpoint first, then paused truth.
    const stored = this.storeCheckpoint(checkpoint);
    this.runs.set(lease.run_id, paused);
    this.leases.delete(lease.run_id);
    return Promise.resolve({
      checkpoint: structuredClone(stored),
      run: structuredClone(paused),
    });
  }

  finishExecution(
    lease: WorkLeaseV1,
    finishedAt: string,
  ): Promise<RunReceiptV1> {
    this.assertLease(lease, finishedAt);
    for (const [key, intent] of this.effectIntents) {
      if (intent.run_id !== lease.run_id) {
        continue;
      }
      const effect = this.effects.get(key);
      if (effect?.state !== "succeeded" || effect.verification_state !== "verified") {
        throw new ExecutionInvariantError(
          "run has an external intent without a verified effect",
        );
      }
    }
    for (const effect of this.effects.values()) {
      if (effect.run_id !== lease.run_id) {
        continue;
      }
      if (effect.state !== "succeeded" || effect.verification_state !== "verified") {
        throw new ExecutionInvariantError(
          "run has an unresolved or unsuccessful effect",
        );
      }
    }
    const delivering = updateRun(
      this.requireRun(lease.run_id),
      "delivering",
      finishedAt,
    );
    this.runs.set(lease.run_id, delivering);
    this.leases.delete(lease.run_id);
    return Promise.resolve(structuredClone(delivering));
  }

  persistEffectIntent(
    lease: WorkLeaseV1,
    draft: ExternalEffectIntentDraft,
    persistedAt: string,
  ): Promise<ExternalEffectIntentCommit> {
    this.assertLease(lease, persistedAt);
    if (
      JSON.stringify(normalizeEffectIntentValue(draft.request)) !==
      JSON.stringify(draft.request)
    ) {
      throw new ExecutionInvariantError("effect intent request is not canonical");
    }
    if (effectIntentDigest(draft) !== draft.request_digest) {
      throw new ExecutionInvariantError("effect intent digest does not match its request");
    }
    const key = effectKey(lease.run_id, draft.idempotency_key);
    const current = this.effectIntents.get(key);
    if (current !== undefined) {
      if (!sameExternalEffectIntent(current, draft)) {
        throw new ExecutionInvariantError(
          "effect idempotency key has a different external intent",
        );
      }
      return Promise.resolve({
        created: false,
        intent: structuredClone(current),
      });
    }

    const intent: ExternalEffectIntentV1 = {
      ...structuredClone(draft),
      fencing_token: lease.fencing_token,
      generation: lease.generation,
      lease_token: lease.lease_token,
      persisted_at: persistedAt,
      run_id: lease.run_id,
      schema_version: "external-effect-intent/v1",
    };
    this.effectIntents.set(key, intent);
    return Promise.resolve({ created: true, intent: structuredClone(intent) });
  }

  getEffectIntent(
    runId: string,
    idempotencyKey: string,
  ): Promise<ExternalEffectIntentV1 | undefined> {
    const intent = this.effectIntents.get(effectKey(runId, idempotencyKey));
    return Promise.resolve(
      intent === undefined ? undefined : structuredClone(intent),
    );
  }

  beginEffect(
    lease: WorkLeaseV1,
    draft: EffectDraft,
    recordedAt: string,
  ): Promise<EffectReceiptV1> {
    this.assertLease(lease, recordedAt);
    const key = effectKey(lease.run_id, draft.idempotency_key);
    const current = this.effects.get(key);
    if (current !== undefined) {
      if (!sameEffectIntent(current, draft)) {
        throw new ExecutionInvariantError(
          "effect idempotency key has different intent",
        );
      }
      return Promise.resolve(structuredClone(current));
    }
    if (draft.approval_required && draft.approval_ref === undefined) {
      throw new ExecutionInvariantError("required effect approval is missing");
    }
    const effect: EffectReceiptV1 = {
      approval_ref: draft.approval_ref,
      approval_required: draft.approval_required,
      effect_id: draft.effect_id,
      fencing_token: lease.fencing_token,
      generation: lease.generation,
      idempotency_key: draft.idempotency_key,
      lease_token: lease.lease_token,
      recorded_at: recordedAt,
      request_digest: draft.request_digest,
      rollback_plan_ref: draft.rollback_plan_ref,
      run_id: lease.run_id,
      schema_version: "effect-receipt/v1",
      state: "planned",
      step_id: draft.step_id,
      target_ref: draft.target_ref,
      verification_state: "pending",
    };
    this.effects.set(key, effect);
    return Promise.resolve(structuredClone(effect));
  }

  markEffectExecuting(
    lease: WorkLeaseV1,
    idempotencyKey: string,
    recordedAt: string,
  ): Promise<EffectReceiptV1> {
    this.assertLease(lease, recordedAt);
    const key = effectKey(lease.run_id, idempotencyKey);
    const current = this.requireEffect(key);
    if (current.state === "executing") {
      return Promise.resolve(structuredClone(current));
    }
    if (current.state !== "planned") {
      throw new ExecutionInvariantError("effect cannot enter executing state");
    }
    this.assertEffectOwner(current, lease);
    const executing = { ...current, recorded_at: recordedAt, state: "executing" as const };
    this.effects.set(key, executing);
    return Promise.resolve(structuredClone(executing));
  }

  resolveEffect(
    lease: WorkLeaseV1,
    idempotencyKey: string,
    resolution: EffectResolution,
    recordedAt: string,
  ): Promise<EffectReceiptV1> {
    this.assertLease(lease, recordedAt);
    const key = effectKey(lease.run_id, idempotencyKey);
    const current = this.requireEffect(key);
    if (current.state === resolution.state) {
      if (
        current.result_digest !== resolution.result_digest ||
        current.result_ref !== resolution.result_ref ||
        current.verification_receipt_ref !== resolution.verification_receipt_ref ||
        current.verification_state !== resolution.verification_state
      ) {
        throw new ExecutionInvariantError("effect result conflicts with prior result");
      }
      return Promise.resolve(structuredClone(current));
    }
    if (current.state !== "executing" && current.state !== "unknown") {
      throw new ExecutionInvariantError("effect is not awaiting a result");
    }
    if (current.state === "executing") {
      this.assertEffectOwner(current, lease);
    }
    const resolved: EffectReceiptV1 = {
      ...current,
      fencing_token: lease.fencing_token,
      generation: lease.generation,
      lease_token: lease.lease_token,
      recorded_at: recordedAt,
      result_digest: resolution.result_digest,
      result_ref: resolution.result_ref,
      state: resolution.state,
      verification_receipt_ref: resolution.verification_receipt_ref,
      verification_state: resolution.verification_state,
    };
    this.effects.set(key, resolved);
    return Promise.resolve(structuredClone(resolved));
  }

  getEffect(
    runId: string,
    idempotencyKey: string,
  ): Promise<EffectReceiptV1 | undefined> {
    const effect = this.effects.get(effectKey(runId, idempotencyKey));
    return Promise.resolve(
      effect === undefined ? undefined : structuredClone(effect),
    );
  }

  listExpiredLeases(observedAt: string): Promise<WorkLeaseV1[]> {
    const observed = Date.parse(observedAt);
    return Promise.resolve(
      [...this.leases.values()]
        .filter((lease) => Date.parse(lease.lease_expires_at) <= observed)
        .map((lease) => structuredClone(lease)),
    );
  }

  recoverExpiredLease(
    lease: WorkLeaseV1,
    recoveredAt: string,
  ): Promise<RecoveredRun> {
    const current = this.leases.get(lease.run_id);
    if (current === undefined || !sameLease(current, lease)) {
      return Promise.resolve({ recovered: false, uncertain_effect_ids: [] });
    }
    if (Date.parse(current.lease_expires_at) > Date.parse(recoveredAt)) {
      return Promise.resolve({ recovered: false, uncertain_effect_ids: [] });
    }

    const uncertainEffectIds: string[] = [];
    for (const [key, effect] of this.effects) {
      if (
        effect.run_id === lease.run_id &&
        effect.state === "executing" &&
        sameEffectLease(effect, lease)
      ) {
        this.effects.set(key, {
          ...effect,
          recorded_at: recoveredAt,
          state: "unknown",
        });
        uncertainEffectIds.push(effect.effect_id);
      }
    }

    const queued = updateRun(this.requireRun(lease.run_id), "queued", recoveredAt);
    this.runs.set(lease.run_id, queued);
    this.leases.delete(lease.run_id);
    return Promise.resolve({
      recovered: true,
      run: structuredClone(queued),
      uncertain_effect_ids: uncertainEffectIds,
    });
  }

  readRun(runId: string): RunReceiptV1 | undefined {
    const run = this.runs.get(runId);
    return run === undefined ? undefined : structuredClone(run);
  }

  private assertLease(lease: WorkLeaseV1, observedAt: string): void {
    const current = this.leases.get(lease.run_id);
    if (current === undefined || !sameLease(current, lease)) {
      throw new StaleLeaseError();
    }
    if (Date.parse(current.lease_expires_at) <= Date.parse(observedAt)) {
      throw new StaleLeaseError();
    }
  }

  private assertEffectOwner(
    effect: EffectReceiptV1,
    lease: WorkLeaseV1,
  ): void {
    if (!sameEffectLease(effect, lease)) {
      throw new StaleLeaseError();
    }
  }

  private buildCheckpoint(
    lease: WorkLeaseV1,
    draft: CheckpointDraft,
    createdAt: string,
  ): CheckpointV1 {
    const run = this.requireRun(lease.run_id);
    return {
      checkpoint_id: draft.checkpoint_id,
      completed_step_ids: [...draft.completed_step_ids],
      effect_receipt_ids: [...draft.effect_receipt_ids],
      generation: lease.generation,
      payload_digest: draft.payload_digest,
      payload_ref: draft.payload_ref,
      resume_cursor: draft.resume_cursor,
      run_id: lease.run_id,
      run_revision: run.revision,
      schema_version: "checkpoint/v1",
      sequence: draft.sequence,
      waiting_on_ref: draft.waiting_on_ref,
      created_at: createdAt,
    };
  }

  private storeCheckpoint(checkpoint: CheckpointV1): CheckpointV1 {
    const records = this.checkpoints.get(checkpoint.run_id) ?? [];
    const latest = records.at(-1);
    if (latest !== undefined && checkpoint.sequence <= latest.sequence) {
      if (
        checkpoint.sequence === latest.sequence &&
        sameCheckpointIntent(checkpoint, latest)
      ) {
        return latest;
      }
      throw new ExecutionInvariantError("checkpoint sequence is not monotonic");
    }
    records.push(checkpoint);
    this.checkpoints.set(checkpoint.run_id, records);
    return checkpoint;
  }

  private requireEffect(key: string): EffectReceiptV1 {
    const effect = this.effects.get(key);
    if (effect === undefined) {
      throw new ExecutionInvariantError("effect does not exist");
    }
    return effect;
  }

  private requireRun(runId: string): RunReceiptV1 {
    const run = this.runs.get(runId);
    if (run === undefined) {
      throw new ExecutionInvariantError("run does not exist");
    }
    return run;
  }
}

export class StaleLeaseError extends Error {
  constructor() {
    super("lease ownership is stale or expired");
    this.name = "StaleLeaseError";
  }
}

function updateRun(
  run: RunReceiptV1,
  state: RunReceiptV1["state"],
  updatedAt: string,
): RunReceiptV1 {
  return { ...run, revision: run.revision + 1, state, updated_at: updatedAt };
}

function validateLeaseClaim(claim: LeaseClaim): void {
  if (!Number.isSafeInteger(claim.generation) || claim.generation <= 0) {
    throw new ExecutionInvariantError("lease generation must be a positive integer");
  }
  if (claim.owner_id.trim() === "") {
    throw new ExecutionInvariantError("lease owner_id must not be empty");
  }
  if (claim.lease_token.trim() === "") {
    throw new ExecutionInvariantError("lease_token must not be empty");
  }
}

function sameCheckpointIntent(
  left: CheckpointV1,
  right: CheckpointV1,
): boolean {
  return (
    left.checkpoint_id === right.checkpoint_id &&
    left.run_id === right.run_id &&
    left.run_revision === right.run_revision &&
    left.generation === right.generation &&
    left.sequence === right.sequence &&
    left.resume_cursor === right.resume_cursor &&
    sameStringArray(left.completed_step_ids, right.completed_step_ids) &&
    sameStringArray(left.effect_receipt_ids, right.effect_receipt_ids) &&
    left.waiting_on_ref === right.waiting_on_ref &&
    left.payload_ref === right.payload_ref &&
    left.payload_digest === right.payload_digest
  );
}

function sameStringArray(left: string[], right: string[]): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function sameLeaseClaim(lease: WorkLeaseV1, claim: LeaseClaim): boolean {
  return (
    lease.run_id === claim.run_id &&
    lease.owner_id === claim.owner_id &&
    lease.generation === claim.generation &&
    lease.lease_token === claim.lease_token
  );
}

function sameLease(left: WorkLeaseV1, right: WorkLeaseV1): boolean {
  return (
    sameLeaseClaim(left, right) &&
    left.fencing_token === right.fencing_token &&
    left.lease_expires_at === right.lease_expires_at &&
    left.heartbeat_at === right.heartbeat_at
  );
}

function sameEffectLease(
  effect: EffectReceiptV1,
  lease: WorkLeaseV1,
): boolean {
  return (
    effect.generation === lease.generation &&
    effect.lease_token === lease.lease_token &&
    effect.fencing_token === lease.fencing_token
  );
}

function sameEffectIntent(
  effect: EffectReceiptV1,
  draft: EffectDraft,
): boolean {
  return (
    effect.effect_id === draft.effect_id &&
    effect.step_id === draft.step_id &&
    effect.target_ref === draft.target_ref &&
    effect.request_digest === draft.request_digest &&
    effect.approval_required === draft.approval_required &&
    effect.approval_ref === draft.approval_ref &&
    effect.rollback_plan_ref === draft.rollback_plan_ref
  );
}

function effectKey(runId: string, idempotencyKey: string): string {
  return `${runId}\u0000${idempotencyKey}`;
}
