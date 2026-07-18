import { IdempotencyConflictError } from "../admission.js";
import { ExecutionInvariantError } from "../execution/coordinator.js";
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
} from "../execution/model.js";
import type { DurableExecutionPort } from "../execution/ports.js";
import { ReferenceMemoryExecutionStore } from "../execution/reference-store.js";
import type {
  DistributedWorkPacketV1,
  DistributedWorkReceiptV1,
} from "./contracts.js";
import type {
  DistributedWorkAdmissionCommit,
  DistributedWorkAdmissionResult,
  DistributedWorkReceiptCommit,
  DistributedWorkReceiptCommitResult,
  DurableDistributedWorkPort,
} from "./ports.js";
import {
  validateDistributedWorkPacket,
  validateDistributedWorkReceiptCommit,
} from "./validation.js";

/**
 * In-memory conformance fixture. It composes the existing execution fixture and
 * models distributed packet, runnable queue, and terminal receipt transactions.
 * Production adapters must provide persistent implementations of the same ports.
 */
export class ReferenceMemoryDistributedWorkStore
  implements DurableDistributedWorkPort, DurableExecutionPort
{
  private readonly activeLeases = new Map<string, WorkLeaseV1>();
  private readonly execution = new ReferenceMemoryExecutionStore();
  private readonly highestGenerations = new Map<string, number>();
  private readonly packetIdByIdempotencyKey = new Map<string, string>();
  private readonly packets = new Map<string, DistributedWorkPacketV1>();
  private readonly receipts = new Map<string, DistributedWorkReceiptV1>();
  private readonly runnableRunIds = new Set<string>();
  private readonly terminalRunIds = new Set<string>();

  admitAndEnqueue(
    commit: DistributedWorkAdmissionCommit,
  ): Promise<DistributedWorkAdmissionResult> {
    validateDistributedWorkPacket(commit.packet);
    const packet = structuredClone(commit.packet);
    const priorPacketId = this.packetIdByIdempotencyKey.get(
      packet.idempotency_key,
    );
    if (priorPacketId !== undefined) {
      const prior = this.requirePacket(priorPacketId);
      if (!samePacketIntent(prior, packet)) {
        return Promise.reject(new IdempotencyConflictError());
      }
      return Promise.resolve({ created: false, packet: structuredClone(prior) });
    }
    if (
      this.packets.has(packet.packet_id) ||
      this.execution.readRun(packet.child_run.run_id) !== undefined
    ) {
      return Promise.reject(
        new DistributedWorkStoreConflictError(
          "packet or child run identity already belongs to different work",
        ),
      );
    }

    // These writes model one transaction, including the runnable queue entry.
    this.execution.seedRun(packet.child_run);
    this.packets.set(packet.packet_id, packet);
    this.packetIdByIdempotencyKey.set(
      packet.idempotency_key,
      packet.packet_id,
    );
    this.runnableRunIds.add(packet.child_run.run_id);
    return Promise.resolve({ created: true, packet: structuredClone(packet) });
  }

  readPacket(packetId: string): Promise<DistributedWorkPacketV1 | undefined> {
    const packet = this.packets.get(packetId);
    return Promise.resolve(
      packet === undefined ? undefined : structuredClone(packet),
    );
  }

  readReceipt(
    packetId: string,
  ): Promise<DistributedWorkReceiptV1 | undefined> {
    const receipt = this.receipts.get(packetId);
    return Promise.resolve(
      receipt === undefined ? undefined : structuredClone(receipt),
    );
  }

  commitReceipt(
    commit: DistributedWorkReceiptCommit,
  ): Promise<DistributedWorkReceiptCommitResult> {
    const packet = this.requirePacket(commit.receipt.packet_id);
    validateDistributedWorkReceiptCommit(packet, commit);
    const prior = this.receipts.get(packet.packet_id);
    if (prior !== undefined) {
      const terminalRun = this.requireRun(packet.child_run.run_id);
      if (
        !sameValue(prior, commit.receipt) ||
        !sameValue(terminalRun, commit.terminal_run)
      ) {
        return Promise.reject(
          new DistributedWorkStoreConflictError(
            "terminal distributed work intent conflicts with its prior receipt",
          ),
        );
      }
      return Promise.resolve({
        created: false,
        receipt: structuredClone(prior),
        run: structuredClone(terminalRun),
      });
    }

    this.assertActiveLease(commit.lease, commit.receipt.recorded_at);
    const currentRun = this.requireRun(packet.child_run.run_id);
    const expectedTerminal: RunReceiptV1 = {
      ...currentRun,
      revision: currentRun.revision + 1,
      state: commit.receipt.status,
      updated_at: commit.receipt.recorded_at,
    };
    if (
      currentRun.revision !== commit.expected_run_revision ||
      !sameValue(expectedTerminal, commit.terminal_run)
    ) {
      return Promise.reject(
        new DistributedWorkStoreConflictError(
          "terminal receipt expected a different child run revision",
        ),
      );
    }

    const receipt = structuredClone(commit.receipt);
    const terminalRun = structuredClone(commit.terminal_run);
    // These writes model one atomic terminal receipt and run transition.
    this.execution.seedRun(terminalRun);
    this.receipts.set(packet.packet_id, receipt);
    this.terminalRunIds.add(terminalRun.run_id);
    this.activeLeases.delete(terminalRun.run_id);
    this.runnableRunIds.delete(terminalRun.run_id);
    return Promise.resolve({
      created: true,
      receipt: structuredClone(receipt),
      run: structuredClone(terminalRun),
    });
  }

  async acquireLease(
    claim: LeaseClaim,
    heartbeatAt: string,
    leaseExpiresAt: string,
  ): Promise<LeaseAcquisition | undefined> {
    this.assertNonTerminal(claim.run_id);
    const current = this.activeLeases.get(claim.run_id);
    if (current !== undefined && !sameLeaseClaim(current, claim)) {
      return undefined;
    }
    const highestGeneration = this.highestGenerations.get(claim.run_id) ?? 0;
    if (current === undefined && claim.generation <= highestGeneration) {
      throw new StaleDistributedWorkerError();
    }
    const acquired = await this.execution.acquireLease(
      claim,
      heartbeatAt,
      leaseExpiresAt,
    );
    if (acquired !== undefined) {
      this.activeLeases.set(claim.run_id, structuredClone(acquired.lease));
      this.highestGenerations.set(claim.run_id, claim.generation);
      this.runnableRunIds.delete(claim.run_id);
    }
    return acquired;
  }

  async renewLease(
    lease: WorkLeaseV1,
    heartbeatAt: string,
    leaseExpiresAt: string,
  ): Promise<WorkLeaseV1> {
    this.assertActiveLease(lease, heartbeatAt);
    const renewed = await this.execution.renewLease(
      lease,
      heartbeatAt,
      leaseExpiresAt,
    );
    this.activeLeases.set(lease.run_id, structuredClone(renewed));
    return renewed;
  }

  async releaseLease(
    lease: WorkLeaseV1,
    releasedAt: string,
  ): Promise<RunReceiptV1> {
    this.assertActiveLease(lease, releasedAt);
    const run = await this.execution.releaseLease(lease, releasedAt);
    this.activeLeases.delete(lease.run_id);
    this.runnableRunIds.add(lease.run_id);
    return run;
  }

  markRunning(lease: WorkLeaseV1, updatedAt: string): Promise<RunReceiptV1> {
    this.assertActiveLease(lease, updatedAt);
    return this.execution.markRunning(lease, updatedAt);
  }

  latestCheckpoint(runId: string): Promise<CheckpointV1 | undefined> {
    return this.execution.latestCheckpoint(runId);
  }

  appendCheckpoint(
    lease: WorkLeaseV1,
    draft: CheckpointDraft,
    createdAt: string,
  ): Promise<CheckpointV1> {
    this.assertActiveLease(lease, createdAt);
    return this.execution.appendCheckpoint(lease, draft, createdAt);
  }

  async pauseWithCheckpoint(
    lease: WorkLeaseV1,
    draft: CheckpointDraft,
    createdAt: string,
  ): Promise<{ checkpoint: CheckpointV1; run: RunReceiptV1 }> {
    this.assertActiveLease(lease, createdAt);
    const paused = await this.execution.pauseWithCheckpoint(
      lease,
      draft,
      createdAt,
    );
    this.activeLeases.delete(lease.run_id);
    this.runnableRunIds.add(lease.run_id);
    return paused;
  }

  async waitWithCheckpoint(
    lease: WorkLeaseV1,
    draft: CheckpointDraft,
    createdAt: string,
  ): Promise<{ checkpoint: CheckpointV1; run: RunReceiptV1 }> {
    this.assertActiveLease(lease, createdAt);
    const waiting = await this.execution.waitWithCheckpoint(
      lease,
      draft,
      createdAt,
    );
    this.activeLeases.delete(lease.run_id);
    return waiting;
  }

  async finishExecution(
    lease: WorkLeaseV1,
    finishedAt: string,
  ): Promise<RunReceiptV1> {
    this.assertActiveLease(lease, finishedAt);
    const delivering = await this.execution.finishExecution(lease, finishedAt);
    this.activeLeases.delete(lease.run_id);
    return delivering;
  }

  persistEffectIntent(
    lease: WorkLeaseV1,
    draft: ExternalEffectIntentDraft,
    persistedAt: string,
  ): Promise<ExternalEffectIntentCommit> {
    this.assertActiveLease(lease, persistedAt);
    return this.execution.persistEffectIntent(lease, draft, persistedAt);
  }

  getEffectIntent(
    runId: string,
    idempotencyKey: string,
  ): Promise<ExternalEffectIntentV1 | undefined> {
    return this.execution.getEffectIntent(runId, idempotencyKey);
  }

  beginEffect(
    lease: WorkLeaseV1,
    draft: EffectDraft,
    recordedAt: string,
  ): Promise<EffectReceiptV1> {
    this.assertActiveLease(lease, recordedAt);
    return this.execution.beginEffect(lease, draft, recordedAt);
  }

  markEffectExecuting(
    lease: WorkLeaseV1,
    idempotencyKey: string,
    recordedAt: string,
  ): Promise<EffectReceiptV1> {
    this.assertActiveLease(lease, recordedAt);
    return this.execution.markEffectExecuting(
      lease,
      idempotencyKey,
      recordedAt,
    );
  }

  resolveEffect(
    lease: WorkLeaseV1,
    idempotencyKey: string,
    resolution: EffectResolution,
    recordedAt: string,
  ): Promise<EffectReceiptV1> {
    this.assertActiveLease(lease, recordedAt);
    return this.execution.resolveEffect(
      lease,
      idempotencyKey,
      resolution,
      recordedAt,
    );
  }

  getEffect(
    runId: string,
    idempotencyKey: string,
  ): Promise<EffectReceiptV1 | undefined> {
    return this.execution.getEffect(runId, idempotencyKey);
  }

  listExpiredLeases(observedAt: string): Promise<WorkLeaseV1[]> {
    const observed = Date.parse(observedAt);
    return Promise.resolve(
      [...this.activeLeases.values()]
        .filter((lease) => Date.parse(lease.lease_expires_at) <= observed)
        .map((lease) => structuredClone(lease)),
    );
  }

  async recoverExpiredLease(
    lease: WorkLeaseV1,
    recoveredAt: string,
  ): Promise<RecoveredRun> {
    const current = this.activeLeases.get(lease.run_id);
    if (current === undefined || !sameLease(current, lease)) {
      return { recovered: false, uncertain_effect_ids: [] };
    }
    const recovered = await this.execution.recoverExpiredLease(
      lease,
      recoveredAt,
    );
    if (recovered.recovered) {
      this.activeLeases.delete(lease.run_id);
      this.runnableRunIds.add(lease.run_id);
    }
    return recovered;
  }

  hasRunnableRun(runId: string): boolean {
    return this.runnableRunIds.has(runId);
  }

  readRun(runId: string): RunReceiptV1 | undefined {
    return this.execution.readRun(runId);
  }

  private assertActiveLease(lease: WorkLeaseV1, observedAt: string): void {
    this.assertNonTerminal(lease.run_id);
    const current = this.activeLeases.get(lease.run_id);
    if (
      current === undefined ||
      !sameLease(current, lease) ||
      Date.parse(current.lease_expires_at) <= Date.parse(observedAt)
    ) {
      throw new StaleDistributedWorkerError();
    }
  }

  private assertNonTerminal(runId: string): void {
    if (this.terminalRunIds.has(runId)) {
      throw new StaleDistributedWorkerError();
    }
  }

  private requirePacket(packetId: string): DistributedWorkPacketV1 {
    const packet = this.packets.get(packetId);
    if (packet === undefined) {
      throw new DistributedWorkStoreConflictError(
        "distributed work packet does not exist",
      );
    }
    return packet;
  }

  private requireRun(runId: string): RunReceiptV1 {
    const run = this.execution.readRun(runId);
    if (run === undefined) {
      throw new ExecutionInvariantError("run does not exist");
    }
    return run;
  }
}

export class DistributedWorkStoreConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DistributedWorkStoreConflictError";
  }
}

export class StaleDistributedWorkerError extends Error {
  constructor() {
    super("distributed worker lease generation or fencing proof is stale");
    this.name = "StaleDistributedWorkerError";
  }
}

function samePacketIntent(
  left: DistributedWorkPacketV1,
  right: DistributedWorkPacketV1,
): boolean {
  return (
    left.packet_id === right.packet_id &&
    left.intent_digest === right.intent_digest &&
    sameValue(left, right)
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

function sameValue(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}
