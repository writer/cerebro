import {
  deriveRecursiveWorkcellState,
  RecursiveWorkcellInvariantError,
  validateLeaseForParent,
  validateRecursiveWorkcellChild,
  validateRecursiveWorkcellProgress,
  validateRecursiveWorkcellResume,
} from "./coordinator.js";
import type {
  RecursiveWorkcellCounterevidenceV1,
  RecursiveWorkcellObservationV1,
  RecursiveWorkcellReconciliationV1,
  WorkLeaseV1,
} from "./contracts.js";
import {
  MAX_RECURSIVE_WORKCELL_CHECKPOINTS,
  MAX_RECURSIVE_WORKCELL_COUNTEREVIDENCE,
  MAX_RECURSIVE_WORKCELL_OBSERVATIONS,
  MAX_RECURSIVE_WORKCELL_PROGRESS_RECORDS,
} from "./contracts.js";
import type {
  DurableRecursiveWorkcellPort,
  RecursiveWorkcellAdmissionCommit,
  RecursiveWorkcellCheckpointCommit,
  RecursiveWorkcellCommitResult,
  RecursiveWorkcellProgressCommit,
  RecursiveWorkcellReceiptCommit,
  RecursiveWorkcellResumeCommit,
} from "./ports.js";
import {
  validateDistributedWorkPacket,
  validateDistributedWorkReceipt,
} from "../validation.js";

const SHA256_DIGEST = /^sha256:[a-f0-9]{64}$/;
const OPAQUE_REFERENCE = /^[a-z][a-z0-9+.-]*:\/\/\S+$/;
const MAX_ID_LENGTH = 256;
const MAX_REF_LENGTH = 1_024;

/** Conformance fixture only. Production adapters must use durable storage. */
export class ReferenceMemoryRecursiveWorkcellStore
  implements DurableRecursiveWorkcellPort
{
  private readonly activeLeaseByParent = new Map<string, WorkLeaseV1>();
  private readonly parentByRun = new Map<string, string>();
  private readonly parentByWorkcell = new Map<string, string>();
  private readonly records = new Map<
    string,
    RecursiveWorkcellReconciliationV1
  >();

  admitChildren(
    commit: RecursiveWorkcellAdmissionCommit,
  ): Promise<RecursiveWorkcellCommitResult> {
    const incoming = commit.reconciliation;
    validateAdmission(commit);
    const parentPacketId = incoming.parent_packet.packet_id;
    const current = this.records.get(parentPacketId);
    if (current !== undefined) {
      if (
        !sameValue(current.parent_packet, incoming.parent_packet) ||
        !sameValue(current.children, incoming.children)
      ) {
        throw new RecursiveWorkcellInvariantError(
          "recursive workcell admission conflicts with durable parent intent",
        );
      }
      return Promise.resolve(result(false, current));
    }

    const stored = structuredClone(incoming);
    this.records.set(parentPacketId, stored);
    this.activeLeaseByParent.set(parentPacketId, structuredClone(commit.lease));
    this.parentByRun.set(incoming.parent_packet.child_run.run_id, parentPacketId);
    for (const child of incoming.children) {
      this.parentByWorkcell.set(child.workcell_id, parentPacketId);
    }
    return Promise.resolve(result(true, stored));
  }

  readReconciliation(
    parentPacketId: string,
  ): Promise<RecursiveWorkcellReconciliationV1 | undefined> {
    const reconciliation = this.records.get(parentPacketId);
    return Promise.resolve(
      reconciliation === undefined
        ? undefined
        : structuredClone(reconciliation),
    );
  }

  appendProgress(
    commit: RecursiveWorkcellProgressCommit,
  ): Promise<RecursiveWorkcellCommitResult> {
    const parentPacketId = this.parentByWorkcell.get(commit.progress.workcell_id);
    if (parentPacketId === undefined) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell progress has no admitted parent",
      );
    }
    const current = this.requireRecord(parentPacketId);
    const child = current.children.find(
      (candidate) => candidate.workcell_id === commit.progress.workcell_id,
    );
    if (child === undefined) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell progress has no admitted child",
      );
    }
    validateRecursiveWorkcellProgress(child, commit.progress);

    const prior = current.progress.find(
      (progress) => progress.progress_id === commit.progress.progress_id,
    );
    if (prior !== undefined) {
      if (!sameValue(prior, commit.progress)) {
        throw new RecursiveWorkcellInvariantError(
          "recursive workcell progress idempotency key changed intent",
        );
      }
      this.assertLeaseProof(parentPacketId, commit.lease, commit.progress.recorded_at);
      return Promise.resolve(result(false, current));
    }

    this.assertMutable(
      parentPacketId,
      current,
      commit.lease,
      commit.expected_revision,
      commit.progress.recorded_at,
    );
    if (
      current.child_receipts.some(
        (receipt) => receipt.packet_id === commit.progress.child_packet_id,
      )
    ) {
      throw new RecursiveWorkcellInvariantError(
        "terminal recursive workcell child cannot append progress",
      );
    }
    const childProgress = current.progress.filter(
      (progress) => progress.child_packet_id === commit.progress.child_packet_id,
    );
    if (commit.progress.sequence !== childProgress.length + 1) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell progress sequence is not contiguous",
      );
    }
    if (current.progress.length >= MAX_RECURSIVE_WORKCELL_PROGRESS_RECORDS) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell progress exceeds the contract bound",
      );
    }

    const next = structuredClone(current);
    next.progress.push(structuredClone(commit.progress));
    mergeObservations(
      next,
      commit.progress.child_packet_id,
      commit.progress.runtime_observations,
    );
    mergeCounterevidence(next, commit.progress.counterevidence);
    advance(next, commit.progress.recorded_at);
    this.records.set(parentPacketId, next);
    return Promise.resolve(result(true, next));
  }

  checkpoint(
    commit: RecursiveWorkcellCheckpointCommit,
  ): Promise<RecursiveWorkcellCommitResult> {
    const parentPacketId = this.parentByRun.get(commit.lease.run_id);
    if (parentPacketId === undefined) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell checkpoint has no admitted parent",
      );
    }
    const current = this.requireRecord(parentPacketId);
    const prior = current.checkpoints.find(
      (checkpoint) => checkpoint.checkpoint_id === commit.checkpoint.checkpoint_id,
    );
    if (prior !== undefined) {
      if (!sameValue(prior, commit.checkpoint)) {
        throw new RecursiveWorkcellInvariantError(
          "recursive workcell checkpoint identity changed intent",
        );
      }
      this.assertLeaseProof(
        parentPacketId,
        commit.lease,
        commit.checkpoint.created_at,
      );
      return Promise.resolve(result(false, current));
    }

    this.assertMutable(
      parentPacketId,
      current,
      commit.lease,
      commit.expected_revision,
      commit.checkpoint.created_at,
    );
    validateCheckpoint(current, commit.checkpoint, commit.lease);
    if (current.checkpoints.length >= MAX_RECURSIVE_WORKCELL_CHECKPOINTS) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell checkpoints exceed the contract bound",
      );
    }
    const next = structuredClone(current);
    next.checkpoints.push(structuredClone(commit.checkpoint));
    next.coordination_state = "checkpointed";
    advance(next, commit.checkpoint.created_at);
    this.records.set(parentPacketId, next);
    return Promise.resolve(result(true, next));
  }

  resume(
    commit: RecursiveWorkcellResumeCommit,
  ): Promise<RecursiveWorkcellCommitResult> {
    const parentPacketId = this.parentByRun.get(commit.lease.run_id);
    if (parentPacketId === undefined) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell resume has no admitted parent",
      );
    }
    const current = this.requireRecord(parentPacketId);
    validateRecursiveWorkcellResume(parentPacketId, commit.lease, commit.resume);
    const prior = current.resumes.find(
      (resume) => resume.resume_id === commit.resume.resume_id,
    );
    if (prior !== undefined) {
      if (!sameValue(prior, commit.resume)) {
        throw new RecursiveWorkcellInvariantError(
          "recursive workcell resume identity changed intent",
        );
      }
      const active = this.requireActiveLease(parentPacketId);
      if (!sameLease(active, commit.lease)) {
        throw new RecursiveWorkcellInvariantError(
          "recursive workcell resume retry does not own the active fence",
        );
      }
      return Promise.resolve(result(false, current));
    }
    requireRevision(current, commit.expected_revision);
    if (current.coordination_state !== "checkpointed") {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell must be checkpointed before resume",
      );
    }
    const checkpoint = current.checkpoints.at(-1);
    if (
      checkpoint === undefined ||
      checkpoint.checkpoint_id !== commit.resume.checkpoint_id
    ) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell resume does not reference the latest checkpoint",
      );
    }
    const oldLease = this.requireActiveLease(parentPacketId);
    validateLeaseForParent(
      current.parent_packet,
      commit.lease,
      commit.resume.recorded_at,
    );
    if (
      commit.lease.generation < oldLease.generation ||
      commit.lease.fencing_token <= oldLease.fencing_token ||
      commit.lease.lease_token === oldLease.lease_token ||
      checkpoint.generation !== oldLease.generation ||
      Date.parse(commit.lease.heartbeat_at) < Date.parse(checkpoint.created_at)
    ) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell resume requires a newer generation-compatible fence",
      );
    }

    const next = structuredClone(current);
    next.resumes.push(structuredClone(commit.resume));
    next.coordination_state = "active";
    advance(next, commit.resume.recorded_at);
    this.records.set(parentPacketId, next);
    this.activeLeaseByParent.set(parentPacketId, structuredClone(commit.lease));
    return Promise.resolve(result(true, next));
  }

  reconcileReceipt(
    commit: RecursiveWorkcellReceiptCommit,
  ): Promise<RecursiveWorkcellCommitResult> {
    const parentPacketId = this.parentByRun.get(commit.lease.run_id);
    if (parentPacketId === undefined) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell receipt has no admitted parent",
      );
    }
    const current = this.requireRecord(parentPacketId);
    const child = current.children.find(
      (candidate) =>
        candidate.child_packet.packet_id === commit.receipt.packet_id,
    );
    if (child === undefined) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell receipt does not belong to the parent",
      );
    }
    validateDistributedWorkReceipt(child.child_packet, commit.receipt);
    const prior = current.child_receipts.find(
      (receipt) => receipt.packet_id === commit.receipt.packet_id,
    );
    if (prior !== undefined) {
      if (
        !sameValue(prior, commit.receipt) ||
        !counterevidenceAlreadyStored(current, commit.counterevidence)
      ) {
        throw new RecursiveWorkcellInvariantError(
          "recursive workcell terminal receipt changed durable truth",
        );
      }
      this.assertLeaseProof(
        parentPacketId,
        commit.lease,
        commit.receipt.recorded_at,
      );
      return Promise.resolve(result(false, current));
    }

    this.assertMutable(
      parentPacketId,
      current,
      commit.lease,
      commit.expected_revision,
      commit.receipt.recorded_at,
    );
    const next = structuredClone(current);
    next.child_receipts.push(structuredClone(commit.receipt));
    next.child_receipts.sort(
      (left, right) =>
        childSequence(next, left.packet_id) - childSequence(next, right.packet_id),
    );
    mergeObservations(
      next,
      commit.receipt.packet_id,
      commit.receipt.runtime_observations,
    );
    mergeCounterevidence(next, commit.counterevidence);
    Object.assign(
      next,
      deriveRecursiveWorkcellState(next.children.length, next.child_receipts),
    );
    advance(next, commit.receipt.recorded_at);
    this.records.set(parentPacketId, next);
    return Promise.resolve(result(true, next));
  }

  private assertMutable(
    parentPacketId: string,
    current: RecursiveWorkcellReconciliationV1,
    lease: WorkLeaseV1,
    expectedRevision: number,
    observedAt: string,
  ): void {
    requireRevision(current, expectedRevision);
    if (current.coordination_state !== "active") {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell is checkpointed and must resume before mutation",
      );
    }
    this.assertLeaseProof(parentPacketId, lease, observedAt);
  }

  private assertLeaseProof(
    parentPacketId: string,
    lease: WorkLeaseV1,
    observedAt: string,
  ): void {
    const current = this.requireRecord(parentPacketId);
    validateLeaseForParent(current.parent_packet, lease, observedAt);
    if (!sameLease(this.requireActiveLease(parentPacketId), lease)) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell lease generation or fence is stale",
      );
    }
  }

  private requireActiveLease(parentPacketId: string): WorkLeaseV1 {
    const lease = this.activeLeaseByParent.get(parentPacketId);
    if (lease === undefined) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell has no active lease",
      );
    }
    return lease;
  }

  private requireRecord(
    parentPacketId: string,
  ): RecursiveWorkcellReconciliationV1 {
    const reconciliation = this.records.get(parentPacketId);
    if (reconciliation === undefined) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell reconciliation does not exist",
      );
    }
    return reconciliation;
  }
}

function validateAdmission(commit: RecursiveWorkcellAdmissionCommit): void {
  const reconciliation = commit.reconciliation;
  if (
    reconciliation.schema_version !== "recursive-workcell-reconciliation/v1" ||
    reconciliation.revision !== 1 ||
    reconciliation.state !== "active" ||
    reconciliation.coordination_state !== "active" ||
    reconciliation.child_receipts.length !== 0 ||
    reconciliation.progress.length !== 0 ||
    reconciliation.checkpoints.length !== 0 ||
    reconciliation.resumes.length !== 0 ||
    reconciliation.observations.length !== 0 ||
    reconciliation.counterevidence.length !== 0 ||
    reconciliation.unresolved_child_count !== reconciliation.children.length ||
    reconciliation.completed_child_count !== 0 ||
    reconciliation.blocked_child_count !== 0 ||
    !sameValue(commit.children, reconciliation.children)
  ) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell admission is not an initial reconciliation",
    );
  }
  validateDistributedWorkPacket(reconciliation.parent_packet);
  validateLeaseForParent(
    reconciliation.parent_packet,
    commit.lease,
    reconciliation.created_at,
  );
  for (const child of reconciliation.children) {
    validateRecursiveWorkcellChild(reconciliation.parent_packet, child);
  }
}

function validateCheckpoint(
  reconciliation: RecursiveWorkcellReconciliationV1,
  checkpoint: RecursiveWorkcellReconciliationV1["checkpoints"][number],
  lease: WorkLeaseV1,
): void {
  if (
    checkpoint.schema_version !== "checkpoint/v1" ||
    checkpoint.run_id !== reconciliation.parent_packet.child_run.run_id ||
    checkpoint.generation !== lease.generation ||
    checkpoint.sequence !== reconciliation.checkpoints.length + 1 ||
    checkpoint.run_revision < reconciliation.parent_packet.child_run.revision
  ) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell checkpoint does not match parent execution",
    );
  }
  requireId(checkpoint.checkpoint_id, "checkpoint_id");
  requireTimestamp(checkpoint.created_at, "checkpoint.created_at");
  requireOpaqueRef(checkpoint.payload_ref, "checkpoint.payload_ref");
  requirePattern(checkpoint.payload_digest, SHA256_DIGEST, "checkpoint.payload_digest");
  requireId(checkpoint.resume_cursor, "checkpoint.resume_cursor");
  for (const stepId of checkpoint.completed_step_ids) {
    requireId(stepId, "checkpoint.completed_step_id");
  }
  for (const receiptId of checkpoint.effect_receipt_ids) {
    requireId(receiptId, "checkpoint.effect_receipt_id");
  }
  if (checkpoint.waiting_on_ref !== undefined) {
    requireOpaqueRef(checkpoint.waiting_on_ref, "checkpoint.waiting_on_ref");
  }
}

function mergeObservations(
  reconciliation: RecursiveWorkcellReconciliationV1,
  childPacketId: string,
  observations: RecursiveWorkcellReconciliationV1["child_receipts"][number]["runtime_observations"],
): void {
  for (const observation of observations) {
    const prior = reconciliation.observations.find(
      (candidate) =>
        candidate.child_packet_id === childPacketId &&
        candidate.observation.observation_id === observation.observation_id,
    );
    if (prior !== undefined) {
      if (!sameValue(prior.observation, observation)) {
        throw new RecursiveWorkcellInvariantError(
          "recursive workcell observation identity changed durable truth",
        );
      }
      continue;
    }
    const childObservationCount = reconciliation.observations.filter(
      (candidate) => candidate.child_packet_id === childPacketId,
    ).length;
    if (observation.sequence !== childObservationCount + 1) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell observations cannot skip runtime order",
      );
    }
    if (reconciliation.observations.length >= MAX_RECURSIVE_WORKCELL_OBSERVATIONS) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell observations exceed the contract bound",
      );
    }
    const wrapped: RecursiveWorkcellObservationV1 = {
      child_packet_id: childPacketId,
      observation: structuredClone(observation),
    };
    reconciliation.observations.push(wrapped);
  }
}

function mergeCounterevidence(
  reconciliation: RecursiveWorkcellReconciliationV1,
  items: RecursiveWorkcellCounterevidenceV1[],
): void {
  for (const item of items) {
    const childExists = reconciliation.children.some(
      (child) => child.child_packet.packet_id === item.child_packet_id,
    );
    if (!childExists) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell counterevidence does not belong to a child",
      );
    }
    const prior = reconciliation.counterevidence.find(
      (candidate) => candidate.counterevidence_id === item.counterevidence_id,
    );
    if (prior !== undefined) {
      if (!sameValue(prior, item)) {
        throw new RecursiveWorkcellInvariantError(
          "recursive workcell counterevidence changed durable truth",
        );
      }
      continue;
    }
    if (
      reconciliation.counterevidence.length >=
      MAX_RECURSIVE_WORKCELL_COUNTEREVIDENCE
    ) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell counterevidence exceeds the contract bound",
      );
    }
    reconciliation.counterevidence.push(structuredClone(item));
  }
}

function counterevidenceAlreadyStored(
  reconciliation: RecursiveWorkcellReconciliationV1,
  items: RecursiveWorkcellCounterevidenceV1[],
): boolean {
  return items.every((item) =>
    reconciliation.counterevidence.some(
      (candidate) =>
        candidate.counterevidence_id === item.counterevidence_id &&
        sameValue(candidate, item),
    ),
  );
}

function childSequence(
  reconciliation: RecursiveWorkcellReconciliationV1,
  packetId: string,
): number {
  const child = reconciliation.children.find(
    (candidate) => candidate.child_packet.packet_id === packetId,
  );
  if (child === undefined) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell child sequence does not exist",
    );
  }
  return child.child_sequence;
}

function advance(
  reconciliation: RecursiveWorkcellReconciliationV1,
  updatedAt: string,
): void {
  if (Date.parse(updatedAt) < Date.parse(reconciliation.updated_at)) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell time cannot move backwards",
    );
  }
  reconciliation.revision += 1;
  reconciliation.updated_at = updatedAt;
}

function requireRevision(
  reconciliation: RecursiveWorkcellReconciliationV1,
  expectedRevision: number,
): void {
  if (
    !Number.isSafeInteger(expectedRevision) ||
    expectedRevision <= 0 ||
    reconciliation.revision !== expectedRevision
  ) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell revision is stale",
    );
  }
}

function sameLease(left: WorkLeaseV1, right: WorkLeaseV1): boolean {
  return (
    left.run_id === right.run_id &&
    left.owner_id === right.owner_id &&
    left.generation === right.generation &&
    left.fencing_token === right.fencing_token &&
    left.lease_token === right.lease_token &&
    left.heartbeat_at === right.heartbeat_at &&
    left.lease_expires_at === right.lease_expires_at
  );
}

function result(
  created: boolean,
  reconciliation: RecursiveWorkcellReconciliationV1,
): RecursiveWorkcellCommitResult {
  return { created, reconciliation: structuredClone(reconciliation) };
}

function sameValue(left: unknown, right: unknown): boolean {
  return stableStringify(left) === stableStringify(right);
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, nested]) => nested !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${stableStringify(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function requireId(value: string | undefined, label: string): asserts value is string {
  if (
    value === undefined ||
    value.trim() === "" ||
    Buffer.byteLength(value, "utf8") > MAX_ID_LENGTH
  ) {
    throw new RecursiveWorkcellInvariantError(
      `${label} must be a bounded identifier`,
    );
  }
}

function requireOpaqueRef(
  value: string | undefined,
  label: string,
): asserts value is string {
  if (
    value === undefined ||
    Buffer.byteLength(value, "utf8") > MAX_REF_LENGTH ||
    !OPAQUE_REFERENCE.test(value)
  ) {
    throw new RecursiveWorkcellInvariantError(
      `${label} must be a bounded opaque reference`,
    );
  }
}

function requirePattern(
  value: string | undefined,
  pattern: RegExp,
  label: string,
): asserts value is string {
  if (value === undefined || !pattern.test(value)) {
    throw new RecursiveWorkcellInvariantError(`${label} has an invalid format`);
  }
}

function requireTimestamp(value: string, label: string): void {
  if (!Number.isFinite(Date.parse(value))) {
    throw new RecursiveWorkcellInvariantError(`${label} must be a timestamp`);
  }
}
