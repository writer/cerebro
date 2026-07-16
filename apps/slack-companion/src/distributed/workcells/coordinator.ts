import { createHash } from "node:crypto";
import type {
  CheckpointV1,
  RecursiveWorkcellAdmissionDraft,
  RecursiveWorkcellChildV1,
  RecursiveWorkcellCounterevidenceDraft,
  RecursiveWorkcellCounterevidenceV1,
  RecursiveWorkcellProgressDraft,
  RecursiveWorkcellProgressV1,
  RecursiveWorkcellReconciliationV1,
  RecursiveWorkcellResumeV1,
  RecursiveWorkcellTerminalDraft,
  WorkLeaseV1,
} from "./contracts.js";
import {
  MAX_RECURSIVE_WORKCELL_CHILDREN,
  MAX_RECURSIVE_WORKCELL_COUNTEREVIDENCE,
  MAX_RECURSIVE_WORKCELL_DEPTH,
  MAX_RECURSIVE_WORKCELL_OBSERVATIONS,
  RECURSIVE_WORKCELL_CHILD_SCHEMA_VERSION,
  RECURSIVE_WORKCELL_COUNTEREVIDENCE_SCHEMA_VERSION,
  RECURSIVE_WORKCELL_PROGRESS_SCHEMA_VERSION,
  RECURSIVE_WORKCELL_RECONCILIATION_SCHEMA_VERSION,
  RECURSIVE_WORKCELL_RESUME_SCHEMA_VERSION,
} from "./contracts.js";
import type {
  DurableRecursiveWorkcellPort,
  RecursiveWorkcellCommitResult,
} from "./ports.js";
import type {
  DistributedWorkPacketV1,
  RuntimeToolObservationV1,
} from "../contracts.js";
import {
  runtimeToolObservationIdentity,
  validateDistributedWorkPacket,
  validateDistributedWorkReceipt,
} from "../validation.js";

const SHA256_DIGEST = /^sha256:[a-f0-9]{64}$/;
const PACKET_ID = /^distributed-work-packet:\/\/sha256\/[a-f0-9]{64}$/;
const WORKCELL_ID = /^recursive-workcell:\/\/sha256\/[a-f0-9]{64}$/;
const PROGRESS_ID = /^recursive-workcell-progress:\/\/sha256\/[a-f0-9]{64}$/;
const COUNTEREVIDENCE_ID =
  /^recursive-workcell-counterevidence:\/\/sha256\/[a-f0-9]{64}$/;
const RESUME_ID = /^recursive-workcell-resume:\/\/sha256\/[a-f0-9]{64}$/;
const OPAQUE_REFERENCE = /^[a-z][a-z0-9+.-]*:\/\/\S+$/;
const MAX_ID_LENGTH = 256;
const MAX_REF_LENGTH = 1_024;

export class RecursiveWorkcellInvariantError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RecursiveWorkcellInvariantError";
  }
}

export class RecursiveWorkcellCoordinator {
  constructor(private readonly store: DurableRecursiveWorkcellPort) {}

  async admit(
    draft: RecursiveWorkcellAdmissionDraft,
    lease: WorkLeaseV1,
  ): Promise<RecursiveWorkcellCommitResult> {
    const parentBinding = await this.store.readChildBinding(
      draft.parent_packet.packet_id,
    );
    if (
      parentBinding === undefined &&
      PACKET_ID.test(draft.parent_packet.parent_subject_ref)
    ) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell durable parent binding does not exist",
      );
    }
    if (
      parentBinding !== undefined &&
      stableStringify(parentBinding.child_packet) !==
        stableStringify(draft.parent_packet)
    ) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell durable parent identity changed",
      );
    }
    const durableAncestors = parentBinding?.ancestor_packet_ids ?? [];
    if (!sameStringArray(draft.parent_ancestor_packet_ids, durableAncestors)) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell ancestry does not match the durable parent binding",
      );
    }
    const reconciliation = createRecursiveWorkcellReconciliation({
      ...draft,
      parent_ancestor_packet_ids: durableAncestors,
    });
    validateLeaseForParent(reconciliation.parent_packet, lease, draft.admitted_at);
    return this.store.admitChildren({
      children: reconciliation.children,
      lease,
      reconciliation,
    });
  }

  async claimActiveLease(
    parentPacketId: string,
    lease: WorkLeaseV1,
    expectedRevision: number,
  ): Promise<RecursiveWorkcellCommitResult> {
    requirePattern(parentPacketId, PACKET_ID, "parent_packet_id");
    return this.store.claimActiveLease({
      expected_revision: expectedRevision,
      lease,
      parent_packet_id: parentPacketId,
    });
  }

  async recordProgress(
    parentPacketId: string,
    childPacketId: string,
    draft: RecursiveWorkcellProgressDraft,
    lease: WorkLeaseV1,
    expectedRevision: number,
  ): Promise<RecursiveWorkcellCommitResult> {
    const reconciliation = await this.requireReconciliation(parentPacketId);
    const child = requireChild(reconciliation, childPacketId);
    const progress = createRecursiveWorkcellProgress(child, draft);
    return this.store.appendProgress({
      expected_revision: expectedRevision,
      lease,
      progress,
    });
  }

  checkpoint(
    checkpoint: CheckpointV1,
    lease: WorkLeaseV1,
    expectedRevision: number,
  ): Promise<RecursiveWorkcellCommitResult> {
    return this.store.checkpoint({
      checkpoint,
      expected_revision: expectedRevision,
      lease,
    });
  }

  resume(
    parentPacketId: string,
    checkpointId: string,
    lease: WorkLeaseV1,
    recordedAt: string,
    expectedRevision: number,
  ): Promise<RecursiveWorkcellCommitResult> {
    const resume = createRecursiveWorkcellResume(
      parentPacketId,
      checkpointId,
      lease,
      recordedAt,
    );
    return this.store.resume({
      expected_revision: expectedRevision,
      lease,
      resume,
    });
  }

  async reconcileTerminal(
    parentPacketId: string,
    childPacketId: string,
    draft: RecursiveWorkcellTerminalDraft,
    lease: WorkLeaseV1,
    expectedRevision: number,
  ): Promise<RecursiveWorkcellCommitResult> {
    const reconciliation = await this.requireReconciliation(parentPacketId);
    const child = requireChild(reconciliation, childPacketId);
    validateDistributedWorkReceipt(child.child_packet, draft.receipt);
    const counterevidence = draft.counterevidence.map((item) =>
      createRecursiveWorkcellCounterevidence(childPacketId, item),
    );
    validateCounterevidenceSet(counterevidence);
    return this.store.reconcileReceipt({
      counterevidence,
      expected_revision: expectedRevision,
      lease,
      receipt: structuredClone(draft.receipt),
    });
  }

  private async requireReconciliation(
    parentPacketId: string,
  ): Promise<RecursiveWorkcellReconciliationV1> {
    requirePattern(parentPacketId, PACKET_ID, "parent_packet_id");
    const reconciliation = await this.store.readReconciliation(parentPacketId);
    if (reconciliation === undefined) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell reconciliation does not exist",
      );
    }
    return reconciliation;
  }
}

export function recursiveWorkcellIdentity(
  parentPacketId: string,
  childPacketId: string,
  childSequence: number,
): string {
  requirePattern(parentPacketId, PACKET_ID, "parent_packet_id");
  requirePattern(childPacketId, PACKET_ID, "child_packet_id");
  requireBoundedPositiveInteger(
    childSequence,
    MAX_RECURSIVE_WORKCELL_CHILDREN,
    "child_sequence",
  );
  return `recursive-workcell://sha256/${hashHex(
    stableStringify([parentPacketId, childPacketId, childSequence]),
  )}`;
}

export function recursiveWorkcellProgressIdentity(
  workcellId: string,
  idempotencyKey: string,
): string {
  requirePattern(workcellId, WORKCELL_ID, "workcell_id");
  requireId(idempotencyKey, "idempotency_key");
  return `recursive-workcell-progress://sha256/${hashHex(
    stableStringify([workcellId, idempotencyKey]),
  )}`;
}

export function recursiveWorkcellCounterevidenceIdentity(
  childPacketId: string,
  draft: RecursiveWorkcellCounterevidenceDraft,
): string {
  requirePattern(childPacketId, PACKET_ID, "child_packet_id");
  validateCounterevidenceDraft(draft);
  return `recursive-workcell-counterevidence://sha256/${hashHex(
    stableStringify([
      childPacketId,
      draft.claim_ref,
      draft.evidence_ref,
      draft.evidence_digest,
    ]),
  )}`;
}

export function recursiveWorkcellResumeIdentity(
  parentPacketId: string,
  checkpointId: string,
  lease: WorkLeaseV1,
): string {
  requirePattern(parentPacketId, PACKET_ID, "parent_packet_id");
  requireId(checkpointId, "checkpoint_id");
  validateLeaseShape(lease);
  return `recursive-workcell-resume://sha256/${hashHex(
    stableStringify([
      parentPacketId,
      checkpointId,
      lease.generation,
      lease.fencing_token,
      lease.lease_token,
    ]),
  )}`;
}

export function createRecursiveWorkcellChild(
  parentPacket: DistributedWorkPacketV1,
  parentAncestorPacketIds: string[],
  childPacket: DistributedWorkPacketV1,
  childSequence: number,
  createdAt: string,
): RecursiveWorkcellChildV1 {
  validateDistributedWorkPacket(parentPacket);
  validateDistributedWorkPacket(childPacket);
  requireTimestamp(createdAt, "created_at");
  validateAncestorPacketIds(parentAncestorPacketIds, parentPacket.packet_id);
  requireBoundedPositiveInteger(
    childSequence,
    MAX_RECURSIVE_WORKCELL_CHILDREN,
    "child_sequence",
  );
  const ancestorPacketIds = [
    ...parentAncestorPacketIds,
    parentPacket.packet_id,
  ];
  if (ancestorPacketIds.includes(childPacket.packet_id)) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell lineage contains a cycle",
    );
  }
  if (ancestorPacketIds.length > MAX_RECURSIVE_WORKCELL_DEPTH) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell depth exceeds the contract bound",
    );
  }
  if (
    childPacket.parent_run_id !== parentPacket.child_run.run_id ||
    childPacket.parent_subject_ref !== parentPacket.packet_id ||
    childPacket.tenant_id !== parentPacket.tenant_id ||
    childPacket.thread_ref !== parentPacket.thread_ref ||
    childPacket.retention_policy_ref !== parentPacket.retention_policy_ref
  ) {
    throw new RecursiveWorkcellInvariantError(
      "recursive child packet is not bound to its exact parent",
    );
  }

  const child: RecursiveWorkcellChildV1 = {
    ancestor_packet_ids: ancestorPacketIds,
    child_packet: structuredClone(childPacket),
    child_sequence: childSequence,
    created_at: createdAt,
    depth: ancestorPacketIds.length,
    parent_packet_id: parentPacket.packet_id,
    schema_version: RECURSIVE_WORKCELL_CHILD_SCHEMA_VERSION,
    workcell_id: recursiveWorkcellIdentity(
      parentPacket.packet_id,
      childPacket.packet_id,
      childSequence,
    ),
  };
  validateRecursiveWorkcellChild(parentPacket, child);
  return child;
}

export function validateRecursiveWorkcellChild(
  parentPacket: DistributedWorkPacketV1,
  child: RecursiveWorkcellChildV1,
): void {
  validateDistributedWorkPacket(parentPacket);
  validateDistributedWorkPacket(child.child_packet);
  if (child.schema_version !== RECURSIVE_WORKCELL_CHILD_SCHEMA_VERSION) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell child schema version is unsupported",
    );
  }
  requirePattern(child.workcell_id, WORKCELL_ID, "workcell_id");
  requireTimestamp(child.created_at, "created_at");
  validateAncestorPacketIds(
    child.ancestor_packet_ids.slice(0, -1),
    parentPacket.packet_id,
  );
  const expectedAncestors = [
    ...child.ancestor_packet_ids.slice(0, -1),
    parentPacket.packet_id,
  ];
  if (
    child.parent_packet_id !== parentPacket.packet_id ||
    child.depth !== child.ancestor_packet_ids.length ||
    child.depth < 1 ||
    child.depth > MAX_RECURSIVE_WORKCELL_DEPTH ||
    stableStringify(child.ancestor_packet_ids) !==
      stableStringify(expectedAncestors) ||
    child.ancestor_packet_ids.includes(child.child_packet.packet_id) ||
    child.workcell_id !==
      recursiveWorkcellIdentity(
        parentPacket.packet_id,
        child.child_packet.packet_id,
        child.child_sequence,
      )
  ) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell child lineage or identity is invalid",
    );
  }
  if (
    child.child_packet.parent_run_id !== parentPacket.child_run.run_id ||
    child.child_packet.parent_subject_ref !== parentPacket.packet_id ||
    child.child_packet.tenant_id !== parentPacket.tenant_id ||
    child.child_packet.thread_ref !== parentPacket.thread_ref ||
    child.child_packet.retention_policy_ref !==
      parentPacket.retention_policy_ref
  ) {
    throw new RecursiveWorkcellInvariantError(
      "recursive child packet is not bound to its exact parent",
    );
  }
}

export function createRecursiveWorkcellProgress(
  child: RecursiveWorkcellChildV1,
  draft: RecursiveWorkcellProgressDraft,
): RecursiveWorkcellProgressV1 {
  validateRecursiveWorkcellChildBinding(child);
  requireId(draft.idempotency_key, "idempotency_key");
  requirePositiveInteger(draft.sequence, "sequence");
  requireTimestamp(draft.recorded_at, "recorded_at");
  validateProgressPhase(draft.phase, draft.checkpoint_ref);
  validateRuntimeObservationBatch(child.child_packet, draft.runtime_observations);
  if (draft.counterevidence.length > MAX_RECURSIVE_WORKCELL_COUNTEREVIDENCE) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell counterevidence exceeds the contract bound",
    );
  }
  const counterevidence = draft.counterevidence.map((item) =>
    createRecursiveWorkcellCounterevidence(
      child.child_packet.packet_id,
      item,
    ),
  );
  validateCounterevidenceSet(counterevidence);
  const progress: RecursiveWorkcellProgressV1 = {
    ...structuredClone(draft),
    child_packet_id: child.child_packet.packet_id,
    counterevidence,
    progress_id: recursiveWorkcellProgressIdentity(
      child.workcell_id,
      draft.idempotency_key,
    ),
    schema_version: RECURSIVE_WORKCELL_PROGRESS_SCHEMA_VERSION,
    workcell_id: child.workcell_id,
  };
  validateRecursiveWorkcellProgress(child, progress);
  return progress;
}

export function validateRecursiveWorkcellProgress(
  child: RecursiveWorkcellChildV1,
  progress: RecursiveWorkcellProgressV1,
): void {
  validateRecursiveWorkcellChildBinding(child);
  if (progress.schema_version !== RECURSIVE_WORKCELL_PROGRESS_SCHEMA_VERSION) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell progress schema version is unsupported",
    );
  }
  requirePattern(progress.progress_id, PROGRESS_ID, "progress_id");
  requireId(progress.idempotency_key, "idempotency_key");
  requirePositiveInteger(progress.sequence, "sequence");
  requireTimestamp(progress.recorded_at, "recorded_at");
  validateProgressPhase(progress.phase, progress.checkpoint_ref);
  validateRuntimeObservationBatch(
    child.child_packet,
    progress.runtime_observations,
  );
  validateCounterevidenceSet(progress.counterevidence);
  if (
    progress.workcell_id !== child.workcell_id ||
    progress.child_packet_id !== child.child_packet.packet_id ||
    progress.progress_id !==
      recursiveWorkcellProgressIdentity(
        child.workcell_id,
        progress.idempotency_key,
      )
  ) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell progress identity does not match its child",
    );
  }
}

export function createRecursiveWorkcellCounterevidence(
  childPacketId: string,
  draft: RecursiveWorkcellCounterevidenceDraft,
): RecursiveWorkcellCounterevidenceV1 {
  return {
    ...structuredClone(draft),
    child_packet_id: childPacketId,
    counterevidence_id: recursiveWorkcellCounterevidenceIdentity(
      childPacketId,
      draft,
    ),
    schema_version: RECURSIVE_WORKCELL_COUNTEREVIDENCE_SCHEMA_VERSION,
  };
}

export function createRecursiveWorkcellResume(
  parentPacketId: string,
  checkpointId: string,
  lease: WorkLeaseV1,
  recordedAt: string,
): RecursiveWorkcellResumeV1 {
  requireTimestamp(recordedAt, "recorded_at");
  return {
    checkpoint_id: checkpointId,
    fencing_token: lease.fencing_token,
    generation: lease.generation,
    lease_token: lease.lease_token,
    recorded_at: recordedAt,
    resume_id: recursiveWorkcellResumeIdentity(
      parentPacketId,
      checkpointId,
      lease,
    ),
    schema_version: RECURSIVE_WORKCELL_RESUME_SCHEMA_VERSION,
  };
}

export function validateRecursiveWorkcellResume(
  parentPacketId: string,
  lease: WorkLeaseV1,
  resume: RecursiveWorkcellResumeV1,
): void {
  if (resume.schema_version !== RECURSIVE_WORKCELL_RESUME_SCHEMA_VERSION) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell resume schema version is unsupported",
    );
  }
  requirePattern(resume.resume_id, RESUME_ID, "resume_id");
  requireId(resume.checkpoint_id, "checkpoint_id");
  requireTimestamp(resume.recorded_at, "recorded_at");
  if (
    resume.generation !== lease.generation ||
    resume.fencing_token !== lease.fencing_token ||
    resume.lease_token !== lease.lease_token ||
    resume.resume_id !==
      recursiveWorkcellResumeIdentity(
        parentPacketId,
        resume.checkpoint_id,
        lease,
      )
  ) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell resume does not match its lease proof",
    );
  }
}

export function createRecursiveWorkcellReconciliation(
  draft: RecursiveWorkcellAdmissionDraft,
): RecursiveWorkcellReconciliationV1 {
  validateDistributedWorkPacket(draft.parent_packet);
  requireTimestamp(draft.admitted_at, "admitted_at");
  validateAncestorPacketIds(
    draft.parent_ancestor_packet_ids,
    draft.parent_packet.packet_id,
  );
  if (
    draft.child_packets.length < 1 ||
    draft.child_packets.length > MAX_RECURSIVE_WORKCELL_CHILDREN
  ) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell children exceed the contract bound",
    );
  }
  const children = draft.child_packets.map((packet, index) =>
    createRecursiveWorkcellChild(
      draft.parent_packet,
      draft.parent_ancestor_packet_ids,
      packet,
      index + 1,
      draft.admitted_at,
    ),
  );
  if (
    new Set(children.map((child) => child.child_packet.packet_id)).size !==
      children.length ||
    new Set(children.map((child) => child.child_packet.child_run.run_id)).size !==
      children.length
  ) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell children must have unique packet and run identities",
    );
  }
  return {
    blocked_child_count: 0,
    checkpoints: [],
    child_receipts: [],
    children,
    completed_child_count: 0,
    coordination_state: "active",
    counterevidence: [],
    created_at: draft.admitted_at,
    observations: [],
    parent_packet: structuredClone(draft.parent_packet),
    progress: [],
    resumes: [],
    revision: 1,
    schema_version: RECURSIVE_WORKCELL_RECONCILIATION_SCHEMA_VERSION,
    state: "active",
    unresolved_child_count: children.length,
    updated_at: draft.admitted_at,
  };
}

export function deriveRecursiveWorkcellState(
  childCount: number,
  receipts: RecursiveWorkcellReconciliationV1["child_receipts"],
): Pick<
  RecursiveWorkcellReconciliationV1,
  | "blocked_child_count"
  | "completed_child_count"
  | "state"
  | "unresolved_child_count"
> {
  if (childCount < 1 || receipts.length > childCount) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell receipt count is inconsistent with its children",
    );
  }
  const completed = receipts.filter(
    (receipt) => receipt.status === "completed",
  ).length;
  const blocked = receipts.filter((receipt) => receipt.status === "blocked").length;
  const unresolved = childCount - receipts.length;
  const state =
    unresolved === 0
      ? blocked > 0
        ? "blocked"
        : "completed"
      : receipts.length > 0
        ? "partially_completed"
        : "active";
  return {
    blocked_child_count: blocked,
    completed_child_count: completed,
    state,
    unresolved_child_count: unresolved,
  };
}

export function validateLeaseForParent(
  parentPacket: DistributedWorkPacketV1,
  lease: WorkLeaseV1,
  observedAt: string,
): void {
  validateDistributedWorkPacket(parentPacket);
  validateLeaseShape(lease);
  requireTimestamp(observedAt, "observed_at");
  if (lease.run_id !== parentPacket.child_run.run_id) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell lease does not own the parent run",
    );
  }
  if (Date.parse(observedAt) >= Date.parse(lease.lease_expires_at)) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell lease is expired",
    );
  }
}

function validateRecursiveWorkcellChildBinding(
  child: RecursiveWorkcellChildV1,
): void {
  if (
    child.schema_version !== RECURSIVE_WORKCELL_CHILD_SCHEMA_VERSION ||
    child.parent_packet_id !== child.ancestor_packet_ids.at(-1) ||
    child.ancestor_packet_ids.includes(child.child_packet.packet_id) ||
    child.depth !== child.ancestor_packet_ids.length ||
    child.depth < 1 ||
    child.depth > MAX_RECURSIVE_WORKCELL_DEPTH ||
    child.workcell_id !==
      recursiveWorkcellIdentity(
        child.parent_packet_id,
        child.child_packet.packet_id,
        child.child_sequence,
      )
  ) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell child binding is invalid",
    );
  }
  validateDistributedWorkPacket(child.child_packet);
}

function requireChild(
  reconciliation: RecursiveWorkcellReconciliationV1,
  childPacketId: string,
): RecursiveWorkcellChildV1 {
  requirePattern(childPacketId, PACKET_ID, "child_packet_id");
  const child = reconciliation.children.find(
    (candidate) => candidate.child_packet.packet_id === childPacketId,
  );
  if (child === undefined) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell child does not belong to the parent",
    );
  }
  return child;
}

function validateAncestorPacketIds(
  ancestorPacketIds: string[],
  parentPacketId: string,
): void {
  if (ancestorPacketIds.length >= MAX_RECURSIVE_WORKCELL_DEPTH) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell parent depth leaves no room for a child",
    );
  }
  const identities = new Set<string>();
  for (const packetId of ancestorPacketIds) {
    requirePattern(packetId, PACKET_ID, "ancestor_packet_id");
    if (identities.has(packetId) || packetId === parentPacketId) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell lineage contains a cycle",
      );
    }
    identities.add(packetId);
  }
}

function validateCounterevidenceSet(
  items: RecursiveWorkcellCounterevidenceV1[],
): void {
  if (items.length > MAX_RECURSIVE_WORKCELL_COUNTEREVIDENCE) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell counterevidence exceeds the contract bound",
    );
  }
  const ids = new Set<string>();
  for (const item of items) {
    if (
      item.schema_version !== RECURSIVE_WORKCELL_COUNTEREVIDENCE_SCHEMA_VERSION
    ) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell counterevidence schema version is unsupported",
      );
    }
    requirePattern(
      item.counterevidence_id,
      COUNTEREVIDENCE_ID,
      "counterevidence_id",
    );
    validateCounterevidenceDraft(item);
    if (
      item.counterevidence_id !==
      recursiveWorkcellCounterevidenceIdentity(item.child_packet_id, item) ||
      ids.has(item.counterevidence_id)
    ) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell counterevidence identity repeats or changed",
      );
    }
    ids.add(item.counterevidence_id);
  }
}

function validateCounterevidenceDraft(
  draft: RecursiveWorkcellCounterevidenceDraft,
): void {
  requireOpaqueRef(draft.claim_ref, "claim_ref");
  requireOpaqueRef(draft.evidence_ref, "evidence_ref");
  requirePattern(draft.evidence_digest, SHA256_DIGEST, "evidence_digest");
  requireTimestamp(draft.observed_at, "observed_at");
}

function validateProgressPhase(
  phase: RecursiveWorkcellProgressDraft["phase"],
  checkpointRef: string | undefined,
): void {
  if (phase === "checkpointed") {
    requireOpaqueRef(checkpointRef, "checkpoint_ref");
    return;
  }
  if (phase !== "running") {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell progress phase is unsupported",
    );
  }
  if (checkpointRef !== undefined) {
    throw new RecursiveWorkcellInvariantError(
      "running recursive workcell progress cannot carry a checkpoint",
    );
  }
}

function validateRuntimeObservationBatch(
  packet: DistributedWorkPacketV1,
  observations: RuntimeToolObservationV1[],
): void {
  if (observations.length > MAX_RECURSIVE_WORKCELL_OBSERVATIONS) {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell observations exceed the contract bound",
    );
  }
  const capabilities = new Set(
    packet.required_capabilities.map(
      (capability) => `${capability.capability_id}\u0000${capability.version}`,
    ),
  );
  let lastSequence = 0;
  const identities = new Set<string>();
  for (const observation of observations) {
    if (
      observation.schema_version !== "distributed-work-observation/v1" ||
      observation.sequence <= lastSequence ||
      !Number.isSafeInteger(observation.sequence)
    ) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell observations must preserve increasing runtime order",
      );
    }
    requirePositiveInteger(observation.attempt, "observation.attempt");
    requireId(observation.capability_id, "observation.capability_id");
    requireId(observation.capability_version, "observation.capability_version");
    requireOpaqueRef(observation.tool_ref, "observation.tool_ref");
    requireTimestamp(observation.started_at, "observation.started_at");
    requireTimestamp(observation.completed_at, "observation.completed_at");
    if (
      Date.parse(observation.completed_at) < Date.parse(observation.started_at) ||
      !capabilities.has(
        `${observation.capability_id}\u0000${observation.capability_version}`,
      ) ||
      observation.observation_id !==
        runtimeToolObservationIdentity(
          packet.packet_id,
          observation.tool_ref,
          observation.attempt,
        ) ||
      identities.has(observation.observation_id)
    ) {
      throw new RecursiveWorkcellInvariantError(
        "recursive workcell observation is not valid for its child packet",
      );
    }
    validateObservationOutcome(observation);
    identities.add(observation.observation_id);
    lastSequence = observation.sequence;
  }
}

function validateObservationOutcome(observation: RuntimeToolObservationV1): void {
  if (observation.status === "completed") {
    requireOpaqueRef(observation.result_ref, "observation.result_ref");
    requirePattern(
      observation.result_digest,
      SHA256_DIGEST,
      "observation.result_digest",
    );
    if (
      observation.failure_ref !== undefined ||
      observation.failure_digest !== undefined
    ) {
      throw new RecursiveWorkcellInvariantError(
        "completed observations cannot carry a failure result",
      );
    }
    return;
  }
  if (observation.status !== "failed") {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell observation status is unsupported",
    );
  }
  requireOpaqueRef(observation.failure_ref, "observation.failure_ref");
  requirePattern(
    observation.failure_digest,
    SHA256_DIGEST,
    "observation.failure_digest",
  );
  if (
    observation.result_ref !== undefined ||
    observation.result_digest !== undefined
  ) {
    throw new RecursiveWorkcellInvariantError(
      "failed observations cannot carry a successful result",
    );
  }
}

function validateLeaseShape(lease: WorkLeaseV1): void {
  if (lease.schema_version !== "work-lease/v1") {
    throw new RecursiveWorkcellInvariantError(
      "recursive workcell lease schema version is unsupported",
    );
  }
  requireId(lease.run_id, "lease.run_id");
  requireId(lease.owner_id, "lease.owner_id");
  requireId(lease.lease_token, "lease.lease_token");
  requirePositiveInteger(lease.generation, "lease.generation");
  requirePositiveInteger(lease.fencing_token, "lease.fencing_token");
  requireTimestamp(lease.heartbeat_at, "lease.heartbeat_at");
  requireTimestamp(lease.lease_expires_at, "lease.lease_expires_at");
}

function requireBoundedPositiveInteger(
  value: number,
  maximum: number,
  label: string,
): void {
  requirePositiveInteger(value, label);
  if (value > maximum) {
    throw new RecursiveWorkcellInvariantError(
      `${label} exceeds the contract bound`,
    );
  }
}

function requirePositiveInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new RecursiveWorkcellInvariantError(
      `${label} must be a positive integer`,
    );
  }
}

function requireId(
  value: string | undefined,
  label: string,
): asserts value is string {
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

function hashHex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
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

function sameStringArray(left: string[], right: string[]): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}
