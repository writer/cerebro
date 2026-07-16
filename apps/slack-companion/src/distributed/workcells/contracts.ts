import type {
  CheckpointV1,
  WorkLeaseV1,
} from "@writer/cerebro-sdk";
import type {
  DistributedWorkPacketV1,
  DistributedWorkReceiptV1,
  RuntimeToolObservationV1,
} from "../contracts.js";

export type { CheckpointV1, WorkLeaseV1 };

export const RECURSIVE_WORKCELL_CHILD_SCHEMA_VERSION =
  "recursive-workcell-child/v1" as const;
export const RECURSIVE_WORKCELL_PROGRESS_SCHEMA_VERSION =
  "recursive-workcell-progress/v1" as const;
export const RECURSIVE_WORKCELL_COUNTEREVIDENCE_SCHEMA_VERSION =
  "recursive-workcell-counterevidence/v1" as const;
export const RECURSIVE_WORKCELL_RESUME_SCHEMA_VERSION =
  "recursive-workcell-resume/v1" as const;
export const RECURSIVE_WORKCELL_RECONCILIATION_SCHEMA_VERSION =
  "recursive-workcell-reconciliation/v1" as const;

export const MAX_RECURSIVE_WORKCELL_DEPTH = 4;
export const MAX_RECURSIVE_WORKCELL_CHILDREN = 8;
export const MAX_RECURSIVE_WORKCELL_PROGRESS_RECORDS = 128;
export const MAX_RECURSIVE_WORKCELL_CHECKPOINTS = 32;
export const MAX_RECURSIVE_WORKCELL_COUNTEREVIDENCE = 128;
export const MAX_RECURSIVE_WORKCELL_OBSERVATIONS = 256;

export type RecursiveWorkcellAggregateState =
  | "active"
  | "partially_completed"
  | "blocked"
  | "completed";

export type RecursiveWorkcellCoordinationState = "active" | "checkpointed";
export type RecursiveWorkcellProgressPhase = "running" | "checkpointed";

/** One deterministic child of an admitted distributed work packet. */
export interface RecursiveWorkcellChildV1 {
  ancestor_packet_ids: string[];
  child_packet: DistributedWorkPacketV1;
  child_sequence: number;
  created_at: string;
  depth: number;
  parent_packet_id: string;
  schema_version: typeof RECURSIVE_WORKCELL_CHILD_SCHEMA_VERSION;
  workcell_id: string;
}

export interface RecursiveWorkcellCounterevidenceDraft {
  claim_ref: string;
  evidence_digest: string;
  evidence_ref: string;
  observed_at: string;
}

/** Append-only contradictory evidence. Payloads remain behind opaque refs. */
export interface RecursiveWorkcellCounterevidenceV1
  extends RecursiveWorkcellCounterevidenceDraft {
  child_packet_id: string;
  counterevidence_id: string;
  schema_version: typeof RECURSIVE_WORKCELL_COUNTEREVIDENCE_SCHEMA_VERSION;
}

export interface RecursiveWorkcellObservationV1 {
  child_packet_id: string;
  observation: RuntimeToolObservationV1;
}

export interface RecursiveWorkcellProgressDraft {
  checkpoint_ref?: string;
  counterevidence: RecursiveWorkcellCounterevidenceDraft[];
  idempotency_key: string;
  phase: RecursiveWorkcellProgressPhase;
  recorded_at: string;
  runtime_observations: RuntimeToolObservationV1[];
  sequence: number;
}

/** An immutable progress fact; retries use the same deterministic identity. */
export interface RecursiveWorkcellProgressV1
  extends RecursiveWorkcellProgressDraft {
  child_packet_id: string;
  counterevidence: RecursiveWorkcellCounterevidenceV1[];
  progress_id: string;
  schema_version: typeof RECURSIVE_WORKCELL_PROGRESS_SCHEMA_VERSION;
  workcell_id: string;
}

export interface RecursiveWorkcellResumeV1 {
  checkpoint_id: string;
  fencing_token: number;
  generation: number;
  lease_token: string;
  recorded_at: string;
  resume_id: string;
  schema_version: typeof RECURSIVE_WORKCELL_RESUME_SCHEMA_VERSION;
}

/**
 * Revisioned parent truth. Full child receipts and ordered observations remain
 * available even when siblings fail or the coordinator resumes elsewhere.
 */
export interface RecursiveWorkcellReconciliationV1 {
  blocked_child_count: number;
  checkpoints: CheckpointV1[];
  child_receipts: DistributedWorkReceiptV1[];
  children: RecursiveWorkcellChildV1[];
  completed_child_count: number;
  coordination_state: RecursiveWorkcellCoordinationState;
  counterevidence: RecursiveWorkcellCounterevidenceV1[];
  created_at: string;
  observations: RecursiveWorkcellObservationV1[];
  parent_packet: DistributedWorkPacketV1;
  progress: RecursiveWorkcellProgressV1[];
  resumes: RecursiveWorkcellResumeV1[];
  revision: number;
  schema_version: typeof RECURSIVE_WORKCELL_RECONCILIATION_SCHEMA_VERSION;
  state: RecursiveWorkcellAggregateState;
  unresolved_child_count: number;
  updated_at: string;
}

export interface RecursiveWorkcellAdmissionDraft {
  admitted_at: string;
  child_packets: DistributedWorkPacketV1[];
  /** Claimed lineage; admission verifies it against the durable parent binding. */
  parent_ancestor_packet_ids: string[];
  parent_packet: DistributedWorkPacketV1;
}

export interface RecursiveWorkcellTerminalDraft {
  counterevidence: RecursiveWorkcellCounterevidenceDraft[];
  receipt: DistributedWorkReceiptV1;
}
