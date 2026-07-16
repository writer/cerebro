import type {
  CheckpointV1,
  RecursiveWorkcellChildV1,
  RecursiveWorkcellCounterevidenceV1,
  RecursiveWorkcellProgressV1,
  RecursiveWorkcellReconciliationV1,
  RecursiveWorkcellResumeV1,
  WorkLeaseV1,
} from "./contracts.js";
import type { DistributedWorkReceiptV1 } from "../contracts.js";

export interface RecursiveWorkcellAdmissionCommit {
  children: RecursiveWorkcellChildV1[];
  lease: WorkLeaseV1;
  reconciliation: RecursiveWorkcellReconciliationV1;
}

export interface RecursiveWorkcellProgressCommit {
  expected_revision: number;
  lease: WorkLeaseV1;
  progress: RecursiveWorkcellProgressV1;
}

export interface RecursiveWorkcellActiveLeaseClaimCommit {
  expected_revision: number;
  lease: WorkLeaseV1;
  parent_packet_id: string;
}

export interface RecursiveWorkcellCheckpointCommit {
  checkpoint: CheckpointV1;
  expected_revision: number;
  lease: WorkLeaseV1;
}

export interface RecursiveWorkcellResumeCommit {
  expected_revision: number;
  lease: WorkLeaseV1;
  resume: RecursiveWorkcellResumeV1;
}

export interface RecursiveWorkcellReceiptCommit {
  counterevidence: RecursiveWorkcellCounterevidenceV1[];
  expected_revision: number;
  lease: WorkLeaseV1;
  receipt: DistributedWorkReceiptV1;
}

export interface RecursiveWorkcellCommitResult {
  created: boolean;
  reconciliation: RecursiveWorkcellReconciliationV1;
}

/**
 * Durable topology-neutral workcell boundary. Production adapters must make
 * every method atomic with the active lease record and exact revision check.
 */
export interface DurableRecursiveWorkcellPort {
  /** Atomically persists the whole child set before any child is dispatched. */
  admitChildren(
    commit: RecursiveWorkcellAdmissionCommit,
  ): Promise<RecursiveWorkcellCommitResult>;

  readReconciliation(
    parentPacketId: string,
  ): Promise<RecursiveWorkcellReconciliationV1 | undefined>;

  /** Returns the durable binding when this packet was admitted as a child. */
  readChildBinding(
    childPacketId: string,
  ): Promise<RecursiveWorkcellChildV1 | undefined>;

  /**
   * Atomically renews the active authority or recovers expired active work
   * under a strictly newer generation and fence. Checkpointed work must use
   * resume instead.
   */
  claimActiveLease(
    commit: RecursiveWorkcellActiveLeaseClaimCommit,
  ): Promise<RecursiveWorkcellCommitResult>;

  /** Appends one idempotent progress fact under the exact active fence. */
  appendProgress(
    commit: RecursiveWorkcellProgressCommit,
  ): Promise<RecursiveWorkcellCommitResult>;

  /** Persists a parent checkpoint before ownership can move. */
  checkpoint(
    commit: RecursiveWorkcellCheckpointCommit,
  ): Promise<RecursiveWorkcellCommitResult>;

  /** Resumes the exact checkpoint under a newer non-stale fence. */
  resume(
    commit: RecursiveWorkcellResumeCommit,
  ): Promise<RecursiveWorkcellCommitResult>;

  /**
   * Commits one terminal child receipt and recomputes parent truth without
   * discarding prior progress, observations, failures, or counterevidence.
   */
  reconcileReceipt(
    commit: RecursiveWorkcellReceiptCommit,
  ): Promise<RecursiveWorkcellCommitResult>;
}
