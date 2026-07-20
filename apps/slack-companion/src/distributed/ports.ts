import type { RunReceiptV1, WorkLeaseV1 } from "@writer/cerebro-sdk";
import type {
  DistributedWorkPacketV1,
  DistributedWorkReceiptV1,
} from "./contracts.js";

export interface DistributedWorkAdmissionCommit {
  packet: DistributedWorkPacketV1;
}

export interface DistributedWorkAdmissionResult {
  created: boolean;
  packet: DistributedWorkPacketV1;
}

export interface DistributedWorkReceiptCommit {
  expected_run_revision: number;
  lease: WorkLeaseV1;
  receipt: DistributedWorkReceiptV1;
  terminal_run: RunReceiptV1;
}

export interface DistributedWorkReceiptCommitResult {
  created: boolean;
  receipt: DistributedWorkReceiptV1;
  run: RunReceiptV1;
}

/**
 * Durable packet boundary. Production adapters choose an existing supported
 * state store; this public port does not select a datastore or topology.
 */
export interface DurableDistributedWorkPort {
  /**
   * Atomically persists packet identity, the queued child run, idempotency
   * mapping, and runnable queue entry before a transport may acknowledge it.
   */
  admitAndEnqueue(
    commit: DistributedWorkAdmissionCommit,
  ): Promise<DistributedWorkAdmissionResult>;

  readPacket(packetId: string): Promise<DistributedWorkPacketV1 | undefined>;

  readReceipt(
    packetId: string,
  ): Promise<DistributedWorkReceiptV1 | undefined>;

  /**
   * Atomically verifies the exact active lease and run revision, advances the
   * child run to the matching terminal state, and commits the one terminal
   * receipt. A retry may return the identical prior records; changed intent or
   * an outdated generation/fence must fail.
   */
  commitReceipt(
    commit: DistributedWorkReceiptCommit,
  ): Promise<DistributedWorkReceiptCommitResult>;
}
