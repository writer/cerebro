import type {
  CheckpointDraft,
  CheckpointV1,
  ExecutionSession,
} from "../execution/model.js";
import type {
  ExecutionCoordinator,
  StartExecutionInput,
} from "../execution/coordinator.js";
import {
  createDistributedWorkReceipt,
  distributedWorkLeaseReference,
  validateDistributedWorkPacket,
} from "./validation.js";
import type {
  DistributedWorkPacketV1,
  DistributedWorkReceiptDraft,
  DistributedWorkReceiptV1,
} from "./contracts.js";
import type { DurableDistributedWorkPort } from "./ports.js";

export interface DistributedWorkCoordinatorOptions {
  execution: ExecutionCoordinator;
  store: DurableDistributedWorkPort;
}

export interface DistributedWorkAdmissionAcknowledgement {
  acknowledgement_permitted: true;
  duplicate: boolean;
  packet: DistributedWorkPacketV1;
  run_id: string;
}

export interface DistributedWorkStartInput
  extends Omit<StartExecutionInput, "run_id"> {}

export type DistributedWorkStartResult =
  | { status: "not_runnable" }
  | {
      packet: DistributedWorkPacketV1;
      session: ExecutionSession;
      status: "resumed" | "started";
    };

export interface DistributedWorkCompletionInput
  extends Omit<DistributedWorkReceiptDraft, "lease_ref" | "packet"> {}

export interface DistributedWorkCompletionAcknowledgement {
  acknowledgement_permitted: true;
  duplicate: boolean;
  receipt: DistributedWorkReceiptV1;
  run_id: string;
}

/**
 * Portable distributed-work continuity. This coordinator owns durable ordering
 * only; transport selection, worker discovery, and deployment topology belong
 * to adapters outside this package.
 */
export class DistributedWorkCoordinator {
  private readonly execution: ExecutionCoordinator;
  private readonly store: DurableDistributedWorkPort;

  constructor(options: DistributedWorkCoordinatorOptions) {
    this.execution = options.execution;
    this.store = options.store;
  }

  /**
   * A caller may acknowledge the transport only after this method returns.
   * The port commits the immutable packet, child run, idempotency mapping, and
   * runnable queue entry as one durable operation.
   */
  async admit(
    packet: DistributedWorkPacketV1,
  ): Promise<DistributedWorkAdmissionAcknowledgement> {
    validateDistributedWorkPacket(packet);
    const committed = await this.store.admitAndEnqueue({ packet });
    if (
      committed.packet.packet_id !== packet.packet_id ||
      committed.packet.intent_digest !== packet.intent_digest ||
      committed.packet.child_run.run_id !== packet.child_run.run_id
    ) {
      throw new DistributedWorkContinuityError(
        "durable admission returned a different distributed work packet",
      );
    }
    return {
      acknowledgement_permitted: true,
      duplicate: !committed.created,
      packet: committed.packet,
      run_id: committed.packet.child_run.run_id,
    };
  }

  /**
   * Starts or resumes the packet's canonical child run. Resume material comes
   * exclusively from the durable CheckpointV1 read by ExecutionCoordinator.
   */
  async start(
    packetId: string,
    input: DistributedWorkStartInput,
  ): Promise<DistributedWorkStartResult> {
    const packet = await this.requirePacket(packetId);
    const started = await this.execution.start({
      ...input,
      run_id: packet.child_run.run_id,
    });
    if (started.status === "not_runnable") {
      return started;
    }
    assertSessionMatchesPacket(packet, started.session);
    return { ...started, packet };
  }

  /**
   * Persists the checkpoint and releases the lease before another generation
   * can claim the child run. No handoff payload crosses this boundary.
   */
  async pauseForHandoff(
    packetId: string,
    session: ExecutionSession,
    checkpoint: CheckpointDraft,
  ): Promise<{ checkpoint: CheckpointV1; run_id: string }> {
    const packet = await this.requirePacket(packetId);
    assertSessionMatchesPacket(packet, session);
    const paused = await this.execution.pauseForDrain(session, checkpoint);
    return { checkpoint: paused.checkpoint, run_id: paused.run.run_id };
  }

  /**
   * Returns completion acknowledgement permission only after the terminal
   * receipt and matching child-run transition have committed atomically.
   */
  async complete(
    packetId: string,
    session: ExecutionSession,
    input: DistributedWorkCompletionInput,
  ): Promise<DistributedWorkCompletionAcknowledgement> {
    const packet = await this.requirePacket(packetId);
    assertSessionMatchesPacket(packet, session);
    const receipt = createDistributedWorkReceipt({
      ...input,
      lease_ref: distributedWorkLeaseReference(session.lease),
      packet,
    });
    const committed = await this.store.commitReceipt({
      expected_run_revision: session.run.revision,
      lease: session.lease,
      receipt,
      terminal_run: {
        ...session.run,
        revision: session.run.revision + 1,
        state: receipt.status,
        updated_at: receipt.recorded_at,
      },
    });
    return {
      acknowledgement_permitted: true,
      duplicate: !committed.created,
      receipt: committed.receipt,
      run_id: committed.run.run_id,
    };
  }

  private async requirePacket(
    packetId: string,
  ): Promise<DistributedWorkPacketV1> {
    const packet = await this.store.readPacket(packetId);
    if (packet === undefined) {
      throw new DistributedWorkContinuityError("distributed work packet is not admitted");
    }
    validateDistributedWorkPacket(packet);
    return packet;
  }
}

export class DistributedWorkContinuityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DistributedWorkContinuityError";
  }
}

function assertSessionMatchesPacket(
  packet: DistributedWorkPacketV1,
  session: ExecutionSession,
): void {
  if (
    session.run.run_id !== packet.child_run.run_id ||
    session.lease.run_id !== packet.child_run.run_id ||
    session.run.subject_ref !== packet.packet_id ||
    session.run.idempotency_key !== packet.idempotency_key ||
    session.run.input_digest !== packet.intent_digest ||
    session.run.tenant_id !== packet.tenant_id ||
    session.run.binding_id !== packet.child_run.binding_id
  ) {
    throw new DistributedWorkContinuityError(
      "execution session does not belong to the distributed work packet",
    );
  }
  if (
    session.checkpoint !== undefined &&
    session.checkpoint.run_id !== packet.child_run.run_id
  ) {
    throw new DistributedWorkContinuityError(
      "resume checkpoint does not belong to the distributed work packet",
    );
  }
}
