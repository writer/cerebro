import { createHash } from "node:crypto";
import type { DurableCapacityPort } from "../execution/capacity-ports.js";
import type {
  AgentFleetAdmissionReceiptV1,
  AgentFleetCapacityAttempt,
  AgentFleetExecutionBindingV1,
  AgentFleetMessageV1,
  AgentFleetReservationResult,
  CapacityPermitV1,
  CheckpointV1,
  DistributedWorkPacketV1,
  WorkLeaseV1,
} from "./contracts.js";
import type { DurableAgentFleetPort } from "./ports.js";
import {
  rankCompatibleAgentFleetPeers,
} from "./selection.js";
import {
  AgentFleetContractError,
  createAgentFleetExecutionBinding,
  validateAgentFleetAdmissionReceipt,
  validateAgentFleetMessageForPacket,
} from "./validation.js";

export interface AgentFleetCoordinatorOptions {
  capacity: DurableCapacityPort;
  fleet: DurableAgentFleetPort;
}

export interface AgentFleetMailboxAcknowledgement {
  acknowledgement_permitted: true;
  duplicate: boolean;
  message: AgentFleetMessageV1;
  receipt: AgentFleetAdmissionReceiptV1;
  run_id: string;
}

export interface AgentFleetReservationInput {
  acquired_at: string;
  expires_at: string;
  permit_limits: Readonly<Record<string, number>>;
  reservation_key: string;
}

export interface AgentFleetExecutionBindingInput {
  bound_at: string;
  checkpoint?: CheckpointV1;
  lease: WorkLeaseV1;
  member_id: string;
  message_id: string;
  permit: CapacityPermitV1;
}

/**
 * Portable fleet ordering only. Discovery, persistence engines, timers,
 * credentials, transport acknowledgement, and deployment placement are ports.
 */
export class AgentFleetCoordinator {
  private readonly capacity: DurableCapacityPort;
  private readonly fleet: DurableAgentFleetPort;

  constructor(options: AgentFleetCoordinatorOptions) {
    this.capacity = options.capacity;
    this.fleet = options.fleet;
  }

  /** The caller may acknowledge its transport only after this method returns. */
  async admit(
    message: AgentFleetMessageV1,
    packet: DistributedWorkPacketV1,
  ): Promise<AgentFleetMailboxAcknowledgement> {
    validateAgentFleetMessageForPacket(message, packet);
    const committed = await this.fleet.admitMailboxAndEnqueue({
      message,
      packet,
    });
    validateAgentFleetAdmissionReceipt(
      committed.receipt,
      committed.message,
      committed.packet,
    );
    if (
      committed.message.message_id !== message.message_id ||
      committed.packet.packet_id !== packet.packet_id
    ) {
      throw new AgentFleetCoordinatorError(
        "durable admission returned different mailbox input",
      );
    }
    return {
      acknowledgement_permitted: true,
      duplicate: !committed.created,
      message: committed.message,
      receipt: committed.receipt,
      run_id: committed.packet.child_run.run_id,
    };
  }

  /**
   * Ranks compatible peers, then acquires the existing durable capacity permit
   * for the first available candidate. Exact retries replay the same permits.
   */
  async reserveCompatiblePeer(
    messageId: string,
    input: AgentFleetReservationInput,
  ): Promise<AgentFleetReservationResult> {
    requireBoundedOpaque(input.reservation_key, "reservation_key");
    requireCanonicalTime(input.acquired_at, "acquired_at");
    requireCanonicalTime(input.expires_at, "expires_at");
    if (Date.parse(input.expires_at) <= Date.parse(input.acquired_at)) {
      throw new AgentFleetCoordinatorError("capacity expiry must follow acquisition");
    }

    const context = await this.requireMessageContext(messageId);
    const ranking = rankCompatibleAgentFleetPeers({
      candidates: context.members,
      message: context.message,
      observed_at: input.acquired_at,
      packet: context.packet,
      sender: context.sender,
    });
    const attempts: AgentFleetCapacityAttempt[] = [];
    for (const candidate of ranking.compatible) {
      const permitLimit = input.permit_limits[candidate.member.member_id];
      if (!Number.isSafeInteger(permitLimit) || (permitLimit ?? 0) < 1) {
        throw new AgentFleetCoordinatorError(
          "every compatible member requires a positive capacity policy",
        );
      }
      const identity = reservationIdentity(
        input.reservation_key,
        context.message.message_id,
        candidate.member.member_id,
      );
      const acquired = await this.capacity.acquire({
        acquired_at: input.acquired_at,
        acquisition_key: `agent-fleet-capacity-acquisition://${identity}`,
        expires_at: input.expires_at,
        generation: candidate.member.generation,
        owner_id: candidate.member.member_id,
        permit_id: `agent-fleet-capacity-permit://${identity}`,
        permit_limit: permitLimit!,
        resource_ref: candidate.member.capacity_resource_ref,
        run_id: context.packet.child_run.run_id,
      });
      if (acquired.status === "unavailable") {
        attempts.push({
          member_id: candidate.member.member_id,
          reason: acquired.reason,
          status: "unavailable",
        });
        continue;
      }
      attempts.push({
        member_id: candidate.member.member_id,
        permit: acquired.permit,
        replayed: acquired.replayed,
        status: "acquired",
      });
      return {
        attempts,
        candidate,
        permit: acquired.permit,
        status: "reserved",
      };
    }
    return { attempts, ranking, status: "unavailable" };
  }

  /** Binds current lease, capacity, and optional checkpoint proofs. */
  async bindExecution(
    input: AgentFleetExecutionBindingInput,
  ): Promise<AgentFleetExecutionBindingV1> {
    const context = await this.requireMessageContext(input.message_id);
    const member = await this.fleet.readMember(input.member_id);
    if (member === undefined) {
      throw new AgentFleetCoordinatorError("execution member is not registered");
    }
    return createAgentFleetExecutionBinding({
      bound_at: input.bound_at,
      checkpoint: input.checkpoint,
      lease: input.lease,
      member,
      message: context.message,
      packet: context.packet,
      permit: input.permit,
    });
  }

  private async requireMessageContext(messageId: string): Promise<{
    members: Awaited<ReturnType<DurableAgentFleetPort["listMembers"]>>;
    message: AgentFleetMessageV1;
    packet: DistributedWorkPacketV1;
    sender: Awaited<ReturnType<DurableAgentFleetPort["readMember"]>> & object;
  }> {
    const message = await this.fleet.readMailboxMessage(messageId);
    if (message === undefined) {
      throw new AgentFleetCoordinatorError("mailbox message is not admitted");
    }
    const packet = await this.fleet.readPacket(message.packet_id);
    const receipt = await this.fleet.readMailboxAdmissionReceipt(messageId);
    const sender = await this.fleet.readMember(message.sender_member_id);
    if (packet === undefined || receipt === undefined || sender === undefined) {
      throw new AgentFleetCoordinatorError(
        "mailbox message is missing durable admission context",
      );
    }
    validateAgentFleetAdmissionReceipt(receipt, message, packet);
    return {
      members: await this.fleet.listMembers(),
      message,
      packet,
      sender,
    };
  }
}

export class AgentFleetCoordinatorError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AgentFleetCoordinatorError";
  }
}

function reservationIdentity(
  reservationKey: string,
  messageId: string,
  memberId: string,
): string {
  return createHash("sha256")
    .update(`${reservationKey}\u0000${messageId}\u0000${memberId}`)
    .digest("hex");
}

function requireBoundedOpaque(value: string, field: string): void {
  if (
    value.length < 1 ||
    value.length > 256 ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new AgentFleetContractError(`${field} must be a bounded opaque value`);
  }
}

function requireCanonicalTime(value: string, field: string): void {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new AgentFleetCoordinatorError(
      `${field} must be a canonical ISO-8601 timestamp`,
    );
  }
}
