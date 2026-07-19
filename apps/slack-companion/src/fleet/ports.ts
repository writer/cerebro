import type { DurableDistributedWorkPort } from "../distributed/ports.js";
import type {
  AgentFleetAdmissionReceiptV1,
  AgentFleetMemberV1,
  AgentFleetMessageV1,
  DistributedWorkPacketV1,
} from "./contracts.js";

export interface AgentFleetMemberRegistrationResult {
  created: boolean;
  member: AgentFleetMemberV1;
}

export interface AgentFleetMemberUpdateCommit {
  expected_revision: number;
  member: AgentFleetMemberV1;
}

export interface AgentFleetMailboxAdmissionCommit {
  message: AgentFleetMessageV1;
  packet: DistributedWorkPacketV1;
}

export interface AgentFleetMailboxAdmissionResult {
  created: boolean;
  message: AgentFleetMessageV1;
  packet: DistributedWorkPacketV1;
  receipt: AgentFleetAdmissionReceiptV1;
}

/**
 * Durable membership and mailbox boundary. A production implementation must
 * commit a message, packet, child run, queue entry, idempotency mapping, and
 * admission receipt atomically before returning from admitMailboxAndEnqueue.
 */
export interface DurableAgentFleetPort extends DurableDistributedWorkPort {
  registerMember(
    member: AgentFleetMemberV1,
  ): Promise<AgentFleetMemberRegistrationResult>;

  updateMember(
    commit: AgentFleetMemberUpdateCommit,
  ): Promise<AgentFleetMemberV1>;

  readMember(memberId: string): Promise<AgentFleetMemberV1 | undefined>;

  listMembers(): Promise<AgentFleetMemberV1[]>;

  admitMailboxAndEnqueue(
    commit: AgentFleetMailboxAdmissionCommit,
  ): Promise<AgentFleetMailboxAdmissionResult>;

  readMailboxMessage(
    messageId: string,
  ): Promise<AgentFleetMessageV1 | undefined>;

  readMailboxAdmissionReceipt(
    messageId: string,
  ): Promise<AgentFleetAdmissionReceiptV1 | undefined>;
}
