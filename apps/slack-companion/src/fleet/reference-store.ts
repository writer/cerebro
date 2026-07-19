import type {
  DistributedWorkAdmissionCommit,
  DistributedWorkAdmissionResult,
  DistributedWorkReceiptCommit,
  DistributedWorkReceiptCommitResult,
} from "../distributed/ports.js";
import { ReferenceMemoryDistributedWorkStore } from "../distributed/reference-store.js";
import type { DistributedWorkReceiptV1 } from "../distributed/contracts.js";
import type {
  AgentFleetAdmissionReceiptV1,
  AgentFleetMemberV1,
  AgentFleetMessageV1,
  DistributedWorkPacketV1,
} from "./contracts.js";
import type {
  AgentFleetMailboxAdmissionCommit,
  AgentFleetMailboxAdmissionResult,
  AgentFleetMemberRegistrationResult,
  AgentFleetMemberUpdateCommit,
  DurableAgentFleetPort,
} from "./ports.js";
import {
  AgentFleetContractError,
  createAgentFleetAdmissionReceipt,
  validateAgentFleetAdmissionReceipt,
  validateAgentFleetMember,
  validateAgentFleetMemberUpdate,
  validateAgentFleetMessageForPacket,
  validateAgentFleetSender,
} from "./validation.js";

/**
 * In-memory conformance fixture. Production adapters must implement the same
 * atomic boundaries with durable storage; this class is not a runtime fallback.
 */
export class ReferenceMemoryAgentFleetStore implements DurableAgentFleetPort {
  readonly distributedWork = new ReferenceMemoryDistributedWorkStore();

  private readonly admissionReceipts = new Map<
    string,
    AgentFleetAdmissionReceiptV1
  >();
  private readonly memberById = new Map<string, AgentFleetMemberV1>();
  private readonly messageIdByIdempotencyKey = new Map<string, string>();
  private readonly messageIdByPacketSequence = new Map<string, string>();
  private readonly messages = new Map<string, AgentFleetMessageV1>();

  registerMember(
    member: AgentFleetMemberV1,
  ): Promise<AgentFleetMemberRegistrationResult> {
    validateAgentFleetMember(member);
    const prior = this.memberById.get(member.member_id);
    if (prior !== undefined) {
      if (!sameValue(prior, member)) {
        return Promise.reject(
          new AgentFleetStoreConflictError(
            "member identity already belongs to another generation record",
          ),
        );
      }
      return Promise.resolve({
        created: false,
        member: structuredClone(prior),
      });
    }
    const stored = structuredClone(member);
    this.memberById.set(stored.member_id, stored);
    return Promise.resolve({ created: true, member: structuredClone(stored) });
  }

  updateMember(commit: AgentFleetMemberUpdateCommit): Promise<AgentFleetMemberV1> {
    const current = this.memberById.get(commit.member.member_id);
    if (current === undefined) {
      return Promise.reject(
        new AgentFleetStoreConflictError("fleet member does not exist"),
      );
    }
    if (current.revision !== commit.expected_revision) {
      return Promise.reject(new StaleAgentFleetMemberError());
    }
    validateAgentFleetMemberUpdate(current, commit.member);
    const stored = structuredClone(commit.member);
    this.memberById.set(stored.member_id, stored);
    return Promise.resolve(structuredClone(stored));
  }

  readMember(memberId: string): Promise<AgentFleetMemberV1 | undefined> {
    const member = this.memberById.get(memberId);
    return Promise.resolve(
      member === undefined ? undefined : structuredClone(member),
    );
  }

  listMembers(): Promise<AgentFleetMemberV1[]> {
    return Promise.resolve(
      [...this.memberById.values()]
        .sort((left, right) => left.member_id.localeCompare(right.member_id))
        .map((member) => structuredClone(member)),
    );
  }

  async admitMailboxAndEnqueue(
    commit: AgentFleetMailboxAdmissionCommit,
  ): Promise<AgentFleetMailboxAdmissionResult> {
    validateAgentFleetMessageForPacket(commit.message, commit.packet);
    const sender = this.memberById.get(commit.message.sender_member_id);
    if (sender === undefined) {
      throw new AgentFleetStoreConflictError(
        "mailbox message sender is not registered",
      );
    }
    validateAgentFleetSender(commit.message, sender, commit.message.created_at);

    const priorMessageId = this.messageIdByIdempotencyKey.get(
      commit.message.idempotency_key,
    );
    if (priorMessageId !== undefined) {
      return this.replayAdmission(priorMessageId, commit);
    }
    const sequenceKey = packetSequenceKey(commit.message);
    const sequenceOwner = this.messageIdByPacketSequence.get(sequenceKey);
    if (
      sequenceOwner !== undefined ||
      this.messages.has(commit.message.message_id)
    ) {
      throw new AgentFleetStoreConflictError(
        "mailbox message identity or packet sequence already belongs to another input",
      );
    }

    const admitted = await this.distributedWork.admitAndEnqueue({
      packet: commit.packet,
    });
    if (!sameValue(admitted.packet, commit.packet)) {
      throw new AgentFleetStoreConflictError(
        "distributed admission returned a different packet",
      );
    }
    const message = structuredClone(commit.message);
    const receipt = createAgentFleetAdmissionReceipt(message, admitted.packet);

    // These mutations model one atomic mailbox, packet, run, queue, and receipt
    // commit. No caller acknowledgement is permitted before this method returns.
    this.messages.set(message.message_id, message);
    this.admissionReceipts.set(message.message_id, receipt);
    this.messageIdByIdempotencyKey.set(
      message.idempotency_key,
      message.message_id,
    );
    this.messageIdByPacketSequence.set(sequenceKey, message.message_id);
    return {
      created: true,
      message: structuredClone(message),
      packet: structuredClone(admitted.packet),
      receipt: structuredClone(receipt),
    };
  }

  readMailboxMessage(
    messageId: string,
  ): Promise<AgentFleetMessageV1 | undefined> {
    const message = this.messages.get(messageId);
    return Promise.resolve(
      message === undefined ? undefined : structuredClone(message),
    );
  }

  readMailboxAdmissionReceipt(
    messageId: string,
  ): Promise<AgentFleetAdmissionReceiptV1 | undefined> {
    const receipt = this.admissionReceipts.get(messageId);
    return Promise.resolve(
      receipt === undefined ? undefined : structuredClone(receipt),
    );
  }

  admitAndEnqueue(
    commit: DistributedWorkAdmissionCommit,
  ): Promise<DistributedWorkAdmissionResult> {
    return this.distributedWork.admitAndEnqueue(commit);
  }

  readPacket(packetId: string): Promise<DistributedWorkPacketV1 | undefined> {
    return this.distributedWork.readPacket(packetId);
  }

  readReceipt(
    packetId: string,
  ): Promise<DistributedWorkReceiptV1 | undefined> {
    return this.distributedWork.readReceipt(packetId);
  }

  commitReceipt(
    commit: DistributedWorkReceiptCommit,
  ): Promise<DistributedWorkReceiptCommitResult> {
    return this.distributedWork.commitReceipt(commit);
  }

  private async replayAdmission(
    priorMessageId: string,
    commit: AgentFleetMailboxAdmissionCommit,
  ): Promise<AgentFleetMailboxAdmissionResult> {
    const prior = this.requireMessage(priorMessageId);
    const receipt = this.requireAdmissionReceipt(priorMessageId);
    const packet = await this.distributedWork.readPacket(prior.packet_id);
    if (
      packet === undefined ||
      !sameValue(prior, commit.message) ||
      !sameValue(packet, commit.packet)
    ) {
      throw new AgentFleetIdempotencyConflictError();
    }
    validateAgentFleetAdmissionReceipt(receipt, prior, packet);
    return {
      created: false,
      message: structuredClone(prior),
      packet: structuredClone(packet),
      receipt: structuredClone(receipt),
    };
  }

  private requireMessage(messageId: string): AgentFleetMessageV1 {
    const message = this.messages.get(messageId);
    if (message === undefined) {
      throw new AgentFleetContractError("mailbox message does not exist");
    }
    return message;
  }

  private requireAdmissionReceipt(
    messageId: string,
  ): AgentFleetAdmissionReceiptV1 {
    const receipt = this.admissionReceipts.get(messageId);
    if (receipt === undefined) {
      throw new AgentFleetContractError(
        "mailbox admission receipt does not exist",
      );
    }
    return receipt;
  }
}

export class AgentFleetStoreConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AgentFleetStoreConflictError";
  }
}

export class AgentFleetIdempotencyConflictError extends Error {
  constructor() {
    super("fleet mailbox idempotency key belongs to different input");
    this.name = "AgentFleetIdempotencyConflictError";
  }
}

export class StaleAgentFleetMemberError extends Error {
  constructor() {
    super("fleet member revision is stale");
    this.name = "StaleAgentFleetMemberError";
  }
}

function packetSequenceKey(message: AgentFleetMessageV1): string {
  return `${message.packet_id}\u0000${message.message_sequence}`;
}

function sameValue(left: unknown, right: unknown): boolean {
  return stableStringify(left) === stableStringify(right);
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${stableStringify(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}
