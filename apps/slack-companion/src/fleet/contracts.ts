import type {
  CapabilityCompatibilityDecision,
  CapabilityManifestV1,
  CheckpointV1,
  SchemaCompatibility,
  ServiceAvailabilityState,
  WorkLeaseV1,
} from "@writer/cerebro-sdk";
import type { DistributedWorkPacketV1 } from "../distributed/contracts.js";
import type { CapacityPermitV1 } from "../execution/capacity.js";

export type {
  CapabilityCompatibilityDecision,
  CapabilityManifestV1,
  CapacityPermitV1,
  CheckpointV1,
  DistributedWorkPacketV1,
  SchemaCompatibility,
  WorkLeaseV1,
};

export const AGENT_FLEET_PROTOCOL_VERSION = "agent-fleet/v1" as const;
export const AGENT_FLEET_MEMBER_SCHEMA_VERSION =
  "agent-fleet-member/v1" as const;
export const AGENT_FLEET_MESSAGE_SCHEMA_VERSION =
  "agent-fleet-message/v1" as const;
export const AGENT_FLEET_ADMISSION_RECEIPT_SCHEMA_VERSION =
  "agent-fleet-admission-receipt/v1" as const;
export const AGENT_FLEET_EXECUTION_BINDING_SCHEMA_VERSION =
  "agent-fleet-execution-binding/v1" as const;

export const MAX_AGENT_FLEET_PAYLOAD_BYTES = 65_536;
export const MAX_AGENT_FLEET_MEMBERS = 1_024;

/**
 * Fleet membership projects the portable service lifecycle. `retired` is the
 * permanent terminal projection of a retired deployment generation.
 */
export type AgentFleetMemberState =
  | Extract<
      ServiceAvailabilityState,
      "ready" | "degraded" | "draining" | "offline" | "recovering"
    >
  | "retired";

/**
 * One addressable worker generation. It contains no route, credential,
 * infrastructure, or provider configuration.
 */
export interface AgentFleetMemberV1 {
  capability_manifest: CapabilityManifestV1;
  capacity_resource_ref: string;
  generation: number;
  member_id: string;
  protocol_version: typeof AGENT_FLEET_PROTOCOL_VERSION;
  registered_at: string;
  revision: number;
  schema_compatibility: SchemaCompatibility;
  schema_version: typeof AGENT_FLEET_MEMBER_SCHEMA_VERSION;
  service_id: string;
  state: AgentFleetMemberState;
  updated_at: string;
  valid_until: string;
}

/** A logical content-addressed reference to already-redacted message input. */
export interface AgentFleetPayloadReferenceV1 {
  byte_length: number;
  media_type: "application/json" | "text/plain";
  payload_digest: string;
  payload_ref: string;
  redaction_receipt_digest: string;
  redaction_receipt_ref: string;
}

/** Resume material is referenced, never copied into a mailbox message. */
export interface AgentFleetResumeReferenceV1 {
  checkpoint_digest: string;
  checkpoint_ref: string;
  handoff_digest: string;
  handoff_ref: string;
}

export interface AgentFleetMessageIdentityInput {
  created_at: string;
  idempotency_key: string;
  message_sequence: number;
  packet_id: string;
  payload: AgentFleetPayloadReferenceV1;
  protocol_version: typeof AGENT_FLEET_PROTOCOL_VERSION;
  resume?: AgentFleetResumeReferenceV1;
  run_id: string;
  sender_generation: number;
  sender_member_id: string;
}

/**
 * Immutable mailbox input tied to the canonical distributed-work packet and
 * child run. Execution state remains on RunReceiptV1 and WorkLeaseV1.
 */
export interface AgentFleetMessageV1 extends AgentFleetMessageIdentityInput {
  message_id: string;
  schema_version: typeof AGENT_FLEET_MESSAGE_SCHEMA_VERSION;
}

/** Committed proof that allows the caller to acknowledge its input transport. */
export interface AgentFleetAdmissionReceiptV1 {
  admitted_at: string;
  idempotency_key: string;
  message_id: string;
  packet_id: string;
  payload_digest: string;
  receipt_id: string;
  run_id: string;
  schema_version: typeof AGENT_FLEET_ADMISSION_RECEIPT_SCHEMA_VERSION;
}

export interface AgentFleetPeerCompatibility {
  decision: CapabilityCompatibilityDecision;
  member_id: string;
  negotiated_write_version?: string;
  reasons: string[];
}

export interface AgentFleetPeerCandidate {
  compatibility: AgentFleetPeerCompatibility;
  member: AgentFleetMemberV1;
  rank: string;
}

export interface AgentFleetPeerRejection {
  member_id: string;
  reasons: string[];
}

export interface AgentFleetPeerRanking {
  compatible: AgentFleetPeerCandidate[];
  rejected: AgentFleetPeerRejection[];
}

export type AgentFleetCapacityAttempt =
  | {
      member_id: string;
      reason: "capacity" | "cooldown" | "reconciliation_required";
      status: "unavailable";
    }
  | {
      member_id: string;
      permit: CapacityPermitV1;
      replayed: boolean;
      status: "acquired";
    };

export type AgentFleetReservationResult =
  | {
      attempts: AgentFleetCapacityAttempt[];
      candidate: AgentFleetPeerCandidate;
      permit: CapacityPermitV1;
      status: "reserved";
    }
  | {
      attempts: AgentFleetCapacityAttempt[];
      ranking: AgentFleetPeerRanking;
      status: "unavailable";
    };

/**
 * Fenced proof that a selected member may execute one mailbox message. It is a
 * binding receipt over existing lease, capacity, and checkpoint records.
 */
export interface AgentFleetExecutionBindingV1 {
  bound_at: string;
  capacity_permit_id: string;
  checkpoint_ref?: string;
  fencing_token: number;
  generation: number;
  handoff_ref?: string;
  lease_ref: string;
  member_id: string;
  message_id: string;
  run_id: string;
  schema_version: typeof AGENT_FLEET_EXECUTION_BINDING_SCHEMA_VERSION;
}
