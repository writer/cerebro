import type {
  CapabilityRequirement,
  RunKind,
  RunReceiptV1,
} from "@writer/cerebro-sdk";

export type {
  CapabilityRequirement,
  RunKind,
  RunReceiptV1,
};

export const DISTRIBUTED_WORK_PACKET_SCHEMA_VERSION =
  "distributed-work-packet/v1" as const;
export const DISTRIBUTED_WORK_RECEIPT_SCHEMA_VERSION =
  "distributed-work-receipt/v1" as const;
export const DISTRIBUTED_WORK_OBSERVATION_SCHEMA_VERSION =
  "distributed-work-observation/v1" as const;
export const DISTRIBUTED_WORK_SUMMARY_SCHEMA_VERSION =
  "distributed-work-generated-summary/v1" as const;

export const MAX_DISTRIBUTED_WORK_CAPABILITIES = 8;
export const MAX_DISTRIBUTED_WORK_DELIVERABLES = 8;
export const MAX_DISTRIBUTED_WORK_CHECKPOINT_REFS = 32;
export const MAX_DISTRIBUTED_WORK_OBSERVATIONS = 32;

/** The stable input used to identify one logical distributed work packet. */
export interface DistributedWorkPacketIdentityInput {
  causation_id?: string;
  child_run_kind: RunKind;
  correlation_id: string;
  deliverables: DistributedWorkDeliverableV1[];
  idempotency_key: string;
  objective_digest: string;
  objective_ref: string;
  parent_run_id: string;
  parent_subject_ref: string;
  required_capabilities: CapabilityRequirement[];
  retention_policy_ref: string;
  tenant_id: string;
  thread_ref: string;
  turn_ref: string;
}

/** A deliverable contains only an opaque requirement reference and digest. */
export interface DistributedWorkDeliverableV1 {
  deliverable_id: string;
  requirement_digest: string;
  requirement_ref: string;
  sequence: number;
}

/**
 * An immutable packet admission record. The child run is the canonical work
 * lifecycle; this record does not introduce another execution state machine.
 */
export interface DistributedWorkPacketV1
  extends DistributedWorkPacketIdentityInput {
  child_run: RunReceiptV1;
  created_at: string;
  intent_digest: string;
  packet_id: string;
  schema_version: typeof DISTRIBUTED_WORK_PACKET_SCHEMA_VERSION;
}

export type DistributedWorkTerminalStatus = "blocked" | "completed";
export type RuntimeToolObservationStatus = "completed" | "failed";

/**
 * An append-only runtime fact. Result and failure payloads remain outside this
 * contract and are addressed only by opaque references and digests.
 */
export interface RuntimeToolObservationV1 {
  attempt: number;
  capability_id: string;
  capability_version: string;
  completed_at: string;
  failure_digest?: string;
  failure_ref?: string;
  observation_id: string;
  result_digest?: string;
  result_ref?: string;
  schema_version: typeof DISTRIBUTED_WORK_OBSERVATION_SCHEMA_VERSION;
  sequence: number;
  started_at: string;
  status: RuntimeToolObservationStatus;
  tool_ref: string;
}

/**
 * Generated narrative is non-authoritative. It cannot supply runtime tool
 * observations or choose the terminal receipt state.
 */
export interface DistributedWorkGeneratedSummaryV1 {
  generated_at: string;
  reported_status: DistributedWorkTerminalStatus;
  schema_version: typeof DISTRIBUTED_WORK_SUMMARY_SCHEMA_VERSION;
  summary_digest: string;
  summary_ref: string;
}

/** A terminal, fenced receipt for one admitted distributed work packet. */
export interface DistributedWorkReceiptV1 {
  checkpoint_refs: string[];
  completed_observation_count: number;
  failed_observation_count: number;
  generated_summary?: DistributedWorkGeneratedSummaryV1;
  lease_ref: string;
  outcome_digest: string;
  outcome_ref: string;
  packet_id: string;
  parent_run_id: string;
  receipt_id: string;
  recorded_at: string;
  run_id: string;
  runtime_observations: RuntimeToolObservationV1[];
  schema_version: typeof DISTRIBUTED_WORK_RECEIPT_SCHEMA_VERSION;
  status: DistributedWorkTerminalStatus;
}

export interface DistributedWorkReceiptDraft {
  checkpoint_refs: string[];
  generated_summary?: DistributedWorkGeneratedSummaryV1;
  lease_ref: string;
  outcome_digest: string;
  outcome_ref: string;
  packet: DistributedWorkPacketV1;
  recorded_at: string;
  runtime_observations: RuntimeToolObservationV1[];
  runtime_status: DistributedWorkTerminalStatus;
}
