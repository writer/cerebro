import type {
  CapabilityRequirement,
  WorkLeaseV1,
} from "@writer/cerebro-sdk";
import type {
  DistributedWorkDeliverableV1,
  DistributedWorkPacketV1,
} from "./contracts.js";

export const DISTRIBUTED_WORK_DELEGATION_SCHEMA_VERSION =
  "distributed-work-delegation/v1" as const;
export const SIGNED_DISTRIBUTED_WORK_DELEGATION_SCHEMA_VERSION =
  "signed-distributed-work-delegation/v1" as const;
export const DISTRIBUTED_WORK_DELEGATION_CANONICALIZATION =
  "sorted-json/v1" as const;

export const MAX_DELEGATION_TOOL_REFS = 16;
export const MAX_DELEGATION_LIFETIME_MS = 60 * 60 * 1_000;

/**
 * The immutable authority and execution scope used to identify one logical
 * delegation. Validity timestamps are signed, but intentionally excluded from
 * this identity so an idempotent issuance retry addresses the same authority.
 */
export interface DistributedWorkDelegationIdentityInput {
  allowed_capabilities: CapabilityRequirement[];
  allowed_deliverables: DistributedWorkDeliverableV1[];
  allowed_tool_refs: string[];
  child_run_id: string;
  fencing_token: number;
  generation: number;
  idempotency_key: string;
  issuer_ref: string;
  lease_ref: string;
  packet_id: string;
  parent_run_id: string;
  revocation_ref: string;
  subject_ref: string;
  tenant_id: string;
  work_intent_digest: string;
}

/** A signed, bounded delegation for one admitted distributed-work packet. */
export interface DistributedWorkDelegationManifestV1
  extends DistributedWorkDelegationIdentityInput {
  delegation_id: string;
  delegation_intent_digest: string;
  expires_at: string;
  issued_at: string;
  not_before: string;
  schema_version: typeof DISTRIBUTED_WORK_DELEGATION_SCHEMA_VERSION;
}

export interface DistributedWorkDelegationManifestDraft {
  allowed_capabilities: CapabilityRequirement[];
  allowed_deliverables: DistributedWorkDeliverableV1[];
  allowed_tool_refs: string[];
  expires_at: string;
  issued_at: string;
  issuer_ref: string;
  lease: WorkLeaseV1;
  not_before: string;
  packet: DistributedWorkPacketV1;
  revocation_ref: string;
}

/**
 * The signature suite and key are opaque contract values. Environment-specific
 * adapters choose the signing implementation and key lifecycle.
 */
export interface DistributedWorkDelegationSignatureV1 {
  key_ref: string;
  signature_suite: string;
  signature_value: string;
}

export interface SignedDistributedWorkDelegationV1 {
  canonicalization: typeof DISTRIBUTED_WORK_DELEGATION_CANONICALIZATION;
  manifest: DistributedWorkDelegationManifestV1;
  manifest_digest: string;
  schema_version: typeof SIGNED_DISTRIBUTED_WORK_DELEGATION_SCHEMA_VERSION;
  signature: DistributedWorkDelegationSignatureV1;
}

/** The exact authority a worker is asking to exercise for this attempt. */
export interface DistributedWorkDelegationUse {
  lease: WorkLeaseV1;
  now: string;
  packet: DistributedWorkPacketV1;
  requested_capabilities: CapabilityRequirement[];
  requested_deliverable_ids: string[];
  requested_tool_refs: string[];
}
