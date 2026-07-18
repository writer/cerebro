import type {
  CapabilityRequirement,
  DeliveryReceiptV1,
  RunReceiptV1,
} from "@writer/cerebro-sdk";

export const EVIDENCE_RECHECK_LIMITS = {
  delivery_parts: 256,
  evidence_artifact_ids: 32,
  operator_refs: 64,
  ref_utf8_bytes: 2_048,
  request_key_utf8_bytes: 256,
  required_capabilities: 32,
} as const;

export type EvidenceRecheckStateV1 =
  | "queued"
  | "running"
  | "completed"
  | "degraded";

export type SlackEvidenceRecheckStatusKindV1 =
  | "queued"
  | "duplicate"
  | "in_progress"
  | "completed"
  | "degraded"
  | "rejected";

/**
 * Immutable server-owned binding for evidence already attached to a fully
 * delivered answer. Interactive requests carry only `binding_ref`.
 */
export interface DeliveredAnswerEvidenceBindingV1 {
  answer_ref: string;
  answer_run_id: string;
  binding_digest: string;
  binding_ref: string;
  bound_at: string;
  conversation_ref: string;
  delivery_digest: string;
  delivery_id: string;
  evidence_artifact_ids: string[];
  operator_refs: string[];
  requester_ref: string;
  schema_version: "delivered-answer-evidence-binding/v1";
  thread_ref: string;
}

export interface BindDeliveredAnswerEvidenceInputV1 {
  answer_ref: string;
  answer_run_id: string;
  bound_at: string;
  conversation_ref: string;
  delivery: DeliveryReceiptV1;
  evidence_artifact_ids: readonly string[];
  operator_refs: readonly string[];
  requester_ref: string;
  thread_ref: string;
}

export type EvidenceRecheckAuthorizationV1 =
  | {
      allowed: true;
      role: "requester" | "operator";
      schema_version: "evidence-recheck-authorization/v1";
    }
  | {
      allowed: false;
      reason_code: "actor_not_authorized" | "binding_reference_mismatch";
      schema_version: "evidence-recheck-authorization/v1";
    };

/** Server-derived lifecycle context for the admitted reconciliation run. */
export interface EvidenceRecheckRunContextV1 {
  required_capabilities: readonly CapabilityRequirement[];
  retention_policy_ref: string;
  service_binding_id: string;
  subject_ref: string;
  tenant_id: string;
}

/**
 * Transport-neutral input. It contains no answer text, prompt, transport
 * payload, destination address, or caller-selected evidence location.
 */
export interface AdmitEvidenceRecheckInputV1 {
  actor_ref: string;
  admitted_at: string;
  binding_ref: string;
  received_at: string;
  request_key: string;
  run_context: EvidenceRecheckRunContextV1;
}

/**
 * Trusted, host-resolved lookup for the immutable binding. This receipt is a
 * policy dependency, never a field accepted from the interactive request.
 */
export type DeliveredAnswerEvidenceBindingLookupV1 =
  | {
      binding_ref: string;
      found: false;
      schema_version: "delivered-answer-evidence-binding-lookup/v1";
    }
  | {
      binding: DeliveredAnswerEvidenceBindingV1;
      found: true;
      schema_version: "delivered-answer-evidence-binding-lookup/v1";
    };

export interface EvidenceRecheckV1 {
  actor_ref: string;
  answer_ref: string;
  binding_digest: string;
  binding_ref: string;
  completed_at?: string;
  created_at: string;
  evidence_artifact_ids: string[];
  outcome_digest?: string;
  outcome_ref?: string;
  reason_code: string;
  recheck_id: string;
  request_key: string;
  revision: number;
  run_id: string;
  schema_version: "evidence-recheck/v1";
  state: EvidenceRecheckStateV1;
  thread_ref: string;
  updated_at: string;
}

export interface EvidenceRecheckQueueItemV1 {
  available_at: string;
  binding_digest: string;
  binding_ref: string;
  evidence_artifact_ids: string[];
  idempotency_key: string;
  queue_item_id: string;
  recheck_id: string;
  run_id: string;
  schema_version: "evidence-recheck-queue-item/v1";
  thread_ref: string;
}

export interface EvidenceRecheckAdmissionReceiptV1 {
  input_digest: string;
  queue_item: EvidenceRecheckQueueItemV1;
  receipt_id: string;
  recheck: EvidenceRecheckV1;
  run: RunReceiptV1;
  schema_version: "evidence-recheck-admission-receipt/v1";
}

/** The host resolves this durable receipt lookup before policy execution. */
export type EvidenceRecheckAdmissionReceiptLookupV1 =
  | {
      found: false;
      receipt_id: string;
      schema_version: "evidence-recheck-admission-receipt-lookup/v1";
    }
  | {
      found: true;
      receipt: EvidenceRecheckAdmissionReceiptV1;
      schema_version: "evidence-recheck-admission-receipt-lookup/v1";
    };

export interface EvidenceRecheckAdmissionCommitV1 {
  receipt: EvidenceRecheckAdmissionReceiptV1;
  transitions: readonly [
    { from: "received"; to: "admitted" },
    { from: "admitted"; to: "queued" },
  ];
}

export interface EvidenceRecheckAdmissionCommitResultV1 {
  created: boolean;
  receipt: EvidenceRecheckAdmissionReceiptV1;
}

/**
 * The production adapter commits the immutable receipt, recheck snapshot,
 * canonical run receipt, transitions, and queue item as one durable unit.
 */
export interface DurableEvidenceRecheckAdmissionPort {
  admitAndEnqueue(
    commit: EvidenceRecheckAdmissionCommitV1,
  ): Promise<EvidenceRecheckAdmissionCommitResultV1>;
}

export type AdmitEvidenceRecheckResultV1 =
  | {
      acknowledgement_permitted: true;
      authorization: Extract<EvidenceRecheckAuthorizationV1, { allowed: true }>;
      duplicate: boolean;
      receipt: EvidenceRecheckAdmissionReceiptV1;
      retryable: false;
      schema_version: "admit-evidence-recheck-result/v1";
      status: "queued" | "duplicate";
    }
  | {
      acknowledgement_permitted: false;
      authorization: Extract<EvidenceRecheckAuthorizationV1, { allowed: false }>;
      duplicate: false;
      reason_code: "actor_not_authorized" | "binding_reference_mismatch";
      retryable: false;
      schema_version: "admit-evidence-recheck-result/v1";
      status: "rejected";
    }
  | {
      acknowledgement_permitted: false;
      authorization: Extract<EvidenceRecheckAuthorizationV1, { allowed: true }>;
      duplicate: false;
      reason_code: "durable_admission_unavailable";
      retryable: true;
      schema_version: "admit-evidence-recheck-result/v1";
      status: "degraded";
    };

export interface SlackEvidenceRecheckStatusV1 {
  message: string;
  recheck_id?: string;
  retryable: boolean;
  schema_version: "slack-evidence-recheck-status/v1";
  status: SlackEvidenceRecheckStatusKindV1;
  terminal: boolean;
}

export type EvidenceRecheckStatusInputV1 =
  | {
      kind: "admission";
      result: AdmitEvidenceRecheckResultV1;
      schema_version: "evidence-recheck-status-input/v1";
    }
  | {
      kind: "recheck";
      recheck: EvidenceRecheckV1;
      schema_version: "evidence-recheck-status-input/v1";
    };
