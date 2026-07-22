export interface CapabilityRequirement {
  capability_id: string;
  level: "optional" | "required";
  version: string;
}

export interface DeliveryPartV1 {
  delivered_at?: string;
  destination_receipt?: string;
  idempotency_key: string;
  part_id: string;
  payload_digest: string;
  payload_ref: string;
  sequence: number;
  state: "abandoned" | "delivered" | "delivering" | "failed" | "paused" | "pending";
}

export interface DeliveryReceiptV1 {
  created_at: string;
  delivery_id: string;
  destination_ref: string;
  parts: DeliveryPartV1[];
  run_id: string;
  schema_version: "delivery-receipt/v1";
  state: "abandoned" | "completed" | "delivering" | "failed" | "paused" | "pending";
  updated_at: string;
}

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

export interface EvidenceRecheckRunContextV1 {
  required_capabilities: readonly CapabilityRequirement[];
  retention_policy_ref: string;
  service_binding_id: string;
  subject_ref: string;
  tenant_id: string;
}

export interface AdmitEvidenceRecheckInputV1 {
  actor_ref: string;
  admitted_at: string;
  binding_ref: string;
  received_at: string;
  request_key: string;
  run_context: EvidenceRecheckRunContextV1;
}

export type EvidenceRecheckAuthorizationV1 =
  | {
      allowed: true;
      role: "operator" | "requester";
      schema_version: "evidence-recheck-authorization/v1";
    }
  | {
      allowed: false;
      reason_code: "actor_not_authorized" | "binding_reference_mismatch";
      schema_version: "evidence-recheck-authorization/v1";
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
  state: "completed" | "degraded" | "queued" | "running";
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

export interface RunReceiptV1 {
  admitted_at: string;
  binding_id: string;
  idempotency_key: string;
  input_digest: string;
  receipt_id: string;
  received_at: string;
  required_capabilities: CapabilityRequirement[];
  retention_policy_ref: string;
  revision: number;
  run_id: string;
  run_kind:
    | "autonomy"
    | "interactive"
    | "reconciliation"
    | "risk_attestation"
    | "scheduled"
    | "triage";
  schema_version: "run-receipt/v1";
  state:
    | "admitted"
    | "blocked"
    | "cancelled"
    | "completed"
    | "delivering"
    | "expired"
    | "leased"
    | "paused"
    | "queued"
    | "running"
    | "waiting";
  subject_ref: string;
  tenant_id: string;
  updated_at: string;
}

export interface EvidenceRecheckAdmissionReceiptV1 {
  input_digest: string;
  queue_item: EvidenceRecheckQueueItemV1;
  receipt_id: string;
  recheck: EvidenceRecheckV1;
  run: RunReceiptV1;
  schema_version: "evidence-recheck-admission-receipt/v1";
}

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
      status: "duplicate" | "queued";
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
  status: "completed" | "degraded" | "duplicate" | "in_progress" | "queued" | "rejected";
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

export interface PortableEvidenceRecheckContract {
  admitEvidenceRecheck(
    input: AdmitEvidenceRecheckInputV1,
    bindingLookup: DeliveredAnswerEvidenceBindingLookupV1,
    receiptLookup: EvidenceRecheckAdmissionReceiptLookupV1,
    store: DurableEvidenceRecheckAdmissionPort,
  ): Promise<AdmitEvidenceRecheckResultV1>;
  bindDeliveredAnswerEvidence(
    input: BindDeliveredAnswerEvidenceInputV1,
  ): DeliveredAnswerEvidenceBindingV1;
  evidenceRecheckAdmissionReceiptIdentity(recheckId: string): string;
  evidenceRecheckIdentity(bindingRef: string, requestKey: string): string;
  projectEvidenceRecheckStatus(input: EvidenceRecheckStatusInputV1): SlackEvidenceRecheckStatusV1;
  validateDeliveredAnswerEvidenceBinding(binding: DeliveredAnswerEvidenceBindingV1): void;
  validateEvidenceRecheck(recheck: EvidenceRecheckV1): void;
}

export interface AtomicDocument<T = unknown> {
  key: string;
  token: string;
  value: T;
}

export interface AtomicDocumentStore {
  compareAndSwap(key: string, token: string, value: unknown): Promise<boolean>;
  list(prefix: string, limit: number, afterKey?: string): Promise<AtomicDocument[]>;
  putIfAbsent(key: string, value: unknown): Promise<boolean>;
  read(key: string): Promise<AtomicDocument | undefined>;
}

export interface VerifiedEvidenceRecheckInvocationV1 {
  actor_ref: string;
  binding_ref: string;
  conversation_ref: string;
  payload_ref: string;
  request_key: string;
  received_at: string;
  run_context: EvidenceRecheckRunContextV1;
  schema_version: "verified-evidence-recheck-invocation/v1";
  thread_ref: string;
}

export interface VerifiedEvidenceRecheckInvocationPort {
  readVerified(payloadRef: string): Promise<VerifiedEvidenceRecheckInvocationV1>;
}

export interface EvidenceRecheckClockPort {
  now(): Date;
}

export interface EvidenceRecheckExecutionLeaseV1 {
  acquired_at: string;
  fencing_token: number;
  generation: number;
  heartbeat_at: string;
  lease_expires_at: string;
  lease_token: string;
  owner_id: string;
  run_id: string;
  schema_version: "private-evidence-recheck-execution-lease/v1";
}

export interface EvidenceRecheckCheckpointV1 {
  checkpoint_digest: string;
  checkpoint_id: string;
  created_at: string;
  fencing_token: number;
  generation: number;
  payload_ref: string;
  run_id: string;
  schema_version: "private-evidence-recheck-checkpoint/v1";
  sequence: number;
}

export interface EvidenceRecheckExecutionClaimV1 {
  generation: number;
  lease_duration_ms: number;
  observed_at: string;
  owner_id: string;
}

export interface EvidenceRecheckExecutionSessionV1 {
  binding: DeliveredAnswerEvidenceBindingV1;
  checkpoint?: EvidenceRecheckCheckpointV1;
  lease: EvidenceRecheckExecutionLeaseV1;
  receipt: EvidenceRecheckAdmissionReceiptV1;
  recheck: EvidenceRecheckV1;
}

export interface EvidenceRecheckCompletionV1 {
  completed_at: string;
  outcome_digest: string;
  outcome_ref: string;
  reason_code: string;
}

export interface EvidenceRecheckExecutorPort {
  execute(
    session: EvidenceRecheckExecutionSessionV1,
    controls: {
      checkpoint(payloadRef: string, checkpointDigest: string): Promise<EvidenceRecheckCheckpointV1>;
      renew(): Promise<EvidenceRecheckExecutionLeaseV1>;
    },
  ): Promise<EvidenceRecheckCompletionV1>;
}

export interface EvidenceRecheckOutboxLeaseV1 {
  fencing_token: number;
  generation: number;
  lease_expires_at: string;
  lease_token: string;
  mode: "inspect" | "send";
  outbox_id: string;
  owner_id: string;
  schema_version: "private-evidence-recheck-outbox-lease/v1";
}

export interface EvidenceRecheckStatusDeliveryReceiptV1 {
  accepted_at: string;
  destination_receipt: string;
  idempotency_key: string;
  outbox_id: string;
  schema_version: "private-evidence-recheck-status-delivery-receipt/v1";
}

export interface EvidenceRecheckStatusDeliveryPort {
  /** Resolves the durable destination receipt for this idempotency key. */
  inspect(idempotencyKey: string): Promise<EvidenceRecheckStatusDeliveryReceiptV1 | undefined>;
  /**
   * The destination must atomically deduplicate concurrent calls by
   * `idempotency_key` and return the same acceptance receipt.
   */
  send(input: {
    idempotency_key: string;
    outbox_id: string;
    status: SlackEvidenceRecheckStatusV1;
    thread_ref: string;
  }): Promise<EvidenceRecheckStatusDeliveryReceiptV1>;
}

export interface EvidenceRecheckRouteRegistrationPort {
  register(input: {
    action_id: string;
    generation: number;
    route_id: string;
  }): Promise<{ registration_receipt_ref: string }>;
}
