import type { DeliveryReceiptV1, RunReceiptV1 } from "@writer/cerebro-sdk";
import type {
  BindSlackThreadRequest,
  SlackThreadBindingV1,
} from "../thread-binding.js";

export type AssistanceStatus =
  | "requested"
  | "delivery_planned"
  | "awaiting_reply"
  | "outcome_recorded"
  | "refinement_admitted"
  | "expired"
  | "cancelled";

export interface AssistanceOutcomeV1 {
  outcome_digest: string;
  outcome_ref: string;
  recorded_at: string;
  redaction_state: "redacted";
  reply_run_id: string;
}

/**
 * Coordination metadata for one assistance request. The request references the
 * existing run, delivery, and thread lifecycles instead of duplicating them.
 */
export interface AssistanceRequestV1 {
  assistance_id: string;
  binding_id: string;
  created_at: string;
  delivery_id?: string;
  destination_ref: string;
  expires_at: string;
  idempotency_key: string;
  installation_id: string;
  intended_actor_ref: string;
  outcome?: AssistanceOutcomeV1;
  payload_digest: string;
  payload_ref: string;
  refinement_ref?: string;
  request_run_id: string;
  revision: number;
  schema_version: "assistance-request/v1";
  status: AssistanceStatus;
  subject_ref: string;
  tenant_id: string;
  thread_binding_id?: string;
  thread_binding_updated_at?: string;
  updated_at: string;
}

export interface AssistanceRequestInput {
  binding_id: string;
  destination_ref: string;
  expires_at: string;
  idempotency_key: string;
  installation_id: string;
  intended_actor_ref: string;
  max_delivery_attempts: number;
  payload_digest: string;
  payload_ref: string;
  request_run_id: string;
  subject_ref: string;
  tenant_id: string;
}

export interface AssistanceRequestCommit {
  payload_fingerprint: string;
  request: AssistanceRequestV1;
}

export interface AssistanceRequestCommitResult {
  created: boolean;
  request: AssistanceRequestV1;
}

export interface AssistanceDeliveryAttachment {
  assistance_id: string;
  delivery_id: string;
  expected_revision: number;
  updated_at: string;
}

export interface AssistanceThreadAttachment {
  assistance_id: string;
  expected_revision: number;
  thread_binding_id: string;
  thread_binding_updated_at: string;
  updated_at: string;
}

export interface NormalizedAssistanceReply {
  action_classification: "informational" | "action_like" | "unsafe";
  actor_kind: "human" | "bot" | "app";
  actor_ref: string;
  app_id: string;
  assistance_id: string;
  binding_id: string;
  conversation_id: string;
  installation_id: string;
  outcome_digest: string;
  outcome_ref: string;
  outcome_size_bytes: number;
  payload_digest: string;
  redaction_state: "redacted" | "raw";
  reply_run_id: string;
  subtype?: string;
  tenant_id: string;
  thread_id: string;
}

export interface AssistanceOutcomeCommit {
  assistance_id: string;
  expected_revision: number;
  outcome: AssistanceOutcomeV1;
  updated_at: string;
}

export interface AssistanceRefinementAdmission {
  assistance_id: string;
  idempotency_key: string;
  outcome_digest: string;
  outcome_ref: string;
  reply_run_id: string;
}

export interface AssistanceRefinementReceipt {
  created: boolean;
  refinement_ref: string;
}

export interface AssistanceRefinementAttachment {
  assistance_id: string;
  expected_revision: number;
  refinement_ref: string;
  updated_at: string;
}

export interface AssistanceRequestResult {
  delivery: DeliveryReceiptV1;
  request: AssistanceRequestV1;
}

export interface AssistanceBindingResult {
  binding: SlackThreadBindingV1;
  request: AssistanceRequestV1;
}

export interface AssistanceReplyResult {
  refinement: AssistanceRefinementReceipt;
  reply_run: RunReceiptV1;
  request: AssistanceRequestV1;
}

export interface BindAssistanceThreadInput {
  bind: BindSlackThreadRequest;
  delivered: DeliveryReceiptV1;
}
