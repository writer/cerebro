import type { WorkLeaseV1 } from "../execution/model.js";

export const QUESTION_WORK_LIMITS = {
  max_attempts: 20,
  max_preflight_refs: 32,
  max_result_bytes: 1_048_576,
  max_steps: 128,
} as const;

export type QuestionWorkKind = "attestation" | "question";
export type QuestionWorkState =
  | "queued"
  | "waiting"
  | "running"
  | "retryable"
  | "completed"
  | "incomplete"
  | "failed";
export type QuestionWorkTerminalState = "completed" | "incomplete" | "failed";

/** Input contains opaque references and digests, never raw Slack content. */
export interface QuestionWorkAdmissionInput {
  binding_id: string;
  idempotency_key: string;
  installation_id: string;
  request_digest: string;
  request_ref: string;
  request_run_id: string;
  subject_ref: string;
  tenant_id: string;
  thread_ref: string;
  work_kind: QuestionWorkKind;
}

export interface QuestionWorkPreflightV1 {
  max_attempts: number;
  max_result_bytes: number;
  max_steps: number;
  receipt_digest: string;
  receipt_ref: string;
  request_digest: string;
  required_capability_refs: string[];
  required_input_refs: string[];
  schema_version: "question-work-preflight/v1";
  state: "ready" | "waiting" | "rejected";
}

export interface QuestionWorkV1 {
  active_lease?: WorkLeaseV1;
  active_task_idempotency_key?: string;
  active_task_revision?: number;
  attempts: number;
  binding_id: string;
  created_at: string;
  idempotency_key: string;
  installation_id: string;
  latest_progress_sequence: number;
  max_attempts: number;
  max_result_bytes: number;
  max_steps: number;
  preflight_receipt_ref: string;
  request_digest: string;
  request_ref: string;
  request_run_id: string;
  revision: number;
  schema_version: "question-work/v1";
  state: QuestionWorkState;
  subject_ref: string;
  tenant_id: string;
  thread_ref: string;
  updated_at: string;
  work_id: string;
  work_kind: QuestionWorkKind;
}

export interface QuestionWorkTaskV1 {
  available_at: string;
  idempotency_key: string;
  request_run_id: string;
  schema_version: "question-work-task/v1";
  thread_ref: string;
  work_id: string;
  work_revision: number;
}

export interface QuestionWorkAdmissionCommit {
  payload_fingerprint: string;
  preflight: QuestionWorkPreflightV1;
  task?: QuestionWorkTaskV1;
  work: QuestionWorkV1;
}

export interface QuestionWorkAdmissionCommitResult {
  created: boolean;
  preflight: QuestionWorkPreflightV1;
  task?: QuestionWorkTaskV1;
  work: QuestionWorkV1;
}

export interface QuestionWorkAcknowledgement {
  acknowledgement_permitted: true;
  continuation_permitted: boolean;
  duplicate: boolean;
  state: QuestionWorkState;
  work_id: string;
}

export interface QuestionWorkRunnableCommit {
  expected_revision: number;
  preflight: QuestionWorkPreflightV1;
  task: QuestionWorkTaskV1;
  updated_at: string;
  work_id: string;
}

export interface QuestionWorkRunnableResult {
  created: boolean;
  task: QuestionWorkTaskV1;
  work: QuestionWorkV1;
}

export interface QuestionWorkClaim {
  claimed_at: string;
  lease: WorkLeaseV1;
  task: QuestionWorkTaskV1;
}

export interface QuestionWorkClaimResult {
  created: boolean;
  latest_progress?: QuestionWorkProgressV1;
  status: "started" | "resumed";
  work: QuestionWorkV1;
}

export interface QuestionWorkProgressInput {
  completed_step_ids: string[];
  expected_revision: number;
  lease: WorkLeaseV1;
  progress_digest: string;
  progress_ref: string;
  resume_cursor: string;
  sequence: number;
  work_id: string;
}

export interface QuestionWorkProgressV1 {
  completed_step_ids: string[];
  fencing_token: number;
  generation: number;
  lease_token: string;
  owner_id: string;
  progress_digest: string;
  progress_ref: string;
  recorded_at: string;
  resume_cursor: string;
  schema_version: "question-work-progress/v1";
  sequence: number;
  work_id: string;
}

export interface QuestionWorkProgressResult {
  created: boolean;
  progress: QuestionWorkProgressV1;
  work: QuestionWorkV1;
}

export interface QuestionWorkRetryInput {
  available_at: string;
  expected_revision: number;
  failure_receipt_digest: string;
  failure_receipt_ref: string;
  lease: WorkLeaseV1;
  reason_code: string;
  work_id: string;
}

export interface QuestionWorkRetryReceiptV1 {
  available_at: string;
  failure_receipt_digest: string;
  failure_receipt_ref: string;
  fencing_token: number;
  generation: number;
  lease_token: string;
  owner_id: string;
  reason_code: string;
  recorded_at: string;
  schema_version: "question-work-retry-receipt/v1";
  work_id: string;
}

export interface QuestionWorkRetryResult {
  created: boolean;
  receipt: QuestionWorkRetryReceiptV1;
  task: QuestionWorkTaskV1;
  work: QuestionWorkV1;
}

export interface QuestionWorkOutcomeInput {
  expected_revision: number;
  lease: WorkLeaseV1;
  outcome: QuestionWorkTerminalState;
  reason_code: string;
  receipt_digest: string;
  receipt_ref: string;
  result_bytes?: number;
  result_digest?: string;
  result_kind?: "answer" | "attestation";
  result_ref?: string;
  work_id: string;
}

export interface QuestionWorkOutcomeReceiptV1 {
  fencing_token: number;
  generation: number;
  lease_token: string;
  owner_id: string;
  outcome: QuestionWorkTerminalState;
  reason_code: string;
  receipt_digest: string;
  receipt_ref: string;
  recorded_at: string;
  result_bytes?: number;
  result_digest?: string;
  result_kind?: "answer" | "attestation";
  result_ref?: string;
  schema_version: "question-work-outcome-receipt/v1";
  work_id: string;
}

export interface QuestionWorkOutcomeResult {
  created: boolean;
  outcome: QuestionWorkOutcomeReceiptV1;
  work: QuestionWorkV1;
}
