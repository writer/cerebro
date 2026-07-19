import type {
  ComplianceWorkCommand,
  ComplianceWorkItem,
  ComplianceWorkItemRecord,
  ComplianceWorkItemState,
  ComplianceWorkVerification,
} from "@writer/cerebro-sdk";

export type CanonicalWorkCaseState =
  | "ready_to_act"
  | "needs_evidence"
  | "verifying"
  | "blocked"
  | "waiting_on_owner"
  | "closed";

export type CanonicalWorkCaseStepState = "pending" | "completed";

export interface CanonicalWorkCaseStepV1 {
  depends_on: string[];
  step_id: string;
  state: CanonicalWorkCaseStepState;
  title: string;
}

/**
 * Portable Slack-facing projection of one canonical Cerebro work item.
 * Canonical state remains owned by Cerebro; this record owns only case
 * coordination state and opaque references needed to resume the conversation.
 */
export interface CanonicalWorkCaseV1 {
  basis: ComplianceWorkItem["basis"];
  case_id: string;
  created_at: string;
  finding_ids: string[];
  next_action?: string;
  owner_id?: string;
  revision: number;
  schema_version: "canonical-work-case/v1";
  state: CanonicalWorkCaseState;
  steps: CanonicalWorkCaseStepV1[];
  title: string;
  updated_at: string;
  verification?: ComplianceWorkVerification;
  work_item_id: string;
  work_item_state: ComplianceWorkItemState;
  work_item_updated_at: string;
  work_item_version: number;
}

export interface OpenCanonicalWorkCaseInput {
  title?: string;
  work_item_id: string;
}

export interface CanonicalWorkCaseCommit {
  case: CanonicalWorkCaseV1;
  payload_fingerprint: string;
}

export interface CanonicalWorkCaseCommitResult {
  case: CanonicalWorkCaseV1;
  created: boolean;
}

export type CanonicalWorkCommandIntentStatus =
  | "planned"
  | "executing"
  | "applied"
  | "conflicted"
  | "unknown";

export interface CanonicalWorkItemBaselineV1 {
  blocker_reason?: string;
  last_remediated_at?: string;
  last_reopen_trigger?: string;
  owner_id: string;
  snooze_until?: string;
  state: ComplianceWorkItemState;
  verification_decision_id?: string;
  verification_evidence_ids: string[];
}

/** Exact, version-fenced command proposed for operator approval. */
export interface CanonicalWorkCommandIntentV1 {
  approval_digest?: string;
  approval_ref?: string;
  approved_at?: string;
  approved_by_ref?: string;
  baseline: CanonicalWorkItemBaselineV1;
  case_id: string;
  command: ComplianceWorkCommand;
  command_digest: string;
  created_at: string;
  intent_id: string;
  reason_code?: string;
  result_digest?: string;
  result_state?: ComplianceWorkItemState;
  result_version?: number;
  revision: number;
  schema_version: "canonical-work-command-intent/v1";
  status: CanonicalWorkCommandIntentStatus;
  updated_at: string;
  work_item_id: string;
}

export interface CanonicalWorkCommandIntentCommit {
  intent: CanonicalWorkCommandIntentV1;
  payload_fingerprint: string;
}

export interface CanonicalWorkCommandIntentCommitResult {
  created: boolean;
  intent: CanonicalWorkCommandIntentV1;
}

/** Approval is portable and bound to the exact command digest. */
export interface CanonicalWorkCommandApprovalV1 {
  approval_digest: string;
  approval_ref: string;
  approved_at: string;
  approved_by_ref: string;
  command_digest: string;
  intent_id: string;
  schema_version: "canonical-work-command-approval/v1";
}

export interface CanonicalWorkCommandExecutionResult {
  case: CanonicalWorkCaseV1;
  duplicate: boolean;
  intent: CanonicalWorkCommandIntentV1;
  outcome: "applied" | "conflicted" | "in_progress" | "unknown";
  record?: ComplianceWorkItemRecord;
}

export interface CanonicalWorkCaseSync {
  case_id: string;
  expected_revision: number;
  next: CanonicalWorkCaseV1;
}

export interface CanonicalWorkIntentBegin {
  approval: CanonicalWorkCommandApprovalV1;
  expected_revision: number;
  intent_id: string;
  updated_at: string;
}

export interface CanonicalWorkIntentBeginResult {
  created: boolean;
  intent: CanonicalWorkCommandIntentV1;
}

export interface CanonicalWorkIntentFinish {
  expected_revision: number;
  intent_id: string;
  reason_code?: string;
  record?: ComplianceWorkItemRecord;
  status: "applied" | "conflicted" | "unknown";
  updated_at: string;
}
