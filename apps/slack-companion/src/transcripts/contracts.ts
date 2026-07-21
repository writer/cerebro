export interface TranscriptSourceV1 {
  readonly captured_at: string;
  readonly schema_version: "transcript-source/v1";
  readonly transcript_digest: string;
  readonly transcript_ref: string;
}

export interface TranscriptEvidenceLocationV1 {
  readonly locator: string;
  readonly transcript_ref: string;
}

export interface TranscriptActionDraftV1 {
  readonly action_id: string;
  readonly description: string;
  readonly due_at?: string;
  readonly evidence: readonly TranscriptEvidenceLocationV1[];
  readonly owner_ref?: string;
  readonly schema_version: "transcript-action-draft/v1";
  readonly state: "draft";
  readonly ticket_system: "jira" | "linear";
  readonly title: string;
}

export interface TranscriptActionApprovalV1 {
  readonly approval_id: string;
  readonly approved_action_ids: readonly string[];
  readonly approved_at: string;
  readonly approved_by_ref: string;
  /** Binds approval to the exact transcript and canonical draft set shown. */
  readonly plan_id: string;
  readonly schema_version: "transcript-action-approval/v1";
}

export interface TranscriptActionPolicyInputV1 {
  readonly approval?: TranscriptActionApprovalV1;
  readonly drafts: readonly TranscriptActionDraftV1[];
  readonly schema_version: "transcript-action-policy-input/v1";
  readonly source: TranscriptSourceV1;
}

export interface TranscriptTicketWriteIntentV1 {
  readonly action_id: string;
  readonly description: string;
  readonly due_at?: string;
  readonly evidence: readonly TranscriptEvidenceLocationV1[];
  readonly idempotency_key: string;
  readonly owner_ref?: string;
  readonly schema_version: "transcript-ticket-write-intent/v1";
  readonly ticket_system: "jira" | "linear";
  readonly title: string;
}

export type TranscriptActionPlanV1 =
  | {
      readonly action_ids: readonly string[];
      readonly disposition: "await_approval";
      readonly plan_id: string;
      readonly proposal_digest: string;
      readonly schema_version: "transcript-action-plan/v1";
    }
  | {
      readonly disposition: "write_tickets";
      readonly intents: readonly TranscriptTicketWriteIntentV1[];
      readonly plan_id: string;
      readonly approval_id: string;
      readonly schema_version: "transcript-action-plan/v1";
    };
