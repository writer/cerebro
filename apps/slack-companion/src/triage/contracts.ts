export type AlertTriageStateV1 =
  | "received"
  | "investigating"
  | "awaiting_evidence"
  | "ready_for_decision"
  | "decided"
  | "suggestion_planned"
  | "published"
  | "suppressed"
  | "needs_reverification"
  | "closed";

export type AlertTriageClassificationV1 =
  | "actionable"
  | "needs_context"
  | "non_actionable";

export type AlertTriageSeverityV1 =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "informational";

export type TriageEvidenceStatusV1 =
  | "current"
  | "expired"
  | "needs_reverification"
  | "contradicted"
  | "inaccessible";

export type TriageSuggestionKindV1 =
  | "follow_up"
  | "monitor"
  | "remediation";

export type TriageSuggestionStateV1 =
  | "planned"
  | "queued"
  | "published"
  | "accepted"
  | "dismissed"
  | "expired"
  | "superseded"
  | "suppressed";

export interface AlertTriageCaseV1 {
  active_suggestion_ref?: string;
  idempotency_key: string;
  latest_decision_ref?: string;
  received_at: string;
  schema_version: "alert-triage-case/v1";
  source_event_ref: string;
  state: AlertTriageStateV1;
  state_sequence: number;
  thread_ref: string;
  triage_id: string;
  updated_at: string;
}

export interface AlertTriageTransitionV1 {
  event_id: string;
  from_state: AlertTriageStateV1;
  idempotency_key: string;
  occurred_at: string;
  reason_code: string;
  schema_version: "alert-triage-transition/v1";
  sequence: number;
  to_state: AlertTriageStateV1;
  triage_id: string;
}

export interface TriageEvidenceReceiptV1 {
  access: "allowed" | "restricted";
  evidence_digest: string;
  evidence_id: string;
  observed_at: string;
  reason_code?: string;
  receipt_ref: string;
  schema_version: "triage-evidence-receipt/v1";
  source_capability: string;
  state_sequence: number;
  status: TriageEvidenceStatusV1;
  subject_ref: string;
  updated_at: string;
  valid_until?: string;
  version: number;
}

export interface TriageEvidenceReplacementV1 {
  evidence_digest: string;
  observed_at: string;
  valid_until?: string;
  version: number;
}

export interface AlertTriageDecisionV1 {
  classification: AlertTriageClassificationV1;
  confidence: number;
  decided_at: string;
  decision_id: string;
  evidence_receipt_refs: string[];
  recommended_actions: string[];
  schema_version: "alert-triage-decision/v1";
  severity: AlertTriageSeverityV1;
  summary: string;
  triage_id: string;
}

export type TriageEvidenceGateReasonV1 =
  | "evidence_expired"
  | "evidence_inaccessible"
  | "evidence_missing"
  | "evidence_not_current"
  | "evidence_observed_in_future";

export interface TriageEvidenceGateV1 {
  current_evidence_receipt_refs: string[];
  passed: boolean;
  reason_codes: TriageEvidenceGateReasonV1[];
  schema_version: "triage-evidence-gate/v1";
}

export interface TriageSuggestionPolicyV1 {
  allowed_kinds: TriageSuggestionKindV1[];
  minimum_confidence: number;
  schema_version: "triage-suggestion-policy/v1";
  ttl_seconds: number;
}

export interface TriageSuggestionRequestV1 {
  action: string;
  action_key: string;
  kind: TriageSuggestionKindV1;
  title: string;
}

export interface TriageSuggestionV1 {
  action: string;
  created_at: string;
  decision_id: string;
  evidence_receipt_refs: string[];
  expires_at: string;
  idempotency_key: string;
  kind: TriageSuggestionKindV1;
  schema_version: "triage-suggestion/v1";
  state: TriageSuggestionStateV1;
  state_sequence: number;
  suggestion_id: string;
  title: string;
  triage_id: string;
  updated_at: string;
}

export type TriageSuggestionSuppressionReasonV1 =
  | "case_not_decided"
  | "classification_not_actionable"
  | "confidence_below_threshold"
  | "decision_mismatch"
  | "evidence_gate_failed"
  | "suggestion_kind_not_allowed";

export type TriageSuggestionPlanV1 =
  | {
      disposition: "planned";
      schema_version: "triage-suggestion-plan/v1";
      suggestion: TriageSuggestionV1;
    }
  | {
      disposition: "suppressed";
      evidence_reason_codes: TriageEvidenceGateReasonV1[];
      reason_code: TriageSuggestionSuppressionReasonV1;
      schema_version: "triage-suggestion-plan/v1";
    };
