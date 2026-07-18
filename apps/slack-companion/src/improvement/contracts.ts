import type {
  EffectReceiptV1,
  ExecutionSession,
  WorkLeaseV1,
} from "../execution/model.js";
import type {
  AssistantTurnEvaluationV1,
  AssistantTurnPromotionDecisionV1,
} from "../assistant-turn/evaluation.js";

export const IMPROVEMENT_EVIDENCE_KINDS = [
  "ci",
  "eval",
  "shadow",
  "canary",
  "promotion",
] as const;

export type ImprovementEvidenceKind =
  (typeof IMPROVEMENT_EVIDENCE_KINDS)[number];

export const IMPROVEMENT_INDEPENDENT_EVIDENCE_KINDS = ["ci", "canary"] as const;

export type ImprovementIndependentEvidenceKind =
  (typeof IMPROVEMENT_INDEPENDENT_EVIDENCE_KINDS)[number];

export type ImprovementCandidateStatus =
  | "open"
  | "authoring"
  | "awaiting_evidence"
  | "ready"
  | "closed";

/** Candidate metadata contains only opaque references, digests, and fences. */
export interface ImprovementCandidateV1 {
  active_execution_generation?: number;
  active_fencing_token?: number;
  author_generation: number;
  author_result_digest?: string;
  author_result_ref?: string;
  authoring_prior_head_digest?: string;
  base_digest: string;
  branch_ref: string;
  candidate_id: string;
  candidate_key_digest: string;
  created_at: string;
  draft_ref: string;
  effect_receipt_ref?: string;
  evidence_invalidation_digest?: string;
  evidence_invalidation_ref?: string;
  fresh_evidence_digest?: string;
  fresh_evidence_ref?: string;
  head_digest: string;
  revision: number;
  schema_version: "improvement-candidate/v1";
  status: ImprovementCandidateStatus;
  updated_at: string;
  verification_receipt_ref?: string;
}

export interface ImprovementCandidateInput {
  base_digest: string;
  branch_ref: string;
  candidate_key_digest: string;
  draft_ref: string;
  head_digest: string;
}

export interface ImprovementCandidateCommit {
  candidate: ImprovementCandidateV1;
  payload_fingerprint: string;
}

export interface ImprovementCandidateCommitResult {
  candidate: ImprovementCandidateV1;
  created: boolean;
}

export interface ImprovementAuthorReservation {
  candidate_id: string;
  expected_author_generation: number;
  expected_base_digest: string;
  expected_branch_ref: string;
  expected_draft_ref: string;
  expected_head_digest: string;
  expected_revision: number;
  lease: WorkLeaseV1;
  reserved_at: string;
}

export interface ImprovementAuthorReservationResult {
  candidate: ImprovementCandidateV1;
  created: boolean;
}

export interface ImprovementAuthoringRequest {
  approval_ref: string;
  candidate_id: string;
  checkpoint_sequence: number;
  expected_author_generation: number;
  expected_base_digest: string;
  expected_branch_ref: string;
  expected_draft_ref: string;
  expected_head_digest: string;
  expected_revision: number;
  rollback_plan_ref: string;
  session: ExecutionSession;
}

export interface ImprovementAuthoringIntent {
  author_generation: number;
  base_digest: string;
  branch_ref: string;
  candidate_id: string;
  candidate_version: string;
  draft_ref: string;
  prior_head_digest: string;
  required_evidence: readonly ImprovementEvidenceKind[];
}

export interface ImprovementDraftSnapshot {
  base_digest: string;
  branch_ref: string;
  draft_ref: string;
  head_digest: string;
  state: "open" | "closed";
}

export interface ImprovementAuthorResult {
  base_digest: string;
  branch_ref: string;
  candidate_version: string;
  draft_ref: string;
  new_head_digest: string;
  prior_head_digest: string;
  result_digest: string;
  result_ref: string;
}

export type ImprovementAuthorInspection =
  | { state: "absent" }
  | {
      candidate_version: string;
      resume_token: string;
      state: "prepared" | "materialized";
    }
  | { result: ImprovementAuthorResult; state: "applied" }
  | {
      reason_code: string;
      state: "ambiguous" | "boundary_mismatch" | "target_moved";
    };

export interface ImprovementAuthorVerification {
  candidate_version: string;
  receipt_ref: string;
  state: "failed" | "verified";
}

export interface ImprovementEvidenceIdentityV1 {
  readonly author_generation: number;
  readonly candidate_id: string;
  readonly kind: ImprovementEvidenceKind;
}

export interface ImprovementEvidenceStateV1 extends ImprovementEvidenceIdentityV1 {
  evidence_digest?: string;
  evidence_ref?: string;
  head_digest?: string;
  schema_version: "improvement-evidence-state/v1";
  state: "invalidated" | "fresh";
  updated_at: string;
}

export interface ImprovementEvidenceSnapshot {
  author_generation: number;
  bundle_digest: string;
  bundle_ref: string;
  candidate_id: string;
  states: ImprovementEvidenceStateV1[];
}

export interface ImprovementEvidenceInvalidationRequest {
  author_generation: number;
  candidate_id: string;
  candidate_version: string;
  kinds: readonly ImprovementEvidenceKind[];
  prior_head_digest: string;
}

export interface ImprovementEvidenceInvalidationReceipt {
  author_generation: number;
  candidate_id: string;
  invalidation_digest: string;
  invalidation_ref: string;
}

export interface ImprovementEvidenceRecord extends ImprovementEvidenceIdentityV1 {
  readonly evidence_digest: string;
  readonly evidence_ref: string;
  readonly expected_revision: number;
  readonly head_digest: string;
}

export interface ImprovementFreshEvidenceInput extends Omit<
  ImprovementEvidenceRecord,
  "kind"
> {
  readonly kind: ImprovementIndependentEvidenceKind;
}

export interface ImprovementOutcomeEvaluationSetV1 {
  /** Rows are sealed by the evaluator receipt; a caller-supplied head label is not authoritative. */
  readonly evaluations: readonly AssistantTurnEvaluationV1[];
  readonly receipt: ImprovementOutcomeEvaluationSetReceiptV1;
}

export interface ImprovementOutcomeEvaluationSetReceiptV1 {
  /** Exact source head used to produce every ordered evaluation row. */
  readonly evaluated_head_digest: string;
  readonly evaluator_ref: string;
  readonly ordered_row_digests: readonly string[];
  readonly receipt_digest: string;
  readonly schema_version: "improvement-outcome-evaluation-set-receipt/v1";
}

export interface ImprovementOutcomeEvidenceInput {
  author_generation: number;
  baseline: ImprovementOutcomeEvaluationSetV1;
  candidate: ImprovementOutcomeEvaluationSetV1;
  candidate_id: string;
  expected_revision: number;
  head_digest: string;
  held_out_evidence_ref: string;
  promotion_evidence_ref: string;
  shadow_evidence_ref: string;
}

export interface ImprovementOutcomeEvidenceOutcome {
  candidate: ImprovementCandidateV1;
  decision: AssistantTurnPromotionDecisionV1;
}

export interface ImprovementAuthorCompletion {
  author_generation: number;
  author_result_digest: string;
  author_result_ref: string;
  candidate_id: string;
  effect_receipt_ref: string;
  evidence_invalidation_digest: string;
  evidence_invalidation_ref: string;
  expected_prior_head_digest: string;
  expected_revision: number;
  lease: WorkLeaseV1;
  new_head_digest: string;
  updated_at: string;
  verification_receipt_ref: string;
}

export interface ImprovementEvidenceCompletion {
  author_generation: number;
  candidate_id: string;
  expected_revision: number;
  fresh_evidence_digest: string;
  fresh_evidence_ref: string;
  head_digest: string;
  updated_at: string;
}

export interface ImprovementAuthoringOutcome {
  candidate: ImprovementCandidateV1;
  effect: EffectReceiptV1;
  result: ImprovementAuthorResult;
}
