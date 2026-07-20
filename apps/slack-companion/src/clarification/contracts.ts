export const CLARIFICATION_LIMITS = {
  candidates: 16,
  history: 64,
  question_code_points: 600,
  ref_utf8_bytes: 2_048,
} as const;

export const CLARIFICATION_AMBIGUITY_KINDS = [
  "missing_subject",
  "ambiguous_scope",
  "missing_parameter",
  "conflicting_request",
  "unsupported_capability",
] as const;

export type ClarificationAmbiguityKindV1 =
  (typeof CLARIFICATION_AMBIGUITY_KINDS)[number];

export const CLARIFICATION_IMPACTS = ["low", "medium", "high"] as const;

export type ClarificationImpactV1 = (typeof CLARIFICATION_IMPACTS)[number];

/**
 * A host-derived clarifying question the companion could ask before answering.
 *
 * `answer_blocking` marks whether proceeding without the missing information
 * would likely produce a wrong or misbound answer, and `has_safe_default`
 * marks whether a safe default assumption exists. Together with `impact` these
 * let the policy ask only when a question is genuinely worth the interruption,
 * avoiding the `unnecessary_clarification` and `user_correction` failure modes.
 */
export interface ClarificationCandidateV1 {
  ambiguity_kind: ClarificationAmbiguityKindV1;
  answer_blocking: boolean;
  has_safe_default: boolean;
  impact: ClarificationImpactV1;
  question: string;
  question_key: string;
}

export interface ClarificationHistoryEntryV1 {
  asked_at: string;
  question_key: string;
}

/**
 * The durable clarification footprint for one conversation thread. It bounds
 * back-and-forth: the policy dedupes questions already asked and enforces a
 * per-thread question budget.
 */
export interface ClarificationEngagementV1 {
  history: ClarificationHistoryEntryV1[];
  questions_in_thread: number;
}

export interface ClarificationRequestV1 {
  candidates: ClarificationCandidateV1[];
  conversation_ref: string;
  engagement: ClarificationEngagementV1;
  schema_version: "clarification-request/v1";
  turn_ref: string;
}

export interface ClarificationPolicyV1 {
  max_questions_per_thread: number;
  min_impact_to_ask: ClarificationImpactV1;
  schema_version: "clarification-policy/v1";
}

export interface ClarificationQuestionV1 {
  ambiguity_kind: ClarificationAmbiguityKindV1;
  impact: ClarificationImpactV1;
  question: string;
  question_id: string;
  question_key: string;
  turn_ref: string;
}

export type ClarificationDeferralReasonV1 =
  | "not_blocking"
  | "safe_default_available"
  | "already_asked"
  | "not_selected";

export interface ClarificationDeferralV1 {
  question_key: string;
  reason_code: ClarificationDeferralReasonV1;
}

export type ClarificationProceedReasonV1 =
  | "no_actionable_question"
  | "clarification_budget_exhausted";

export type ClarificationPlanV1 =
  | {
      deferred: ClarificationDeferralV1[];
      disposition: "ask";
      question: ClarificationQuestionV1;
      schema_version: "clarification-plan/v1";
    }
  | {
      deferred: ClarificationDeferralV1[];
      disposition: "proceed";
      reason_code: ClarificationProceedReasonV1;
      schema_version: "clarification-plan/v1";
    };
