import type { AssistantTurnOutputStateV1 } from "../assistant-turn/contracts.js";

export const PROACTIVE_FOLLOWUP_LIMITS = {
  candidates: 32,
  grounding_refs: 16,
  history: 128,
  ref_utf8_bytes: 2_048,
  title_code_points: 160,
} as const;

/**
 * The bounded set of proactive next steps the companion may offer after a
 * delivered assistant turn. Each kind maps to an existing durable companion
 * capability, never to free-form model output.
 */
export const PROACTIVE_FOLLOWUP_KINDS = [
  "watch_answer",
  "recheck_evidence",
  "open_triage",
  "resume_work",
  "share_summary",
  "remediation",
] as const;

export type ProactiveFollowupKindV1 = (typeof PROACTIVE_FOLLOWUP_KINDS)[number];

/**
 * A host-derived, already-grounded candidate action. `action` is an opaque
 * host-owned intent token; the policy never inspects or renders it. A candidate
 * with no `grounding_refs` is treated as ungrounded and dropped, so the
 * companion only offers steps it can defend from durable evidence.
 */
export interface ProactiveFollowupCandidateV1 {
  action: string;
  action_key: string;
  grounding_refs: string[];
  kind: ProactiveFollowupKindV1;
  priority: number;
  title: string;
}

export type ProactiveFollowupOfferStateV1 =
  | "offered"
  | "accepted"
  | "dismissed"
  | "superseded"
  | "expired";

export interface ProactiveFollowupHistoryEntryV1 {
  action_key: string;
  offered_at: string;
  state: ProactiveFollowupOfferStateV1;
}

/**
 * The durable engagement footprint for one conversation thread. It lets the
 * policy stay engaged without nagging: it dedupes prior offers and enforces a
 * per-window budget and cooldown.
 */
export interface ProactiveFollowupEngagementV1 {
  history: ProactiveFollowupHistoryEntryV1[];
  last_offered_at?: string;
  offers_in_window: number;
}

export interface ProactiveFollowupRequestV1 {
  candidates: ProactiveFollowupCandidateV1[];
  conversation_ref: string;
  engagement: ProactiveFollowupEngagementV1;
  schema_version: "proactive-followup-request/v1";
  turn_ref: string;
  turn_state: AssistantTurnOutputStateV1;
}

export interface ProactiveFollowupPolicyV1 {
  allowed_kinds: ProactiveFollowupKindV1[];
  cooldown_seconds: number;
  max_offers: number;
  max_offers_per_window: number;
  schema_version: "proactive-followup-policy/v1";
  ttl_seconds: number;
}

export interface ProactiveFollowupSuggestionV1 {
  action: string;
  action_key: string;
  created_at: string;
  expires_at: string;
  grounding_refs: string[];
  idempotency_key: string;
  kind: ProactiveFollowupKindV1;
  priority: number;
  schema_version: "proactive-followup-suggestion/v1";
  suggestion_id: string;
  title: string;
  turn_ref: string;
}

export type ProactiveFollowupDropReasonV1 =
  | "kind_not_allowed"
  | "already_offered"
  | "already_accepted"
  | "ungrounded"
  | "over_offer_limit";

export interface ProactiveFollowupDropV1 {
  action_key: string;
  reason_code: ProactiveFollowupDropReasonV1;
}

export type ProactiveFollowupSuppressionReasonV1 =
  | "turn_not_offerable"
  | "within_cooldown"
  | "engagement_budget_exhausted"
  | "no_actionable_followups";

export type ProactiveFollowupPlanV1 =
  | {
      disposition: "offered";
      dropped: ProactiveFollowupDropV1[];
      schema_version: "proactive-followup-plan/v1";
      suggestions: ProactiveFollowupSuggestionV1[];
    }
  | {
      disposition: "suppressed";
      dropped: ProactiveFollowupDropV1[];
      reason_code: ProactiveFollowupSuppressionReasonV1;
      schema_version: "proactive-followup-plan/v1";
    };
