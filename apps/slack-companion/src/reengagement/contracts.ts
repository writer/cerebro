export const REENGAGEMENT_LIMITS = {
  candidates: 32,
  history: 128,
  ref_utf8_bytes: 2_048,
  summary_code_points: 280,
} as const;

export const REENGAGEMENT_KINDS = ["answer_watch", "canonical_case"] as const;

export type ReengagementKindV1 = (typeof REENGAGEMENT_KINDS)[number];

/**
 * A host-derived open work item that may have gone quiet. The host owns which
 * items are still open and their last material-progress timestamp; the policy
 * decides only whether a quiet item is stale enough, and un-nudged recently
 * enough, to be worth re-engaging on.
 */
export interface ReengagementCandidateV1 {
  grounding_ref: string;
  is_open: boolean;
  item_key: string;
  item_ref: string;
  kind: ReengagementKindV1;
  last_activity_at: string;
  priority: number;
  summary: string;
}

export interface ReengagementHistoryEntryV1 {
  item_key: string;
  nudged_at: string;
}

/**
 * The durable re-engagement footprint for one conversation thread. History
 * dedupes per item and enforces a per-item cooldown; `nudges_in_window` bounds
 * how often the companion re-engages overall.
 */
export interface ReengagementEngagementV1 {
  history: ReengagementHistoryEntryV1[];
  nudges_in_window: number;
}

export interface ReengagementRequestV1 {
  candidates: ReengagementCandidateV1[];
  conversation_ref: string;
  engagement: ReengagementEngagementV1;
  schema_version: "reengagement-request/v1";
}

export interface ReengagementPolicyV1 {
  allowed_kinds: ReengagementKindV1[];
  cooldown_seconds: number;
  max_nudges: number;
  max_nudges_per_window: number;
  schema_version: "reengagement-policy/v1";
  staleness_seconds: number;
  ttl_seconds: number;
}

export interface ReengagementNudgeV1 {
  created_at: string;
  expires_at: string;
  grounding_ref: string;
  idempotency_key: string;
  idle_seconds: number;
  item_key: string;
  item_ref: string;
  kind: ReengagementKindV1;
  nudge_id: string;
  priority: number;
  schema_version: "reengagement-nudge/v1";
  summary: string;
}

export type ReengagementDropReasonV1 =
  | "kind_not_allowed"
  | "not_open"
  | "not_stale"
  | "within_cooldown"
  | "over_nudge_limit";

export interface ReengagementDropV1 {
  item_key: string;
  reason_code: ReengagementDropReasonV1;
}

export type ReengagementSuppressionReasonV1 =
  | "engagement_budget_exhausted"
  | "no_stale_work";

export type ReengagementPlanV1 =
  | {
      disposition: "nudge";
      dropped: ReengagementDropV1[];
      nudges: ReengagementNudgeV1[];
      schema_version: "reengagement-plan/v1";
    }
  | {
      disposition: "suppressed";
      dropped: ReengagementDropV1[];
      reason_code: ReengagementSuppressionReasonV1;
      schema_version: "reengagement-plan/v1";
    };
