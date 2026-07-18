import type { ScheduledOccurrenceV1 } from "@writer/cerebro-sdk";
import type {
  ScheduledLeaseClaim,
  ScheduledLeaseDecision,
} from "../operations/schedules.js";

export type AnswerWatchStateV1 =
  | "queued"
  | "active"
  | "degraded"
  | "completed"
  | "closed"
  | "failed"
  | "cancelled"
  | "retired";

export type AnswerWatchObservationStatusV1 =
  | "pending"
  | "satisfied"
  | "closed"
  | "unavailable"
  | "failed";

/**
 * A server-resolved target bound to evidence recorded with the delivered
 * answer. Interactive payloads carry only `binding_ref`; they do not define or
 * replace the target.
 */
export interface AnswerWatchTargetBindingV1 {
  answer_ref: string;
  authority: "read";
  binding_digest: string;
  binding_ref: string;
  evidence_ref: string;
  resolved_at: string;
  schema_version: "answer-watch-target-binding/v1";
  target_kind: string;
  target_ref: string;
  target_version: string;
}

export interface AnswerWatchTargetCandidateV1 {
  authority: "read";
  target_kind: string;
  target_ref: string;
  target_version: string;
}

export interface AnswerWatchAuthorityV1 {
  answer_ref: string;
  operator_refs: string[];
  requester_ref: string;
  schema_version: "answer-watch-authority/v1";
}

export type AnswerWatchAuthorizationV1 =
  | {
      allowed: true;
      role: "requester" | "operator";
      schema_version: "answer-watch-authorization/v1";
    }
  | {
      allowed: false;
      reason_code: "actor_not_authorized" | "answer_binding_mismatch";
      schema_version: "answer-watch-authorization/v1";
    };

export interface AnswerWatchV1 {
  answer_ref: string;
  authority: "read";
  binding_digest: string;
  binding_ref: string;
  conversation_ref: string;
  created_at: string;
  last_material_digest?: string;
  last_observation_digest?: string;
  last_observation_id?: string;
  last_target_version?: string;
  last_update?: AnswerWatchUpdateV1;
  request_key: string;
  revision: number;
  schedule_ref: string;
  schema_version: "answer-watch/v1";
  state: AnswerWatchStateV1;
  state_sequence: number;
  target_kind: string;
  target_ref: string;
  target_version: string;
  updated_at: string;
  watch_id: string;
}

export interface StartAnswerWatchInputV1 {
  actor_ref: string;
  authority: AnswerWatchAuthorityV1;
  binding: AnswerWatchTargetBindingV1;
  conversation_ref: string;
  created_at: string;
  prior_watch?: AnswerWatchV1;
  request_key: string;
  schedule_ref: string;
}

export type StartAnswerWatchResultV1 =
  | {
      authorization: Extract<AnswerWatchAuthorizationV1, { allowed: false }>;
      disposition: "denied";
      schema_version: "start-answer-watch-result/v1";
    }
  | {
      authorization: Extract<AnswerWatchAuthorizationV1, { allowed: true }>;
      created: boolean;
      disposition: "started";
      schema_version: "start-answer-watch-result/v1";
      watch: AnswerWatchV1;
    };

/**
 * Portable projection of a canonical scheduled occurrence. The host keeps the
 * referenced scheduled-occurrence and its lease/fencing data authoritative.
 */
export interface AnswerWatchOccurrenceV1 {
  observation_ref?: string;
  occurrence: ScheduledOccurrenceV1;
  schema_version: "answer-watch-occurrence/v1";
  watch_id: string;
}

export type AnswerWatchOccurrenceClaimV1 =
  | Exclude<ScheduledLeaseDecision, { acquired: true }>
  | {
      acquired: true;
      claim: ScheduledLeaseClaim;
      created: boolean;
      occurrence: AnswerWatchOccurrenceV1;
    };

export interface AnswerWatchCheckCountsV1 {
  failed: number;
  passed: number;
  pending: number;
}

/** Structured equality input for material-change decisions. */
export interface AnswerWatchMaterialStateV1 {
  checks: AnswerWatchCheckCountsV1;
  draft: boolean;
  head_ref: string;
  merge_state: string;
  schema_version: "answer-watch-material-state/v1";
  terminal_state: "open" | "satisfied" | "closed_without_satisfaction" | "failed";
}

export interface AnswerWatchObservationV1 {
  material_digest: string;
  material_state: AnswerWatchMaterialStateV1;
  observation_digest: string;
  observation_id: string;
  observed_at: string;
  occurrence_id: string;
  reason_code: string;
  schema_version: "answer-watch-observation/v1";
  status: AnswerWatchObservationStatusV1;
  summary: string;
  target_ref: string;
  target_version: string;
  watch_id: string;
}

export interface AnswerWatchUpdateV1 {
  event_id: string;
  from_state: AnswerWatchStateV1;
  idempotency_key: string;
  material_change: boolean;
  observation_ref: string;
  occurred_at: string;
  publish: boolean;
  reason_code: string;
  schema_version: "answer-watch-update/v1";
  sequence: number;
  summary: string;
  terminal: boolean;
  to_state: AnswerWatchStateV1;
  watch_id: string;
}

export interface ApplyAnswerWatchObservationResultV1 {
  occurrence: AnswerWatchOccurrenceV1;
  replayed: boolean;
  schema_version: "apply-answer-watch-observation-result/v1";
  update: AnswerWatchUpdateV1;
  watch: AnswerWatchV1;
}

export interface SlackAnswerWatchStatusV1 {
  schema_version: "slack-answer-watch-status/v1";
  should_publish: boolean;
  state:
    | "queued"
    | "watching"
    | "degraded"
    | "completed"
    | "closed"
    | "failed"
    | "stopped";
  terminal: boolean;
  text: string;
  watch_id: string;
}
