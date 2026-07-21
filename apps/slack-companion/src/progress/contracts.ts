import type { AssistantTurnProgressPhaseV1 } from "../assistant-turn/contracts.js";

export const PROGRESS_NARRATION_LIMITS = {
  detail_code_points: 280,
  ref_utf8_bytes: 2_048,
  sequence: 128,
  status_code_points: 160,
} as const;

/**
 * A single host-emitted progress observation for an in-flight assistant turn.
 * `status` is bounded operator copy and `detail` an optional richer sentence;
 * neither carries hidden model reasoning or raw tool output.
 */
export interface ProgressEventV1 {
  detail?: string;
  occurred_at: string;
  phase: AssistantTurnProgressPhaseV1;
  sequence: number;
  status: string;
}

/**
 * What the companion has already narrated for this turn. The host keeps this
 * durable so the policy can throttle, dedupe, and choose post-vs-edit without
 * re-publishing stale or redundant updates.
 */
export interface ProgressNarrationStateV1 {
  last_phase?: AssistantTurnProgressPhaseV1;
  last_published_at?: string;
  last_published_sequence?: number;
  last_status?: string;
  updates_published: number;
}

export interface ProgressNarrationRequestV1 {
  event: ProgressEventV1;
  schema_version: "progress-narration-request/v1";
  state: ProgressNarrationStateV1;
  turn_ref: string;
}

export interface ProgressNarrationPolicyV1 {
  heartbeat_seconds: number;
  max_updates: number;
  min_interval_seconds: number;
  schema_version: "progress-narration-policy/v1";
}

export interface ProgressNarrationUpdateV1 {
  detail?: string;
  method: "post" | "edit";
  narrated_at: string;
  phase: AssistantTurnProgressPhaseV1;
  schema_version: "progress-narration-update/v1";
  sequence: number;
  status: string;
  terminal: boolean;
  turn_ref: string;
  update_id: string;
}

export type ProgressNarrationSuppressionReasonV1 =
  | "superseded"
  | "update_budget_exhausted"
  | "within_min_interval"
  | "no_material_change";

export type ProgressNarrationPlanV1 =
  | {
      disposition: "publish";
      schema_version: "progress-narration-plan/v1";
      update: ProgressNarrationUpdateV1;
    }
  | {
      disposition: "suppress";
      reason_code: ProgressNarrationSuppressionReasonV1;
      schema_version: "progress-narration-plan/v1";
    };
