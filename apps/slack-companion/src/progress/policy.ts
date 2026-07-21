import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { ASSISTANT_TURN_PROGRESS_PHASES } from "../assistant-turn/contracts.js";
import type { AssistantTurnProgressPhaseV1 } from "../assistant-turn/contracts.js";
import {
  PROGRESS_NARRATION_LIMITS,
  type ProgressEventV1,
  type ProgressNarrationPlanV1,
  type ProgressNarrationPolicyV1,
  type ProgressNarrationRequestV1,
  type ProgressNarrationStateV1,
  type ProgressNarrationUpdateV1,
} from "./contracts.js";

const UNSAFE_TEXT_CONTROL_CHARACTERS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
const TERMINAL_PHASES: readonly AssistantTurnProgressPhaseV1[] = ["completed", "blocked"];

export class ProgressNarrationInvariantError extends Error {}

/**
 * Deterministically decides whether an in-flight progress event is worth
 * narrating to Slack, so long-running turns feel alive without noisy edits.
 *
 * A terminal phase always publishes (past the throttle and budget) so the final
 * state is never dropped. Otherwise an event is published only when it advances
 * the phase, changes the status text, or the heartbeat interval has elapsed —
 * subject to a minimum interval between updates and a per-turn update budget.
 * Out-of-order or already-narrated sequences are suppressed. Identities are
 * stable per `(turn_ref, sequence)` so a retry never double-posts.
 */
export function planProgressNarration(
  request: ProgressNarrationRequestV1,
  policy: ProgressNarrationPolicyV1,
  now: string,
): ProgressNarrationPlanV1 {
  validateRequest(request);
  validatePolicy(policy);
  const nowMs = Date.parse(requireTimestamp(now, "now"));

  const { event, state } = request;
  if (
    state.last_published_sequence !== undefined &&
    event.sequence <= state.last_published_sequence
  ) {
    return suppress("superseded");
  }

  const terminal = TERMINAL_PHASES.includes(event.phase);
  if (!terminal) {
    if (state.updates_published >= policy.max_updates) {
      return suppress("update_budget_exhausted");
    }
    const sinceLast =
      state.last_published_at === undefined
        ? undefined
        : nowMs - Date.parse(state.last_published_at);
    if (sinceLast !== undefined && sinceLast < policy.min_interval_seconds * 1_000) {
      return suppress("within_min_interval");
    }
    const phaseChanged = event.phase !== state.last_phase;
    const statusChanged = event.status !== state.last_status;
    const heartbeatDue = sinceLast === undefined || sinceLast >= policy.heartbeat_seconds * 1_000;
    if (!phaseChanged && !statusChanged && !heartbeatDue) {
      return suppress("no_material_change");
    }
  }

  return {
    disposition: "publish",
    schema_version: "progress-narration-plan/v1",
    update: buildUpdate(request.turn_ref, event, state, terminal, new Date(nowMs).toISOString()),
  };
}

function buildUpdate(
  turnRef: string,
  event: ProgressEventV1,
  state: ProgressNarrationStateV1,
  terminal: boolean,
  narratedAt: string,
): ProgressNarrationUpdateV1 {
  const detail = event.detail?.trim();
  return {
    ...(detail ? { detail } : {}),
    method: state.last_published_sequence === undefined ? "post" : "edit",
    narrated_at: narratedAt,
    phase: event.phase,
    schema_version: "progress-narration-update/v1",
    sequence: event.sequence,
    status: event.status,
    terminal,
    turn_ref: turnRef,
    update_id: `progress:${stableDigest([turnRef, String(event.sequence)]).slice(0, 32)}`,
  };
}

function suppress(
  reasonCode: Extract<ProgressNarrationPlanV1, { disposition: "suppress" }>["reason_code"],
): ProgressNarrationPlanV1 {
  return { disposition: "suppress", reason_code: reasonCode, schema_version: "progress-narration-plan/v1" };
}

function validateRequest(request: ProgressNarrationRequestV1): void {
  if (request.schema_version !== "progress-narration-request/v1") {
    throw new ProgressNarrationInvariantError("Unsupported progress narration request version.");
  }
  requireRef(request.turn_ref, "turn_ref");
  validateEvent(request.event);
  validateState(request.state);
}

function validateEvent(event: ProgressEventV1): void {
  requirePhase(event.phase);
  requireSequence(event.sequence, "sequence");
  requireTimestamp(event.occurred_at, "occurred_at");
  requireStatus(event.status);
  if (event.detail !== undefined) requireDetail(event.detail);
}

function validateState(state: ProgressNarrationStateV1): void {
  requireNonNegativeInteger(state.updates_published, "updates_published");
  if (state.last_phase !== undefined) requirePhase(state.last_phase);
  if (state.last_published_sequence !== undefined) {
    requireSequence(state.last_published_sequence, "last_published_sequence");
  }
  if (state.last_published_at !== undefined) requireTimestamp(state.last_published_at, "last_published_at");
  if (state.last_status !== undefined) requireStatus(state.last_status);
}

function validatePolicy(policy: ProgressNarrationPolicyV1): void {
  if (policy.schema_version !== "progress-narration-policy/v1") {
    throw new ProgressNarrationInvariantError("Unsupported progress narration policy version.");
  }
  requirePositiveInteger(policy.max_updates, "max_updates");
  requirePositiveInteger(policy.heartbeat_seconds, "heartbeat_seconds");
  requireNonNegativeInteger(policy.min_interval_seconds, "min_interval_seconds");
}

function requirePhase(value: AssistantTurnProgressPhaseV1): void {
  if (!ASSISTANT_TURN_PROGRESS_PHASES.includes(value)) {
    throw new ProgressNarrationInvariantError("Unsupported progress phase.");
  }
}

function requireSequence(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > PROGRESS_NARRATION_LIMITS.sequence) {
    throw new ProgressNarrationInvariantError(`${label} is out of bounds.`);
  }
}

function requireStatus(value: string): void {
  requireText(value, "status");
  if (
    Array.from(value).length > PROGRESS_NARRATION_LIMITS.status_code_points ||
    UNSAFE_TEXT_CONTROL_CHARACTERS.test(value)
  ) {
    throw new ProgressNarrationInvariantError("status is invalid.");
  }
}

function requireDetail(value: string): void {
  requireText(value, "detail");
  if (
    Array.from(value).length > PROGRESS_NARRATION_LIMITS.detail_code_points ||
    UNSAFE_TEXT_CONTROL_CHARACTERS.test(value)
  ) {
    throw new ProgressNarrationInvariantError("detail is invalid.");
  }
}

function requireRef(value: string, label: string): void {
  requireText(value, label);
  if (
    Buffer.byteLength(value, "utf8") > PROGRESS_NARRATION_LIMITS.ref_utf8_bytes ||
    UNSAFE_TEXT_CONTROL_CHARACTERS.test(value)
  ) {
    throw new ProgressNarrationInvariantError(`${label} is invalid.`);
  }
}

function requireText(value: string, label: string): void {
  if (typeof value !== "string" || !value.trim()) {
    throw new ProgressNarrationInvariantError(`${label} must be non-empty.`);
  }
}

function requirePositiveInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new ProgressNarrationInvariantError(`${label} must be a positive integer.`);
  }
}

function requireNonNegativeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new ProgressNarrationInvariantError(`${label} must be a non-negative integer.`);
  }
}

function requireTimestamp(value: string, label: string): string {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new ProgressNarrationInvariantError(`${label} must be an ISO timestamp.`);
  }
  return new Date(parsed).toISOString();
}

function stableDigest(parts: readonly string[]): string {
  return createHash("sha256").update(JSON.stringify(parts), "utf8").digest("hex");
}
