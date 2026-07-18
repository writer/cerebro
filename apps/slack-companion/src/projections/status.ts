import type { AssistantTurnProgressV1 } from "../assistant-turn/contracts.js";
import { normalizeAssistantTurnProgress } from "../assistant-turn/policy.js";
import type {
  SlackVisibleStatus,
  SlackVisibleStatusCode,
} from "../operations/status.js";

export type SlackStatusProjectionKind = "assistant_progress" | "run_status";

export interface SlackStatusProjectionV1 {
  readonly code: SlackVisibleStatusCode | `assistant_${AssistantTurnProgressV1["phase"]}`;
  readonly evidence_ref?: string;
  readonly expires_at?: string;
  readonly kind: SlackStatusProjectionKind;
  readonly observed_at: string;
  readonly operation: "upsert";
  readonly projection_id: string;
  readonly run_id: string;
  readonly schema_version: "slack-status-projection/v1";
  readonly sequence?: number;
  readonly text: string;
}

export class SlackProjectionError extends Error {}

export function projectSlackVisibleStatus(
  status: SlackVisibleStatus,
): SlackStatusProjectionV1 {
  const observedAt = requiredTimestamp(status.observed_at, "status observed_at");
  const expiresAt = requiredTimestamp(status.expires_at, "status expires_at");
  if (Date.parse(expiresAt) <= Date.parse(observedAt)) {
    throw new SlackProjectionError("Slack status must expire after it was observed.");
  }
  return Object.freeze({
    code: status.code,
    ...(status.evidence_ref === undefined
      ? {}
      : { evidence_ref: requiredRef(status.evidence_ref, "status evidence_ref") }),
    expires_at: expiresAt,
    kind: "run_status",
    observed_at: observedAt,
    operation: "upsert",
    projection_id: requiredKey(status.idempotency_key, "status idempotency_key"),
    run_id: requiredKey(status.run_id, "status run_id"),
    schema_version: "slack-status-projection/v1",
    text: requiredText(status.message, "status message", 600),
  });
}

export function projectAssistantTurnProgress(
  runId: string,
  progress: AssistantTurnProgressV1,
): SlackStatusProjectionV1 {
  const normalized = normalizeAssistantTurnProgress(progress);
  const run = requiredKey(runId, "assistant progress run_id");
  return Object.freeze({
    code: `assistant_${normalized.phase}`,
    ...(normalized.capability_ref === undefined
      ? {}
      : {
          evidence_ref: requiredRef(
            normalized.capability_ref,
            "assistant progress capability_ref",
          ),
        }),
    kind: "assistant_progress",
    observed_at: normalized.occurred_at,
    operation: "upsert",
    projection_id: `${run}:assistant-progress:${normalized.sequence}`,
    run_id: run,
    schema_version: "slack-status-projection/v1",
    sequence: normalized.sequence,
    text: normalized.status,
  });
}

function requiredTimestamp(value: string, field: string): string {
  const normalized = requiredText(value, field, 64);
  if (!Number.isFinite(Date.parse(normalized))) {
    throw new SlackProjectionError(`${field} must be a timestamp.`);
  }
  return normalized;
}

function requiredRef(value: string, field: string): string {
  const normalized = requiredText(value, field, 2_048);
  if (!/^[a-z][a-z0-9+.-]*:\/\/\S+$/.test(normalized)) {
    throw new SlackProjectionError(`${field} must be an opaque reference.`);
  }
  return normalized;
}

function requiredKey(value: string, field: string): string {
  const normalized = requiredText(value, field, 512);
  if (/\s/.test(normalized)) {
    throw new SlackProjectionError(`${field} must not contain whitespace.`);
  }
  return normalized;
}

function requiredText(value: string, field: string, maximum: number): string {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > maximum
    || /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new SlackProjectionError(`${field} is invalid.`);
  }
  return value;
}
