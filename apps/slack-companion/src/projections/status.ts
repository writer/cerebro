import { createHash } from "node:crypto";
import type { AssistantTurnProgressV1 } from "../assistant-turn/contracts.js";
import { normalizeAssistantTurnProgress } from "../assistant-turn/policy.js";
import {
  SLACK_VISIBLE_STATUS_CODES,
  type SlackVisibleStatus,
  type SlackVisibleStatusCode,
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
  const code = requiredStatusCode(status.code);
  const observedAt = requiredTimestamp(status.observed_at, "status observed_at");
  const expiresAt = requiredTimestamp(status.expires_at, "status expires_at");
  if (Date.parse(expiresAt) <= Date.parse(observedAt)) {
    throw new SlackProjectionError("Slack status must expire after it was observed.");
  }
  const evidenceRef = status.evidence_ref === undefined
    ? undefined
    : requiredRef(status.evidence_ref, "status evidence_ref");
  const idempotencyKey = requiredKey(
    status.idempotency_key,
    "status idempotency_key",
  );
  const runId = requiredKey(status.run_id, "status run_id");
  const text = requiredText(status.message, "status message", 600);
  const truth = {
    code,
    ...(evidenceRef === undefined ? {} : { evidence_ref: evidenceRef }),
    expires_at: expiresAt,
    kind: "run_status" as const,
    observed_at: observedAt,
    operation: "upsert" as const,
    run_id: runId,
    schema_version: "slack-status-projection/v1" as const,
    text,
  };
  return Object.freeze({
    ...truth,
    projection_id: contentBoundProjectionId(idempotencyKey, truth),
  });
}

export function projectAssistantTurnProgress(
  runId: string,
  progress: AssistantTurnProgressV1,
): SlackStatusProjectionV1 {
  if (progress.schema_version !== "assistant-turn-progress/v1") {
    throw new SlackProjectionError(
      "Assistant progress version is unsupported.",
    );
  }
  const normalized = normalizeAssistantTurnProgress(progress);
  const run = requiredKey(runId, "assistant progress run_id");
  const observedAt = requiredTimestamp(
    normalized.occurred_at,
    "assistant progress occurred_at",
  );
  const evidenceRef = normalized.capability_ref === undefined
    ? undefined
    : requiredRef(
        normalized.capability_ref,
        "assistant progress capability_ref",
      );
  const logicalId = `${run}:assistant-progress:${normalized.sequence}`;
  const truth = {
    code: `assistant_${normalized.phase}` as const,
    ...(evidenceRef === undefined ? {} : { evidence_ref: evidenceRef }),
    kind: "assistant_progress",
    observed_at: observedAt,
    operation: "upsert",
    run_id: run,
    schema_version: "slack-status-projection/v1",
    sequence: normalized.sequence,
    text: normalized.status,
  } as const;
  return Object.freeze({
    ...truth,
    projection_id: contentBoundProjectionId(logicalId, truth),
  });
}

function contentBoundProjectionId(logicalId: string, truth: object): string {
  const digest = createHash("sha256")
    .update(JSON.stringify(truth))
    .digest("hex");
  return `${logicalId}:sha256:${digest}`;
}

function requiredStatusCode(value: unknown): SlackVisibleStatusCode {
  if (
    typeof value !== "string"
    || !SLACK_VISIBLE_STATUS_CODES.some((code) => code === value)
  ) {
    throw new SlackProjectionError("Slack status code is unsupported.");
  }
  return value as SlackVisibleStatusCode;
}

function requiredTimestamp(value: string, field: string): string {
  const normalized = requiredText(value, field, 64);
  const parsed = Date.parse(normalized);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== normalized) {
    throw new SlackProjectionError(
      `${field} must be a canonical ISO-8601 timestamp.`,
    );
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
