import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import {
  REENGAGEMENT_KINDS,
  REENGAGEMENT_LIMITS,
  type ReengagementCandidateV1,
  type ReengagementDropV1,
  type ReengagementEngagementV1,
  type ReengagementHistoryEntryV1,
  type ReengagementKindV1,
  type ReengagementNudgeV1,
  type ReengagementPlanV1,
  type ReengagementPolicyV1,
  type ReengagementRequestV1,
} from "./contracts.js";

const ITEM_KEY = /^[a-z0-9][a-z0-9._:-]{0,127}$/;
const UNSAFE_TEXT_CONTROL_CHARACTERS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;

export class ReengagementInvariantError extends Error {}

/**
 * Deterministically decides whether, and on which quiet work items, to
 * re-engage so the companion does not drop the ball on open watches or cases.
 *
 * An item is eligible only when it is still open, has been idle at least the
 * policy's staleness window, and has not been nudged within the per-item
 * cooldown. Eligible items are ordered by priority then staleness, capped by a
 * per-run limit and a per-window engagement budget, and carry stable idempotent
 * identities keyed to the observed state so a retry never double-nudges while a
 * genuinely advanced item earns a fresh nudge.
 */
export function planReengagement(
  request: ReengagementRequestV1,
  policy: ReengagementPolicyV1,
  now: string,
): ReengagementPlanV1 {
  validateRequest(request);
  validatePolicy(policy);
  const normalizedNow = requireTimestamp(now, "now");
  const nowMs = Date.parse(normalizedNow);

  const remainingBudget = policy.max_nudges_per_window - request.engagement.nudges_in_window;
  if (remainingBudget <= 0) {
    return suppressed("engagement_budget_exhausted");
  }

  const lastNudgedByKey = new Map<string, number>();
  for (const entry of request.engagement.history) {
    const at = Date.parse(entry.nudged_at);
    const existing = lastNudgedByKey.get(entry.item_key);
    if (existing === undefined || at > existing) {
      lastNudgedByKey.set(entry.item_key, at);
    }
  }

  const dropped: ReengagementDropV1[] = [];
  const eligible: { candidate: ReengagementCandidateV1; idleSeconds: number }[] = [];
  for (const candidate of request.candidates) {
    if (!policy.allowed_kinds.includes(candidate.kind)) {
      dropped.push({ item_key: candidate.item_key, reason_code: "kind_not_allowed" });
      continue;
    }
    if (!candidate.is_open) {
      dropped.push({ item_key: candidate.item_key, reason_code: "not_open" });
      continue;
    }
    const idleSeconds = Math.floor((nowMs - Date.parse(candidate.last_activity_at)) / 1_000);
    if (idleSeconds < policy.staleness_seconds) {
      dropped.push({ item_key: candidate.item_key, reason_code: "not_stale" });
      continue;
    }
    const lastNudged = lastNudgedByKey.get(candidate.item_key);
    if (lastNudged !== undefined && nowMs - lastNudged < policy.cooldown_seconds * 1_000) {
      dropped.push({ item_key: candidate.item_key, reason_code: "within_cooldown" });
      continue;
    }
    eligible.push({ candidate, idleSeconds });
  }

  eligible.sort(compareEligible);
  const nudgeLimit = Math.min(policy.max_nudges, remainingBudget);
  const selected = eligible.slice(0, nudgeLimit);
  for (const { candidate } of eligible.slice(nudgeLimit)) {
    dropped.push({ item_key: candidate.item_key, reason_code: "over_nudge_limit" });
  }

  if (selected.length === 0) {
    return suppressed("no_stale_work", dropped);
  }

  const expiresAt = new Date(nowMs + policy.ttl_seconds * 1_000).toISOString();
  const nudges = selected.map(({ candidate, idleSeconds }) =>
    buildNudge(candidate, idleSeconds, normalizedNow, expiresAt),
  );
  return { disposition: "nudge", dropped, nudges, schema_version: "reengagement-plan/v1" };
}

function buildNudge(
  candidate: ReengagementCandidateV1,
  idleSeconds: number,
  createdAt: string,
  expiresAt: string,
): ReengagementNudgeV1 {
  const identity = stableDigest([
    candidate.item_ref,
    candidate.item_key,
    candidate.last_activity_at,
  ]);
  return {
    created_at: createdAt,
    expires_at: expiresAt,
    grounding_ref: candidate.grounding_ref,
    idempotency_key: identity,
    idle_seconds: idleSeconds,
    item_key: candidate.item_key,
    item_ref: candidate.item_ref,
    kind: candidate.kind,
    nudge_id: `reengagement:${identity.slice(0, 32)}`,
    priority: candidate.priority,
    schema_version: "reengagement-nudge/v1",
    summary: candidate.summary,
  };
}

function compareEligible(
  a: { candidate: ReengagementCandidateV1; idleSeconds: number },
  b: { candidate: ReengagementCandidateV1; idleSeconds: number },
): number {
  if (a.candidate.priority !== b.candidate.priority) {
    return b.candidate.priority - a.candidate.priority;
  }
  if (a.idleSeconds !== b.idleSeconds) return b.idleSeconds - a.idleSeconds;
  return a.candidate.item_key.localeCompare(b.candidate.item_key);
}

function suppressed(
  reasonCode: Extract<ReengagementPlanV1, { disposition: "suppressed" }>["reason_code"],
  dropped: ReengagementDropV1[] = [],
): ReengagementPlanV1 {
  return {
    disposition: "suppressed",
    dropped,
    reason_code: reasonCode,
    schema_version: "reengagement-plan/v1",
  };
}

function validateRequest(request: ReengagementRequestV1): void {
  if (request.schema_version !== "reengagement-request/v1") {
    throw new ReengagementInvariantError("Unsupported reengagement request version.");
  }
  requireRef(request.conversation_ref, "conversation_ref");
  if (request.candidates.length > REENGAGEMENT_LIMITS.candidates) {
    throw new ReengagementInvariantError("Too many reengagement candidates.");
  }
  const itemKeys = new Set<string>();
  for (const candidate of request.candidates) {
    validateCandidate(candidate);
    if (itemKeys.has(candidate.item_key)) {
      throw new ReengagementInvariantError("Candidate item keys must be unique.");
    }
    itemKeys.add(candidate.item_key);
  }
  validateEngagement(request.engagement);
}

function validateCandidate(candidate: ReengagementCandidateV1): void {
  requireItemKey(candidate.item_key);
  requireRef(candidate.item_ref, "item_ref");
  requireRef(candidate.grounding_ref, "grounding_ref");
  requireKind(candidate.kind);
  requireSummary(candidate.summary);
  requirePriority(candidate.priority);
  requireBoolean(candidate.is_open, "is_open");
  requireTimestamp(candidate.last_activity_at, "last_activity_at");
}

function validateEngagement(engagement: ReengagementEngagementV1): void {
  requireNonNegativeInteger(engagement.nudges_in_window, "nudges_in_window");
  if (engagement.history.length > REENGAGEMENT_LIMITS.history) {
    throw new ReengagementInvariantError("Engagement history is too long.");
  }
  for (const entry of engagement.history) {
    validateHistoryEntry(entry);
  }
}

function validateHistoryEntry(entry: ReengagementHistoryEntryV1): void {
  requireItemKey(entry.item_key);
  requireTimestamp(entry.nudged_at, "nudged_at");
}

function validatePolicy(policy: ReengagementPolicyV1): void {
  if (policy.schema_version !== "reengagement-policy/v1") {
    throw new ReengagementInvariantError("Unsupported reengagement policy version.");
  }
  requirePositiveInteger(policy.max_nudges, "max_nudges");
  requirePositiveInteger(policy.max_nudges_per_window, "max_nudges_per_window");
  requirePositiveInteger(policy.ttl_seconds, "ttl_seconds");
  requirePositiveInteger(policy.staleness_seconds, "staleness_seconds");
  requireNonNegativeInteger(policy.cooldown_seconds, "cooldown_seconds");
  if (policy.allowed_kinds.length === 0) {
    throw new ReengagementInvariantError("A policy must allow at least one reengagement kind.");
  }
  const kinds = new Set<ReengagementKindV1>();
  for (const kind of policy.allowed_kinds) {
    requireKind(kind);
    if (kinds.has(kind)) {
      throw new ReengagementInvariantError("allowed_kinds must be unique.");
    }
    kinds.add(kind);
  }
}

function requireKind(value: ReengagementKindV1): void {
  if (!REENGAGEMENT_KINDS.includes(value)) {
    throw new ReengagementInvariantError("Unsupported reengagement kind.");
  }
}

function requireItemKey(value: string): void {
  if (typeof value !== "string" || !ITEM_KEY.test(value)) {
    throw new ReengagementInvariantError("item_key must be a stable lowercase token.");
  }
}

function requireSummary(value: string): void {
  requireText(value, "summary");
  if (
    Array.from(value).length > REENGAGEMENT_LIMITS.summary_code_points ||
    UNSAFE_TEXT_CONTROL_CHARACTERS.test(value)
  ) {
    throw new ReengagementInvariantError("summary is invalid.");
  }
}

function requireRef(value: string, label: string): void {
  requireText(value, label);
  if (
    Buffer.byteLength(value, "utf8") > REENGAGEMENT_LIMITS.ref_utf8_bytes ||
    UNSAFE_TEXT_CONTROL_CHARACTERS.test(value)
  ) {
    throw new ReengagementInvariantError(`${label} is invalid.`);
  }
}

function requireText(value: string, label: string): void {
  if (typeof value !== "string" || !value.trim()) {
    throw new ReengagementInvariantError(`${label} must be non-empty.`);
  }
}

function requireBoolean(value: boolean, label: string): void {
  if (typeof value !== "boolean") {
    throw new ReengagementInvariantError(`${label} must be boolean.`);
  }
}

function requirePriority(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > 100) {
    throw new ReengagementInvariantError("priority must be an integer between 0 and 100.");
  }
}

function requirePositiveInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new ReengagementInvariantError(`${label} must be a positive integer.`);
  }
}

function requireNonNegativeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new ReengagementInvariantError(`${label} must be a non-negative integer.`);
  }
}

function requireTimestamp(value: string, label: string): string {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new ReengagementInvariantError(`${label} must be an ISO timestamp.`);
  }
  return new Date(parsed).toISOString();
}

function stableDigest(parts: readonly string[]): string {
  return createHash("sha256").update(JSON.stringify(parts), "utf8").digest("hex");
}
