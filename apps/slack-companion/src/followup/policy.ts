import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { ASSISTANT_TURN_OUTPUT_STATES } from "../assistant-turn/contracts.js";
import type { AssistantTurnOutputStateV1 } from "../assistant-turn/contracts.js";
import {
  PROACTIVE_FOLLOWUP_KINDS,
  PROACTIVE_FOLLOWUP_LIMITS,
  type ProactiveFollowupCandidateV1,
  type ProactiveFollowupDropV1,
  type ProactiveFollowupEngagementV1,
  type ProactiveFollowupHistoryEntryV1,
  type ProactiveFollowupKindV1,
  type ProactiveFollowupOfferStateV1,
  type ProactiveFollowupPlanV1,
  type ProactiveFollowupPolicyV1,
  type ProactiveFollowupRequestV1,
  type ProactiveFollowupSuggestionV1,
} from "./contracts.js";

const ACTION_KEY = /^[a-z0-9][a-z0-9._:-]{0,127}$/;
const UNSAFE_TEXT_CONTROL_CHARACTERS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
const OFFER_STATES: readonly ProactiveFollowupOfferStateV1[] = [
  "offered",
  "accepted",
  "dismissed",
  "superseded",
  "expired",
];
const OFFERABLE_TURN_STATES: readonly AssistantTurnOutputStateV1[] = ["answered", "partial"];

export class ProactiveFollowupInvariantError extends Error {}

/**
 * Deterministically decides whether, and what, to proactively offer after a
 * delivered assistant turn.
 *
 * The policy stays engaged without nagging. It only offers when the turn is
 * answerable, dedupes actions already offered or accepted in the thread, drops
 * ungrounded or disallowed candidates, and enforces a cooldown plus a
 * per-window engagement budget. The result is bounded, deduped, and
 * deterministically ordered, with stable idempotent identities so retries never
 * double-offer.
 */
export function planProactiveFollowup(
  request: ProactiveFollowupRequestV1,
  policy: ProactiveFollowupPolicyV1,
  now: string,
): ProactiveFollowupPlanV1 {
  validateRequest(request);
  validatePolicy(policy);
  const normalizedNow = requireTimestamp(now, "now");

  if (!OFFERABLE_TURN_STATES.includes(request.turn_state)) {
    return suppressed("turn_not_offerable");
  }

  const { last_offered_at: lastOfferedAt, offers_in_window: offersInWindow } = request.engagement;
  if (
    lastOfferedAt !== undefined &&
    Date.parse(normalizedNow) - Date.parse(lastOfferedAt) < policy.cooldown_seconds * 1_000
  ) {
    return suppressed("within_cooldown");
  }

  const remainingBudget = policy.max_offers_per_window - offersInWindow;
  if (remainingBudget <= 0) {
    return suppressed("engagement_budget_exhausted");
  }

  const acceptedKeys = new Set<string>();
  const offeredKeys = new Set<string>();
  for (const entry of request.engagement.history) {
    if (entry.state === "accepted") {
      acceptedKeys.add(entry.action_key);
    } else if (entry.state !== "expired") {
      offeredKeys.add(entry.action_key);
    }
  }

  const dropped: ProactiveFollowupDropV1[] = [];
  const eligible: ProactiveFollowupCandidateV1[] = [];
  for (const candidate of request.candidates) {
    if (!policy.allowed_kinds.includes(candidate.kind)) {
      dropped.push({ action_key: candidate.action_key, reason_code: "kind_not_allowed" });
      continue;
    }
    if (candidate.grounding_refs.length === 0) {
      dropped.push({ action_key: candidate.action_key, reason_code: "ungrounded" });
      continue;
    }
    if (acceptedKeys.has(candidate.action_key)) {
      dropped.push({ action_key: candidate.action_key, reason_code: "already_accepted" });
      continue;
    }
    if (offeredKeys.has(candidate.action_key)) {
      dropped.push({ action_key: candidate.action_key, reason_code: "already_offered" });
      continue;
    }
    eligible.push(candidate);
  }

  eligible.sort(compareCandidates);
  const offerLimit = Math.min(policy.max_offers, remainingBudget);
  const selected = eligible.slice(0, offerLimit);
  for (const candidate of eligible.slice(offerLimit)) {
    dropped.push({ action_key: candidate.action_key, reason_code: "over_offer_limit" });
  }

  if (selected.length === 0) {
    return suppressed("no_actionable_followups", dropped);
  }

  const expiresAt = new Date(Date.parse(normalizedNow) + policy.ttl_seconds * 1_000).toISOString();
  const suggestions = selected.map((candidate) =>
    buildSuggestion(request, candidate, normalizedNow, expiresAt),
  );
  return {
    disposition: "offered",
    dropped,
    schema_version: "proactive-followup-plan/v1",
    suggestions,
  };
}

function buildSuggestion(
  request: ProactiveFollowupRequestV1,
  candidate: ProactiveFollowupCandidateV1,
  createdAt: string,
  expiresAt: string,
): ProactiveFollowupSuggestionV1 {
  const suggestionId = `proactive-followup:${stableDigest([
    request.conversation_ref,
    request.turn_ref,
    candidate.action_key,
  ]).slice(0, 32)}`;
  return {
    action: candidate.action,
    action_key: candidate.action_key,
    created_at: createdAt,
    expires_at: expiresAt,
    grounding_refs: [...candidate.grounding_refs],
    idempotency_key: suggestionId,
    kind: candidate.kind,
    priority: candidate.priority,
    schema_version: "proactive-followup-suggestion/v1",
    suggestion_id: suggestionId,
    title: candidate.title,
    turn_ref: request.turn_ref,
  };
}

function compareCandidates(
  a: ProactiveFollowupCandidateV1,
  b: ProactiveFollowupCandidateV1,
): number {
  if (a.priority !== b.priority) return b.priority - a.priority;
  const byTitle = a.title.localeCompare(b.title);
  if (byTitle !== 0) return byTitle;
  return a.action_key.localeCompare(b.action_key);
}

function suppressed(
  reasonCode: Extract<
    ProactiveFollowupPlanV1,
    { disposition: "suppressed" }
  >["reason_code"],
  dropped: ProactiveFollowupDropV1[] = [],
): ProactiveFollowupPlanV1 {
  return {
    disposition: "suppressed",
    dropped,
    reason_code: reasonCode,
    schema_version: "proactive-followup-plan/v1",
  };
}

function validateRequest(request: ProactiveFollowupRequestV1): void {
  if (request.schema_version !== "proactive-followup-request/v1") {
    throw new ProactiveFollowupInvariantError("Unsupported proactive follow-up request version.");
  }
  requireRef(request.conversation_ref, "conversation_ref");
  requireRef(request.turn_ref, "turn_ref");
  if (!ASSISTANT_TURN_OUTPUT_STATES.includes(request.turn_state)) {
    throw new ProactiveFollowupInvariantError("Unsupported assistant turn state.");
  }
  if (request.candidates.length > PROACTIVE_FOLLOWUP_LIMITS.candidates) {
    throw new ProactiveFollowupInvariantError("Too many proactive follow-up candidates.");
  }
  const actionKeys = new Set<string>();
  for (const candidate of request.candidates) {
    validateCandidate(candidate);
    if (actionKeys.has(candidate.action_key)) {
      throw new ProactiveFollowupInvariantError("Candidate action keys must be unique.");
    }
    actionKeys.add(candidate.action_key);
  }
  validateEngagement(request.engagement);
}

function validateCandidate(candidate: ProactiveFollowupCandidateV1): void {
  requireActionKey(candidate.action_key);
  requireText(candidate.action, "action");
  requireTitle(candidate.title);
  requireKind(candidate.kind);
  requirePriority(candidate.priority);
  if (candidate.grounding_refs.length > PROACTIVE_FOLLOWUP_LIMITS.grounding_refs) {
    throw new ProactiveFollowupInvariantError("Too many grounding refs on a candidate.");
  }
  const refs = new Set<string>();
  for (const ref of candidate.grounding_refs) {
    requireRef(ref, "grounding_ref");
    if (refs.has(ref)) {
      throw new ProactiveFollowupInvariantError("Grounding refs must be unique.");
    }
    refs.add(ref);
  }
}

function validateEngagement(engagement: ProactiveFollowupEngagementV1): void {
  requireNonNegativeInteger(engagement.offers_in_window, "offers_in_window");
  if (engagement.last_offered_at !== undefined) {
    requireTimestamp(engagement.last_offered_at, "last_offered_at");
  }
  if (engagement.history.length > PROACTIVE_FOLLOWUP_LIMITS.history) {
    throw new ProactiveFollowupInvariantError("Engagement history is too long.");
  }
  for (const entry of engagement.history) {
    validateHistoryEntry(entry);
  }
}

function validateHistoryEntry(entry: ProactiveFollowupHistoryEntryV1): void {
  requireActionKey(entry.action_key);
  requireTimestamp(entry.offered_at, "offered_at");
  if (!OFFER_STATES.includes(entry.state)) {
    throw new ProactiveFollowupInvariantError("Unsupported proactive follow-up offer state.");
  }
}

function validatePolicy(policy: ProactiveFollowupPolicyV1): void {
  if (policy.schema_version !== "proactive-followup-policy/v1") {
    throw new ProactiveFollowupInvariantError("Unsupported proactive follow-up policy version.");
  }
  requirePositiveInteger(policy.max_offers, "max_offers");
  requirePositiveInteger(policy.max_offers_per_window, "max_offers_per_window");
  requirePositiveInteger(policy.ttl_seconds, "ttl_seconds");
  requireNonNegativeInteger(policy.cooldown_seconds, "cooldown_seconds");
  if (policy.allowed_kinds.length === 0) {
    throw new ProactiveFollowupInvariantError("A policy must allow at least one follow-up kind.");
  }
  const kinds = new Set<ProactiveFollowupKindV1>();
  for (const kind of policy.allowed_kinds) {
    requireKind(kind);
    if (kinds.has(kind)) {
      throw new ProactiveFollowupInvariantError("allowed_kinds must be unique.");
    }
    kinds.add(kind);
  }
}

function requireKind(value: ProactiveFollowupKindV1): void {
  if (!PROACTIVE_FOLLOWUP_KINDS.includes(value)) {
    throw new ProactiveFollowupInvariantError("Unsupported proactive follow-up kind.");
  }
}

function requireActionKey(value: string): void {
  if (typeof value !== "string" || !ACTION_KEY.test(value)) {
    throw new ProactiveFollowupInvariantError("action_key must be a stable lowercase token.");
  }
}

function requireTitle(value: string): void {
  requireText(value, "title");
  if (
    Array.from(value).length > PROACTIVE_FOLLOWUP_LIMITS.title_code_points ||
    UNSAFE_TEXT_CONTROL_CHARACTERS.test(value)
  ) {
    throw new ProactiveFollowupInvariantError("title is invalid.");
  }
}

function requireRef(value: string, label: string): void {
  requireText(value, label);
  if (
    Buffer.byteLength(value, "utf8") > PROACTIVE_FOLLOWUP_LIMITS.ref_utf8_bytes ||
    UNSAFE_TEXT_CONTROL_CHARACTERS.test(value)
  ) {
    throw new ProactiveFollowupInvariantError(`${label} is invalid.`);
  }
}

function requireText(value: string, label: string): void {
  if (typeof value !== "string" || !value.trim()) {
    throw new ProactiveFollowupInvariantError(`${label} must be non-empty.`);
  }
}

function requirePriority(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > 100) {
    throw new ProactiveFollowupInvariantError("priority must be an integer between 0 and 100.");
  }
}

function requirePositiveInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new ProactiveFollowupInvariantError(`${label} must be a positive integer.`);
  }
}

function requireNonNegativeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new ProactiveFollowupInvariantError(`${label} must be a non-negative integer.`);
  }
}

function requireTimestamp(value: string, label: string): string {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new ProactiveFollowupInvariantError(`${label} must be an ISO timestamp.`);
  }
  return new Date(parsed).toISOString();
}

function stableDigest(parts: readonly string[]): string {
  return createHash("sha256").update(JSON.stringify(parts), "utf8").digest("hex");
}
