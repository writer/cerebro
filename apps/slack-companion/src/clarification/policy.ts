import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import {
  CLARIFICATION_AMBIGUITY_KINDS,
  CLARIFICATION_IMPACTS,
  CLARIFICATION_LIMITS,
  type ClarificationAmbiguityKindV1,
  type ClarificationCandidateV1,
  type ClarificationDeferralV1,
  type ClarificationEngagementV1,
  type ClarificationHistoryEntryV1,
  type ClarificationImpactV1,
  type ClarificationPlanV1,
  type ClarificationPolicyV1,
  type ClarificationQuestionV1,
  type ClarificationRequestV1,
} from "./contracts.js";

const QUESTION_KEY = /^[a-z0-9][a-z0-9._:-]{0,127}$/;
const UNSAFE_TEXT_CONTROL_CHARACTERS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
const IMPACT_RANK: Readonly<Record<ClarificationImpactV1, number>> = {
  high: 2,
  low: 0,
  medium: 1,
};

export class ClarificationInvariantError extends Error {}

/**
 * Deterministically decides whether to ask exactly one high-value clarifying
 * question or to proceed with a best-effort answer.
 *
 * A candidate is only askable when the missing information is answer-blocking,
 * when no safe default covers it below the policy's impact threshold, and when
 * the same question has not already been asked in the thread. If several remain,
 * the policy asks the single most consequential one; the rest are deferred with
 * a reason. When nothing is askable, or the per-thread question budget is spent,
 * the companion proceeds instead of nagging.
 */
export function planClarification(
  request: ClarificationRequestV1,
  policy: ClarificationPolicyV1,
): ClarificationPlanV1 {
  validateRequest(request);
  validatePolicy(policy);

  const askedKeys = new Set(request.engagement.history.map((entry) => entry.question_key));
  const threshold = IMPACT_RANK[policy.min_impact_to_ask];

  const deferred: ClarificationDeferralV1[] = [];
  const askable: ClarificationCandidateV1[] = [];
  for (const candidate of request.candidates) {
    if (!candidate.answer_blocking) {
      deferred.push({ question_key: candidate.question_key, reason_code: "not_blocking" });
      continue;
    }
    if (askedKeys.has(candidate.question_key)) {
      deferred.push({ question_key: candidate.question_key, reason_code: "already_asked" });
      continue;
    }
    if (candidate.has_safe_default && IMPACT_RANK[candidate.impact] < threshold) {
      deferred.push({
        question_key: candidate.question_key,
        reason_code: "safe_default_available",
      });
      continue;
    }
    askable.push(candidate);
  }

  if (askable.length === 0) {
    return { deferred, disposition: "proceed", reason_code: "no_actionable_question", schema_version: "clarification-plan/v1" };
  }

  if (request.engagement.questions_in_thread >= policy.max_questions_per_thread) {
    for (const candidate of askable) {
      deferred.push({ question_key: candidate.question_key, reason_code: "not_selected" });
    }
    return {
      deferred,
      disposition: "proceed",
      reason_code: "clarification_budget_exhausted",
      schema_version: "clarification-plan/v1",
    };
  }

  askable.sort(compareCandidates);
  const [chosen, ...rest] = askable;
  for (const candidate of rest) {
    deferred.push({ question_key: candidate.question_key, reason_code: "not_selected" });
  }
  return {
    deferred,
    disposition: "ask",
    question: buildQuestion(request, chosen!),
    schema_version: "clarification-plan/v1",
  };
}

function buildQuestion(
  request: ClarificationRequestV1,
  candidate: ClarificationCandidateV1,
): ClarificationQuestionV1 {
  return {
    ambiguity_kind: candidate.ambiguity_kind,
    impact: candidate.impact,
    question: candidate.question,
    question_id: `clarification:${stableDigest([
      request.conversation_ref,
      request.turn_ref,
      candidate.question_key,
    ]).slice(0, 32)}`,
    question_key: candidate.question_key,
    turn_ref: request.turn_ref,
  };
}

function compareCandidates(
  a: ClarificationCandidateV1,
  b: ClarificationCandidateV1,
): number {
  if (IMPACT_RANK[a.impact] !== IMPACT_RANK[b.impact]) {
    return IMPACT_RANK[b.impact] - IMPACT_RANK[a.impact];
  }
  if (a.has_safe_default !== b.has_safe_default) {
    return a.has_safe_default ? 1 : -1;
  }
  return a.question_key.localeCompare(b.question_key);
}

function validateRequest(request: ClarificationRequestV1): void {
  if (request.schema_version !== "clarification-request/v1") {
    throw new ClarificationInvariantError("Unsupported clarification request version.");
  }
  requireRef(request.conversation_ref, "conversation_ref");
  requireRef(request.turn_ref, "turn_ref");
  if (request.candidates.length > CLARIFICATION_LIMITS.candidates) {
    throw new ClarificationInvariantError("Too many clarification candidates.");
  }
  const questionKeys = new Set<string>();
  for (const candidate of request.candidates) {
    validateCandidate(candidate);
    if (questionKeys.has(candidate.question_key)) {
      throw new ClarificationInvariantError("Candidate question keys must be unique.");
    }
    questionKeys.add(candidate.question_key);
  }
  validateEngagement(request.engagement);
}

function validateCandidate(candidate: ClarificationCandidateV1): void {
  requireQuestionKey(candidate.question_key);
  requireQuestion(candidate.question);
  requireAmbiguityKind(candidate.ambiguity_kind);
  requireImpact(candidate.impact);
  requireBoolean(candidate.answer_blocking, "answer_blocking");
  requireBoolean(candidate.has_safe_default, "has_safe_default");
}

function validateEngagement(engagement: ClarificationEngagementV1): void {
  requireNonNegativeInteger(engagement.questions_in_thread, "questions_in_thread");
  if (engagement.history.length > CLARIFICATION_LIMITS.history) {
    throw new ClarificationInvariantError("Clarification history is too long.");
  }
  for (const entry of engagement.history) {
    validateHistoryEntry(entry);
  }
}

function validateHistoryEntry(entry: ClarificationHistoryEntryV1): void {
  requireQuestionKey(entry.question_key);
  requireTimestamp(entry.asked_at, "asked_at");
}

function validatePolicy(policy: ClarificationPolicyV1): void {
  if (policy.schema_version !== "clarification-policy/v1") {
    throw new ClarificationInvariantError("Unsupported clarification policy version.");
  }
  requirePositiveInteger(policy.max_questions_per_thread, "max_questions_per_thread");
  requireImpact(policy.min_impact_to_ask);
}

function requireAmbiguityKind(value: ClarificationAmbiguityKindV1): void {
  if (!CLARIFICATION_AMBIGUITY_KINDS.includes(value)) {
    throw new ClarificationInvariantError("Unsupported clarification ambiguity kind.");
  }
}

function requireImpact(value: ClarificationImpactV1): void {
  if (!CLARIFICATION_IMPACTS.includes(value)) {
    throw new ClarificationInvariantError("Unsupported clarification impact.");
  }
}

function requireQuestionKey(value: string): void {
  if (typeof value !== "string" || !QUESTION_KEY.test(value)) {
    throw new ClarificationInvariantError("question_key must be a stable lowercase token.");
  }
}

function requireQuestion(value: string): void {
  requireText(value, "question");
  if (
    Array.from(value).length > CLARIFICATION_LIMITS.question_code_points ||
    UNSAFE_TEXT_CONTROL_CHARACTERS.test(value)
  ) {
    throw new ClarificationInvariantError("question is invalid.");
  }
}

function requireRef(value: string, label: string): void {
  requireText(value, label);
  if (
    Buffer.byteLength(value, "utf8") > CLARIFICATION_LIMITS.ref_utf8_bytes ||
    UNSAFE_TEXT_CONTROL_CHARACTERS.test(value)
  ) {
    throw new ClarificationInvariantError(`${label} is invalid.`);
  }
}

function requireText(value: string, label: string): void {
  if (typeof value !== "string" || !value.trim()) {
    throw new ClarificationInvariantError(`${label} must be non-empty.`);
  }
}

function requireBoolean(value: boolean, label: string): void {
  if (typeof value !== "boolean") {
    throw new ClarificationInvariantError(`${label} must be boolean.`);
  }
}

function requirePositiveInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new ClarificationInvariantError(`${label} must be a positive integer.`);
  }
}

function requireNonNegativeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new ClarificationInvariantError(`${label} must be a non-negative integer.`);
  }
}

function requireTimestamp(value: string, label: string): void {
  if (!Number.isFinite(Date.parse(value))) {
    throw new ClarificationInvariantError(`${label} must be an ISO timestamp.`);
  }
}

function stableDigest(parts: readonly string[]): string {
  return createHash("sha256").update(JSON.stringify(parts), "utf8").digest("hex");
}
