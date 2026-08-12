import { createHash } from "node:crypto";

export const ANSWER_FEEDBACK_CATEGORIES = [
  "helpful",
  "missed_source",
  "wrong_owner",
  "needs_followup",
] as const;

export type AnswerFeedbackCategoryV1 =
  (typeof ANSWER_FEEDBACK_CATEGORIES)[number];

export interface AnswerFeedbackInputV1 {
  readonly actor_ref: string;
  readonly answer_ref: string;
  readonly category: AnswerFeedbackCategoryV1;
  readonly feedback_key: string;
  readonly observed_at: string;
  readonly request_ref: string;
  readonly tenant_ref: string;
  readonly thread_ref: string;
}

export interface AnswerFeedbackRecordV1 extends AnswerFeedbackInputV1 {
  readonly idempotency_key: string;
  readonly improvement_signal:
    | "none"
    | "ownership_gap"
    | "source_gap"
    | "followup_required";
  readonly record_ref: string;
  readonly schema_version: "answer-feedback-record/v1";
}

export class AnswerFeedbackPolicyError extends Error {}

/** Produces an immutable, answer-bound signal for the host's existing learning ledger. */
export function recordAnswerFeedback(
  input: AnswerFeedbackInputV1,
): AnswerFeedbackRecordV1 {
  exact(input, [
    "actor_ref",
    "answer_ref",
    "category",
    "feedback_key",
    "observed_at",
    "request_ref",
    "tenant_ref",
    "thread_ref",
  ]);
  if (!ANSWER_FEEDBACK_CATEGORIES.includes(input.category)) {
    throw new AnswerFeedbackPolicyError("The answer feedback category is unsupported.");
  }
  const canonical = {
    actor_ref: ref(input.actor_ref, "actor_ref"),
    answer_ref: ref(input.answer_ref, "answer_ref"),
    category: input.category,
    feedback_key: token(input.feedback_key, "feedback_key"),
    observed_at: timestamp(input.observed_at),
    request_ref: ref(input.request_ref, "request_ref"),
    tenant_ref: ref(input.tenant_ref, "tenant_ref"),
    thread_ref: ref(input.thread_ref, "thread_ref"),
  };
  const digest = hash(canonical);
  return Object.freeze({
    ...canonical,
    idempotency_key: `answer-feedback:${digest}`,
    improvement_signal: signal(input.category),
    record_ref: `feedback://answer/${digest}`,
    schema_version: "answer-feedback-record/v1",
  });
}

function signal(category: AnswerFeedbackCategoryV1): AnswerFeedbackRecordV1["improvement_signal"] {
  switch (category) {
    case "helpful": return "none";
    case "missed_source": return "source_gap";
    case "wrong_owner": return "ownership_gap";
    case "needs_followup": return "followup_required";
  }
}

function exact(value: object, keys: readonly string[]): void {
  if (Object.getPrototypeOf(value) !== Object.prototype
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) {
    throw new AnswerFeedbackPolicyError("Answer feedback fields are invalid.");
  }
}

function ref(value: string, field: string): string {
  if (!/^[a-z][a-z0-9+.-]*:\/\/[^\s\u0000-\u001f]{1,500}$/u.test(value)) {
    throw new AnswerFeedbackPolicyError(`${field} is invalid.`);
  }
  return value;
}

function token(value: string, field: string): string {
  if (!/^[a-z0-9][a-z0-9:._-]{0,255}$/u.test(value)) {
    throw new AnswerFeedbackPolicyError(`${field} is invalid.`);
  }
  return value;
}

function timestamp(value: string): string {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new AnswerFeedbackPolicyError("observed_at must be a canonical timestamp.");
  }
  return value;
}

function hash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
