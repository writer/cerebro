import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type {
  ClarificationCandidateV1,
  ClarificationEngagementV1,
  ClarificationPolicyV1,
  ClarificationRequestV1,
} from "../src/clarification/contracts.js";
import {
  ClarificationInvariantError,
  planClarification,
} from "../src/clarification/policy.js";

function candidate(
  overrides: Partial<ClarificationCandidateV1> = {},
): ClarificationCandidateV1 {
  return {
    ambiguity_kind: "missing_subject",
    answer_blocking: true,
    has_safe_default: false,
    impact: "high",
    question: "Which account do you mean?",
    question_key: "which-account",
    ...overrides,
  };
}

function engagement(
  overrides: Partial<ClarificationEngagementV1> = {},
): ClarificationEngagementV1 {
  return { history: [], questions_in_thread: 0, ...overrides };
}

function request(
  overrides: Partial<ClarificationRequestV1> = {},
): ClarificationRequestV1 {
  return {
    candidates: [candidate()],
    conversation_ref: "conversation://sample/1",
    engagement: engagement(),
    schema_version: "clarification-request/v1",
    turn_ref: "turn://sample/1",
    ...overrides,
  };
}

function policy(overrides: Partial<ClarificationPolicyV1> = {}): ClarificationPolicyV1 {
  return {
    max_questions_per_thread: 2,
    min_impact_to_ask: "medium",
    schema_version: "clarification-policy/v1",
    ...overrides,
  };
}

describe("clarification planning", () => {
  test("asks the single most consequential blocking question", () => {
    const plan = planClarification(
      request({
        candidates: [
          candidate({ impact: "medium", question_key: "medium-q" }),
          candidate({ impact: "high", question_key: "high-q" }),
          candidate({ impact: "high", has_safe_default: true, question_key: "high-with-default" }),
        ],
      }),
      policy(),
    );
    assert.equal(plan.disposition, "ask");
    if (plan.disposition !== "ask") return;
    assert.equal(plan.question.question_key, "high-q");
    assert.equal(plan.question.turn_ref, "turn://sample/1");
    assert.deepEqual(
      [...plan.deferred].sort((a, b) => a.question_key.localeCompare(b.question_key)),
      [
        { question_key: "high-with-default", reason_code: "not_selected" },
        { question_key: "medium-q", reason_code: "not_selected" },
      ],
    );
  });

  test("prefers a blocking question with no safe default on an impact tie", () => {
    const plan = planClarification(
      request({
        candidates: [
          candidate({ impact: "high", has_safe_default: true, question_key: "with-default" }),
          candidate({ impact: "high", has_safe_default: false, question_key: "no-default" }),
        ],
      }),
      policy(),
    );
    assert.equal(plan.disposition, "ask");
    if (plan.disposition !== "ask") return;
    assert.equal(plan.question.question_key, "no-default");
  });

  test("produces a stable question identity", () => {
    const first = planClarification(request(), policy());
    const second = planClarification(request(), policy());
    assert.equal(first.disposition, "ask");
    assert.equal(second.disposition, "ask");
    if (first.disposition !== "ask" || second.disposition !== "ask") return;
    assert.equal(first.question.question_id, second.question.question_id);
    assert.match(first.question.question_id, /^clarification:[a-f0-9]{32}$/);
  });

  test("proceeds when nothing is answer-blocking", () => {
    const plan = planClarification(
      request({ candidates: [candidate({ answer_blocking: false })] }),
      policy(),
    );
    assert.equal(plan.disposition, "proceed");
    if (plan.disposition !== "proceed") return;
    assert.equal(plan.reason_code, "no_actionable_question");
    assert.deepEqual(plan.deferred, [
      { question_key: "which-account", reason_code: "not_blocking" },
    ]);
  });

  test("proceeds when a safe default covers a low-impact ambiguity", () => {
    const plan = planClarification(
      request({
        candidates: [candidate({ has_safe_default: true, impact: "low" })],
      }),
      policy({ min_impact_to_ask: "medium" }),
    );
    assert.equal(plan.disposition, "proceed");
    if (plan.disposition !== "proceed") return;
    assert.equal(plan.reason_code, "no_actionable_question");
    assert.deepEqual(plan.deferred, [
      { question_key: "which-account", reason_code: "safe_default_available" },
    ]);
  });

  test("still asks past the safe default when impact meets the threshold", () => {
    const plan = planClarification(
      request({
        candidates: [candidate({ has_safe_default: true, impact: "high" })],
      }),
      policy({ min_impact_to_ask: "high" }),
    );
    assert.equal(plan.disposition, "ask");
  });

  test("does not re-ask a question already asked in the thread", () => {
    const plan = planClarification(
      request({
        engagement: engagement({
          history: [{ asked_at: "2030-01-01T00:00:00.000Z", question_key: "which-account" }],
        }),
      }),
      policy(),
    );
    assert.equal(plan.disposition, "proceed");
    if (plan.disposition !== "proceed") return;
    assert.equal(plan.reason_code, "no_actionable_question");
    assert.deepEqual(plan.deferred, [
      { question_key: "which-account", reason_code: "already_asked" },
    ]);
  });

  test("proceeds when the per-thread question budget is exhausted", () => {
    const plan = planClarification(
      request({ engagement: engagement({ questions_in_thread: 2 }) }),
      policy({ max_questions_per_thread: 2 }),
    );
    assert.equal(plan.disposition, "proceed");
    if (plan.disposition !== "proceed") return;
    assert.equal(plan.reason_code, "clarification_budget_exhausted");
    assert.deepEqual(plan.deferred, [
      { question_key: "which-account", reason_code: "not_selected" },
    ]);
  });

  test("proceeds with no candidates", () => {
    const plan = planClarification(request({ candidates: [] }), policy());
    assert.equal(plan.disposition, "proceed");
    if (plan.disposition !== "proceed") return;
    assert.equal(plan.reason_code, "no_actionable_question");
    assert.deepEqual(plan.deferred, []);
  });
});

describe("clarification validation", () => {
  test("rejects malformed and duplicate question keys", () => {
    assert.throws(
      () =>
        planClarification(
          request({ candidates: [candidate({ question_key: "Not Valid" })] }),
          policy(),
        ),
      /question_key must be a stable lowercase token/,
    );
    assert.throws(
      () =>
        planClarification(
          request({
            candidates: [candidate({ question_key: "dup" }), candidate({ question_key: "dup" })],
          }),
          policy(),
        ),
      /Candidate question keys must be unique/,
    );
  });

  test("rejects unsupported enums and schema versions", () => {
    assert.throws(
      () =>
        planClarification(
          request({ candidates: [candidate({ impact: "critical" as never })] }),
          policy(),
        ),
      /Unsupported clarification impact/,
    );
    assert.throws(
      () =>
        planClarification(
          request({ candidates: [candidate({ ambiguity_kind: "mystery" as never })] }),
          policy(),
        ),
      /Unsupported clarification ambiguity kind/,
    );
    assert.throws(
      () =>
        planClarification(
          { ...request(), schema_version: "clarification-request/v2" as never },
          policy(),
        ),
      ClarificationInvariantError,
    );
  });

  test("rejects invalid policy bounds", () => {
    assert.throws(
      () => planClarification(request(), policy({ max_questions_per_thread: 0 })),
      /max_questions_per_thread must be a positive integer/,
    );
    assert.throws(
      () => planClarification(request(), policy({ min_impact_to_ask: "urgent" as never })),
      /Unsupported clarification impact/,
    );
  });

  test("rejects a non-boolean blocking flag and bad history timestamp", () => {
    assert.throws(
      () =>
        planClarification(
          request({ candidates: [candidate({ answer_blocking: "yes" as never })] }),
          policy(),
        ),
      /answer_blocking must be boolean/,
    );
    assert.throws(
      () =>
        planClarification(
          request({
            engagement: engagement({
              history: [{ asked_at: "nope", question_key: "which-account" }],
            }),
          }),
          policy(),
        ),
      /asked_at must be an ISO timestamp/,
    );
  });
});
