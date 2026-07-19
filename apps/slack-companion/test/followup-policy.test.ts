import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type {
  ProactiveFollowupCandidateV1,
  ProactiveFollowupEngagementV1,
  ProactiveFollowupPolicyV1,
  ProactiveFollowupRequestV1,
} from "../src/followup/contracts.js";
import {
  ProactiveFollowupInvariantError,
  planProactiveFollowup,
} from "../src/followup/policy.js";

const now = "2030-05-01T12:00:00.000Z";

function candidate(
  overrides: Partial<ProactiveFollowupCandidateV1> = {},
): ProactiveFollowupCandidateV1 {
  return {
    action: "opaque-action-intent",
    action_key: "watch-answer-1",
    grounding_refs: ["evidence://sample/1"],
    kind: "watch_answer",
    priority: 50,
    title: "Watch this answer for changes",
    ...overrides,
  };
}

function engagement(
  overrides: Partial<ProactiveFollowupEngagementV1> = {},
): ProactiveFollowupEngagementV1 {
  return { history: [], offers_in_window: 0, ...overrides };
}

function request(
  overrides: Partial<ProactiveFollowupRequestV1> = {},
): ProactiveFollowupRequestV1 {
  return {
    candidates: [candidate()],
    conversation_ref: "conversation://sample/1",
    engagement: engagement(),
    schema_version: "proactive-followup-request/v1",
    turn_ref: "turn://sample/1",
    turn_state: "answered",
    ...overrides,
  };
}

function policy(overrides: Partial<ProactiveFollowupPolicyV1> = {}): ProactiveFollowupPolicyV1 {
  return {
    allowed_kinds: ["watch_answer", "recheck_evidence", "open_triage"],
    cooldown_seconds: 300,
    max_offers: 2,
    max_offers_per_window: 5,
    schema_version: "proactive-followup-policy/v1",
    ttl_seconds: 3_600,
    ...overrides,
  };
}

describe("proactive follow-up planning", () => {
  test("offers grounded candidates ordered by priority then title", () => {
    const plan = planProactiveFollowup(
      request({
        candidates: [
          candidate({ action_key: "b-low", priority: 10, title: "B action" }),
          candidate({ action_key: "a-high", priority: 90, title: "A action" }),
          candidate({
            action_key: "c-mid",
            kind: "recheck_evidence",
            priority: 90,
            title: "C action",
          }),
        ],
      }),
      policy({ max_offers: 3 }),
      now,
    );

    assert.equal(plan.disposition, "offered");
    if (plan.disposition !== "offered") return;
    assert.deepEqual(
      plan.suggestions.map((suggestion) => suggestion.action_key),
      ["a-high", "c-mid", "b-low"],
    );
    assert.equal(plan.suggestions[0]!.expires_at, "2030-05-01T13:00:00.000Z");
    assert.equal(plan.suggestions[0]!.created_at, now);
    assert.equal(plan.dropped.length, 0);
  });

  test("produces stable idempotent identities across calls", () => {
    const first = planProactiveFollowup(request(), policy(), now);
    const second = planProactiveFollowup(request(), policy(), "2030-05-01T12:30:00.000Z");
    assert.equal(first.disposition, "offered");
    assert.equal(second.disposition, "offered");
    if (first.disposition !== "offered" || second.disposition !== "offered") return;
    assert.equal(
      first.suggestions[0]!.suggestion_id,
      second.suggestions[0]!.suggestion_id,
    );
    assert.equal(
      first.suggestions[0]!.idempotency_key,
      first.suggestions[0]!.suggestion_id,
    );
  });

  test("suppresses when the turn is blocked or awaiting input", () => {
    for (const turnState of ["blocked", "needs_input"] as const) {
      const plan = planProactiveFollowup(request({ turn_state: turnState }), policy(), now);
      assert.equal(plan.disposition, "suppressed");
      if (plan.disposition !== "suppressed") return;
      assert.equal(plan.reason_code, "turn_not_offerable");
    }
  });

  test("suppresses within the cooldown window", () => {
    const plan = planProactiveFollowup(
      request({
        engagement: engagement({ last_offered_at: "2030-05-01T11:57:00.000Z" }),
      }),
      policy({ cooldown_seconds: 300 }),
      now,
    );
    assert.equal(plan.disposition, "suppressed");
    if (plan.disposition !== "suppressed") return;
    assert.equal(plan.reason_code, "within_cooldown");
  });

  test("offers once the cooldown has elapsed", () => {
    const plan = planProactiveFollowup(
      request({
        engagement: engagement({ last_offered_at: "2030-05-01T11:54:59.000Z" }),
      }),
      policy({ cooldown_seconds: 300 }),
      now,
    );
    assert.equal(plan.disposition, "offered");
  });

  test("suppresses when the engagement budget is exhausted", () => {
    const plan = planProactiveFollowup(
      request({ engagement: engagement({ offers_in_window: 5 }) }),
      policy({ max_offers_per_window: 5 }),
      now,
    );
    assert.equal(plan.disposition, "suppressed");
    if (plan.disposition !== "suppressed") return;
    assert.equal(plan.reason_code, "engagement_budget_exhausted");
  });

  test("caps offers by the remaining window budget", () => {
    const plan = planProactiveFollowup(
      request({
        candidates: [
          candidate({ action_key: "a", priority: 90 }),
          candidate({ action_key: "b", priority: 80 }),
          candidate({ action_key: "c", priority: 70 }),
        ],
        engagement: engagement({ offers_in_window: 4 }),
      }),
      policy({ max_offers: 3, max_offers_per_window: 5 }),
      now,
    );
    assert.equal(plan.disposition, "offered");
    if (plan.disposition !== "offered") return;
    assert.deepEqual(plan.suggestions.map((suggestion) => suggestion.action_key), ["a"]);
    assert.deepEqual(
      plan.dropped,
      [
        { action_key: "b", reason_code: "over_offer_limit" },
        { action_key: "c", reason_code: "over_offer_limit" },
      ],
    );
  });

  test("drops disallowed kinds, ungrounded, and already-handled candidates", () => {
    const plan = planProactiveFollowup(
      request({
        candidates: [
          candidate({ action_key: "allowed", priority: 60 }),
          candidate({ action_key: "wrong-kind", kind: "remediation" }),
          candidate({ action_key: "ungrounded", grounding_refs: [] }),
          candidate({ action_key: "already-offered" }),
          candidate({ action_key: "already-accepted" }),
        ],
        engagement: engagement({
          history: [
            { action_key: "already-offered", offered_at: now, state: "offered" },
            { action_key: "already-accepted", offered_at: now, state: "accepted" },
          ],
        }),
      }),
      policy({ allowed_kinds: ["watch_answer"], max_offers: 5 }),
      now,
    );
    assert.equal(plan.disposition, "offered");
    if (plan.disposition !== "offered") return;
    assert.deepEqual(plan.suggestions.map((suggestion) => suggestion.action_key), ["allowed"]);
    assert.deepEqual(
      [...plan.dropped].sort((a, b) => a.action_key.localeCompare(b.action_key)),
      [
        { action_key: "already-accepted", reason_code: "already_accepted" },
        { action_key: "already-offered", reason_code: "already_offered" },
        { action_key: "ungrounded", reason_code: "ungrounded" },
        { action_key: "wrong-kind", reason_code: "kind_not_allowed" },
      ],
    );
  });

  test("re-offers an expired action but not a dismissed or superseded one", () => {
    const expired = planProactiveFollowup(
      request({
        engagement: engagement({
          history: [{ action_key: "watch-answer-1", offered_at: now, state: "expired" }],
        }),
      }),
      policy(),
      now,
    );
    assert.equal(expired.disposition, "offered");

    for (const state of ["dismissed", "superseded"] as const) {
      const plan = planProactiveFollowup(
        request({
          engagement: engagement({
            history: [{ action_key: "watch-answer-1", offered_at: now, state }],
          }),
        }),
        policy(),
        now,
      );
      assert.equal(plan.disposition, "suppressed");
      if (plan.disposition !== "suppressed") continue;
      assert.equal(plan.reason_code, "no_actionable_followups");
      assert.deepEqual(plan.dropped, [
        { action_key: "watch-answer-1", reason_code: "already_offered" },
      ]);
    }
  });

  test("suppresses with no_actionable_followups when everything is filtered", () => {
    const plan = planProactiveFollowup(
      request({ candidates: [candidate({ grounding_refs: [] })] }),
      policy(),
      now,
    );
    assert.equal(plan.disposition, "suppressed");
    if (plan.disposition !== "suppressed") return;
    assert.equal(plan.reason_code, "no_actionable_followups");
    assert.deepEqual(plan.dropped, [
      { action_key: "watch-answer-1", reason_code: "ungrounded" },
    ]);
  });

  test("suppresses with an empty candidate list", () => {
    const plan = planProactiveFollowup(request({ candidates: [] }), policy(), now);
    assert.equal(plan.disposition, "suppressed");
    if (plan.disposition !== "suppressed") return;
    assert.equal(plan.reason_code, "no_actionable_followups");
  });

  test("copies grounding refs so the plan does not alias input", () => {
    const refs = ["evidence://sample/1"];
    const plan = planProactiveFollowup(
      request({ candidates: [candidate({ grounding_refs: refs })] }),
      policy(),
      now,
    );
    assert.equal(plan.disposition, "offered");
    if (plan.disposition !== "offered") return;
    refs.push("evidence://mutated");
    assert.deepEqual(plan.suggestions[0]!.grounding_refs, ["evidence://sample/1"]);
  });
});

describe("proactive follow-up validation", () => {
  test("rejects malformed action keys and duplicates", () => {
    assert.throws(
      () =>
        planProactiveFollowup(
          request({ candidates: [candidate({ action_key: "Not Valid" })] }),
          policy(),
          now,
        ),
      /action_key must be a stable lowercase token/,
    );
    assert.throws(
      () =>
        planProactiveFollowup(
          request({
            candidates: [candidate({ action_key: "dup" }), candidate({ action_key: "dup" })],
          }),
          policy(),
          now,
        ),
      /Candidate action keys must be unique/,
    );
  });

  test("rejects duplicate grounding refs and out-of-range priority", () => {
    assert.throws(
      () =>
        planProactiveFollowup(
          request({
            candidates: [candidate({ grounding_refs: ["ref://a", "ref://a"] })],
          }),
          policy(),
          now,
        ),
      /Grounding refs must be unique/,
    );
    assert.throws(
      () =>
        planProactiveFollowup(
          request({ candidates: [candidate({ priority: 101 })] }),
          policy(),
          now,
        ),
      /priority must be an integer between 0 and 100/,
    );
  });

  test("rejects unsupported schema versions and invalid policy bounds", () => {
    assert.throws(
      () =>
        planProactiveFollowup(
          { ...request(), schema_version: "proactive-followup-request/v2" as never },
          policy(),
          now,
        ),
      ProactiveFollowupInvariantError,
    );
    assert.throws(
      () => planProactiveFollowup(request(), policy({ max_offers: 0 }), now),
      /max_offers must be a positive integer/,
    );
    assert.throws(
      () => planProactiveFollowup(request(), policy({ allowed_kinds: [] }), now),
      /must allow at least one follow-up kind/,
    );
    assert.throws(
      () =>
        planProactiveFollowup(
          request(),
          policy({ allowed_kinds: ["watch_answer", "watch_answer"] }),
          now,
        ),
      /allowed_kinds must be unique/,
    );
  });

  test("rejects an invalid now timestamp", () => {
    assert.throws(
      () => planProactiveFollowup(request(), policy(), "not-a-timestamp"),
      /now must be an ISO timestamp/,
    );
  });
});
