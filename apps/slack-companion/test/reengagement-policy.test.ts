import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type {
  ReengagementCandidateV1,
  ReengagementEngagementV1,
  ReengagementPolicyV1,
  ReengagementRequestV1,
} from "../src/reengagement/contracts.js";
import {
  ReengagementInvariantError,
  planReengagement,
} from "../src/reengagement/policy.js";

const NOW = "2030-01-01T12:00:00.000Z";

function candidate(
  overrides: Partial<ReengagementCandidateV1> = {},
): ReengagementCandidateV1 {
  return {
    grounding_ref: "evidence://sample/1",
    is_open: true,
    item_key: "watch-1",
    item_ref: "watch://sample/1",
    kind: "answer_watch",
    last_activity_at: "2030-01-01T00:00:00.000Z",
    priority: 50,
    summary: "PR watch has had no update in 12h.",
    ...overrides,
  };
}

function engagement(
  overrides: Partial<ReengagementEngagementV1> = {},
): ReengagementEngagementV1 {
  return { history: [], nudges_in_window: 0, ...overrides };
}

function request(
  overrides: Partial<ReengagementRequestV1> = {},
): ReengagementRequestV1 {
  return {
    candidates: [candidate()],
    conversation_ref: "conversation://sample/1",
    engagement: engagement(),
    schema_version: "reengagement-request/v1",
    ...overrides,
  };
}

function policy(overrides: Partial<ReengagementPolicyV1> = {}): ReengagementPolicyV1 {
  return {
    allowed_kinds: ["answer_watch", "canonical_case"],
    cooldown_seconds: 3_600,
    max_nudges: 2,
    max_nudges_per_window: 3,
    schema_version: "reengagement-policy/v1",
    staleness_seconds: 3_600,
    ttl_seconds: 86_400,
    ...overrides,
  };
}

describe("reengagement planning", () => {
  test("nudges a stale open item with a stable identity and idle duration", () => {
    const plan = planReengagement(request(), policy(), NOW);
    assert.equal(plan.disposition, "nudge");
    if (plan.disposition !== "nudge") return;
    assert.equal(plan.nudges.length, 1);
    const [nudge] = plan.nudges;
    assert.equal(nudge!.item_key, "watch-1");
    assert.equal(nudge!.idle_seconds, 12 * 3_600);
    assert.equal(nudge!.expires_at, "2030-01-02T12:00:00.000Z");
    assert.match(nudge!.nudge_id, /^reengagement:[a-f0-9]{32}$/);
    assert.equal(nudge!.idempotency_key.length, 64);
    const replay = planReengagement(request(), policy(), NOW);
    assert.equal(replay.disposition, "nudge");
    if (replay.disposition !== "nudge") return;
    assert.equal(replay.nudges[0]!.nudge_id, nudge!.nudge_id);
  });

  test("a fresh material state earns a distinct nudge identity", () => {
    const stale = planReengagement(request(), policy(), NOW);
    const advanced = planReengagement(
      request({ candidates: [candidate({ last_activity_at: "2030-01-01T06:00:00.000Z" })] }),
      policy(),
      NOW,
    );
    assert.equal(stale.disposition, "nudge");
    assert.equal(advanced.disposition, "nudge");
    if (stale.disposition !== "nudge" || advanced.disposition !== "nudge") return;
    assert.notEqual(stale.nudges[0]!.nudge_id, advanced.nudges[0]!.nudge_id);
  });

  test("orders by priority then staleness and caps to the per-run limit", () => {
    const plan = planReengagement(
      request({
        candidates: [
          candidate({ item_key: "low", priority: 10 }),
          candidate({ item_key: "high-fresh", priority: 90, last_activity_at: "2030-01-01T10:00:00.000Z" }),
          candidate({ item_key: "high-stale", priority: 90, last_activity_at: "2030-01-01T01:00:00.000Z" }),
        ],
      }),
      policy({ max_nudges: 2 }),
      NOW,
    );
    assert.equal(plan.disposition, "nudge");
    if (plan.disposition !== "nudge") return;
    assert.deepEqual(
      plan.nudges.map((n) => n.item_key),
      ["high-stale", "high-fresh"],
    );
    assert.deepEqual(plan.dropped, [{ item_key: "low", reason_code: "over_nudge_limit" }]);
  });

  test("drops closed, not-yet-stale, and disallowed-kind items", () => {
    const plan = planReengagement(
      request({
        candidates: [
          candidate({ item_key: "closed", is_open: false }),
          candidate({ item_key: "fresh", last_activity_at: "2030-01-01T11:59:00.000Z" }),
          candidate({ item_key: "other", kind: "canonical_case" }),
        ],
      }),
      policy({ allowed_kinds: ["answer_watch"] }),
      NOW,
    );
    assert.equal(plan.disposition, "suppressed");
    if (plan.disposition !== "suppressed") return;
    assert.equal(plan.reason_code, "no_stale_work");
    assert.deepEqual(
      [...plan.dropped].sort((a, b) => a.item_key.localeCompare(b.item_key)),
      [
        { item_key: "closed", reason_code: "not_open" },
        { item_key: "fresh", reason_code: "not_stale" },
        { item_key: "other", reason_code: "kind_not_allowed" },
      ],
    );
  });

  test("respects a per-item cooldown from history", () => {
    const plan = planReengagement(
      request({
        engagement: engagement({
          history: [{ item_key: "watch-1", nudged_at: "2030-01-01T11:30:00.000Z" }],
        }),
      }),
      policy({ cooldown_seconds: 3_600 }),
      NOW,
    );
    assert.equal(plan.disposition, "suppressed");
    if (plan.disposition !== "suppressed") return;
    assert.deepEqual(plan.dropped, [{ item_key: "watch-1", reason_code: "within_cooldown" }]);
  });

  test("re-nudges once the per-item cooldown has elapsed", () => {
    const plan = planReengagement(
      request({
        engagement: engagement({
          history: [{ item_key: "watch-1", nudged_at: "2030-01-01T10:00:00.000Z" }],
        }),
      }),
      policy({ cooldown_seconds: 3_600 }),
      NOW,
    );
    assert.equal(plan.disposition, "nudge");
  });

  test("suppresses when the per-window budget is exhausted", () => {
    const plan = planReengagement(
      request({ engagement: engagement({ nudges_in_window: 3 }) }),
      policy({ max_nudges_per_window: 3 }),
      NOW,
    );
    assert.equal(plan.disposition, "suppressed");
    if (plan.disposition !== "suppressed") return;
    assert.equal(plan.reason_code, "engagement_budget_exhausted");
    assert.deepEqual(plan.dropped, []);
  });

  test("caps output by the remaining window budget", () => {
    const plan = planReengagement(
      request({
        candidates: [
          candidate({ item_key: "a", priority: 90 }),
          candidate({ item_key: "b", priority: 80 }),
        ],
        engagement: engagement({ nudges_in_window: 2 }),
      }),
      policy({ max_nudges: 2, max_nudges_per_window: 3 }),
      NOW,
    );
    assert.equal(plan.disposition, "nudge");
    if (plan.disposition !== "nudge") return;
    assert.deepEqual(plan.nudges.map((n) => n.item_key), ["a"]);
    assert.deepEqual(plan.dropped, [{ item_key: "b", reason_code: "over_nudge_limit" }]);
  });

  test("suppresses with no candidates", () => {
    const plan = planReengagement(request({ candidates: [] }), policy(), NOW);
    assert.equal(plan.disposition, "suppressed");
    if (plan.disposition !== "suppressed") return;
    assert.equal(plan.reason_code, "no_stale_work");
  });
});

describe("reengagement validation", () => {
  test("rejects malformed and duplicate item keys", () => {
    assert.throws(
      () => planReengagement(request({ candidates: [candidate({ item_key: "Bad Key" })] }), policy(), NOW),
      /item_key must be a stable lowercase token/,
    );
    assert.throws(
      () =>
        planReengagement(
          request({
            candidates: [candidate({ item_key: "dup" }), candidate({ item_key: "dup" })],
          }),
          policy(),
          NOW,
        ),
      /Candidate item keys must be unique/,
    );
  });

  test("rejects unsupported kinds and schema versions", () => {
    assert.throws(
      () => planReengagement(request({ candidates: [candidate({ kind: "mystery" as never })] }), policy(), NOW),
      /Unsupported reengagement kind/,
    );
    assert.throws(
      () => planReengagement({ ...request(), schema_version: "reengagement-request/v2" as never }, policy(), NOW),
      ReengagementInvariantError,
    );
  });

  test("rejects invalid policy bounds and timestamps", () => {
    assert.throws(
      () => planReengagement(request(), policy({ staleness_seconds: 0 }), NOW),
      /staleness_seconds must be a positive integer/,
    );
    assert.throws(
      () => planReengagement(request(), policy({ allowed_kinds: [] }), NOW),
      /must allow at least one reengagement kind/,
    );
    assert.throws(
      () => planReengagement(request({ candidates: [candidate({ last_activity_at: "nope" })] }), policy(), NOW),
      /last_activity_at must be an ISO timestamp/,
    );
    assert.throws(() => planReengagement(request(), policy(), "not-a-time"), /now must be an ISO timestamp/);
  });
});
