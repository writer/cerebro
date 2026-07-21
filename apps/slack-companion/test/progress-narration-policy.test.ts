import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type {
  ProgressEventV1,
  ProgressNarrationPolicyV1,
  ProgressNarrationRequestV1,
  ProgressNarrationStateV1,
} from "../src/progress/contracts.js";
import {
  ProgressNarrationInvariantError,
  planProgressNarration,
} from "../src/progress/policy.js";

const NOW = "2030-01-01T00:10:00.000Z";

function event(overrides: Partial<ProgressEventV1> = {}): ProgressEventV1 {
  return {
    occurred_at: NOW,
    phase: "checking",
    sequence: 2,
    status: "Checking 3 sources for exposure evidence.",
    ...overrides,
  };
}

function state(overrides: Partial<ProgressNarrationStateV1> = {}): ProgressNarrationStateV1 {
  return { updates_published: 0, ...overrides };
}

function request(
  overrides: Partial<ProgressNarrationRequestV1> = {},
): ProgressNarrationRequestV1 {
  return {
    event: event(),
    schema_version: "progress-narration-request/v1",
    state: state(),
    turn_ref: "turn://sample/1",
    ...overrides,
  };
}

function policy(
  overrides: Partial<ProgressNarrationPolicyV1> = {},
): ProgressNarrationPolicyV1 {
  return {
    heartbeat_seconds: 30,
    max_updates: 6,
    min_interval_seconds: 10,
    schema_version: "progress-narration-policy/v1",
    ...overrides,
  };
}

describe("progress narration planning", () => {
  test("posts the first update with a stable identity", () => {
    const plan = planProgressNarration(request({ state: state() }), policy(), NOW);
    assert.equal(plan.disposition, "publish");
    if (plan.disposition !== "publish") return;
    assert.equal(plan.update.method, "post");
    assert.equal(plan.update.terminal, false);
    assert.match(plan.update.update_id, /^progress:[a-f0-9]{32}$/);
    const replay = planProgressNarration(request({ state: state() }), policy(), NOW);
    assert.equal(replay.disposition, "publish");
    if (replay.disposition !== "publish") return;
    assert.equal(replay.update.update_id, plan.update.update_id);
  });

  test("edits on a phase change once a prior update exists", () => {
    const plan = planProgressNarration(
      request({
        event: event({ phase: "synthesizing", sequence: 3, status: "Synthesizing an answer." }),
        state: state({
          last_phase: "checking",
          last_published_at: "2030-01-01T00:09:00.000Z",
          last_published_sequence: 2,
          last_status: "Checking sources.",
          updates_published: 1,
        }),
      }),
      policy(),
      NOW,
    );
    assert.equal(plan.disposition, "publish");
    if (plan.disposition !== "publish") return;
    assert.equal(plan.update.method, "edit");
    assert.equal(plan.update.phase, "synthesizing");
  });

  test("carries an optional detail sentence", () => {
    const plan = planProgressNarration(
      request({ event: event({ detail: "  Found 2 candidate exposures.  " }) }),
      policy(),
      NOW,
    );
    assert.equal(plan.disposition, "publish");
    if (plan.disposition !== "publish") return;
    assert.equal(plan.update.detail, "Found 2 candidate exposures.");
  });

  test("always publishes a terminal phase past throttle and budget", () => {
    const plan = planProgressNarration(
      request({
        event: event({ phase: "completed", sequence: 9, status: "Delivered the answer." }),
        state: state({
          last_phase: "delivering",
          last_published_at: "2030-01-01T00:09:59.000Z",
          last_published_sequence: 8,
          last_status: "Delivering.",
          updates_published: 6,
        }),
      }),
      policy({ max_updates: 6, min_interval_seconds: 10 }),
      NOW,
    );
    assert.equal(plan.disposition, "publish");
    if (plan.disposition !== "publish") return;
    assert.equal(plan.update.terminal, true);
    assert.equal(plan.update.method, "edit");
  });

  test("suppresses an out-of-order or already-narrated sequence", () => {
    const plan = planProgressNarration(
      request({
        event: event({ sequence: 2 }),
        state: state({ last_published_sequence: 2, updates_published: 1 }),
      }),
      policy(),
      NOW,
    );
    assert.equal(plan.disposition, "suppress");
    if (plan.disposition !== "suppress") return;
    assert.equal(plan.reason_code, "superseded");
  });

  test("suppresses within the minimum interval", () => {
    const plan = planProgressNarration(
      request({
        event: event({ phase: "synthesizing", sequence: 3 }),
        state: state({
          last_phase: "checking",
          last_published_at: "2030-01-01T00:09:55.000Z",
          last_published_sequence: 2,
          updates_published: 1,
        }),
      }),
      policy({ min_interval_seconds: 10 }),
      NOW,
    );
    assert.equal(plan.disposition, "suppress");
    if (plan.disposition !== "suppress") return;
    assert.equal(plan.reason_code, "within_min_interval");
  });

  test("suppresses when the update budget is exhausted", () => {
    const plan = planProgressNarration(
      request({
        event: event({ sequence: 7 }),
        state: state({
          last_published_at: "2030-01-01T00:00:00.000Z",
          last_published_sequence: 6,
          updates_published: 6,
        }),
      }),
      policy({ max_updates: 6 }),
      NOW,
    );
    assert.equal(plan.disposition, "suppress");
    if (plan.disposition !== "suppress") return;
    assert.equal(plan.reason_code, "update_budget_exhausted");
  });

  test("suppresses a same-phase, same-status event before the heartbeat", () => {
    const plan = planProgressNarration(
      request({
        event: event({ phase: "checking", sequence: 3, status: "Checking sources." }),
        state: state({
          last_phase: "checking",
          last_published_at: "2030-01-01T00:09:45.000Z",
          last_published_sequence: 2,
          last_status: "Checking sources.",
          updates_published: 1,
        }),
      }),
      policy({ heartbeat_seconds: 30, min_interval_seconds: 10 }),
      NOW,
    );
    assert.equal(plan.disposition, "suppress");
    if (plan.disposition !== "suppress") return;
    assert.equal(plan.reason_code, "no_material_change");
  });

  test("publishes a heartbeat when the same phase persists past the interval", () => {
    const plan = planProgressNarration(
      request({
        event: event({ phase: "checking", sequence: 3, status: "Checking sources." }),
        state: state({
          last_phase: "checking",
          last_published_at: "2030-01-01T00:09:00.000Z",
          last_published_sequence: 2,
          last_status: "Checking sources.",
          updates_published: 1,
        }),
      }),
      policy({ heartbeat_seconds: 30, min_interval_seconds: 10 }),
      NOW,
    );
    assert.equal(plan.disposition, "publish");
  });
});

describe("progress narration validation", () => {
  test("rejects an out-of-bounds sequence and unsupported phase", () => {
    assert.throws(
      () => planProgressNarration(request({ event: event({ sequence: 0 }) }), policy(), NOW),
      /sequence is out of bounds/,
    );
    assert.throws(
      () => planProgressNarration(request({ event: event({ phase: "mystery" as never }) }), policy(), NOW),
      /Unsupported progress phase/,
    );
  });

  test("rejects invalid text, schema versions, and policy bounds", () => {
    assert.throws(
      () => planProgressNarration(request({ event: event({ status: "  " }) }), policy(), NOW),
      /status must be non-empty/,
    );
    assert.throws(
      () =>
        planProgressNarration(
          { ...request(), schema_version: "progress-narration-request/v2" as never },
          policy(),
          NOW,
        ),
      ProgressNarrationInvariantError,
    );
    assert.throws(
      () => planProgressNarration(request(), policy({ max_updates: 0 }), NOW),
      /max_updates must be a positive integer/,
    );
    assert.throws(() => planProgressNarration(request(), policy(), "nope"), /now must be an ISO timestamp/);
  });
});
