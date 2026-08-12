import assert from "node:assert/strict";
import test from "node:test";

import {
  createAgentGymStaleEvidenceFixture,
  createAgentGymToolPageFixture,
} from "../src/index.js";

test("stale evidence fixtures use the replay clock", () => {
  const fixture = createAgentGymStaleEvidenceFixture({
    evaluated_at: "2026-08-12T09:05:00.000Z",
    evidence_ref: "evidence://one",
    max_age_ms: 60_000,
    observed_at: "2026-08-12T09:00:00.000Z",
  });
  assert.equal(fixture.age_ms, 300_000);
  assert.equal(fixture.stale, true);
});

test("stale evidence fixtures reject future observations", () => {
  assert.throws(() => createAgentGymStaleEvidenceFixture({
    evaluated_at: "2026-08-12T09:00:00.000Z",
    evidence_ref: "evidence://one",
    max_age_ms: 60_000,
    observed_at: "2026-08-12T09:05:00.000Z",
  }), /stale evidence fixture is invalid/u);
});

test("pagination fixtures retain a deterministic continuation boundary", () => {
  const fixture = createAgentGymToolPageFixture({
    call_ref: "tool-call://search/one",
    items: [{ evidence_ref: "evidence://one" }],
    next_cursor: "cursor-two",
    page_index: 0,
    tool_id: "cerebro.search",
  });
  assert.equal(fixture.next_cursor, "cursor-two");
  assert.equal(fixture.schema_version, "agent-gym-tool-page-fixture/v1");
  assert.equal(Object.isFrozen(fixture.items), true);
});

test("pagination fixtures reject invalid page indexes", () => {
  assert.throws(() => createAgentGymToolPageFixture({
    call_ref: "tool-call://search/one",
    items: [],
    next_cursor: null,
    page_index: -1,
    tool_id: "cerebro.search",
  }), /page fixture is invalid/u);
});
