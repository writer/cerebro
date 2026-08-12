import assert from "node:assert/strict";
import test from "node:test";

import {
  createAgentGymAuthorizationFixture,
  createAgentGymStaleEvidenceFixture,
  createAgentGymToolPageFixture,
  createAgentGymToolRegistry,
  validateAgentGymToolCall,
} from "../src/index.js";

test("tool-call validation reports missing required input", () => {
  const registry = createAgentGymToolRegistry([{
    description: "Read current evidence.",
    input_schema: {
      additionalProperties: false,
      properties: { query: { type: "string" } },
      required: ["query"],
      type: "object",
    },
    tool_id: "cerebro.search",
  }]);
  const validation = validateAgentGymToolCall(registry, {
    call_ref: "tool-call://search/one",
    input: {},
    tool_id: "cerebro.search",
  });
  assert.equal(validation.valid, false);
  assert.deepEqual(validation.issues, ["$.query:input.required_missing"]);
});

test("tool-call validation accepts schema-conforming input", () => {
  const registry = createAgentGymToolRegistry([{
    description: "Read current evidence.",
    input_schema: {
      additionalProperties: false,
      properties: { query: { type: "string" } },
      required: ["query"],
      type: "object",
    },
    tool_id: "cerebro.search",
  }]);
  const validation = validateAgentGymToolCall(registry, {
    call_ref: "tool-call://search/one",
    input: { query: "current evidence" },
    tool_id: "cerebro.search",
  });
  assert.equal(validation.valid, true);
  assert.deepEqual(validation.issues, []);
});

test("authorization fixtures retain the policy evidence for a denial", () => {
  const fixture = createAgentGymAuthorizationFixture({
    action: "evidence.read",
    decision: "deny",
    policy_ref: "policy://evidence-reader/v3",
    principal_ref: "principal://user/U123",
    reason_code: "principal.not_entitled",
    request_ref: "authorization-request://one",
    resource_ref: "evidence://one",
  });
  assert.equal(fixture.decision, "deny");
  assert.equal(fixture.policy_ref, "policy://evidence-reader/v3");
});

test("authorization fixtures fail closed on unknown decisions", () => {
  assert.throws(() => createAgentGymAuthorizationFixture({
    action: "evidence.read",
    decision: "unknown" as "allow",
    policy_ref: "policy://evidence-reader/v3",
    principal_ref: "principal://user/U123",
    reason_code: "decision.unavailable",
    request_ref: "authorization-request://one",
    resource_ref: "evidence://one",
  }), /authorization fixture is invalid/u);
});

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
