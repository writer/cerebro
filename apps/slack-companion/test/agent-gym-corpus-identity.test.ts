import assert from "node:assert/strict";
import test from "node:test";

import {
  agentGymFixtureCaseDigest,
  canonicalAgentGymJson,
  digestAgentGymJson,
} from "../src/index.js";

test("canonical agent-gym JSON ignores object insertion order", () => {
  const first = { beta: [true, null], alpha: { two: 2, one: 1 } };
  const second = { alpha: { one: 1, two: 2 }, beta: [true, null] };
  assert.equal(canonicalAgentGymJson(first), canonicalAgentGymJson(second));
  assert.equal(digestAgentGymJson(first), digestAgentGymJson(second));
});

test("canonical agent-gym JSON rejects non-data properties", () => {
  const value = Object.defineProperty({ visible: true }, "hidden", { value: 1 });
  assert.throws(
    () => canonicalAgentGymJson(value),
    /canonical JSON is invalid/u,
  );
});

test("fixture case digests bind the complete portable scenario", () => {
  const first = fixtureCase();
  const second = { ...fixtureCase(), labels: ["safety", "support"] };
  assert.notEqual(agentGymFixtureCaseDigest(first), agentGymFixtureCaseDigest(second));
});

test("fixture case digests are stable across object insertion order", () => {
  const fixture = fixtureCase();
  const reordered = {
    tool_fixtures: fixture.tool_fixtures,
    slack_events: fixture.slack_events,
    schema_version: fixture.schema_version,
    partition: fixture.partition,
    labels: fixture.labels,
    expected_invariants: fixture.expected_invariants,
    case_ref: fixture.case_ref,
  };
  assert.equal(agentGymFixtureCaseDigest(fixture), agentGymFixtureCaseDigest(reordered));
});

function fixtureCase() {
  return {
    case_ref: "agent-gym-case://support/one",
    expected_invariants: ["answer-grounded"],
    labels: ["support"],
    partition: "train" as const,
    schema_version: "agent-gym-fixture-case/v1" as const,
    slack_events: [{
      event_ref: "slack-event://one",
      kind: "mention" as const,
      occurred_at: "2026-08-12T10:00:00.000Z",
      payload: { text: "Help with this alert." },
    }],
    tool_fixtures: [{
      call_ref: "tool-call://one",
      input: { alert_ref: "alert://one" },
      outcome: "success" as const,
      output: { severity: "high" },
      tool_id: "alerts.read",
    }],
  };
}
