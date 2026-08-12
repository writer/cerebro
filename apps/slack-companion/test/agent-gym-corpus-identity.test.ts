import assert from "node:assert/strict";
import test from "node:test";

import {
  agentGymFixtureCaseDigest,
  canonicalAgentGymJson,
  createAgentGymCorpusInventory,
  createAgentGymCorpusManifest,
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

test("corpus manifests are stable across fixture input order", () => {
  const first = fixtureCase("agent-gym-case://support/one");
  const second = fixtureCase("agent-gym-case://support/two");
  assert.deepEqual(
    createAgentGymCorpusManifest([first, second]),
    createAgentGymCorpusManifest([second, first]),
  );
});

test("corpus manifests reject duplicate case references", () => {
  assert.throws(
    () => createAgentGymCorpusManifest([fixtureCase(), fixtureCase()]),
    /corpus manifest is invalid/u,
  );
});

test("corpus inventories count every partition and label", () => {
  const inventory = createAgentGymCorpusInventory([
    fixtureCase("agent-gym-case://support/one", "train", ["support", "safety"]),
    fixtureCase("agent-gym-case://support/two", "held_out", ["support"]),
  ]);
  assert.deepEqual(inventory.partitions, { held_out: 1, shadow: 0, train: 1 });
  assert.deepEqual(inventory.labels, [
    { case_count: 1, label: "safety" },
    { case_count: 2, label: "support" },
  ]);
});

test("corpus inventories bind the manifest digest", () => {
  const fixtures = [fixtureCase()];
  assert.equal(
    createAgentGymCorpusInventory(fixtures).corpus_digest,
    createAgentGymCorpusManifest(fixtures).corpus_digest,
  );
});

function fixtureCase(
  caseRef = "agent-gym-case://support/one",
  partition: "held_out" | "shadow" | "train" = "train",
  labels: readonly string[] = ["support"],
) {
  return {
    case_ref: caseRef,
    expected_invariants: ["answer-grounded"],
    labels,
    partition,
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
