import assert from "node:assert/strict";
import test from "node:test";

import {
  agentGymFixtureScenarioDigest,
  auditAgentGymCorpusLeakage,
} from "../src/index.js";

test("scenario digests ignore case metadata and partition", () => {
  const renamed = fixtureCase("two", "held_out", ["regression"]);
  assert.equal(
    agentGymFixtureScenarioDigest(fixtureCase("one", "train", ["support"])),
    agentGymFixtureScenarioDigest({
      ...renamed,
      slack_events: [{
        ...renamed.slack_events[0]!,
        event_ref: "slack-event://quality/renamed",
        occurred_at: "2026-08-13T08:00:00.000Z",
      }],
      tool_fixtures: [{
        ...renamed.tool_fixtures[0]!,
        call_ref: "tool-call://quality/renamed",
      }],
    }),
  );
});

test("scenario digests change when replay content changes", () => {
  const first = fixtureCase("one");
  const second = {
    ...fixtureCase("two"),
    slack_events: [{ ...fixtureCase("two").slack_events[0]!, payload: { text: "Different request." } }],
  };
  assert.notEqual(
    agentGymFixtureScenarioDigest(first),
    agentGymFixtureScenarioDigest(second),
  );
});

test("corpus leakage reports scenarios copied into held-out evaluation", () => {
  const report = auditAgentGymCorpusLeakage([
    fixtureCase("train", "train"),
    fixtureCase("evaluation", "held_out"),
  ]);
  assert.equal(report.passed, false);
  assert.equal(report.findings[0]?.finding_code, "corpus.partition_leakage");
  assert.deepEqual(report.findings[0]?.partitions, ["held_out", "train"]);
});

test("corpus leakage passes distinct replay scenarios", () => {
  const second = fixtureCase("held-out", "held_out");
  const report = auditAgentGymCorpusLeakage([
    fixtureCase("train"),
    { ...second, slack_events: [{ ...second.slack_events[0]!, payload: { text: "Another alert." } }] },
  ]);
  assert.equal(report.passed, true);
  assert.deepEqual(report.findings, []);
});

function fixtureCase(
  suffix: string,
  partition: "held_out" | "shadow" | "train" = "train",
  labels: readonly string[] = ["support"],
) {
  return {
    case_ref: `agent-gym-case://quality/${suffix}`,
    expected_invariants: ["answer-grounded"],
    labels,
    partition,
    schema_version: "agent-gym-fixture-case/v1" as const,
    slack_events: [{
      event_ref: "slack-event://quality/one",
      kind: "mention" as const,
      occurred_at: "2026-08-12T10:20:00.000Z",
      payload: { text: "Help with this alert." },
    }],
    tool_fixtures: [{
      call_ref: "tool-call://quality/one",
      input: { alert_ref: "alert://quality/one" },
      outcome: "success" as const,
      output: { severity: "high" },
      tool_id: "alerts.read",
    }],
  };
}
