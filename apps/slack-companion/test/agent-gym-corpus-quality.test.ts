import assert from "node:assert/strict";
import test from "node:test";

import { agentGymFixtureScenarioDigest } from "../src/index.js";

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
