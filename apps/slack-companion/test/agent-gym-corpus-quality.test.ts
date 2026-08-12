import assert from "node:assert/strict";
import test from "node:test";

import {
  agentGymFixtureScenarioDigest,
  auditAgentGymCorpusLeakage,
  buildAgentGymCorpus,
  decideAgentGymCorpusAdmission,
  evaluateAgentGymCorpusCoverage,
  recordAgentGymCorpusQuality,
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

test("corpus coverage names missing partitions and protected slices", () => {
  const report = evaluateAgentGymCorpusCoverage([fixtureCase("train")], coveragePolicy());
  assert.equal(report.passed, false);
  assert.deepEqual(report.gaps, [
    {
      actual_case_count: 0,
      gap_code: "corpus.partition_underfilled",
      minimum_case_count: 1,
      partition: "held_out",
    },
    {
      actual_case_count: 0,
      gap_code: "corpus.slice_underfilled",
      label: "safety",
      minimum_case_count: 1,
      partition: "held_out",
    },
  ]);
});

test("corpus coverage passes explicit partition and slice minimums", () => {
  const report = evaluateAgentGymCorpusCoverage([
    fixtureCase("train"),
    fixtureCase("held-out", "held_out", ["safety"]),
  ], coveragePolicy());
  assert.equal(report.passed, true);
  assert.deepEqual(report.gaps, []);
});

test("corpus admission fails closed with stable blocker codes", () => {
  const decision = decideAgentGymCorpusAdmission([
    fixtureCase("train"),
    fixtureCase("held-out", "held_out", ["safety"]),
  ], coveragePolicy());
  assert.equal(decision.admitted, false);
  assert.deepEqual(decision.blocker_codes, ["corpus.partition_leakage"]);
  assert.match(decision.decision_digest, /^sha256:[0-9a-f]{64}$/u);
});

test("corpus admission accepts covered and isolated scenarios", () => {
  const heldOut = fixtureCase("held-out", "held_out", ["safety"]);
  const decision = decideAgentGymCorpusAdmission([
    fixtureCase("train"),
    { ...heldOut, slack_events: [{ ...heldOut.slack_events[0]!, payload: { text: "Held-out alert." } }] },
  ], coveragePolicy());
  assert.equal(decision.admitted, true);
  assert.deepEqual(decision.blocker_codes, []);
});

test("corpus quality receipts bind source build and admission evidence", () => {
  const fixtures = isolatedCorpus();
  const receipt = recordAgentGymCorpusQuality(
    buildAgentGymCorpus(fixtures, buildInput()),
    decideAgentGymCorpusAdmission(fixtures, coveragePolicy()),
    { evaluated_at: "2026-08-12T10:30:00.000Z", evaluation_ref: "agent-gym-quality://nightly/one" },
  );
  assert.equal(receipt.admitted, true);
  assert.match(receipt.receipt_digest, /^sha256:[0-9a-f]{64}$/u);
});

test("corpus quality receipts reject a decision for another corpus", () => {
  const fixtures = isolatedCorpus();
  assert.throws(() => recordAgentGymCorpusQuality(
    buildAgentGymCorpus([fixtureCase("train")], buildInput()),
    decideAgentGymCorpusAdmission(fixtures, coveragePolicy()),
    { evaluated_at: "2026-08-12T10:30:00.000Z", evaluation_ref: "agent-gym-quality://nightly/one" },
  ), /quality receipt is invalid/u);
});

function isolatedCorpus() {
  const heldOut = fixtureCase("held-out", "held_out", ["safety"]);
  return [
    fixtureCase("train"),
    { ...heldOut, slack_events: [{ ...heldOut.slack_events[0]!, payload: { text: "Held-out alert." } }] },
  ];
}

function buildInput() {
  return {
    build_ref: "agent-gym-corpus-build://nightly/quality",
    built_at: "2026-08-12T10:25:00.000Z",
    source_revision: "source-revision://cerebro/quality",
  };
}

function coveragePolicy() {
  return {
    minimum_partition_cases: { held_out: 1, shadow: 0, train: 1 },
    policy_ref: "agent-gym-corpus-policy://default/v1",
    required_slices: [{ label: "safety", minimum_case_count: 1, partition: "held_out" as const }],
    schema_version: "agent-gym-corpus-coverage-policy/v1" as const,
  };
}

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
