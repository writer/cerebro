import assert from "node:assert/strict";
import test from "node:test";

import {
  digestAgentGymJson,
  agentGymFixtureScenarioDigest,
  augmentAgentGymRegressionCorpus,
  buildAgentGymRegressionFixture,
  inspectAgentGymRegressionDuplicates,
  validateAgentGymRegressionSanitization,
  validateAgentGymRegressionDuplicateReport,
  validateAgentGymRegressionFixtureReceipt,
  validateAgentGymRegressionCorpusAugmentation,
  type AgentGymFixtureCaseV1,
  verifyAgentGymRegressionSanitization,
  type AgentGymRegressionLearningCandidateV1,
} from "../src/index.js";

test("regression sanitization seals a public-safe scenario digest", () => {
  const receipt = verifyAgentGymRegressionSanitization(learningCandidate(), {
    evidence_refs: ["agent-gym-evidence://sanitization/one"],
    prohibited_value_count: 0,
    redaction_count: 3,
    sanitized_scenario_digest: digest("b"),
    sanitizer_ref: "agent-gym-sanitizer://portable/default",
    source_content_digest: digest("c"),
    verified_at: "2026-08-12T11:38:00.000Z",
    verification_ref: "agent-gym-regression-sanitization://nightly/one",
  });
  assert.deepEqual(validateAgentGymRegressionSanitization(receipt), receipt);
});

test("regression sanitization rejects remaining prohibited values", () => {
  assert.throws(() => verifyAgentGymRegressionSanitization(learningCandidate(), {
    evidence_refs: ["agent-gym-evidence://sanitization/invalid"],
    prohibited_value_count: 1 as 0,
    redaction_count: 3,
    sanitized_scenario_digest: digest("b"),
    sanitizer_ref: "agent-gym-sanitizer://portable/default",
    source_content_digest: digest("c"),
    verified_at: "2026-08-12T11:38:00.000Z",
    verification_ref: "agent-gym-regression-sanitization://nightly/invalid",
  }), /regression sanitization is invalid/u);
});

test("regression duplicate reports admit a distinct scenario", () => {
  const report = inspectAgentGymRegressionDuplicates(sanitization(digest("b")), [fixtureCase()],
    "agent-gym-regression-duplicate-report://nightly/one");
  assert.equal(report.admissible, true);
  assert.deepEqual(validateAgentGymRegressionDuplicateReport(report), report);
});

test("regression duplicate reports name matching existing cases", () => {
  const fixture = fixtureCase();
  const report = inspectAgentGymRegressionDuplicates(sanitization(agentGymFixtureScenarioDigest(fixture)), [fixture],
    "agent-gym-regression-duplicate-report://nightly/duplicate");
  assert.equal(report.admissible, false);
  assert.deepEqual(report.duplicate_case_refs, [fixture.case_ref]);
});

test("regression fixtures bind sanitized admitted scenarios to training cases", () => {
  const fixture = fixtureCase("agent-gym-case://regression/new", ["live_sample_failed", "regression"]);
  const receipt = regressionFixtureReceipt(fixture);
  assert.equal(receipt.fixture_digest.length, 71);
  assert.deepEqual(validateAgentGymRegressionFixtureReceipt(receipt), receipt);
});

test("regression fixtures cannot place incident-derived cases in held-out data", () => {
  const fixture = { ...fixtureCase("agent-gym-case://regression/invalid", ["live_sample_failed"]), partition: "held_out" as const };
  const proof = sanitization(agentGymFixtureScenarioDigest(fixture));
  const report = inspectAgentGymRegressionDuplicates(proof, [], "agent-gym-regression-duplicate-report://nightly/new");
  assert.throws(() => buildAgentGymRegressionFixture(learningCandidate(), proof, report, fixture,
    "agent-gym-regression-fixture-receipt://nightly/invalid"), /regression fixture receipt is invalid/u);
});

test("regression corpus augmentation binds the append-only manifest transition", () => {
  const fixture = fixtureCase("agent-gym-case://regression/new", ["live_sample_failed"]);
  const augmentation = augmentAgentGymRegressionCorpus([fixtureCase()], regressionFixtureReceipt(fixture), {
    augmented_at: "2026-08-12T11:39:00.000Z",
    augmentation_ref: "agent-gym-regression-corpus-augmentation://nightly/one",
  });
  assert.equal(augmentation.next_case_count, augmentation.previous_case_count + 1);
  assert.deepEqual(validateAgentGymRegressionCorpusAugmentation(augmentation), augmentation);
});

test("regression corpus augmentation rejects scenario duplicates", () => {
  const fixture = fixtureCase("agent-gym-case://regression/new", ["live_sample_failed"]);
  assert.throws(() => augmentAgentGymRegressionCorpus([
    { ...fixture, case_ref: "agent-gym-case://existing/same-scenario" },
  ], regressionFixtureReceipt(fixture), {
    augmented_at: "2026-08-12T11:39:00.000Z",
    augmentation_ref: "agent-gym-regression-corpus-augmentation://nightly/invalid",
  }), /corpus augmentation is invalid/u);
});

function regressionFixtureReceipt(fixture: AgentGymFixtureCaseV1) {
  const proof = sanitization(agentGymFixtureScenarioDigest(fixture));
  const report = inspectAgentGymRegressionDuplicates(proof, [], "agent-gym-regression-duplicate-report://nightly/new");
  return buildAgentGymRegressionFixture(learningCandidate(), proof, report, fixture,
    "agent-gym-regression-fixture-receipt://nightly/new");
}

function sanitization(scenarioDigest: string) {
  return verifyAgentGymRegressionSanitization(learningCandidate(), {
    evidence_refs: ["agent-gym-evidence://sanitization/one"], prohibited_value_count: 0, redaction_count: 3,
    sanitized_scenario_digest: scenarioDigest, sanitizer_ref: "agent-gym-sanitizer://portable/default",
    source_content_digest: digest("c"), verified_at: "2026-08-12T11:38:00.000Z",
    verification_ref: "agent-gym-regression-sanitization://nightly/one",
  });
}

function fixtureCase(caseRef = "agent-gym-case://existing/one", labels = ["regression"]): AgentGymFixtureCaseV1 {
  return {
    case_ref: caseRef, expected_invariants: ["answer_is_grounded"], labels,
    partition: "train", schema_version: "agent-gym-fixture-case/v1",
    slack_events: [{ event_ref: "agent-gym-event://existing/one", kind: "mention",
      occurred_at: "2026-08-12T11:00:00.000Z", payload: { case_ref: caseRef, text: "sanitized request" } }], tool_fixtures: [],
  };
}

function learningCandidate(): AgentGymRegressionLearningCandidateV1 {
  const body = {
    candidate_ref: "agent-gym-regression-learning-candidate://nightly/one",
    evidence_refs: ["agent-gym-evidence://learning/regression-one"],
    expected_candidate_ref: "agent-gym-candidate://nightly/baseline",
    failure_labels: ["live_sample_failed"],
    proposed_at: "2026-08-12T11:37:00.000Z",
    rollback_incident_digest: digest("a"),
    schema_version: "agent-gym-regression-learning-candidate/v1" as const,
    source_case_ref: "agent-gym-source-case://post-rollout/regression-one",
    target_ref: "agent-gym-target://slack-companion/default",
  };
  return { ...body, candidate_digest: digestAgentGymJson(body) };
}

function digest(character: string): string { return `sha256:${character.repeat(64)}`; }
