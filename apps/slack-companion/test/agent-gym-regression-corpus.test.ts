import assert from "node:assert/strict";
import test from "node:test";

import {
  digestAgentGymJson,
  validateAgentGymRegressionSanitization,
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
