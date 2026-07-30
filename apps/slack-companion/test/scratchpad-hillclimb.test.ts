import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateSlackWorkingStateCase,
  runSlackWorkingStateHillclimb,
  SLACK_WORKING_STATE_HILLCLIMB_CORPUS,
} from "../src/index.js";

test("working-state candidate clears the sealed hillclimb goal", () => {
  const receipt = runSlackWorkingStateHillclimb(
    SLACK_WORKING_STATE_HILLCLIMB_CORPUS,
    new Date("2026-07-29T12:00:00.000Z"),
  );

  assert.equal(receipt.baseline.context_recall_rate, 0);
  assert.equal(receipt.baseline.restatement_risk_rate, 1);
  assert.equal(receipt.candidate.context_recall_rate, 1);
  assert.equal(receipt.baseline.semantic_state_contract_rate, 0.1);
  assert.equal(receipt.candidate.semantic_state_contract_rate, 1);
  assert.equal(receipt.baseline.evidence_context_retention_rate, 0);
  assert.equal(receipt.candidate.evidence_context_retention_rate, 1);
  assert.equal(receipt.baseline.expected_restatement_turns_per_case, 0.9);
  assert.equal(receipt.candidate.expected_restatement_turns_per_case, 0);
  assert.equal(receipt.candidate.restatement_risk_rate, 0);
  assert.equal(receipt.candidate.authority_boundary_rate, 1);
  assert.equal(receipt.candidate.byte_limit_violation_count, 0);
  assert.equal(receipt.promotion.context_recall_gain, 1);
  assert.equal(receipt.promotion.regression_count, 0);
  assert.deepEqual(receipt.promotion.blockers, []);
  assert.equal(receipt.promotion.promotion_ready, true);
  assert.equal(receipt.baseline.held_out_case_count, 10);
  assert.equal(receipt.baseline.shadow_case_count, 10);
});

test("hillclimb rejects a corpus without independently partitioned coverage", () => {
  assert.throws(
    () => runSlackWorkingStateHillclimb(
      SLACK_WORKING_STATE_HILLCLIMB_CORPUS.filter((evalCase) =>
        evalCase.partition === "held_out"
      ),
    ),
    /at least 8 held-out and shadow cases/u,
  );
});

test("baseline and candidate are evaluated against one exact case digest", () => {
  const evalCase = SLACK_WORKING_STATE_HILLCLIMB_CORPUS[0]!;
  const baseline = evaluateSlackWorkingStateCase(evalCase, "baseline");
  const candidate = evaluateSlackWorkingStateCase(evalCase, "candidate");

  assert.equal(baseline.case_digest, candidate.case_digest);
  assert.equal(baseline.case_ref, candidate.case_ref);
  assert.notEqual(baseline.policy_ref, candidate.policy_ref);
  assert.deepEqual(baseline.blockers, [
    "required_context_missing",
    "evidence_context_missing",
  ]);
  assert.deepEqual(candidate.blockers, []);
});

test("candidate fails a case when evidence instructions are not retained", () => {
  const source = SLACK_WORKING_STATE_HILLCLIMB_CORPUS[0]!;
  const result = evaluateSlackWorkingStateCase({
    ...source,
    evidence_context: ["cite the unavailable source receipt"],
  }, "candidate");

  assert.equal(result.retained_evidence_context_count, 0);
  assert.ok(result.blockers.includes("evidence_context_missing"));
  assert.equal(result.passed, false);
});

test("promotion stops when the candidate drops required evidence context", () => {
  const corpus = SLACK_WORKING_STATE_HILLCLIMB_CORPUS.map((evalCase, index) =>
    index === 0
      ? {
        ...evalCase,
        evidence_context: ["cite the unavailable source receipt"],
      }
      : evalCase
  );
  const receipt = runSlackWorkingStateHillclimb(corpus);

  assert.ok(
    receipt.promotion.blockers.includes(
      "candidate_evidence_context_retention_below_goal",
    ),
  );
  assert.equal(receipt.promotion.promotion_ready, false);
});
