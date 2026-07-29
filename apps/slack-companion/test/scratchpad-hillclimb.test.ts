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
  assert.deepEqual(baseline.blockers, ["required_context_missing"]);
  assert.deepEqual(candidate.blockers, []);
});
