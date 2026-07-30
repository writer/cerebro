import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  evaluateSlackWorkingStateCase,
  runSlackWorkingStateHillclimb,
  SLACK_WORKING_STATE_HILLCLIMB_CORPUS,
} from "../src/index.js";

test("hillclimb CLI runs inside the enforced offline boundary", () => {
  const runner = fileURLToPath(
    new URL("../src/scratchpad/run-hillclimb-offline.js", import.meta.url),
  );
  const result = spawnSync(process.execPath, [
    "--permission",
    "--allow-fs-read=.",
    runner,
  ], {
    cwd: fileURLToPath(new URL("..", import.meta.url)),
    encoding: "utf8",
  });

  assert.equal(result.status, 0, result.stderr);
  const receipt = JSON.parse(result.stdout) as {
    offline_execution: {
      child_process_access: string;
      filesystem_write_access: string;
      native_addon_access: string;
      network_access: string;
      network_probe: string;
      schema_version: string;
      worker_access: string;
    };
    promotion: { promotion_ready: boolean };
  };
  assert.deepEqual(receipt.offline_execution, {
    child_process_access: "denied",
    filesystem_write_access: "denied",
    native_addon_access: "denied",
    network_access: "denied",
    network_probe: "passed",
    schema_version: "slack-working-state-offline-execution/v1",
    worker_access: "denied",
  });
  assert.equal(receipt.promotion.promotion_ready, true);
});

test("working-state candidate clears the sealed hillclimb goal", () => {
  const receipt = runSlackWorkingStateHillclimb(
    SLACK_WORKING_STATE_HILLCLIMB_CORPUS,
    new Date("2026-07-29T12:00:00.000Z"),
  );

  assert.equal(receipt.baseline.context_recall_rate, 0);
  assert.equal(receipt.baseline.restatement_risk_rate, 1);
  assert.equal(receipt.candidate.context_recall_rate, 1);
  assert.equal(receipt.baseline.semantic_state_contract_rate, 0.0909);
  assert.equal(receipt.candidate.semantic_state_contract_rate, 1);
  assert.equal(receipt.baseline.evidence_context_retention_rate, 0);
  assert.equal(receipt.candidate.evidence_context_retention_rate, 1);
  assert.equal(receipt.baseline.expected_restatement_turns_per_case, 0.9091);
  assert.equal(receipt.candidate.expected_restatement_turns_per_case, 0);
  assert.equal(receipt.candidate.restatement_risk_rate, 0);
  assert.equal(receipt.candidate.authority_boundary_rate, 1);
  assert.equal(receipt.candidate.byte_limit_violation_count, 0);
  assert.equal(receipt.promotion.context_recall_gain, 1);
  assert.equal(receipt.promotion.regression_count, 0);
  assert.deepEqual(receipt.promotion.blockers, []);
  assert.equal(receipt.promotion.promotion_ready, true);
  assert.equal(receipt.baseline.held_out_case_count, 11);
  assert.equal(receipt.baseline.shadow_case_count, 11);
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
