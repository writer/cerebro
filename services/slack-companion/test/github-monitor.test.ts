import assert from "node:assert/strict";
import test from "node:test";
import { githubMonitorDecision, githubMonitorTarget, githubMonitorTargetLabel } from "../src/autonomy/github-monitor.js";

test("GitHub monitor target prefers PR artifact URLs", () => {
  const target = githubMonitorTarget({
    objective: "watch PR #12",
    artifactUrls: ["https://github.com/WriterInternal/cerebro-slack-companion/pull/76"],
  });

  assert.deepEqual(target, {
    kind: "pull_request",
    source: "artifact_url",
    repo: "WriterInternal/cerebro-slack-companion",
    pullNumber: 76,
  });
  assert.equal(githubMonitorTargetLabel(target!), "WriterInternal/cerebro-slack-companion PR #76");
});

test("GitHub monitor target reads PR numbers and refs from the objective", () => {
  assert.deepEqual(githubMonitorTarget({
    objective: "watch PR #17",
    artifactUrls: [],
  }), {
    kind: "pull_request",
    source: "objective",
    pullNumber: 17,
  });

  assert.deepEqual(githubMonitorTarget({
    objective: "watch commit 55085b7",
    artifactUrls: [],
  }), {
    kind: "ref",
    source: "objective",
    ref: "55085b7",
  });
});

test("GitHub monitor decision summarizes merged pending passed and failed states", () => {
  assert.deepEqual(githubMonitorDecision({
    pull_request: { number: 76, merged: true },
    checks: { summary: { state: "passed", passed: 4, pending: 0, failed: 0 } },
  }), {
    state: "merged",
    summary: "Pull request #76 is merged.",
    passed: 0,
    pending: 0,
    failed: 0,
  });

  assert.equal(githubMonitorDecision({ checks: { summary: { state: "pending", passed: 2, pending: 1, failed: 0 } } }).state, "pending");
  assert.equal(githubMonitorDecision({ checks: { summary: { state: "passed", passed: 3, pending: 0, failed: 0 } } }).state, "passed");
  assert.equal(githubMonitorDecision({ checks: { summary: { state: "failed", passed: 2, pending: 0, failed: 1 } } }).state, "failed");
  assert.equal(githubMonitorDecision({ checks: { summary: { state: "unknown", passed: 0, pending: 0, failed: 0 } } }).state, "unknown");
});
