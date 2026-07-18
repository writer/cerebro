import assert from "node:assert/strict";
import test from "node:test";
import type { AutonomousGoalRecord } from "../src/autonomy/goals.js";
import { reconcileTeammateGoals, verifiedTeammateGoalPromptBlock } from "../src/agent/teammate-goals.js";

test("unfinished teammate commitments reflect verified goal state", async () => {
  const goal = activeGoal();
  const result = await reconcileTeammateGoals({
    answer: answerWithCommitment("goal-1"),
    question: { channelId: "CSEC", userId: "UUSER", ts: "1784000010.000000", threadTs: "1784000010.000000", question: "Land it." },
    goals: { get: async (id) => id === goal.id ? goal : undefined },
  });
  const commitment = result.answer.teammate?.commitments[0];
  assert.equal(result.reconciliation.linked, 1);
  assert.equal(commitment?.status, "in_progress");
  assert.equal(commitment?.goalStatus, "active");
  assert.equal(commitment?.nextAction, "Run the verification suite");
  assert.deepEqual(commitment?.acceptanceCriteria, ["All checks pass [pending]"]);
  assert.match(commitment?.verification ?? "", /0 of 1 acceptance criteria passed/);
  assert.ok(commitment?.artifactRefs.includes("goal:goal-1"));
});

test("unpersisted or missing goals cannot remain active teammate promises", async () => {
  const unbacked = await reconcileTeammateGoals({
    answer: answerWithCommitment(),
    question: { channelId: "CSEC", ts: "1784000011.000000", question: "Land it." },
  });
  assert.equal(unbacked.reconciliation.unbacked, 1);
  assert.equal(unbacked.answer.teammate?.commitments[0]?.status, "blocked");
  assert.match(unbacked.answer.teammate?.commitments[0]?.blocker ?? "", /No follow-up run is scheduled/);
  assert.equal(unbacked.answer.presentationReady, false);
  assert.match(unbacked.answer.messages.join(" "), /Remaining: Land the change/);
  assert.match(unbacked.answer.messages.join(" "), /No follow-up run is scheduled/);
  assert.doesNotMatch(unbacked.answer.messages.join(" "), /durable goal|ping me/i);
  assert.doesNotMatch(unbacked.answer.messages.join(" "), /I own the remaining verification/);

  const missing = await reconcileTeammateGoals({
    answer: answerWithCommitment("goal-missing"),
    question: { channelId: "CSEC", ts: "1784000011.000000", question: "Land it." },
    goals: { get: async () => undefined },
  });
  assert.equal(missing.reconciliation.missing, 1);
  assert.equal(missing.answer.teammate?.commitments[0]?.goalStatus, undefined);
  assert.match(missing.answer.teammate?.commitments[0]?.verification ?? "", /follow-up run could not be verified/);
  assert.doesNotMatch(missing.answer.messages.join(" "), /durable goal|ping me/i);
});

test("the host links one created goal when the model omits its id", async () => {
  const goal = activeGoal();
  const result = await reconcileTeammateGoals({
    answer: answerWithCommitment(),
    question: { channelId: "CSEC", ts: "1784000010.000000", threadTs: "1784000010.000000", question: "Land it." },
    goals: { get: async () => goal },
    createdGoalIds: [goal.id],
  });
  assert.equal(result.reconciliation.linked, 1);
  assert.equal(result.reconciliation.unbacked, 0);
  assert.equal(result.answer.teammate?.commitments[0]?.goalId, goal.id);
});

test("later turns receive refreshed goal evidence instead of stale commitment state", async () => {
  const goal = activeGoal();
  const prompt = await verifiedTeammateGoalPromptBlock({
    state: {
      resolvedScope: [],
      scopeAssumptions: [],
      commitments: [{ id: "land", summary: "Land the change.", status: "in_progress", artifactRefs: [], goalId: goal.id }],
      openLoops: [],
    },
    goals: { get: async () => goal },
    channelId: "CSEC",
    threadTs: "1784000010.000000",
  });
  assert.match(prompt, /Verified teammate goal state/);
  assert.match(prompt, /Run the verification suite/);
  assert.match(prompt, /All checks pass/);
  assert.match(prompt, /goal-1/);
});

function answerWithCommitment(goalId?: string): any {
  return {
    executionLane: "act",
    answer: "I own the remaining verification.",
    messages: ["I own the remaining verification."],
    keyPoints: [], evidence: ["PR 12 is open."], actionsTaken: [], nextActions: ["Run checks."], research: ["github_pr: checked"], memoryUpdates: [], source: "flue",
    teammate: {
      objective: "Land the change.",
      desiredOutcome: "The change is merged with passing checks.",
      resolvedScope: ["pr:12"],
      scopeAssumptions: [],
      commitments: [{ id: "land", summary: "Land the change.", status: "in_progress", nextAction: "Run checks.", artifactRefs: [], goalId }],
      openLoops: [],
      userDecision: { required: false },
    },
  };
}

function activeGoal(): AutonomousGoalRecord {
  return {
    id: "goal-1",
    status: "active",
    capabilityId: "executor",
    objective: "Land the change.",
    channelId: "CSEC",
    threadTs: "1784000010.000000",
    createdBy: { slackUserId: "UUSER" },
    createdAt: "2026-07-14T12:00:00.000Z",
    updatedAt: "2026-07-14T12:05:00.000Z",
    currentPlan: [{ id: "verify", title: "Run the verification suite", status: "active", dependsOn: [] }],
    activeStepId: "verify",
    assumptions: [], blockers: [], artifactUrls: [], resourceRefs: [], artifacts: [], corrections: [], toolRuns: [], approvals: [], workLog: [],
    acceptanceCriteria: [{ id: "checks", description: "All checks pass", kind: "tool_success", status: "pending", evidenceRefs: [] }],
    nextWakeAt: "2026-07-14T12:10:00.000Z",
  };
}
