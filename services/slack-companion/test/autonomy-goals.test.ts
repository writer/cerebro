import assert from "node:assert/strict";
import test from "node:test";
import { AutonomyGoalService } from "../src/autonomy/goal-service.js";
import { InMemoryAutonomyGoalStore, type AutonomyPlanStep } from "../src/autonomy/goals.js";
import { testConfig } from "./fixtures.js";

test("autonomy goal store creates durable goal records with initial work log", async () => {
  const store = new InMemoryAutonomyGoalStore(() => new Date("2026-06-26T20:00:00.000Z"));
  const plan: AutonomyPlanStep[] = [{
    id: "inspect",
    title: "Inspect current agent tools",
    status: "pending",
    dependsOn: [],
  }];

  const goal = await store.create({
    objective: "Make Cerebro more autonomous",
    channelId: "CSEC",
    threadTs: "1782500000.000000",
    createdBy: { slackUserId: "UUSER", actorId: "actor-1", displayName: "Operator" },
    assumptions: ["Use exfil controls as the hard boundary."],
    plan,
  });

  assert.match(goal.id, /^goal-/);
  assert.equal(goal.status, "active");
  assert.equal(goal.capabilityId, "planner");
  assert.equal(goal.objective, "Make Cerebro more autonomous");
  assert.deepEqual(goal.currentPlan, plan);
  assert.deepEqual(goal.toolRuns, []);
  assert.deepEqual(goal.approvals, []);
  assert.equal(goal.workLog[0]?.kind, "goal_created");
  assert.match(goal.workLog[0]?.summary ?? "", /Goal created/);
});

test("autonomy goal store updates state and appends work log entries", async () => {
  const dates = [
    new Date("2026-06-26T20:00:00.000Z"),
    new Date("2026-06-26T20:01:00.000Z"),
    new Date("2026-06-26T20:02:00.000Z"),
  ];
  const store = new InMemoryAutonomyGoalStore(() => dates.shift() ?? new Date("2026-06-26T20:03:00.000Z"));
  const goal = await store.create({
    objective: "Debug CI and merge the PR",
    createdBy: { slackUserId: "UUSER" },
  });

  const updated = await store.update(goal.id, {
    status: "waiting",
    activeStepId: "watch-checks",
    artifactUrls: ["https://github.com/WriterInternal/cerebro-slack-companion/pull/17"],
    nextWakeAt: "2026-06-26T20:05:00.000Z",
  });
  assert.equal(updated.status, "waiting");
  assert.equal(updated.activeStepId, "watch-checks");
  assert.equal(updated.updatedAt, "2026-06-26T20:01:00.000Z");

  const logged = await store.appendLog(goal.id, {
    kind: "check_result",
    summary: "CI passed.",
    artifactUrl: "https://github.com/WriterInternal/cerebro-slack-companion/actions",
  });
  assert.equal(logged.workLog.at(-1)?.kind, "check_result");
  assert.equal(logged.workLog.at(-1)?.summary, "CI passed.");
  assert.equal(logged.updatedAt, "2026-06-26T20:02:00.000Z");
});

test("autonomy goal store filters by status and returns defensive copies", async () => {
  const store = new InMemoryAutonomyGoalStore(() => new Date("2026-06-26T20:00:00.000Z"));
  const active = await store.create({ objective: "Active goal", createdBy: {} });
  const paused = await store.create({ objective: "Paused goal", createdBy: {} });
  await store.update(paused.id, { status: "paused" });

  const activeGoals = await store.list("active");
  assert.deepEqual(activeGoals.map((goal) => goal.id), [active.id]);

  const fetched = await store.get(active.id);
  assert.ok(fetched);
  fetched.assumptions.push("mutated outside store");

  const refetched = await store.get(active.id);
  assert.deepEqual(refetched?.assumptions, []);
});

test("autonomy goal service creates goals and logs operator status changes", async () => {
  const dates = [
    new Date("2026-06-26T20:00:00.000Z"),
    new Date("2026-06-26T20:01:00.000Z"),
    new Date("2026-06-26T20:02:00.000Z"),
  ];
  const store = new InMemoryAutonomyGoalStore(() => dates.shift() ?? new Date("2026-06-26T20:03:00.000Z"));
  const service = new AutonomyGoalService(testConfig(), { store });

  const goal = await service.createFromText({
    text: "Open a PR that gives Cerebro check watching",
    actor: { slackUserId: "UUSER", actorId: "actor-1", displayName: "Operator" },
    channelId: "CSEC",
  });
  assert.equal(goal.status, "active");
  assert.equal(goal.currentPlan[0]?.id, "inspect-context");

  const paused = await service.setStatus({
    goalId: goal.id.slice(-8),
    status: "paused",
    actor: { slackUserId: "UUSER", actorId: "actor-1", displayName: "Operator" },
  });
  assert.equal(paused.status, "paused");
  assert.equal(paused.workLog.at(-1)?.kind, "decision_made");
  assert.match(paused.workLog.at(-1)?.summary ?? "", /Paused by Operator/);
});

test("autonomy goal service stores execution contract from Cerebro control plane", async () => {
  const now = () => new Date("2026-06-26T20:00:00.000Z");
  const store = new InMemoryAutonomyGoalStore(now);
  const service = new AutonomyGoalService(testConfig(), {
    store,
    now,
    cerebro: {
      getAgentControlPlane: async () => ({
        version: "2026-06-17.cerebro-agent-platform",
        agentProfiles: [{
          id: "remediation-executor",
          defaultOn: false,
          maxActionStage: "execute",
          requiredVerifierIds: ["tenant-scope", "human-approval"],
        }],
        verifierLayer: [{ id: "tenant-scope" }, { id: "human-approval" }],
        actionLadder: [],
        evalScenarios: [],
        connectorToolGateIds: [],
      }),
    },
  });

  const goal = await service.createFromText({
    text: "execute approved remediation for finding-1",
    actor: { slackUserId: "UUSER", actorId: "actor-1" },
    channelId: "CSEC",
  });
  const refetched = await store.get(goal.id);

  assert.equal(goal.capabilityId, "executor");
  assert.equal(refetched?.executionContract?.source, "cerebro");
  assert.equal(refetched?.executionContract?.version, "2026-06-17.cerebro-agent-platform");
  assert.equal(refetched?.executionContract?.profileId, "remediation-executor");
  assert.equal(refetched?.executionContract?.maxActionStage, "execute");
  assert.equal(refetched?.executionContract?.requestedActionStage, "execute");
  assert.deepEqual(refetched?.executionContract?.requiredVerifierIds, ["tenant-scope", "human-approval"]);
});

test("autonomy goal service records approval decisions", async () => {
  const now = () => new Date("2026-06-26T20:00:00.000Z");
  const store = new InMemoryAutonomyGoalStore(now);
  const service = new AutonomyGoalService(testConfig(), { store, now });
  const goal = await store.create({
    objective: "Execute approved remediation",
    capabilityId: "executor",
    createdBy: { slackUserId: "UUSER" },
  });
  const approvalGoal = await service.requestApproval(goal.id, {
    toolId: "autonomy.execute",
    toolName: "Remediation Executor",
    actionSummary: "Advance Remediation Executor",
    reason: "Tenant-scoped execution needs approval.",
    risk: "Blast radius: tenant.",
    requestSummary: "Execute approved remediation",
  });

  assert.equal(approvalGoal.status, "approval_needed");
  assert.equal(approvalGoal.approvals[0]?.status, "pending");

  const decided = await service.decideApproval({
    goalId: goal.id,
    approvalId: approvalGoal.approvals[0]!.id.slice(-8),
    decision: "approved",
    actor: { slackUserId: "UAPPROVER", actorId: "slack:UAPPROVER", displayName: "Approver" },
  });

  assert.equal(decided.status, "active");
  assert.equal(decided.approvals[0]?.status, "approved");
  assert.equal(decided.approvals[0]?.decidedBy?.displayName, "Approver");
  assert.match(decided.workLog.at(-1)?.summary ?? "", /Approved Advance Remediation Executor/);
});
