import assert from "node:assert/strict";
import test from "node:test";
import { AutonomyGoalService } from "../src/autonomy/goal-service.js";
import { InMemoryAutonomyGoalStore } from "../src/autonomy/goals.js";
import { AutonomyRunner } from "../src/autonomy/runner.js";
import { recordRunnerAdvanceFailure } from "../src/autonomy/runner-retry.js";
import { testConfig } from "./fixtures.js";

test("autonomy runner claims a due self-repair goal and records a playbook tool run", async () => {
  const dates = [
    new Date("2026-06-26T20:00:00.000Z"),
    new Date("2026-06-26T20:00:01.000Z"),
    new Date("2026-06-26T20:00:02.000Z"),
    new Date("2026-06-26T20:00:03.000Z"),
    new Date("2026-06-26T20:00:04.000Z"),
    new Date("2026-06-26T20:00:05.000Z"),
  ];
  const now = () => dates.shift() ?? new Date("2026-06-26T20:00:06.000Z");
  const store = new InMemoryAutonomyGoalStore(now);
  const config = testConfig({ autonomy: { runnerLeaseMs: 30_000, runnerMaxGoalsPerTick: 1 } });
  const service = new AutonomyGoalService(config, { store, now });
  const runner = new AutonomyRunner(config, service, { workerId: "worker-1", now });

  const goal = await service.createFromText({
    text: "fix the Cerebro PR checks",
    actor: { slackUserId: "UUSER", actorId: "actor-1" },
    channelId: "CSEC",
  });
  assert.equal(goal.capabilityId, "self_repair");

  const result = await runner.advance(goal.id);
  const updated = await service.get(goal.id);

  assert.equal(result.status, "advanced");
  assert.equal(updated?.status, "active");
  assert.equal(updated?.claim, undefined);
  assert.equal(updated?.currentPlan[0]?.status, "completed");
  assert.equal(updated?.currentPlan[1]?.status, "pending");
  assert.equal(updated?.currentPlan[2]?.id, "monitor-github-checks");
  assert.equal(updated?.toolRuns.at(-1)?.toolId, "autonomy.self_repair_playbook");
  assert.match(updated?.toolRuns.at(-1)?.responseSummary ?? "", /workspace search\/read-many/i);
  assert.match(updated?.workLog.at(-1)?.summary ?? "", /Completed Inspect current context/);
});

test("autonomy runner keeps self-repair goals active while GitHub checks are pending", async () => {
  const now = () => new Date("2026-06-26T20:00:00.000Z");
  const store = new InMemoryAutonomyGoalStore(now);
  const config = testConfig({ autonomy: { runnerLeaseMs: 30_000, runnerPollIntervalMs: 1_000 } });
  const service = new AutonomyGoalService(config, { store, now });
  const runner = new AutonomyRunner(config, service, {
    workerId: "worker-1",
    now,
    code: githubCode({
      merged: false,
      checks: { state: "pending", passed: 2, pending: 1, failed: 0 },
    }),
  });
  const goal = await store.create({
    objective: "watch PR #17",
    capabilityId: "self_repair",
    createdBy: { slackUserId: "UUSER", actorId: "actor-1" },
    nextWakeAt: "2026-06-26T19:59:00.000Z",
    plan: [monitorStep()],
  });

  const result = await runner.advance(goal.id);
  const updated = await service.get(goal.id);

  assert.equal(result.status, "advanced");
  assert.match(result.summary, /Next check is scheduled/);
  assert.equal(updated?.status, "active");
  assert.equal(updated?.activeStepId, "monitor-github-checks");
  assert.equal(updated?.nextWakeAt, "2026-06-26T20:01:00.000Z");
  assert.equal(updated?.currentPlan[0]?.status, "pending");
  assert.match(updated?.currentPlan[0]?.summary ?? "", /Checks pending/);
  assert.equal(updated?.toolRuns.at(-1)?.toolId, "autonomy.github_monitor");
  assert.equal(updated?.toolRuns.at(-1)?.status, "completed");
  assert.match(updated?.workLog.at(-1)?.summary ?? "", /Checks pending/);
});

test("autonomy runner waits for review when GitHub checks pass", async () => {
  const now = () => new Date("2026-06-26T20:00:00.000Z");
  const store = new InMemoryAutonomyGoalStore(now);
  const config = testConfig({ autonomy: { runnerLeaseMs: 30_000 } });
  const service = new AutonomyGoalService(config, { store, now });
  const runner = new AutonomyRunner(config, service, {
    workerId: "worker-1",
    now,
    code: githubCode({
      merged: false,
      checks: { state: "passed", passed: 3, pending: 0, failed: 0 },
    }),
  });
  const goal = await store.create({
    objective: "watch https://github.com/WriterInternal/cerebro-slack-companion/pull/17",
    capabilityId: "self_repair",
    createdBy: { slackUserId: "UUSER", actorId: "actor-1" },
    plan: [monitorStep()],
  });

  const result = await runner.advance(goal.id);
  const updated = await service.get(goal.id);

  assert.equal(result.status, "advanced");
  assert.match(result.summary, /waiting for review or merge/);
  assert.equal(updated?.status, "waiting");
  assert.equal(updated?.currentPlan[0]?.status, "completed");
  assert.match(updated?.currentPlan[0]?.summary ?? "", /Checks passed/);
  assert.deepEqual(updated?.artifactUrls, ["https://github.com/WriterInternal/cerebro-slack-companion/pull/17"]);
});

test("autonomy runner completes a self-repair monitor goal after the PR is merged", async () => {
  const now = () => new Date("2026-06-26T20:00:00.000Z");
  const store = new InMemoryAutonomyGoalStore(now);
  const config = testConfig({ autonomy: { runnerLeaseMs: 30_000 } });
  const service = new AutonomyGoalService(config, { store, now });
  const runner = new AutonomyRunner(config, service, {
    workerId: "worker-1",
    now,
    code: githubCode({
      merged: true,
      checks: { state: "passed", passed: 3, pending: 0, failed: 0 },
    }),
  });
  const goal = await store.create({
    objective: "watch PR #17",
    capabilityId: "self_repair",
    createdBy: { slackUserId: "UUSER", actorId: "actor-1" },
    plan: [monitorStep()],
  });

  await runner.advance(goal.id);
  const updated = await service.get(goal.id);

  assert.equal(updated?.status, "completed");
  assert.match(updated?.completionSummary ?? "", /Pull request #17 is merged/);
  assert.equal(updated?.currentPlan[0]?.status, "completed");
  assert.equal(updated?.workLog.at(-1)?.kind, "goal_completed");
});

test("security case monitor keeps checking after checks pass until the PR merges", async () => {
  const now = () => new Date("2026-06-26T20:00:00.000Z");
  const store = new InMemoryAutonomyGoalStore(now);
  const config = testConfig({ autonomy: { runnerLeaseMs: 30_000, runnerPollIntervalMs: 1_000 } });
  const service = new AutonomyGoalService(config, { store, now });
  const runner = new AutonomyRunner(config, service, {
    workerId: "worker-1",
    now,
    code: githubCode({ merged: false, checks: { state: "passed", passed: 3, pending: 0, failed: 0 } }),
  });
  const goal = await store.create({
    objective: "Handle https://github.com/WriterInternal/example/pull/17",
    capabilityId: "remediation",
    createdBy: { slackUserId: "UUSER", actorId: "actor-1" },
    plan: [{ id: "monitor-github-merge", title: "Wait for the pull request to merge", status: "pending", dependsOn: [] }],
  });

  const result = await runner.advance(goal.id);
  const updated = await service.get(goal.id);

  assert.match(result.summary, /Waiting for merge/);
  assert.equal(updated?.status, "active");
  assert.equal(updated?.currentPlan[0]?.status, "pending");
  assert.equal(updated?.nextWakeAt, "2026-06-26T20:01:00.000Z");
});

test("security case monitor advances to fresh verification after the PR merges", async () => {
  const now = () => new Date("2026-06-26T20:00:00.000Z");
  const store = new InMemoryAutonomyGoalStore(now);
  const config = testConfig({ autonomy: { runnerLeaseMs: 30_000 } });
  const service = new AutonomyGoalService(config, { store, now });
  const runner = new AutonomyRunner(config, service, {
    workerId: "worker-1",
    now,
    code: githubCode({ merged: true, checks: { state: "passed", passed: 3, pending: 0, failed: 0 } }),
  });
  const goal = await store.create({
    objective: "Handle https://github.com/WriterInternal/example/pull/17",
    capabilityId: "remediation",
    createdBy: { slackUserId: "UUSER", actorId: "actor-1" },
    plan: [
      { id: "monitor-github-merge", title: "Wait for the pull request to merge", status: "pending", dependsOn: [] },
      { id: "verify-finding-resolved", title: "Verify the finding is resolved", status: "pending", dependsOn: ["monitor-github-merge"] },
    ],
  });

  const result = await runner.advance(goal.id);
  const updated = await service.get(goal.id);

  assert.match(result.summary, /Fresh finding verification is ready/);
  assert.equal(updated?.status, "active");
  assert.equal(updated?.completionSummary, undefined);
  assert.equal(updated?.currentPlan[0]?.status, "completed");
  assert.equal(updated?.currentPlan[1]?.status, "pending");
  assert.equal(updated?.nextWakeAt, "2026-06-26T20:00:00.000Z");
});

test("autonomy runner blocks a self-repair monitor goal when GitHub checks fail", async () => {
  const now = () => new Date("2026-06-26T20:00:00.000Z");
  const store = new InMemoryAutonomyGoalStore(now);
  const config = testConfig({ autonomy: { runnerLeaseMs: 30_000 } });
  const service = new AutonomyGoalService(config, { store, now });
  const runner = new AutonomyRunner(config, service, {
    workerId: "worker-1",
    now,
    code: githubCode({
      merged: false,
      checks: { state: "failed", passed: 2, pending: 0, failed: 1 },
    }),
  });
  const goal = await store.create({
    objective: "watch PR #17",
    capabilityId: "self_repair",
    createdBy: { slackUserId: "UUSER", actorId: "actor-1" },
    plan: [monitorStep()],
  });

  const result = await runner.advance(goal.id);
  const updated = await service.get(goal.id);

  assert.equal(result.status, "advanced");
  assert.match(result.summary, /Checks failed/);
  assert.equal(updated?.status, "blocked");
  assert.equal(updated?.currentPlan[0]?.status, "failed");
  assert.match(updated?.blockers.at(-1) ?? "", /Checks failed/);
});

test("autonomy runner waits when a self-repair monitor goal has no GitHub target", async () => {
  const now = () => new Date("2026-06-26T20:00:00.000Z");
  const store = new InMemoryAutonomyGoalStore(now);
  const config = testConfig({ autonomy: { runnerLeaseMs: 30_000 } });
  const service = new AutonomyGoalService(config, { store, now });
  const runner = new AutonomyRunner(config, service, { workerId: "worker-1", now });
  const goal = await store.create({
    objective: "keep working on the repair",
    capabilityId: "self_repair",
    createdBy: { slackUserId: "UUSER", actorId: "actor-1" },
    plan: [monitorStep()],
  });

  const result = await runner.advance(goal.id);
  const updated = await service.get(goal.id);

  assert.equal(result.status, "advanced");
  assert.match(result.summary, /needs a PR or ref/);
  assert.equal(updated?.status, "waiting");
  assert.equal(updated?.currentPlan[0]?.status, "waiting");
  assert.equal(updated?.toolRuns.at(-1)?.status, "skipped");
});

test("autonomy runner failure handling blocks a goal after repeated retries", async () => {
  let nowMs = Date.parse("2026-06-26T20:00:00.000Z");
  const now = () => new Date(nowMs);
  const store = new InMemoryAutonomyGoalStore(now);
  const config = testConfig({ autonomy: { runnerPollIntervalMs: 60_000 } });
  const service = new AutonomyGoalService(config, { store, now });
  const goal = await service.createFromText({
    text: "fix flaky CI",
    actor: { slackUserId: "UUSER", actorId: "actor-1" },
    channelId: "CSEC",
  });

  await recordRunnerAdvanceFailure({ config, goals: service, goal, error: new Error("DynamoDB timeout"), now });
  nowMs += 60_000;
  const firstRetry = await service.get(goal.id);
  await recordRunnerAdvanceFailure({ config, goals: service, goal: firstRetry!, error: new Error("DynamoDB timeout"), now });
  nowMs += 60_000;
  const secondRetry = await service.get(goal.id);
  await recordRunnerAdvanceFailure({ config, goals: service, goal: secondRetry!, error: new Error("DynamoDB timeout"), now });

  const updated = await service.get(goal.id);
  assert.equal(updated?.status, "blocked");
  assert.equal(updated?.nextWakeAt ?? null, null);
  assert.match(updated?.blockers.at(-1) ?? "", /stopped after 3 equivalent failures/i);
  assert.match(updated?.workLog.at(-1)?.summary ?? "", /Runner stopped after 3 equivalent failures/);
});

test("autonomy runner gives investigation goals an evidence-ledger plan", async () => {
  const now = () => new Date("2026-06-26T20:00:00.000Z");
  const store = new InMemoryAutonomyGoalStore(now);
  const config = testConfig({ autonomy: { runnerLeaseMs: 30_000 } });
  const service = new AutonomyGoalService(config, { store, now });
  const runner = new AutonomyRunner(config, service, { workerId: "worker-1", now });

  const goal = await service.createFromText({
    text: "investigate finding-1 blast radius",
    actor: { slackUserId: "UUSER", actorId: "actor-1" },
    channelId: "CSEC",
  });
  assert.equal(goal.capabilityId, "investigation");

  const result = await runner.advance(goal.id);
  const updated = await service.get(goal.id);

  assert.equal(result.status, "advanced");
  assert.equal(updated?.status, "active");
  assert.equal(updated?.currentPlan.length, 3);
  assert.equal(updated?.currentPlan[0]?.status, "completed");
  assert.equal(updated?.currentPlan[1]?.title, "Build evidence ledger and related-entity scope");
  assert.equal(updated?.toolRuns.at(-1)?.toolId, "autonomy.investigation_playbook");
  assert.match(updated?.toolRuns.at(-1)?.responseSummary ?? "", /cerebro_finding_investigation/);
  assert.match(updated?.toolRuns.at(-1)?.responseSummary ?? "", /Do not execute response actions/);
});

test("autonomy runner executes read-only Cerebro investigation when dependencies are wired", async () => {
  const now = () => new Date("2026-06-26T20:00:00.000Z");
  const store = new InMemoryAutonomyGoalStore(now);
  const config = testConfig({ autonomy: { runnerLeaseMs: 30_000 } });
  const service = new AutonomyGoalService(config, { store, now });
  const calls: string[] = [];
  const verificationCalls: any[] = [];
  const cerebro = {
    listFindings: async (runtimeId: string, input: any) => {
      calls.push(`findings:${runtimeId}:${input.findingId ?? input.ruleId ?? "none"}`);
      if (input.findingId) {
        return [{
          id: input.findingId,
          runtime_id: runtimeId,
          rule_id: "okta.mfa",
          title: "Privileged user missing MFA",
          severity: "high",
          status: "open",
          primary_resource_urn: "urn:okta:user:123",
        }];
      }
      return [{
        id: "related-1",
        runtime_id: runtimeId,
        rule_id: "okta.mfa",
        title: "Related MFA issue",
        status: "open",
      }];
    },
    listFindingEvidence: async (runtimeId: string, findingId: string) => {
      calls.push(`evidence:${runtimeId}:${findingId}`);
      return [{
        id: "ev-1",
        finding_id: findingId,
        evidence_type: "identity",
        summary: "MFA factor missing.",
        graph_root_urn: "urn:okta:user:123",
      }];
    },
    listRuntimeHealth: async (input: any) => {
      calls.push(`health:${input.runtimeId ?? input.runtimeIds?.join(",")}`);
      return [{ runtime_id: input.runtimeId ?? "writer-okta", status: "healthy" }];
    },
    graphNeighborhood: async (urn: string) => {
      calls.push(`graph:${urn}`);
      return { root_urn: urn, neighbors: [] };
    },
    verifyAgentClaim: async (request: any) => {
      verificationCalls.push(request);
      return { verdict: "weakly_supported", allowed_next_stage: "explain" };
    },
  };
  const memory = {
    search: async () => [{ id: "m1", kind: "investigation_note", topic: "Okta", summary: "Check MFA evidence.", tags: [], createdAt: now().toISOString() }],
  };
  const runner = new AutonomyRunner(config, service, { workerId: "worker-1", now, cerebro: cerebro as any, memory: memory as any });

  const goal = await service.createFromText({
    text: "investigate finding finding-1",
    actor: { slackUserId: "UUSER", actorId: "actor-1" },
    channelId: "CSEC",
  });

  const result = await runner.advance(goal.id);
  const updated = await service.get(goal.id);

  assert.equal(result.status, "advanced");
  assert.equal(updated?.status, "active");
  assert.equal(updated?.currentPlan[0]?.status, "completed");
  assert.equal(updated?.currentPlan[1]?.title, "Collect missing evidence before recommendation");
  assert.match(updated?.currentPlan[1]?.summary ?? "", /Claim weakly_supported allows explain/);
  assert.equal(updated?.toolRuns.at(-1)?.toolId, "autonomy.cerebro_finding_investigation");
  assert.equal(updated?.toolRuns.at(-1)?.status, "completed");
  assert.match(updated?.toolRuns.at(-1)?.responseSummary ?? "", /1 evidence row/);
  assert.match(updated?.toolRuns.at(-1)?.responseSummary ?? "", /Claim weakly_supported allows explain/);
  assert.equal(updated?.workLog.at(-2)?.kind, "plan_updated");
  assert.match(updated?.workLog.at(-2)?.summary ?? "", /Collect missing evidence/);
  assert.match(updated?.workLog.at(-1)?.details ?? "", /Privileged user missing MFA/);
  assert.equal(verificationCalls[0].claim_type, "finding_triage");
  assert.equal(verificationCalls[0].requested_action_stage, "recommend");
  assert.deepEqual(calls, [
    "findings:writer-okta:finding-1",
    "evidence:writer-okta:finding-1",
    "health:writer-okta",
    "findings:writer-okta:okta.mfa",
    "graph:urn:okta:user:123",
  ]);
});

test("autonomy runner advances supported investigations toward recommendations", async () => {
  const now = () => new Date("2026-06-26T20:00:00.000Z");
  const store = new InMemoryAutonomyGoalStore(now);
  const config = testConfig({ autonomy: { runnerLeaseMs: 30_000 } });
  const service = new AutonomyGoalService(config, { store, now });
  const cerebro = {
    listFindings: async (runtimeId: string, input: any) => {
      if (input.findingId) {
        return [{
          id: input.findingId,
          runtime_id: runtimeId,
          rule_id: "okta.mfa",
          title: "Privileged user missing MFA",
          severity: "high",
          status: "open",
          primary_resource_urn: "urn:cerebro:writer:entity:okta-user-123",
          last_observed_at: "2026-06-26T19:50:00.000Z",
        }];
      }
      return [{
        id: "related-1",
        runtime_id: runtimeId,
        rule_id: "okta.mfa",
        title: "Related MFA issue",
        status: "open",
      }];
    },
    listFindingEvidence: async (_runtimeId: string, findingId: string) => [{
      id: "ev-1",
      finding_id: findingId,
      evidence_type: "identity",
      summary: "MFA factor missing.",
      graph_root_urn: "urn:cerebro:writer:entity:okta-user-123",
      observed_at: "2026-06-26T19:50:00.000Z",
    }],
    listRuntimeHealth: async () => [{ runtime_id: "writer-okta", status: "healthy" }],
    graphNeighborhood: async (urn: string) => ({ root_urn: urn, neighbors: [] }),
    verifyAgentClaim: async () => ({ verdict: "supported", allowed_next_stage: "recommend", blockers: [] }),
  };
  const memory = {
    search: async () => [],
  };
  const runner = new AutonomyRunner(config, service, { workerId: "worker-1", now, cerebro: cerebro as any, memory: memory as any });

  const goal = await service.createFromText({
    text: "investigate finding finding-1",
    actor: { slackUserId: "UUSER", actorId: "actor-1" },
    channelId: "CSEC",
  });

  const result = await runner.advance(goal.id);
  const updated = await service.get(goal.id);

  assert.equal(result.status, "advanced");
  assert.equal(updated?.status, "active");
  assert.equal(updated?.currentPlan[0]?.status, "completed");
  assert.equal(updated?.currentPlan[1]?.title, "Write recommendation from verified evidence");
  assert.match(updated?.currentPlan[1]?.summary ?? "", /Claim supported allows recommend/);
  assert.match(updated?.toolRuns.at(-1)?.responseSummary ?? "", /0 gap/);
  assert.match(updated?.workLog.at(-2)?.details ?? "", /no execution step/);
});

test("autonomy runner creates an approval record for executor goals", async () => {
  const now = () => new Date("2026-06-26T20:00:00.000Z");
  const store = new InMemoryAutonomyGoalStore(now);
  const config = testConfig({ autonomy: { runnerLeaseMs: 30_000 } });
  const service = new AutonomyGoalService(config, { store, now });
  const runner = new AutonomyRunner(config, service, { workerId: "worker-1", now });

  const goal = await store.create({
    objective: "execute approved remediation for finding-1",
    capabilityId: "executor",
    createdBy: { slackUserId: "UUSER", actorId: "actor-1" },
    nextWakeAt: "2026-06-26T19:59:00.000Z",
    plan: [{
      id: "execute",
      title: "Execute approved remediation",
      status: "pending",
      dependsOn: [],
    }],
  });

  const result = await runner.advance(goal.id);
  const updated = await service.get(goal.id);

  assert.equal(result.status, "advanced");
  assert.equal(updated?.status, "approval_needed");
  assert.equal(updated?.approvals.length, 1);
  assert.equal(updated?.approvals[0]?.status, "pending");
  assert.match(updated?.approvals[0]?.risk ?? "", /Blast radius: tenant/);
  assert.equal(updated?.currentPlan[0]?.status, "waiting");
  assert.equal(updated?.toolRuns.at(-1)?.status, "approval_requested");
  assert.equal(updated?.approvals[0]?.stepId, "execute");
});

test("autonomy runner blocks executor goals above the stored execution contract", async () => {
  const now = () => new Date("2026-06-26T20:00:00.000Z");
  const store = new InMemoryAutonomyGoalStore(now);
  const config = testConfig({ autonomy: { runnerLeaseMs: 30_000 } });
  const service = new AutonomyGoalService(config, { store, now });
  const runner = new AutonomyRunner(config, service, { workerId: "worker-1", now });

  const goal = await store.create({
    objective: "execute approved remediation for finding-1",
    capabilityId: "executor",
    createdBy: { slackUserId: "UUSER", actorId: "actor-1" },
    executionContract: {
      source: "cerebro",
      version: "2026-06-17.cerebro-agent-platform",
      capabilityId: "executor",
      profileId: "exposure-analyst",
      maxActionStage: "recommend",
      requestedActionStage: "execute",
      requiredVerifierIds: ["tenant-scope"],
      selectedAt: "2026-06-26T19:59:00.000Z",
    },
    nextWakeAt: "2026-06-26T19:59:00.000Z",
    plan: [{
      id: "execute",
      title: "Execute approved remediation",
      status: "pending",
      dependsOn: [],
    }],
  });

  const result = await runner.advance(goal.id);
  const updated = await service.get(goal.id);

  assert.equal(result.status, "advanced");
  assert.match(result.summary, /allows recommend/);
  assert.equal(updated?.status, "blocked");
  assert.equal(updated?.currentPlan[0]?.status, "failed");
  assert.equal(updated?.approvals.length, 0);
  assert.match(updated?.blockers.at(-1) ?? "", /needs execute/);
  assert.equal(updated?.workLog.at(-1)?.kind, "blocker_found");
});

test("autonomy runner keeps an approved non-executable step waiting for an exact tool", async () => {
  const now = () => new Date("2026-06-26T20:00:00.000Z");
  const store = new InMemoryAutonomyGoalStore(now);
  const config = testConfig({ autonomy: { runnerLeaseMs: 30_000 } });
  const service = new AutonomyGoalService(config, { store, now });
  const runner = new AutonomyRunner(config, service, { workerId: "worker-1", now });

  const goal = await store.create({
    objective: "execute approved remediation for finding-1",
    capabilityId: "executor",
    createdBy: { slackUserId: "UUSER", actorId: "actor-1" },
    nextWakeAt: "2026-06-26T19:59:00.000Z",
    plan: [{
      id: "execute",
      title: "Execute approved remediation",
      status: "pending",
      dependsOn: [],
    }],
  });
  const approvalResult = await runner.advance(goal.id);
  assert.equal(approvalResult.status, "advanced");
  const approvalGoal = await service.get(goal.id);
  assert.equal(approvalGoal?.status, "approval_needed");

  const approved = await service.decideApproval({
    goalId: goal.id,
    approvalId: approvalGoal!.approvals[0]!.id,
    decision: "approved",
    actor: { slackUserId: "UAPPROVER", actorId: "actor-approver", displayName: "Approver" },
  });
  assert.equal(approved.status, "active");

  const executionResult = await runner.advance(goal.id);
  const updated = await service.get(goal.id);

  assert.equal(executionResult.status, "advanced");
  assert.equal(updated?.status, "waiting");
  assert.equal(updated?.approvals.length, 1);
  assert.equal(updated?.currentPlan[0]?.status, "waiting");
  assert.equal(updated?.toolRuns.at(-1)?.toolId, "autonomy.approved_execution");
  assert.match(updated?.workLog.at(-1)?.summary ?? "", /exact execution tool is required/);
});

test("autonomy runner skips goals leased by another worker", async () => {
  const now = () => new Date("2026-06-26T20:00:00.000Z");
  const store = new InMemoryAutonomyGoalStore(now);
  const config = testConfig({ autonomy: { runnerLeaseMs: 30_000 } });
  const service = new AutonomyGoalService(config, { store, now });
  const runner = new AutonomyRunner(config, service, { workerId: "worker-2", now });

  const goal = await service.createFromText({
    text: "investigate recurring Slack alert",
    actor: { slackUserId: "UUSER", actorId: "actor-1" },
  });
  const claimed = await service.claim(goal.id, "worker-1", 30_000);
  assert.ok(claimed);

  const result = await runner.advance(goal.id);

  assert.equal(result.status, "claimed_elsewhere");
  assert.equal((await service.get(goal.id))?.claim?.workerId, "worker-1");
});

function monitorStep() {
  return {
    id: "monitor-github-checks",
    title: "Watch GitHub PR checks until they pass, fail, or need review",
    status: "pending" as const,
    dependsOn: [],
  };
}

function githubCode(input: {
  merged: boolean;
  checks: { state: string; passed: number; pending: number; failed: number };
}) {
  return {
    githubPullRequestStatus: async (args: { pullNumber: number }) => ({
      ok: true,
      pull_request: {
        number: args.pullNumber,
        url: `https://github.com/WriterInternal/cerebro-slack-companion/pull/${args.pullNumber}`,
        merged: input.merged,
        head_sha: "abc123",
      },
      checks: {
        summary: input.checks,
        check_runs: [],
        statuses: [],
      },
    }),
    githubChecksStatus: async () => ({
      ok: true,
      checks: {
        summary: input.checks,
        check_runs: [],
        statuses: [],
      },
    }),
  };
}
