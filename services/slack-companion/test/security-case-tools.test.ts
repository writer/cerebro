import assert from "node:assert/strict";
import test from "node:test";
import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import { createSecurityCaseTools } from "../src/agent/tools/security-case-tools.js";
import { toolResult } from "../src/agent/tools/tool-result.js";
import { AutonomyGoalService } from "../src/autonomy/goal-service.js";
import { InMemoryAutonomyGoalStore } from "../src/autonomy/goals.js";
import { AutonomyRunner } from "../src/autonomy/runner.js";
import { AutonomyToolDispatcher } from "../src/autonomy/tool-dispatcher.js";
import { testConfig } from "./fixtures.js";

test("security case tools create one durable case and attach the verified GitHub fix journey", async () => {
  const now = () => new Date("2026-07-14T20:00:00.000Z");
  const config = testConfig();
  const store = new InMemoryAutonomyGoalStore(now);
  const goals = new AutonomyGoalService(config, { store, now });
  const tools = createSecurityCaseTools({ config, cerebro: {} as any, memory: {} as any, autonomyGoals: goals });
  const startTool = tools.find((tool) => tool.name === "operator_security_case_start");
  const attachTool = tools.find((tool) => tool.name === "operator_security_case_attach_fix");
  const statusTool = tools.find((tool) => tool.name === "operator_security_case_status");
  const listTool = tools.find((tool) => tool.name === "operator_security_case_list");
  assert.ok(startTool && attachTool && statusTool && listTool);

  const started = await startTool.execute("start-case", {
    title: "Reachable dependency vulnerability",
    alert_ref: "https://github.com/WriterInternal/example/security/dependabot/17",
    repository: "WriterInternal/example",
    runtime_id: "writer-github-dependabot",
    finding_id: "finding-17",
    owner: "team-example",
    channel_id: "CSEC",
    thread_ts: "1710000000.000100",
    requested_by_slack_user_id: "U1",
  }) as any;

  assert.equal(started.details.created, true);
  assert.equal(started.details.case.state, "investigating");
  const caseId = started.details.case.id as string;
  const goalId = started.details.case.goalId as string;
  const initial = await goals.get(goalId);
  assert.equal(initial?.capabilityId, "remediation");
  assert.equal(initial?.securityCase?.id, caseId);
  assert.deepEqual(initial?.currentPlan.map((step) => step.id), ["investigate-finding", "prepare-reviewable-fix"]);

  const attached = await attachTool.execute("attach-fix", {
    case_id: caseId,
    title: "Upgrade the affected dependency",
    body: "Updates the affected package and keeps the existing API behavior.",
    files: [{ path: "package.json", content: "{\n  \"dependencies\": {}\n}\n" }],
    draft: true,
  }) as any;

  assert.equal(attached.details.attached, true);
  assert.equal(attached.details.case.state, "investigating");
  const updated = await goals.get(goalId);
  assert.equal(updated?.status, "active");
  assert.deepEqual(updated?.currentPlan.map((step) => step.id), [
    "investigate-finding",
    "prepare-reviewable-fix",
    "open-reviewable-pr",
    "monitor-github-merge",
    "reevaluate-finding",
    "verify-finding-resolved",
  ]);
  assert.equal(updated?.currentPlan[2]?.execution?.verificationToolName, "cerebro_code_github_pr_status");
  assert.equal(updated?.currentPlan[4]?.execution?.approvalRequired, true);
  assert.equal(updated?.currentPlan[5]?.acceptanceCriteriaIds?.[0], "finding-resolved");

  const status = await statusTool.execute("case-status", { case_id: caseId }) as any;
  assert.equal(status.details.found, true);
  assert.equal(status.details.case.goalId, goalId);
  const listed = await listTool.execute("case-list", {}) as any;
  assert.equal(listed.details.count, 1);
  assert.equal(listed.details.cases[0].id, caseId);
});

test("security case state exposes the concrete operator decision", async () => {
  const now = () => new Date("2026-07-14T20:00:00.000Z");
  const config = testConfig();
  const store = new InMemoryAutonomyGoalStore(now);
  const goals = new AutonomyGoalService(config, { store, now });
  const tools = createSecurityCaseTools({ config, cerebro: {} as any, memory: {} as any, autonomyGoals: goals });
  const startTool = tools.find((tool) => tool.name === "operator_security_case_start")!;
  const statusTool = tools.find((tool) => tool.name === "operator_security_case_status")!;
  const started = await startTool.execute("start-case", {
    title: "Code scanning finding",
    alert_ref: "github-alert-22",
    repository: "WriterInternal/example",
    runtime_id: "writer-github-code-scanning",
    finding_id: "finding-22",
  }) as any;
  const goalId = started.details.case.goalId as string;
  const caseId = started.details.case.id as string;

  await goals.update(goalId, { status: "approval_needed" });
  const status = await statusTool.execute("case-status", { case_id: caseId }) as any;

  assert.equal(status.details.case.state, "needs_decision");
  assert.equal(status.details.case.nextAction, "Investigate the finding and affected resources");
});

test("GitHub security case runs from finding investigation to fresh verified closure", async () => {
  const now = () => new Date("2026-07-14T20:00:00.000Z");
  const config = testConfig({ autonomy: { runnerLeaseMs: 30_000 } });
  const store = new InMemoryAutonomyGoalStore(now);
  const goals = new AutonomyGoalService(config, { store, now });
  const caseTools = createSecurityCaseTools({ config, cerebro: {} as any, memory: {} as any, autonomyGoals: goals });
  const startTool = caseTools.find((tool) => tool.name === "operator_security_case_start")!;
  const attachTool = caseTools.find((tool) => tool.name === "operator_security_case_attach_fix")!;
  const started = await startTool.execute("start-case", {
    title: "Reachable dependency vulnerability",
    alert_ref: "https://github.com/WriterInternal/example/security/dependabot/17",
    repository: "WriterInternal/example",
    runtime_id: "writer-github-dependabot",
    finding_id: "finding-17",
    requested_by_slack_user_id: "U1",
  }) as any;
  const goalId = started.details.case.goalId as string;
  await attachTool.execute("attach-fix", {
    case_id: started.details.case.id,
    title: "Upgrade the affected dependency",
    files: [{ path: "package.json", content: "{\n  \"dependencies\": {}\n}\n" }],
  });

  const runner = new AutonomyRunner(config, goals, {
    now,
    workerId: "security-case-test",
    dispatcher: new AutonomyToolDispatcher(securityCaseExecutionTools()),
    code: {
      githubPullRequestStatus: async () => ({
        ok: true,
        pull_request: { number: 17, url: "https://github.com/WriterInternal/example/pull/17", merged: true },
        checks: { summary: { state: "passed", passed: 2, pending: 0, failed: 0 } },
      }),
      githubChecksStatus: async () => ({ ok: true, checks: { summary: { state: "passed", passed: 2, pending: 0, failed: 0 } } }),
    },
  });

  await runner.advance(goalId);
  await runner.advance(goalId);
  await runner.advance(goalId);
  await runner.advance(goalId);
  const waiting = await goals.get(goalId);
  assert.equal(waiting?.status, "approval_needed", JSON.stringify({
    blockers: waiting?.blockers,
    plan: waiting?.currentPlan,
    toolRuns: waiting?.toolRuns,
  }, null, 2));
  assert.equal(waiting?.currentPlan[4]?.id, "reevaluate-finding");
  await goals.decideApproval({
    goalId,
    approvalId: waiting!.approvals[0]!.id,
    decision: "approved",
    actor: { slackUserId: "U2", actorId: "slack:U2" },
  });
  await runner.advance(goalId);
  await runner.advance(goalId);
  const completed = await goals.get(goalId);

  assert.equal(completed?.status, "completed");
  assert.equal(completed?.completionReceipt?.status, "complete");
  assert.deepEqual(completed?.completionReceipt?.criteriaFailed, []);
  assert.equal(completed?.acceptanceCriteria.find((criterion) => criterion.id === "finding-resolved")?.status, "passed");
  assert.ok(completed?.artifacts.some((artifact) => artifact.kind === "pull_request"));
});

function securityCaseExecutionTools(): AgentTool[] {
  return [
    {
      name: "cerebro_finding_investigation",
      label: "Finding investigation",
      description: "Inspect one finding.",
      parameters: Type.Object({ runtime_id: Type.String(), finding_id: Type.String(), include_graph: Type.Optional(Type.Boolean()) }),
      execute: async () => toolResult({ finding_found: true, finding: { id: "finding-17", status: "open" }, evidence_ref: "finding:finding-17" }),
    },
    {
      name: "cerebro_code_github_pr",
      label: "GitHub PR",
      description: "Open a reviewable PR.",
      parameters: Type.Object({
        repo: Type.String(),
        title: Type.String(),
        body: Type.Optional(Type.String()),
        files: Type.Array(Type.Object({ path: Type.String(), content: Type.String() })),
        branch: Type.Optional(Type.String()),
        base: Type.Optional(Type.String()),
        draft: Type.Optional(Type.Boolean()),
      }),
      execute: async () => toolResult({ ok: true, pull_request: { number: 17, url: "https://github.com/WriterInternal/example/pull/17" } }),
    },
    {
      name: "cerebro_code_github_pr_status",
      label: "GitHub PR status",
      description: "Read a PR.",
      parameters: Type.Object({ repo: Type.String(), pull_number: Type.Number(), include_checks: Type.Optional(Type.Boolean()) }),
      execute: async () => toolResult({ ok: true, pull_request: { number: 17, url: "https://github.com/WriterInternal/example/pull/17", merged: false } }),
    },
    {
      name: "source_run_trigger",
      label: "Source run trigger",
      description: "Run finding evaluation.",
      parameters: Type.Object({ runtime_id: Type.String(), action: Type.String(), reason: Type.Optional(Type.String()), execute: Type.Boolean(), approved: Type.Boolean() }),
      execute: async () => toolResult({ attempted: true, result: { status: "accepted" }, evidence_ref: "source-run:17" }),
    },
    {
      name: "source_run_status",
      label: "Source run status",
      description: "Read source status.",
      parameters: Type.Object({ runtime_id: Type.String() }),
      execute: async () => toolResult({ runtimes: [{ runtime_id: "writer-github-dependabot", finding_status: "complete" }], evidence_ref: "runtime:writer-github-dependabot" }),
    },
    {
      name: "finding_lookup",
      label: "Finding lookup",
      description: "Read one finding.",
      parameters: Type.Object({ runtime_id: Type.String(), finding_id: Type.String(), limit: Type.Optional(Type.Number()) }),
      execute: async () => toolResult({ findings: [{ id: "finding-17", status: "resolved" }], evidence_ref: "finding:finding-17:resolved" }),
    },
  ];
}
