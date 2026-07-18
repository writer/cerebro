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
import type { ComplianceWorkCommand, ComplianceWorkItemRecord } from "../src/cerebro/types.js";
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

test("canonical work-item cases stay idempotent and resolve only after approved fresh assurance", async () => {
  const now = () => new Date("2026-07-15T00:00:00.000Z");
  const config = testConfig();
  const store = new InMemoryAutonomyGoalStore(now);
  const goals = new AutonomyGoalService(config, { store, now });
  let current = canonicalWorkItemRecord();
  const commands: ComplianceWorkCommand[] = [];
  const cerebro = {
    getComplianceWorkItem: async () => current,
    listComplianceWorkItems: async () => ({ items: [current.item], next_cursor: "next-work-page" }),
    commandComplianceWorkItem: async (_workItemId: string, command: ComplianceWorkCommand) => {
      commands.push(command);
      if (command.action === "remediate") {
        current = {
          ...current,
          item: {
            ...current.item,
            state: "in_progress" as const,
            last_remediated_by: "slack:U1",
            last_remediated_at: "2026-07-15T00:05:00.000Z",
            version: 2,
          },
        };
      } else if (command.action === "verify_assurance") {
        current = {
          ...current,
          item: {
            ...current.item,
            state: "resolved" as const,
            verification: {
              assurance_decision_id: command.assurance_decision_id!,
              assessment_run_id: "run-post-change",
              objective_result_id: "result-post-change",
              decision_digest: "sha256:decision",
              record_digest: "sha256:record",
              evidence_ids: ["evidence-post-change"],
              evaluated_at: "2026-07-15T00:10:00.000Z",
              decision_as_of: "2026-07-15T00:10:00.000Z",
            },
            version: 3,
          },
        };
      }
      return current;
    },
  };
  const tools = createSecurityCaseTools({ config, cerebro: cerebro as any, memory: {} as any, autonomyGoals: goals });
  const openTool = tools.find((tool) => tool.name === "operator_security_case_open_work_item")!;
  const commandTool = tools.find((tool) => tool.name === "operator_security_case_command")!;
  const executeCommandTool = tools.find((tool) => tool.name === "operator_security_case_execute_command")!;
  const workItemStatusTool = tools.find((tool) => tool.name === "operator_security_case_work_item_status")!;
  const statusTool = tools.find((tool) => tool.name === "operator_security_case_status")!;
  const listTool = tools.find((tool) => tool.name === "operator_security_case_list")!;
  const runner = new AutonomyRunner(config, goals, {
    now,
    workerId: "canonical-work-item-test",
    dispatcher: new AutonomyToolDispatcher([executeCommandTool, workItemStatusTool]),
  });

  const opened = await openTool.execute("open-work", {
    work_item_id: "work-1",
    requested_by_slack_user_id: "U1",
  }) as any;
  assert.equal(opened.details.created, true);
  assert.equal(opened.details.case.id, "work-1");
  assert.equal(opened.details.case.state, "ready_to_act");
  assert.equal(opened.details.case.workItemVersion, 1);
  const goalId = opened.details.case.goalId as string;

  const duplicate = await openTool.execute("open-work-again", { work_item_id: "work-1" }) as any;
  assert.equal(duplicate.details.created, false);
  assert.equal(duplicate.details.case.goalId, goalId);
  assert.equal((await goals.list()).length, 1);

  const listed = await listTool.execute("list-work", {
    work_state: "open",
    owner_id: "team-security",
    cursor: "cursor-1",
    limit: 25,
  }) as any;
  assert.equal(listed.details.work_items[0].id, "work-1");
  assert.equal(listed.details.next_cursor, "next-work-page");

  const scheduledRemediation = await commandTool.execute("plan-remediation", {
    case_id: "work-1",
    expected_version: 1,
    action: "remediate",
    rationale: "The access grant was removed.",
  }) as any;
  assert.equal(scheduledRemediation.details.scheduled, true);
  assert.equal(scheduledRemediation.details.approval_required, true);

  const notApproved = await executeCommandTool.execute("remediate-without-approval", {
    case_id: "work-1",
    expected_version: 1,
    action: "remediate",
    rationale: "The access grant was removed.",
  }) as any;
  assert.equal(notApproved.details.approval_required, true);
  assert.equal(commands.length, 0);

  await runner.advance(goalId);
  const remediationApproval = await goals.get(goalId);
  assert.equal(remediationApproval?.status, "approval_needed");
  assert.equal(remediationApproval?.approvals.at(-1)?.toolName, "operator_security_case_execute_command");
  await goals.decideApproval({
    goalId,
    approvalId: remediationApproval!.approvals.at(-1)!.id,
    decision: "approved",
    actor: { slackUserId: "U2", actorId: "slack:U2" },
  });
  await runner.advance(goalId);
  const remediated = await statusTool.execute("remediated-status", { case_id: "work-1" }) as any;
  assert.equal(remediated.details.case.workItemVersion, 2);
  assert.equal(remediated.details.case.state, "needs_evidence");
  assert.equal(commands[0]?.expected_version, 1);

  const scheduledVerification = await commandTool.execute("plan-verification", {
    case_id: "work-1",
    expected_version: 2,
    action: "verify_assurance",
    assurance_decision_id: "decision-post-change",
    rationale: "Fresh evidence satisfies the control objective.",
  }) as any;
  assert.equal(scheduledVerification.details.scheduled, true);
  await runner.advance(goalId);
  const verificationApproval = await goals.get(goalId);
  assert.equal(verificationApproval?.status, "approval_needed");
  await goals.decideApproval({
    goalId,
    approvalId: verificationApproval!.approvals.at(-1)!.id,
    decision: "approved",
    actor: { slackUserId: "U2", actorId: "slack:U2" },
  });
  await runner.advance(goalId);
  const verified = await statusTool.execute("verified-status", { case_id: "work-1" }) as any;
  assert.equal(verified.details.case.state, "closed");
  assert.equal(verified.details.case.workItemVersion, 3);
  assert.equal(verified.details.case.assuranceDecisionId, "decision-post-change");
  assert.equal(commands[1]?.assurance_decision_id, "decision-post-change");

  const status = await statusTool.execute("status", { case_id: "work-1" }) as any;
  assert.equal(status.details.case.state, "closed");
  assert.equal(status.details.work_item.item.verification.assurance_decision_id, "decision-post-change");
  const stored = await goals.get(goalId);
  assert.equal(stored?.status, "completed");
  assert.equal(stored?.completionReceipt?.status, "complete");
  assert.deepEqual(stored?.currentPlan.map((step) => [step.id, step.status]), [
    ["inspect-work-item", "completed"],
    ["record-remediation", "completed"],
    ["record-post-change-assurance", "completed"],
    ["verify-canonical-work", "completed"],
  ]);
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

function canonicalWorkItemRecord(): ComplianceWorkItemRecord {
  return {
    item: {
      id: "work-1",
      fingerprint_version: "v1",
      fingerprint: "sha256:work-1",
      basis: {
        tenant_id: "writer",
        program_id: "soc2",
        scope_revision_id: "scope-1",
        control_id: "CC6.1",
        objective_id: "objective-access",
        kind: "finding",
        subject_id: "aws:iam:user/operator",
        reason: "privileged access lacks current evidence",
        source_id: "aws",
      },
      state: "open",
      owner_id: "team-security",
      due_at: "2026-07-20T00:00:00.000Z",
      priority: "high",
      verification_required: true,
      occurrences: [{
        id: "occurrence-1",
        work_item_id: "work-1",
        assessment_run_id: "run-before-change",
        objective_result_id: "result-before-change",
        automated_result_hash: "sha256:automated",
        evidence_ids: ["evidence-before-change"],
        finding_ids: ["finding-1"],
        occurred_at: "2026-07-14T23:00:00.000Z",
        occurrence_hash: "sha256:occurrence",
      }],
      version: 1,
      updated_at: "2026-07-14T23:00:00.000Z",
    },
    occurrences: [],
    actions: [],
  };
}
