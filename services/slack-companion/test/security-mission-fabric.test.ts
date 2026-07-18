import assert from "node:assert/strict";
import test from "node:test";
import { Type } from "@earendil-works/pi-ai";
import { AgentToolCatalog } from "../src/agent/tool-catalog.js";
import { createAgentRuntimeTools } from "../src/agent/tools/agent-runtime-tools.js";
import { securityAgentToolPolicy } from "../src/agent/tool-policy.js";
import { securityAgentToolMetadata } from "../src/agent/tools/tool-metadata.js";
import { verifyAgentRunStep } from "../src/autonomy/acceptance-verifier.js";
import { compileSecurityMission } from "../src/autonomy/mission-compiler.js";
import { securityMissionPacks, validateSecurityMissionPacks } from "../src/autonomy/mission-packs.js";
import { AutonomyGoalService } from "../src/autonomy/goal-service.js";
import { cloneGoal, toAutonomousGoalRecord } from "../src/autonomy/goal-codec.js";
import { InMemoryAutonomyGoalStore } from "../src/autonomy/goals.js";
import { AutonomyRunner } from "../src/autonomy/runner.js";
import { testConfig } from "./fixtures.js";

const NOW = new Date("2026-07-16T18:00:00.000Z");

test("security mission packs cover AppSec, identity, and detection with action-level controls", () => {
  const packs = securityMissionPacks();
  assert.doesNotThrow(() => validateSecurityMissionPacks(packs));
  assert.deepEqual(packs.map((pack) => pack.id), [
    "appsec.remediation",
    "identity.access-risk",
    "detection.response",
  ]);
  for (const pack of packs) {
    assert.match(pack.version, /^2026-07-16\./);
    assert.ok(pack.owner.startsWith("@writer/"));
    assert.ok(pack.requiredEvidence.length >= 5);
    assert.ok(pack.eventTriggers.length > 0);
    const executeSteps = pack.steps.filter((step) => step.actionStage === "execute");
    assert.ok(executeSteps.length > 0);
    assert.ok(executeSteps.every((step) => step.approvalRequired && step.verificationRequired && step.rollback));
    const securityWrites = pack.steps.filter((step) => step.toolSelector.authorities.includes("security_write"));
    assert.ok(securityWrites.every((step) => step.approvalRequired && step.verificationRequired && step.rollback));
  }
});

test("mission pack validation rejects dependency cycles", () => {
  const [appsec] = securityMissionPacks();
  assert.ok(appsec);
  appsec.steps.find((step) => step.id === "investigate-finding")!.dependsOn = ["verify-finding-closure"];
  assert.throws(() => validateSecurityMissionPacks([appsec]), /dependency cycle/);
});

test("AppSec mission compilation binds safe source reads and preserves later write gates", () => {
  const compilation = compileSecurityMission({
    objective: "Handle GitHub security alert finding-17 in runtime writer-github-dependabot for WriterInternal/example and PR #42",
    now: NOW,
  });
  assert.ok(compilation);
  assert.equal(compilation.pack.id, "appsec.remediation");
  assert.equal(compilation.pack.capabilityId, "remediation");
  assert.equal(compilation.receipt.status, "needs_tool");
  assert.deepEqual(compilation.receipt.missingInputIds, []);
  assert.equal(compilation.plan.find((step) => step.id === "investigate-finding")?.execution?.toolName, "cerebro_finding_investigation");
  assert.equal(compilation.plan.find((step) => step.id === "resolve-owner")?.execution?.toolName, "owner_resolve");
  assert.equal(compilation.plan.find((step) => step.id === "prepare-fix")?.mission?.bindingState, "needs_tool");
  assert.deepEqual(compilation.plan.find((step) => step.id === "open-fix-pr")?.mission?.toolSelector.names, ["cerebro_code_github_pr"]);
  const sourceRun = compilation.plan.find((step) => step.id === "rerun-source");
  assert.equal(sourceRun?.execution?.toolName, "source_run_trigger");
  assert.equal(sourceRun?.execution?.approvalRequired, true);
  assert.equal(sourceRun?.execution?.verificationToolName, "source_run_status");
  assert.ok(sourceRun?.execution?.idempotencyKey);
  assert.ok(sourceRun?.execution?.rollback);
  assert.match(compilation.receipt.planDigest, /^sha256:[a-f0-9]{64}$/);
});

test("identity mission skips unavailable optional attestation and waits for a reviewed revocation tool", () => {
  assert.equal(compileSecurityMission({ objective: "Investigate Okta blast radius", now: NOW }), undefined);
  const compilation = compileSecurityMission({
    objective: "Investigate Okta offboarding access",
    requestedPackId: "identity.access-risk",
    bindings: { identity_ref: "person://user-17", risk_ref: "finding-17" },
    now: NOW,
  });
  assert.ok(compilation);
  assert.equal(compilation.pack.capabilityId, "identity_response");
  assert.equal(compilation.plan.find((step) => step.id === "collect-identity-evidence")?.execution?.toolName, "cerebro_evidence_packet");
  assert.equal(compilation.plan.find((step) => step.id === "request-attestation")?.status, "skipped");
  const revoke = compilation.plan.find((step) => step.id === "revoke-access");
  assert.equal(revoke?.mission?.bindingState, "needs_tool");
  assert.equal(revoke?.mission?.approvalRequired, true);
  assert.deepEqual(revoke?.mission?.toolSelector.authorities, ["security_write"]);
  assert.deepEqual(revoke?.acceptanceCriteriaIds, ["identity-revocation-approved", "identity-access-revoked"]);
  assert.deepEqual(revoke?.dependsOn, ["correlate-access"]);
  assert.equal(compilation.acceptanceCriteria.some((criterion) => criterion.id === "identity-attestation-recorded"), false);
});

test("detection mission starts with provider discovery and treats mutating Panther tools as reviewed writes", () => {
  const compilation = compileSecurityMission({
    objective: "Handle Panther alert alert-17 for detection rule rule-9",
    now: NOW,
  });
  assert.ok(compilation);
  assert.equal(compilation.pack.id, "detection.response");
  assert.equal(compilation.pack.capabilityId, "detection_response");
  assert.equal(compilation.plan[0]?.execution?.toolName, "panther_mcp_status");
  assert.equal(securityAgentToolMetadata("panther_mcp_update_detection_rule").authority, "security_write");
  assert.equal(securityAgentToolMetadata("panther_mcp_get_alert").authority, "read");
  const policy = securityAgentToolPolicy("panther_mcp_update_detection_rule");
  assert.equal(policy.tier, "approval");
  assert.equal(policy.approvalRequired, true);
  assert.deepEqual(compilation.plan.find((step) => step.id === "deploy-rule")?.acceptanceCriteriaIds, [
    "detection-deployment-approved",
    "detection-rule-deployed",
  ]);
});

test("an action-level reviewed approval satisfies its manual acceptance check", async () => {
  const service = new AutonomyGoalService(testConfig(), { store: new InMemoryAutonomyGoalStore(() => NOW), now: () => NOW });
  const goal = await service.createFromText({
    text: "Revoke access for person://user-17 tied to finding-17",
    missionPackId: "identity.access-risk",
    missionBindings: { identity_ref: "person://user-17", risk_ref: "finding-17" },
    actor: { slackUserId: "UOPERATOR", actorId: "slack:UOPERATOR" },
  });
  const step = goal.currentPlan.find((candidate) => candidate.id === "revoke-access")!;
  const checked = verifyAgentRunStep({
    goal: {
      ...goal,
      approvals: [{
        id: "approval-17",
        status: "approved",
        stepId: step.id,
        toolId: "okta_revoke_assignment",
        actionSummary: step.title,
        reason: "Exact assignment and rollback reviewed.",
        risk: "One assignment is removed.",
        createdAt: NOW.toISOString(),
      }],
    },
    step,
    execution: { ok: true, toolName: "okta_revoke_assignment", summary: "Revoked.", details: {}, evidenceRefs: ["receipt://revocation-17"] },
    verification: { ok: true, toolName: "okta_assignment_status", summary: "Absent.", details: {}, evidenceRefs: ["receipt://verification-17"] },
    now: NOW,
  });
  assert.equal(checked.passed, true);
  assert.deepEqual(checked.passedIds, ["identity-revocation-approved", "identity-access-revoked"]);
  assert.equal(checked.evidenceRefs.includes("approval-17"), true);
});

test("goal creation persists the compiled mission receipt, plan, and acceptance checks", async () => {
  const store = new InMemoryAutonomyGoalStore(() => NOW);
  const service = new AutonomyGoalService(testConfig(), { store, now: () => NOW });
  const goal = await service.createFromText({
    text: "Handle finding-17 in runtime writer-github-dependabot for WriterInternal/example",
    missionPackId: "appsec.remediation",
    actor: { slackUserId: "UOPERATOR", actorId: "slack:UOPERATOR" },
  });
  const stored = await service.get(goal.id);
  assert.equal(stored?.mission?.packId, "appsec.remediation");
  assert.equal(stored?.capabilityId, "remediation");
  assert.equal(stored?.currentPlan.length, 9);
  assert.equal(stored?.acceptanceCriteria.length, 8);
  assert.equal(stored?.executionContract?.requestedActionStage, "execute");
  assert.equal(stored?.mission?.bindings.find((binding) => binding.id === "repository")?.value, "WriterInternal/example");

  const decoded = toAutonomousGoalRecord(JSON.parse(JSON.stringify(stored)));
  assert.equal(decoded?.mission?.planDigest, stored?.mission?.planDigest);
  assert.equal(decoded?.currentPlan.find((step) => step.id === "rerun-source")?.mission?.approvalRequired, true);
  const cloned = cloneGoal(stored!);
  cloned.mission!.bindings[0]!.value = "changed-outside-store";
  assert.notEqual(stored?.mission?.bindings[0]?.value, "changed-outside-store");
});

test("mission step binding enforces the pack selector and resumes the durable run", async () => {
  const store = new InMemoryAutonomyGoalStore(() => NOW);
  const service = new AutonomyGoalService(testConfig(), { store, now: () => NOW });
  const goal = await service.createFromText({
    text: "Handle finding-17 in runtime writer-github-dependabot for WriterInternal/example",
    missionPackId: "appsec.remediation",
    actor: { slackUserId: "UOPERATOR", actorId: "slack:UOPERATOR" },
  });
  await assert.rejects(() => service.bindMissionStep({
    goalId: goal.id,
    stepId: "open-fix-pr",
    execution: {
      toolName: "slack_message_search",
      arguments: { query: "finding-17" },
      verificationArguments: {},
      approvalRequired: false,
      maxAttempts: 1,
      attempts: 0,
    },
    toolMetadata: { name: "slack_message_search", ...securityAgentToolMetadata("slack_message_search") },
    acceptanceCriteriaIds: ["appsec-pr-created"],
  }), /outside the selector/);

  await assert.rejects(() => service.bindMissionStep({
    goalId: goal.id,
    stepId: "open-fix-pr",
    execution: {
      toolName: "cerebro_code_github_pr",
      arguments: { repo: "WriterInternal/example", title: "Fix finding-17", files: [] },
      verificationToolName: "cerebro_code_github_pr_status",
      verificationArguments: { repo: "WriterInternal/example", pull_number: 42, include_checks: true },
      approvalRequired: false,
      rollback: "Close the draft pull request and revert the workspace change.",
      maxAttempts: 1,
      attempts: 0,
    },
    toolMetadata: { name: "cerebro_code_github_pr", ...securityAgentToolMetadata("cerebro_code_github_pr") },
    missionBindings: { rule_ref: "rule-9" },
    acceptanceCriteriaIds: ["appsec-pr-created"],
  }), /does not accept input rule_ref/);

  const updated = await service.bindMissionStep({
    goalId: goal.id,
    stepId: "open-fix-pr",
    execution: {
      toolName: "cerebro_code_github_pr",
      arguments: { repo: "WriterInternal/example", title: "Fix finding-17", files: [] },
      verificationToolName: "cerebro_code_github_pr_status",
      verificationArguments: { repo: "WriterInternal/example", pull_number: 42, include_checks: true },
      approvalRequired: false,
      rollback: "Close the draft pull request and revert the workspace change.",
      maxAttempts: 1,
      attempts: 0,
    },
    toolMetadata: { name: "cerebro_code_github_pr", ...securityAgentToolMetadata("cerebro_code_github_pr") },
    acceptanceCriteriaIds: ["appsec-pr-created"],
  });
  assert.equal(updated.status, "active");
  assert.equal(updated.currentPlan.find((step) => step.id === "open-fix-pr")?.mission?.bindingState, "bound");
  assert.equal(updated.currentPlan.find((step) => step.id === "open-fix-pr")?.execution?.toolName, "cerebro_code_github_pr");
});

test("public mission tools compile host plans and enforce catalog metadata before binding", async () => {
  const store = new InMemoryAutonomyGoalStore(() => NOW);
  const service = new AutonomyGoalService(testConfig(), { store, now: () => NOW });
  const goal = await service.createFromText({
    text: "Handle finding-17 in runtime writer-github-dependabot for WriterInternal/example",
    missionPackId: "appsec.remediation",
    actor: { slackUserId: "UOPERATOR", actorId: "slack:UOPERATOR" },
  });
  const catalogOnlyTools = [
    {
      name: "cerebro_code_github_pr",
      label: "Open pull request",
      description: "Open a pull request.",
      parameters: Type.Object({ repo: Type.String(), title: Type.String() }),
      execute: async () => ({ content: [] }),
    },
    {
      name: "slack_message_search",
      label: "Search Slack",
      description: "Search Slack messages.",
      parameters: Type.Object({ query: Type.String() }),
      execute: async () => ({ content: [] }),
    },
    {
      name: "cerebro_code_github_pr_status",
      label: "Pull request status",
      description: "Read pull request status.",
      parameters: Type.Object({ repo: Type.String(), pull_number: Type.Number() }),
      execute: async () => ({ content: [] }),
    },
  ];
  let catalog: AgentToolCatalog;
  const runtimeTools = createAgentRuntimeTools({
    config: testConfig(),
    cerebro: {} as any,
    memory: {} as any,
    autonomyGoals: service,
  }, () => catalog);
  catalog = new AgentToolCatalog([...catalogOnlyTools, ...runtimeTools] as any);

  const compileTool = runtimeTools.find((tool) => tool.name === "operator_mission_compile")!;
  const compiled = await compileTool.execute("compile", {
    objective: "Handle finding-17 in runtime writer-github-dependabot for WriterInternal/example",
    pack_id: "appsec.remediation",
  }) as any;
  assert.equal(compiled.details.matched, true);
  assert.equal(compiled.details.mission.packId, "appsec.remediation");
  assert.equal(compiled.details.plan.length, 9);

  const bindTool = runtimeTools.find((tool) => tool.name === "operator_agent_run_step_bind")!;
  const rejected = await bindTool.execute("bind-rejected", {
    goal_id: goal.id,
    step_id: "open-fix-pr",
    tool_name: "slack_message_search",
    tool_arguments: { query: "finding-17" },
    acceptance_criteria_ids: ["appsec-pr-created"],
  }) as any;
  assert.equal(rejected.details.bound, false);
  assert.equal(rejected.details.error, "tool_outside_mission_selector");

  const bound = await bindTool.execute("bind", {
    goal_id: goal.id,
    step_id: "open-fix-pr",
    tool_name: "cerebro_code_github_pr",
    tool_arguments: { repo: "WriterInternal/example", title: "Fix finding-17" },
    verification_tool_name: "cerebro_code_github_pr_status",
    verification_arguments: { repo: "WriterInternal/example", pull_number: 42 },
    rollback: "Close the draft pull request and revert the workspace change.",
    acceptance_criteria_ids: ["appsec-pr-created"],
  }) as any;
  assert.equal(bound.details.bound, true);
  assert.equal(bound.details.step.execution.toolName, "cerebro_code_github_pr");
});

test("runner waits on an unbound mission decision instead of claiming completion", async () => {
  const now = () => NOW;
  const store = new InMemoryAutonomyGoalStore(now);
  const config = testConfig({ autonomy: { runnerLeaseMs: 30_000 } });
  const service = new AutonomyGoalService(config, { store, now });
  const compilation = compileSecurityMission({
    objective: "Handle Panther alert alert-17 for detection rule rule-9",
    now: NOW,
  });
  assert.ok(compilation);
  const plan = compilation.plan.map((step) => ({
    ...step,
    status: step.id === "record-disposition" ? "pending" as const : step.dependsOn.includes("record-disposition") ? step.status : "completed" as const,
  }));
  const goal = await store.create({
    objective: "Handle Panther alert alert-17 for detection rule rule-9",
    capabilityId: "detection_response",
    createdBy: { slackUserId: "UOPERATOR" },
    plan,
    mission: compilation.receipt,
    acceptanceCriteria: compilation.acceptanceCriteria,
    nextWakeAt: NOW.toISOString(),
  });
  const runner = new AutonomyRunner(config, service, { workerId: "worker-1", now });
  const result = await runner.advance(goal.id);
  const updated = await service.get(goal.id);
  assert.match(result.summary, /operator_agent_run_step_decide/);
  assert.equal(updated?.status, "waiting");
  assert.equal(updated?.currentPlan.find((step) => step.id === "record-disposition")?.status, "waiting");
  assert.match(updated?.blockers.at(-1) ?? "", /^\[mission:record-disposition\]/);
});
