import assert from "node:assert/strict";
import test from "node:test";
import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import { AgentToolCatalog } from "../src/agent/tool-catalog.js";
import { toolResult } from "../src/agent/tools/index.js";
import { canonicalResourceRef, parseAgentStepExecution } from "../src/autonomy/agent-run.js";
import { AutonomyGoalService } from "../src/autonomy/goal-service.js";
import { InMemoryAutonomyGoalStore } from "../src/autonomy/goals.js";
import { AutonomyRunner } from "../src/autonomy/runner.js";
import { AutonomyToolDispatcher } from "../src/autonomy/tool-dispatcher.js";
import { testConfig } from "./fixtures.js";

test("agent tool catalog discovers exact tools and validates arguments", () => {
  const catalog = new AgentToolCatalog([readFindingTool(async () => ({ id: "f-1", status: "open" }))]);

  assert.equal(catalog.search({ query: "finding lookup" })[0]?.name, "finding_lookup");
  assert.deepEqual(catalog.validateArguments("finding_lookup", {}), {
    valid: false,
    errors: ["Missing required argument finding_id."],
  });
  assert.equal(catalog.validateArguments("finding_lookup", { finding_id: "f-1" }).valid, true);
  assert.equal(catalog.validateArguments("finding_lookup", { finding_id: "f-1", extra: true }).valid, false);
});

test("agent run execution rejects secret-like durable arguments", () => {
  assert.equal(parseAgentStepExecution({ toolName: "finding_lookup", arguments: { token: "secret-value" } }), undefined);
  assert.equal(parseAgentStepExecution({ toolName: "finding_lookup", arguments: { query: "api_key=secret-value" } }), undefined);
});

test("agent run executes an exact read tool and records a verified completion receipt", async () => {
  const now = () => new Date("2026-07-14T18:00:00.000Z");
  const store = new InMemoryAutonomyGoalStore(now);
  const service = new AutonomyGoalService(testConfig(), { store, now });
  const tool = readFindingTool(async () => ({ id: "f-1", status: "open", evidence_ref: "finding:f-1" }));
  const runner = new AutonomyRunner(testConfig({ autonomy: { runnerLeaseMs: 30_000 } }), service, {
    now,
    workerId: "runtime-test",
    dispatcher: new AutonomyToolDispatcher([tool]),
  });
  const goal = await service.createFromPlan({
    objective: "Verify finding f-1 is open.",
    capabilityId: "planner",
    actor: { slackUserId: "U1", actorId: "slack:U1" },
    resourceRefs: [canonicalResourceRef({ kind: "cerebro", id: "finding:f-1", source: "finding_lookup" })],
    acceptanceCriteria: [{ id: "finding-open", description: "Finding f-1 is open.", kind: "field_equals", field: "status", expected: "open", status: "pending", evidenceRefs: [] }],
    plan: [{
      id: "read-finding",
      title: "Read finding f-1",
      status: "pending",
      dependsOn: [],
      execution: { toolName: "finding_lookup", arguments: { finding_id: "f-1" }, verificationArguments: {}, approvalRequired: false, maxAttempts: 1, attempts: 0 },
      acceptanceCriteriaIds: ["finding-open"],
    }],
  });

  const result = await runner.advance(goal.id);
  const completed = await service.get(goal.id);

  assert.equal(result.status, "advanced");
  assert.equal(completed?.status, "completed");
  assert.equal(completed?.acceptanceCriteria[0]?.status, "passed");
  assert.equal(completed?.completionReceipt?.status, "complete");
  assert.deepEqual(completed?.completionReceipt?.evidenceRefs, ["finding:f-1"]);
  assert.equal(completed?.toolRuns[0]?.toolName, "finding_lookup");
});

test("agent run acceptance can verify a field inside a returned list", async () => {
  const now = () => new Date("2026-07-14T18:00:00.000Z");
  const store = new InMemoryAutonomyGoalStore(now);
  const service = new AutonomyGoalService(testConfig(), { store, now });
  const tool: AgentTool = {
    name: "finding_list",
    label: "Finding list",
    description: "Read findings.",
    parameters: Type.Object({}),
    execute: async () => toolResult({ findings: [{ id: "f-1", status: "resolved" }], evidence_ref: "finding:f-1" }),
  };
  const runner = new AutonomyRunner(testConfig({ autonomy: { runnerLeaseMs: 30_000 } }), service, {
    now,
    workerId: "runtime-test",
    dispatcher: new AutonomyToolDispatcher([tool]),
  });
  const goal = await service.createFromPlan({
    objective: "Verify finding f-1 is resolved.",
    capabilityId: "remediation",
    actor: { slackUserId: "U1", actorId: "slack:U1" },
    acceptanceCriteria: [{ id: "finding-resolved", description: "Finding f-1 is resolved.", kind: "field_equals", field: "findings.0.status", expected: "resolved", status: "pending", evidenceRefs: [] }],
    plan: [{
      id: "verify-finding-resolved",
      title: "Verify finding f-1 is resolved",
      status: "pending",
      dependsOn: [],
      execution: { toolName: "finding_list", arguments: {}, verificationArguments: {}, approvalRequired: false, maxAttempts: 1, attempts: 0 },
      acceptanceCriteriaIds: ["finding-resolved"],
    }],
  });

  await runner.advance(goal.id);
  const completed = await service.get(goal.id);

  assert.equal(completed?.status, "completed");
  assert.equal(completed?.acceptanceCriteria[0]?.status, "passed");
});

test("agent run requires approval for a write, resumes it, and verifies the result independently", async () => {
  const now = () => new Date("2026-07-14T18:00:00.000Z");
  const calls: string[] = [];
  const writeTool: AgentTool = {
    name: "finding_update",
    label: "Finding update",
    description: "Update one finding.",
    parameters: Type.Object({ finding_id: Type.String(), action: Type.String() }),
    execute: async (_id, args) => {
      calls.push(`write:${String((args as Record<string, unknown>).finding_id)}`);
      return toolResult({ finding_id: "f-1", status: "resolved", evidence_ref: "finding:f-1" });
    },
  };
  const readTool = readFindingTool(async (findingId) => {
    calls.push(`verify:${findingId}`);
    return { id: findingId, status: "resolved", evidence_ref: `finding:${findingId}` };
  });
  const config = testConfig({ autonomy: { runnerLeaseMs: 30_000 } });
  const store = new InMemoryAutonomyGoalStore(now);
  const service = new AutonomyGoalService(config, { store, now });
  const runner = new AutonomyRunner(config, service, {
    now,
    workerId: "runtime-test",
    dispatcher: new AutonomyToolDispatcher([writeTool, readTool]),
  });
  const goal = await service.createFromPlan({
    objective: "Resolve finding f-1 after approval.",
    capabilityId: "executor",
    actor: { slackUserId: "U1", actorId: "slack:U1" },
    acceptanceCriteria: [{ id: "finding-resolved", description: "Finding f-1 is resolved.", kind: "field_equals", field: "status", expected: "resolved", status: "pending", evidenceRefs: [] }],
    plan: [{
      id: "resolve-finding",
      title: "Resolve finding f-1",
      status: "pending",
      dependsOn: [],
      execution: {
        toolName: "finding_update",
        arguments: { finding_id: "f-1", action: "resolve" },
        verificationToolName: "finding_lookup",
        verificationArguments: { finding_id: "$result.finding_id" },
        approvalRequired: true,
        idempotencyKey: "resolve:f-1",
        rollback: "Reopen finding f-1.",
        maxAttempts: 1,
        attempts: 0,
      },
      acceptanceCriteriaIds: ["finding-resolved"],
    }],
  });

  await runner.advance(goal.id);
  const waiting = await service.get(goal.id);
  assert.equal(waiting?.status, "approval_needed");
  assert.equal(waiting?.currentPlan[0]?.status, "waiting");
  assert.deepEqual(calls, []);

  await service.decideApproval({ goalId: goal.id, approvalId: waiting!.approvals[0]!.id, decision: "approved", actor: { slackUserId: "U2", actorId: "slack:U2" } });
  await runner.advance(goal.id);
  const completed = await service.get(goal.id);

  assert.deepEqual(calls, ["write:f-1", "verify:f-1"]);
  assert.equal(completed?.status, "completed");
  assert.equal(completed?.approvals[0]?.status, "executed");
  assert.equal(completed?.acceptanceCriteria[0]?.status, "passed");
  assert.equal(completed?.completionReceipt?.verifier, "finding_lookup");
});

test("agent run checkpoints a bounded retry and completes on the next attempt", async () => {
  const now = () => new Date("2026-07-14T18:00:00.000Z");
  let attempts = 0;
  const tool = readFindingTool(async () => {
    attempts += 1;
    return attempts === 1
      ? { error: "temporary_source_failure" }
      : { id: "f-1", status: "open", evidence_ref: "finding:f-1" };
  });
  const config = testConfig({ autonomy: { runnerLeaseMs: 30_000 } });
  const store = new InMemoryAutonomyGoalStore(now);
  const service = new AutonomyGoalService(config, { store, now });
  const runner = new AutonomyRunner(config, service, { now, workerId: "runtime-test", dispatcher: new AutonomyToolDispatcher([tool]) });
  const goal = await service.createFromPlan({
    objective: "Retry the bounded finding read.",
    capabilityId: "planner",
    actor: { slackUserId: "U1", actorId: "slack:U1" },
    plan: [{
      id: "read-finding",
      title: "Read finding f-1",
      status: "pending",
      dependsOn: [],
      execution: { toolName: "finding_lookup", arguments: { finding_id: "f-1" }, verificationArguments: {}, approvalRequired: false, maxAttempts: 2, attempts: 0 },
    }],
  });

  const first = await runner.advance(goal.id);
  const retrying = await service.get(goal.id);
  assert.match(first.summary, /Retry 2 is scheduled/);
  assert.equal(retrying?.status, "active");
  assert.equal(retrying?.currentPlan[0]?.execution?.attempts, 1);
  assert.equal(retrying?.nextWakeAt, "2026-07-14T18:00:30.000Z");

  await runner.advance(goal.id);
  const completed = await service.get(goal.id);
  assert.equal(attempts, 2);
  assert.equal(completed?.status, "completed");
  assert.equal(completed?.currentPlan[0]?.execution?.attempts, 2);
});

function readFindingTool(read: (findingId: string) => Promise<Record<string, unknown>>): AgentTool {
  return {
    name: "finding_lookup",
    label: "Finding lookup",
    description: "Read one finding by id.",
    parameters: Type.Object({ finding_id: Type.String() }),
    execute: async (_id, args) => toolResult(await read(String((args as Record<string, unknown>).finding_id))),
  };
}
