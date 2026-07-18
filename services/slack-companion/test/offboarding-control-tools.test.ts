import assert from "node:assert/strict";
import test from "node:test";
import type { AgentTool } from "@earendil-works/pi-agent-core";
import { createOffboardingControlTools } from "../src/agent/tools/offboarding-control-tools.js";
import { securityAgentToolMetadata } from "../src/agent/tools/tool-metadata.js";
import type { SecurityToolDeps } from "../src/agent/tools/types.js";
import { AutonomyGoalService } from "../src/autonomy/goal-service.js";
import { InMemoryAutonomyGoalStore } from "../src/autonomy/goals.js";
import { AutonomyRunner } from "../src/autonomy/runner.js";
import { AutonomyToolDispatcher } from "../src/autonomy/tool-dispatcher.js";
import { testConfig } from "./fixtures.js";

const runtimeSets = {
  okta_runtime_ids: ["okta-users"],
  github_runtime_ids: ["github-audit"],
  aws_runtime_ids: ["aws-identity"],
};
const subjectURN = "urn:cerebro:identity:person-1";
const findingID = "finding-offboarding-1";

test("offboarding preflight discovers provider coverage once and conditionally creates the durable snapshot", async () => {
  const fixture = sourceFixture();
  const result = await execute(fixture.deps, "cerebro_offboarding_preflight", {
    subject_urn: subjectURN,
    finding_id: findingID,
    create_snapshot_when_ready: true,
  });

  assert.equal(result.provider_coverage_complete, true);
  assert.equal(result.provider_validation_complete, true);
  assert.equal(result.ready_for_snapshot, true);
  assert.equal(result.snapshot_created, true);
  assert.equal(result.snapshot.provider_coverage_complete, true);
  assert.equal(result.snapshot.exact_finding_open, true);
  assert.equal(result.mutations_attempted, false);
  assert.equal(result.answer_complete, true);
  assert.equal(result.stop_after_preflight, true);
  assert.deepEqual(result.provider_state.map((row: any) => row.provider), ["okta", "github", "aws"]);
  assert.ok(result.provider_state.every((row: any) => row.provider_sync_validated));
  assert.deepEqual(fixture.calls.connectorDetail.sort(), ["aws", "github", "okta"]);
  assert.deepEqual(fixture.calls.connectorCoverage.sort(), ["aws", "github", "okta"]);
  assert.deepEqual(fixture.calls.runtimeFilters.sort(), ["aws", "github", "okta"]);
  assert.deepEqual(fixture.calls.healthFilters.sort(), ["aws", "github", "okta"]);
  assert.ok(result.provider_state.every((row: any) => row.protected_credential_metadata.status === "not_requested_by_design"));
  assert.ok(JSON.stringify(result).length < 20_000);
  assert.equal(fixture.calls.sync.length, 0);
  assert.equal(fixture.calls.actions.length, 0);
});

test("offboarding preflight returns the exact GitHub onboarding action and gates the snapshot", async () => {
  const fixture = sourceFixture({ omitRuntime: "github-audit" });
  const result = await execute(fixture.deps, "cerebro_offboarding_preflight", {
    create_snapshot_when_ready: true,
  });

  const github = result.provider_state.find((row: any) => row.provider === "github");
  assert.equal(result.provider_coverage_complete, false);
  assert.equal(result.provider_validation_complete, false);
  assert.equal(result.snapshot_created, false);
  assert.equal(github.connector_catalog_present, true);
  assert.deepEqual(github.source_ids, ["github"]);
  assert.deepEqual(github.runtime_ids, []);
  assert.equal(github.connector_attestation.status, "not_configured");
  assert.match(github.next_operator_action, /Configure one GitHub source runtime from connector github/);
  assert.ok(result.blockers.includes("No GitHub source runtime is enrolled."));
  assert.ok(result.blockers.includes("Snapshot creation was gated off because provider coverage or validation is incomplete."));
  assert.equal(fixture.calls.packets.length, 0);
});

test("offboarding preflight never infers provider coverage from a runtime name", async () => {
  const fixture = sourceFixture({ omitSourceIdentity: "github-audit" });
  const result = await execute(fixture.deps, "cerebro_offboarding_preflight", {});

  const github = result.provider_state.find((row: any) => row.provider === "github");
  assert.equal(result.provider_coverage_complete, false);
  assert.deepEqual(github.runtime_ids, []);
  assert.deepEqual(github.source_ids, ["github"]);
});

test("offboarding snapshot proves Okta, GitHub, and AWS coverage and persists a decision receipt", async () => {
  const fixture = sourceFixture();
  const result = await execute(fixture.deps, "cerebro_offboarding_snapshot", {
    ...runtimeSets,
    subject_urn: subjectURN,
    finding_id: findingID,
  });

  assert.equal(result.provider_coverage_complete, true);
  assert.deepEqual(result.source_systems_validated, ["okta", "github", "aws"]);
  assert.equal(result.subject_bound, true);
  assert.equal(result.exact_finding_open, true);
  assert.equal(result.ready_for_action, true);
  assert.match(result.snapshot_digest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(result.decision_packet_id, "dpr_offboarding_baseline");
  assert.equal(fixture.calls.claims.length, 3);
  assert.equal(fixture.calls.packets.length, 1);
  assert.deepEqual(fixture.calls.packets[0].required_sources.sort(), ["aws", "github", "okta"]);
});

test("offboarding snapshot fails closed when one provider read is unavailable", async () => {
  const fixture = sourceFixture({ failRuntime: "aws-identity" });
  const result = await execute(fixture.deps, "cerebro_offboarding_snapshot", {
    ...runtimeSets,
    subject_urn: subjectURN,
    finding_id: findingID,
    persist_receipt: false,
  });

  assert.equal(result.provider_coverage_complete, true);
  assert.equal(result.ready_for_action, false);
  assert.ok(result.blockers.some((value: string) => value.includes("Source reads failed")));
});

test("offboarding snapshot does not count an unknown runtime as observed provider coverage", async () => {
  const fixture = sourceFixture({ omitRuntime: "github-audit" });
  const result = await execute(fixture.deps, "cerebro_offboarding_snapshot", {
    ...runtimeSets,
    subject_urn: subjectURN,
    finding_id: findingID,
    persist_receipt: false,
  });

  assert.equal(result.provider_coverage_complete, false);
  assert.deepEqual(result.source_systems_validated, ["okta", "aws"]);
  assert.equal(result.runtime_state.find((row: any) => row.runtime_id === "github-audit")?.observed, false);
  assert.equal(result.ready_for_action, false);
});

test("offboarding refresh is approval-gated and verifies new revisions after all source stages", async () => {
  const fixture = sourceFixture();
  const dryRun = await execute(fixture.deps, "cerebro_offboarding_refresh", {
    ...runtimeSets,
    subject_urn: subjectURN,
    finding_id: findingID,
    reason: "Refresh exact provider evidence",
    idempotency_key: "refresh-1",
  });
  assert.equal(dryRun.dry_run, true);
  assert.equal(fixture.calls.sync.length, 0);

  const blocked = await execute(fixture.deps, "cerebro_offboarding_refresh", {
    ...runtimeSets,
    subject_urn: subjectURN,
    finding_id: findingID,
    reason: "Refresh exact provider evidence",
    idempotency_key: "refresh-1",
    execute: true,
  });
  assert.equal(blocked.error, "approval_required");
  assert.equal(fixture.calls.sync.length, 0);

  const refreshed = await execute(fixture.deps, "cerebro_offboarding_refresh", {
    ...runtimeSets,
    subject_urn: subjectURN,
    finding_id: findingID,
    reason: "Refresh exact provider evidence",
    idempotency_key: "refresh-1",
    execute: true,
    approved: true,
  });
  assert.equal(refreshed.refresh_verified, true);
  assert.equal(fixture.calls.sync.length, 3);
  assert.equal(fixture.calls.graph.length, 3);
  assert.deepEqual(fixture.calls.evaluate, ["okta-users"]);
  assert.equal(refreshed.refresh_receipt.changed_runtime_ids.length, 3);
  assert.match(refreshed.refresh_receipt.digest, /^sha256:[a-f0-9]{64}$/);
});

test("offboarding action binds execution to the reviewed stable dry-run digest", async () => {
  const fixture = sourceFixture();
  const proposal = await execute(fixture.deps, "cerebro_offboarding_action", {
    action: "identity.okta.suspend_user",
    finding_id: findingID,
    target: "person-1",
    reason: "Terminated identity retains production access",
    idempotency_key: "action-1",
  });
  assert.equal(proposal.dry_run, true);
  assert.match(proposal.proposal_digest, /^sha256:[a-f0-9]{64}$/);

  const stale = await execute(fixture.deps, "cerebro_offboarding_action", {
    action: "identity.okta.suspend_user",
    finding_id: findingID,
    target: "person-1",
    reason: "Terminated identity retains production access",
    idempotency_key: "action-1",
    expected_proposal_digest: "sha256:stale",
    execute: true,
    approved: true,
  });
  assert.equal(stale.error, "stale_proposal");
  assert.equal(fixture.calls.actions.filter((request) => request.dry_run === false).length, 0);

  const executed = await execute(fixture.deps, "cerebro_offboarding_action", {
    action: "identity.okta.suspend_user",
    finding_id: findingID,
    target: "person-1",
    reason: "Terminated identity retains production access",
    idempotency_key: "action-1",
    expected_proposal_digest: proposal.proposal_digest,
    execute: true,
    approved: true,
  });
  assert.equal(executed.action_succeeded, true);
  assert.equal(executed.action_receipt.external_id, "provider-action-1");
  assert.equal(fixture.calls.actions.filter((request) => request.dry_run === false).length, 1);
});

test("offboarding verification closes only from changed revisions, a successful action ref, and the independent verifier", async () => {
  const fixture = sourceFixture({ findingOpen: false, resolvedAction: true });
  const result = await execute(fixture.deps, "cerebro_offboarding_verify", {
    ...runtimeSets,
    subject_urn: subjectURN,
    finding_id: findingID,
    baseline_snapshot_digest: "sha256:baseline",
    baseline_runtime_revisions: {
      "okta-users": "sha256:old-okta",
      "github-audit": "sha256:old-github",
      "aws-identity": "sha256:old-aws",
    },
    baseline_subject_revision: "sha256:old-subject",
    action_actor_id: "slack:U123",
    verifier_id: "cerebro:source-recollection-verifier",
  });

  assert.equal(result.closure_verified, true);
  assert.equal(result.closure_receipt.status, "verified_closed");
  assert.equal(result.closure_receipt.action_external_id, "provider-action-1");
  assert.equal(result.closure_receipt.decision_packet_id, "dpr_offboarding_baseline");
  assert.match(result.closure_receipt.digest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(fixture.calls.verify.length, 1);
});

test("offboarding verification refuses closure without a successful provider action receipt", async () => {
  const fixture = sourceFixture({ findingOpen: false, resolvedAction: false });
  const result = await execute(fixture.deps, "cerebro_offboarding_verify", {
    ...runtimeSets,
    subject_urn: subjectURN,
    finding_id: findingID,
    baseline_snapshot_digest: "sha256:baseline",
    baseline_runtime_revisions: {
      "okta-users": "sha256:old-okta",
      "github-audit": "sha256:old-github",
      "aws-identity": "sha256:old-aws",
    },
    baseline_subject_revision: "sha256:old-subject",
    action_actor_id: "slack:U123",
  });

  assert.equal(result.closure_verified, false);
  assert.ok(result.blockers.includes("No successful provider action receipt is linked to the finding."));
});

test("durable offboarding run contains approval-gated execution, recollection, and closure checks", async () => {
  const fixture = sourceFixture();
  let createInput: any;
  fixture.deps.autonomyGoals = {
    createFromText: async () => { throw new Error("unexpected createFromText"); },
    createFromPlan: async (input: any) => {
      createInput = input;
      return {
        id: "goal-offboarding-1",
        status: "active",
        objective: input.objective,
        currentPlan: input.plan,
        resourceRefs: input.resourceRefs,
        acceptanceCriteria: input.acceptanceCriteria,
        nextWakeAt: "2026-07-16T12:00:00.000Z",
      } as any;
    },
  } as any;
  const result = await execute(fixture.deps, "operator_offboarding_control_start", {
    ...runtimeSets,
    subject_urn: subjectURN,
    finding_id: findingID,
    finding_runtime_id: "okta-users",
    action: "identity.okta.suspend_user",
    target: "person-1",
    reason: "Terminated identity retains production access",
    idempotency_key: "action-1",
    proposal_digest: "sha256:proposal",
    baseline_snapshot_digest: "sha256:baseline",
    baseline_runtime_revisions: {
      "okta-users": "sha256:old-okta",
      "github-audit": "sha256:old-github",
      "aws-identity": "sha256:old-aws",
    },
    baseline_subject_revision: "sha256:old-subject",
    action_actor_id: "slack:U123",
    requested_by_slack_user_id: "U123",
  });

  assert.equal(result.created, true);
  assert.equal(result.goal_id, "goal-offboarding-1");
  assert.equal(createInput.capabilityId, "remediation");
  assert.deepEqual(createInput.plan.map((step: any) => step.execution.toolName), [
    "cerebro_offboarding_action",
    "cerebro_offboarding_refresh",
    "cerebro_offboarding_verify",
  ]);
  assert.equal(createInput.plan[0].execution.approvalRequired, true);
  assert.equal(createInput.plan[1].execution.approvalRequired, true);
  assert.equal(createInput.plan[2].execution.approvalRequired, false);
  assert.equal(createInput.acceptanceCriteria.at(-1).field, "closure_verified");
});

test("durable offboarding run executes end to end through two approvals and verified closure", async () => {
  const now = () => new Date("2026-07-16T12:00:00.000Z");
  const config = testConfig({ autonomy: { runnerLeaseMs: 30_000 } });
  const store = new InMemoryAutonomyGoalStore(now);
  const goals = new AutonomyGoalService(config, { store, now });
  const fixture = sourceFixture();
  fixture.deps.autonomyGoals = goals;
  const tools = createOffboardingControlTools(fixture.deps);
  const proposal = await execute(fixture.deps, "cerebro_offboarding_action", {
    action: "identity.okta.suspend_user",
    finding_id: findingID,
    target: "person-1",
    reason: "Terminated identity retains production access",
    idempotency_key: "action-e2e",
  });
  const baseline = await execute(fixture.deps, "cerebro_offboarding_snapshot", {
    ...runtimeSets,
    subject_urn: subjectURN,
    finding_id: findingID,
  });
  const started = await execute(fixture.deps, "operator_offboarding_control_start", {
    ...runtimeSets,
    subject_urn: subjectURN,
    finding_id: findingID,
    finding_runtime_id: "okta-users",
    action: "identity.okta.suspend_user",
    target: "person-1",
    reason: "Terminated identity retains production access",
    idempotency_key: "action-e2e",
    proposal_digest: proposal.proposal_digest,
    baseline_snapshot_digest: baseline.snapshot_digest,
    baseline_runtime_revisions: baseline.runtime_revisions,
    baseline_subject_revision: baseline.subject_revision,
    baseline_decision_packet_id: baseline.decision_packet_id,
    action_actor_id: "slack:U1",
    requested_by_slack_user_id: "U1",
  });
  const runner = new AutonomyRunner(config, goals, {
    now,
    workerId: "offboarding-e2e",
    dispatcher: new AutonomyToolDispatcher(tools),
  });

  await runner.advance(started.goal_id);
  let goal = await goals.get(started.goal_id);
  assert.equal(goal?.status, "approval_needed");
  assert.equal(goal?.approvals.length, 1);
  await goals.decideApproval({
    goalId: goal!.id,
    approvalId: goal!.approvals[0]!.id,
    decision: "approved",
    actor: { slackUserId: "U2", actorId: "slack:U2" },
  });

  await runner.advance(started.goal_id);
  goal = await goals.get(started.goal_id);
  assert.equal(goal?.currentPlan[0]?.status, "completed");
  assert.equal(fixture.calls.actions.filter((request) => request.dry_run === false).length, 1);

  await runner.advance(started.goal_id);
  goal = await goals.get(started.goal_id);
  assert.equal(goal?.status, "approval_needed");
  assert.equal(goal?.approvals.length, 2);
  await goals.decideApproval({
    goalId: goal!.id,
    approvalId: goal!.approvals[1]!.id,
    decision: "approved",
    actor: { slackUserId: "U2", actorId: "slack:U2" },
  });

  await runner.advance(started.goal_id);
  goal = await goals.get(started.goal_id);
  assert.equal(goal?.currentPlan[1]?.status, "completed");
  assert.equal(fixture.state.findingOpen, false);

  await runner.advance(started.goal_id);
  goal = await goals.get(started.goal_id);
  assert.equal(goal?.status, "completed", JSON.stringify({
    plan: goal?.currentPlan,
    blockers: goal?.blockers,
    toolRuns: goal?.toolRuns,
    workLog: goal?.workLog,
  }, null, 2));
  assert.equal(goal?.currentPlan[2]?.status, "completed");
  assert.equal(goal?.completionReceipt?.status, "complete");
  assert.deepEqual(goal?.completionReceipt?.criteriaPassed, [
    "provider-action-executed",
    "provider-state-recollected",
    "closure-verified",
  ]);
  assert.ok(goal?.completionReceipt?.evidenceRefs.some((ref) => ref.includes("offboarding-closure")));
});

test("offboarding tool metadata keeps reads separate from provider and source writes", () => {
  assert.equal(securityAgentToolMetadata("cerebro_offboarding_preflight").authority, "read");
  assert.equal(securityAgentToolMetadata("cerebro_offboarding_snapshot").authority, "read");
  assert.equal(securityAgentToolMetadata("cerebro_offboarding_verify").authority, "read");
  assert.equal(securityAgentToolMetadata("cerebro_offboarding_refresh").sideEffect, "cerebro_source_run");
  assert.equal(securityAgentToolMetadata("cerebro_offboarding_action").sideEffect, "cerebro_graph_action");
  assert.equal(securityAgentToolMetadata("operator_offboarding_control_start").authority, "autonomy_write");
});

async function execute(deps: SecurityToolDeps, name: string, args: Record<string, unknown>): Promise<any> {
  const tool = createOffboardingControlTools(deps).find((candidate) => candidate.name === name);
  assert.ok(tool, `missing tool ${name}`);
  const result = await tool.execute(`call-${name}`, args) as any;
  return result.details;
}

function sourceFixture(options: {
  failRuntime?: string;
  omitRuntime?: string;
  omitSourceIdentity?: string;
  findingOpen?: boolean;
  resolvedAction?: boolean;
} = {}) {
  let revision = 1;
  const state = {
    findingOpen: options.findingOpen !== false,
    actionExecuted: false,
  };
  const calls = {
    claims: [] as string[],
    packets: [] as any[],
    sync: [] as string[],
    graph: [] as string[],
    evaluate: [] as string[],
    actions: [] as any[],
    verify: [] as any[],
    connectorDetail: [] as string[],
    connectorCoverage: [] as string[],
    runtimeFilters: [] as string[],
    healthFilters: [] as string[],
  };
  const runtimeIDs = Object.values(runtimeSets).flat();
  const sourceID = (runtimeID: string) => runtimeID.startsWith("okta") ? "okta" : runtimeID.startsWith("github") ? "github" : "aws";
  const now = () => new Date().toISOString();
  const openFinding = {
    id: findingID,
    runtime_id: "okta-users",
    rule_id: "identity-okta-deprovisioned-active-cloud-access",
    status: "open",
    primary_resource_urn: subjectURN,
    last_observed_at: now(),
  };
  const resolvedFinding = {
    ...openFinding,
    status: "resolved",
    external_refs: options.resolvedAction === false ? [] : [{
      system: "access-approvals",
      kind: "graph_action",
      external_id: "provider-action-1",
      external_status: "succeeded",
    }],
  };
  const deps: SecurityToolDeps = {
    config: testConfig(),
    memory: { search: async () => [] } as any,
    cerebro: {
      listRuntimeHealth: async ({ runtimeIds, sourceId }: { runtimeIds?: string[]; sourceId?: string }) => {
        if (sourceId) calls.healthFilters.push(sourceId);
        const selected = runtimeIds ?? (sourceId ? runtimeIDs.filter((runtimeID) => sourceID(runtimeID) === sourceId) : runtimeIDs);
        return selected.filter((runtimeID) => runtimeID !== options.omitRuntime).map((runtimeID) => ({
        runtime_id: runtimeID,
        source_id: runtimeID === options.omitSourceIdentity ? undefined : sourceID(runtimeID),
        status: "healthy",
        sync_status: "completed",
        contract_probe_status: "passing",
        last_synced_at: now(),
        generated_at: now(),
        latest_graph_run: { id: `graph-${runtimeID}-${revision}`, status: "succeeded", checkpoint_cursor: `cursor-${revision}` },
        latest_finding_evaluation: { id: `finding-eval-${runtimeID}-${revision}`, status: "succeeded" },
        }));
      },
      listSourceRuntimes: async ({ runtimeIds, sourceId }: { runtimeIds?: string[]; sourceId?: string }) => {
        if (sourceId) calls.runtimeFilters.push(sourceId);
        const selected = runtimeIds ?? (sourceId ? runtimeIDs.filter((runtimeID) => sourceID(runtimeID) === sourceId) : runtimeIDs);
        return { runtimes: selected.filter((runtimeID) => runtimeID !== options.omitRuntime).map((runtimeID) => ({
          id: runtimeID,
          source_id: runtimeID === options.omitSourceIdentity ? undefined : sourceID(runtimeID),
          last_synced_at: now(),
          checkpoint: { revision },
          next_cursor: { revision },
        })) };
      },
      getConnector: async (sourceIDValue: string) => {
        calls.connectorDetail.push(sourceIDValue);
        const configured = !options.omitRuntime || sourceID(options.omitRuntime) !== sourceIDValue;
        return {
          source_id: sourceIDValue,
          status: configured ? "available" : "not_configured",
          availability: configured ? "healthy" : "not_configured",
          auth_model: "provider_api",
          has_provider_api_contract: true,
          has_provider_api_mapping: true,
          has_provider_api_proof: configured,
          provider_api_status: configured ? "verified" : "not_configured",
          provider_api_verified_at: configured ? now() : undefined,
          provider_api_base_url: `https://api.${sourceIDValue}.example.com`,
          provider_api_auth: "reference",
          provider_api_auth_mechanics: "runtime_reference",
          verification_endpoint: `/connectors/${sourceIDValue}`,
          setup_guidance: `Configure ${sourceIDValue} with credential references.`,
          summary: {
            total_connections: configured ? 1 : 0,
            healthy_connections: configured ? 1 : 0,
          },
          connections: configured ? [{ status: "healthy", last_activity_at: now() }] : [],
        };
      },
      connectorCoverage: async ({ sourceId }: { sourceId?: string }) => {
        calls.connectorCoverage.push(sourceId ?? "");
        return {
          coverage: [{ source_id: sourceId, state: sourceId === "github" && options.omitRuntime ? "unconfigured" : "healthy" }],
          coverage_gate: { status: sourceId === "github" && options.omitRuntime ? "failed" : "passed", reason: "provider_coverage" },
        };
      },
      listClaims: async (runtimeID: string) => {
        calls.claims.push(runtimeID);
        if (options.failRuntime === runtimeID) throw new Error(`provider read failed for ${runtimeID}`);
        return { claims: [{ id: `claim-${runtimeID}-${revision}`, subject_urn: subjectURN, predicate: "active", object_value: "false" }] };
      },
      listFindings: async (runtimeID: string, input: { status?: string; findingId?: string }) => {
        if (runtimeID !== "okta-users") return [];
        if (input.status === "resolved" && !state.findingOpen) return [resolvedFinding];
        if (input.status === "open" && state.findingOpen) return [openFinding];
        return [];
      },
      buildDecisionPacket: async (request: any) => {
        calls.packets.push(request);
        return decisionPacket(request);
      },
      syncRuntime: async (runtimeID: string) => {
        calls.sync.push(runtimeID);
        revision += 1;
        return { runtime_id: runtimeID, status: "succeeded", revision };
      },
      runGraphIngest: async (runtimeID: string) => {
        calls.graph.push(runtimeID);
        revision += 1;
        return { runtime_id: runtimeID, status: "succeeded", revision };
      },
      evaluateFindings: async (runtimeID: string) => {
        calls.evaluate.push(runtimeID);
        revision += 1;
        if (state.actionExecuted) state.findingOpen = false;
        return { runtime_id: runtimeID, status: "succeeded", revision };
      },
      executeGraphAction: async (request: any) => {
        calls.actions.push(request);
        if (!request.dry_run) state.actionExecuted = true;
        return {
          action: {
            action: request.action,
            provider: "access-approvals",
            target: request.target,
            status: request.dry_run ? "dry_run" : "succeeded",
            external_status: request.dry_run ? undefined : "succeeded",
            external_id: request.dry_run ? undefined : "provider-action-1",
            idempotency_key: request.idempotency_key,
            completed_at: request.dry_run ? undefined : now(),
          },
        };
      },
      verifyAgentClaim: async (request: any) => {
        calls.verify.push(request);
        return { claim: request.claim, verdict: "supported", allowed_next_stage: "close_loop" };
      },
    } as any,
  };
  assert.deepEqual(runtimeIDs, ["okta-users", "github-audit", "aws-identity"]);
  return { deps, calls, state };
}

function decisionPacket(request: any): any {
  return {
    schema_version: "1",
    id: "dpr_offboarding_baseline",
    generated_at: new Date().toISOString(),
    workflow: { id: request.workflow, question: request.question },
    scope: { urn: request.scope_urn },
    inputs: {
      finding_ids: request.finding_ids ?? [],
      claim_ids: [],
      evidence_urns: [],
      audit_packet_ids: [],
      required_sources: request.required_sources ?? [],
      requested_action: request.requested_action,
    },
    decision: { state: "review", reasons: [] },
    confidence: { level: "high", basis: ["source coverage"] },
    freshness: { state: "fresh", required_stale: false },
    evidence: [],
    contradictions: [],
    coverage_gaps: [],
    affected: [],
    controls: [],
    audit_packets: [],
    actions: [],
    provenance: {
      resolver_ids: ["source-runtimes"],
      source_ids: request.required_sources ?? [],
      evidence_digest: "sha256:evidence",
      coverage_digest: "sha256:coverage",
    },
  };
}
