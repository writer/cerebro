import assert from "node:assert/strict";
import test from "node:test";
import { AutonomyGoalService } from "../src/autonomy/goal-service.js";
import { InMemoryAutonomyGoalStore, type AutonomousGoalRecord } from "../src/autonomy/goals.js";
import { claimVerificationText, investigationPlanRevision } from "../src/autonomy/investigation-plan-revision.js";
import { AutonomyRunner } from "../src/autonomy/runner.js";
import type { ClaimVerification, ClaimVerificationActionStage, ClaimVerificationVerdict, Finding, FindingEvidence, RuntimeHealth } from "../src/cerebro/types.js";
import { testConfig } from "./fixtures.js";

const NOW = new Date("2026-06-26T20:00:00.000Z");
const DEFAULT_RUNTIME = "writer-okta";
const FINDING_ID = "finding-1";
const RESOURCE_URN = "urn:cerebro:writer:entity:okta-user-123";

type VerificationOverride = Partial<ClaimVerification> & {
  verdict?: ClaimVerificationVerdict;
  allowed_next_stage?: ClaimVerificationActionStage;
};

interface PlanRevisionEval {
  name: string;
  packet: Record<string, unknown>;
  expectedTitle?: string;
  expectedSummaryIncludes?: string;
  expectedVerificationText?: string;
}

const planRevisionEvals: PlanRevisionEval[] = [
  {
    name: "no claim verification keeps the existing plan",
    packet: { gaps: [] },
  },
  {
    name: "supported recommend evidence moves to recommendation writing",
    packet: {
      gaps: [],
      claim_verification: verification({ verdict: "supported", allowed_next_stage: "recommend" }),
    },
    expectedTitle: "Write recommendation from verified evidence",
    expectedSummaryIncludes: "Claim supported allows recommend",
    expectedVerificationText: "Claim supported allows recommend",
  },
  {
    name: "supported dry-run clearance can still write the recommendation",
    packet: {
      gaps: [],
      claim_verification: verification({ verdict: "supported", allowed_next_stage: "dry_run" }),
    },
    expectedTitle: "Write recommendation from verified evidence",
    expectedSummaryIncludes: "Claim supported allows dry_run",
  },
  {
    name: "supported approve clearance can still write the recommendation",
    packet: {
      gaps: [],
      claim_verification: verification({ verdict: "supported", allowed_next_stage: "approve" }),
    },
    expectedTitle: "Write recommendation from verified evidence",
    expectedSummaryIncludes: "Claim supported allows approve",
  },
  {
    name: "supported execute clearance can still write the recommendation",
    packet: {
      gaps: [],
      claim_verification: verification({ verdict: "supported", allowed_next_stage: "execute" }),
    },
    expectedTitle: "Write recommendation from verified evidence",
    expectedSummaryIncludes: "Claim supported allows execute",
  },
  {
    name: "supported claim with gaps stays in evidence collection",
    packet: {
      gaps: ["Runtime health was unavailable for this runtime."],
      claim_verification: verification({ verdict: "supported", allowed_next_stage: "recommend" }),
    },
    expectedTitle: "Collect missing evidence before recommendation",
    expectedSummaryIncludes: "Runtime health was unavailable",
  },
  {
    name: "weak evidence stays in evidence collection",
    packet: {
      gaps: [],
      claim_verification: verification({ verdict: "weakly_supported", allowed_next_stage: "explain" }),
    },
    expectedTitle: "Collect missing evidence before recommendation",
    expectedSummaryIncludes: "Claim weakly_supported allows explain",
  },
  {
    name: "unknown verdict stays in evidence collection",
    packet: {
      gaps: [],
      claim_verification: verification({ verdict: "unknown", allowed_next_stage: "observe" }),
    },
    expectedTitle: "Collect missing evidence before recommendation",
    expectedSummaryIncludes: "Claim unknown allows observe",
  },
  {
    name: "supported explain clearance stays in evidence collection",
    packet: {
      gaps: [],
      claim_verification: verification({ verdict: "supported", allowed_next_stage: "explain" }),
    },
    expectedTitle: "Collect missing evidence before recommendation",
    expectedSummaryIncludes: "Claim supported allows explain",
  },
  {
    name: "counterevidence verdict blocks recommendation",
    packet: {
      gaps: [],
      claim_verification: verification({ verdict: "contradicted", allowed_next_stage: "observe" }),
    },
    expectedTitle: "Resolve counterevidence before recommendation",
    expectedSummaryIncludes: "counterevidence blocks recommendation",
  },
  {
    name: "counterevidence blocker blocks recommendation even with supported verdict",
    packet: {
      gaps: [],
      claim_verification: verification({
        verdict: "supported",
        allowed_next_stage: "recommend",
        blockers: [{ code: "counterevidence_present", message: "Conflicting evidence exists." }],
      }),
    },
    expectedTitle: "Resolve counterevidence before recommendation",
    expectedSummaryIncludes: "counterevidence blocks recommendation",
  },
  {
    name: "verifier error creates a retry step",
    packet: {
      gaps: [],
      claim_verification: { error: "claim verifier timed out" },
    },
    expectedTitle: "Retry claim verification before recommendation",
    expectedSummaryIncludes: "claim verifier timed out",
    expectedVerificationText: "Claim unknown allows observe",
  },
  {
    name: "malformed verification fields default to observe",
    packet: {
      gaps: [],
      claim_verification: { verdict: "", allowed_next_stage: "", blockers: [{ code: "" }] },
    },
    expectedTitle: "Collect missing evidence before recommendation",
    expectedSummaryIncludes: "Claim unknown allows observe",
    expectedVerificationText: "Claim unknown allows observe",
  },
  {
    name: "multiple gap strings are summarized without losing the first gap",
    packet: {
      gaps: [
        "No evidence rows were returned; verify ingestion coverage before making a confidence claim.",
        "Finding does not include a returned observation timestamp.",
        "No primary resource URN or graph root was available for neighborhood expansion.",
        "Runtime health was unavailable for this runtime.",
      ],
      claim_verification: verification({ verdict: "weakly_supported", allowed_next_stage: "explain" }),
    },
    expectedTitle: "Collect missing evidence before recommendation",
    expectedSummaryIncludes: "No evidence rows were returned",
  },
];

for (const scenario of planRevisionEvals) {
  test(`synthetic plan revision eval: ${scenario.name}`, () => {
    const revision = investigationPlanRevision(scenario.packet);
    const text = claimVerificationText(scenario.packet);

    if (!scenario.expectedTitle) {
      assert.equal(revision, undefined);
      assert.equal(text, "");
      return;
    }

    assert.equal(revision?.title, scenario.expectedTitle);
    assert.match(revision?.summary ?? "", new RegExp(escapeRegExp(scenario.expectedSummaryIncludes ?? scenario.expectedTitle)));
    if (scenario.expectedVerificationText) {
      assert.match(text, new RegExp(escapeRegExp(scenario.expectedVerificationText)));
    }
  });
}

interface RunnerEval {
  name: string;
  objective?: string;
  defaultRuntimeIds?: string[];
  finding?: Finding | null;
  evidence?: FindingEvidence[];
  health?: RuntimeHealth[];
  verification?: VerificationOverride;
  verificationError?: string;
  relatedFindings?: Finding[];
  recentFindings?: Finding[];
  findingEvidenceError?: string;
  runtimeHealthError?: string;
  graphError?: string;
  expectedToolId: "autonomy.cerebro_finding_investigation" | "autonomy.cerebro_context_investigation";
  expectedNextTitle: string;
  expectedSummaryIncludes: string[];
  expectedStatus?: AutonomousGoalRecord["status"];
  expectedCallsInclude?: string[];
  expectedCallsExclude?: string[];
  expectedVerificationCount?: number;
  expectedPlanUpdated?: boolean;
  expectedAssumptionIncludes?: string;
  expectedGaps?: number;
}

const runnerEvals: RunnerEval[] = [
  {
    name: "fresh supported evidence prepares a recommendation",
    verification: verification({ verdict: "supported", allowed_next_stage: "recommend" }),
    expectedToolId: "autonomy.cerebro_finding_investigation",
    expectedNextTitle: "Write recommendation from verified evidence",
    expectedSummaryIncludes: ["1 evidence row(s)", "0 gap(s)", "Claim supported allows recommend"],
    expectedGaps: 0,
  },
  {
    name: "dry-run clearance still stops at recommendation writing",
    verification: verification({ verdict: "supported", allowed_next_stage: "dry_run" }),
    expectedToolId: "autonomy.cerebro_finding_investigation",
    expectedNextTitle: "Write recommendation from verified evidence",
    expectedSummaryIncludes: ["Claim supported allows dry_run"],
    expectedGaps: 0,
  },
  {
    name: "weak support collects more evidence",
    verification: verification({ verdict: "weakly_supported", allowed_next_stage: "explain" }),
    expectedToolId: "autonomy.cerebro_finding_investigation",
    expectedNextTitle: "Collect missing evidence before recommendation",
    expectedSummaryIncludes: ["Claim weakly_supported allows explain"],
    expectedGaps: 0,
  },
  {
    name: "unknown verdict collects more evidence",
    verification: verification({ verdict: "unknown", allowed_next_stage: "observe" }),
    expectedToolId: "autonomy.cerebro_finding_investigation",
    expectedNextTitle: "Collect missing evidence before recommendation",
    expectedSummaryIncludes: ["Claim unknown allows observe"],
    expectedGaps: 0,
  },
  {
    name: "supported explain clearance collects more evidence",
    verification: verification({ verdict: "supported", allowed_next_stage: "explain" }),
    expectedToolId: "autonomy.cerebro_finding_investigation",
    expectedNextTitle: "Collect missing evidence before recommendation",
    expectedSummaryIncludes: ["Claim supported allows explain"],
    expectedGaps: 0,
  },
  {
    name: "contradicted evidence creates a counterevidence step",
    verification: verification({ verdict: "contradicted", allowed_next_stage: "observe" }),
    expectedToolId: "autonomy.cerebro_finding_investigation",
    expectedNextTitle: "Resolve counterevidence before recommendation",
    expectedSummaryIncludes: ["Claim contradicted allows observe"],
    expectedGaps: 0,
  },
  {
    name: "counterevidence blocker wins over supported verdict",
    verification: verification({
      verdict: "supported",
      allowed_next_stage: "recommend",
      blockers: [{ code: "counterevidence_present", message: "Another artifact contradicts the finding state." }],
    }),
    expectedToolId: "autonomy.cerebro_finding_investigation",
    expectedNextTitle: "Resolve counterevidence before recommendation",
    expectedSummaryIncludes: ["Claim supported allows recommend"],
    expectedGaps: 0,
  },
  {
    name: "verifier outage creates a retry step",
    verificationError: "claim verifier returned 503",
    expectedToolId: "autonomy.cerebro_finding_investigation",
    expectedNextTitle: "Retry claim verification before recommendation",
    expectedSummaryIncludes: ["Claim unknown allows observe"],
    expectedGaps: 0,
  },
  {
    name: "no evidence rows blocks recommendation",
    evidence: [],
    verification: verification({ verdict: "weakly_supported", allowed_next_stage: "explain" }),
    expectedToolId: "autonomy.cerebro_finding_investigation",
    expectedNextTitle: "Collect missing evidence before recommendation",
    expectedSummaryIncludes: ["0 evidence row(s)", "1 gap(s)", "Claim weakly_supported allows explain"],
    expectedGaps: 1,
  },
  {
    name: "missing runtime health blocks recommendation",
    health: [],
    verification: verification({ verdict: "supported", allowed_next_stage: "recommend" }),
    expectedToolId: "autonomy.cerebro_finding_investigation",
    expectedNextTitle: "Collect missing evidence before recommendation",
    expectedSummaryIncludes: ["1 gap(s)", "Claim supported allows recommend"],
    expectedGaps: 1,
  },
  {
    name: "runtime health read failure blocks recommendation",
    runtimeHealthError: "runtime health timed out",
    verification: verification({ verdict: "supported", allowed_next_stage: "recommend" }),
    expectedToolId: "autonomy.cerebro_finding_investigation",
    expectedNextTitle: "Collect missing evidence before recommendation",
    expectedSummaryIncludes: ["1 gap(s)", "Claim supported allows recommend"],
    expectedGaps: 1,
  },
  {
    name: "missing observation timestamp blocks recommendation",
    finding: { last_observed_at: undefined, observed_at: undefined },
    evidence: [evidenceRow({ observed_at: undefined })],
    verification: verification({ verdict: "supported", allowed_next_stage: "recommend" }),
    expectedToolId: "autonomy.cerebro_finding_investigation",
    expectedNextTitle: "Collect missing evidence before recommendation",
    expectedSummaryIncludes: ["1 gap(s)", "Claim supported allows recommend"],
    expectedGaps: 1,
  },
  {
    name: "missing resource context skips graph and blocks recommendation",
    finding: { primary_resource_urn: undefined, resource_urn: undefined },
    evidence: [evidenceRow({ graph_root_urn: undefined, graph_path_urn: undefined })],
    verification: verification({ verdict: "supported", allowed_next_stage: "recommend" }),
    expectedToolId: "autonomy.cerebro_finding_investigation",
    expectedNextTitle: "Collect missing evidence before recommendation",
    expectedSummaryIncludes: ["1 gap(s)", "Claim supported allows recommend"],
    expectedCallsExclude: [`graph:${RESOURCE_URN}`],
    expectedGaps: 1,
  },
  {
    name: "finding lookup miss blocks recommendation",
    finding: null,
    verification: verification({ verdict: "unknown", allowed_next_stage: "observe" }),
    expectedToolId: "autonomy.cerebro_finding_investigation",
    expectedNextTitle: "Collect missing evidence before recommendation",
    expectedSummaryIncludes: ["1 gap(s)", "Claim unknown allows observe"],
    expectedCallsExclude: [`findings:${DEFAULT_RUNTIME}:rule:okta.mfa`],
    expectedGaps: 1,
  },
  {
    name: "evidence read failure blocks recommendation",
    findingEvidenceError: "evidence API timed out",
    verification: verification({ verdict: "weakly_supported", allowed_next_stage: "explain" }),
    expectedToolId: "autonomy.cerebro_finding_investigation",
    expectedNextTitle: "Collect missing evidence before recommendation",
    expectedSummaryIncludes: ["0 evidence row(s)", "1 gap(s)", "Claim weakly_supported allows explain"],
    expectedGaps: 1,
  },
  {
    name: "graph read failure does not block verified recommendation",
    graphError: "graph read timed out",
    verification: verification({ verdict: "supported", allowed_next_stage: "recommend" }),
    expectedToolId: "autonomy.cerebro_finding_investigation",
    expectedNextTitle: "Write recommendation from verified evidence",
    expectedSummaryIncludes: ["0 gap(s)", "Claim supported allows recommend"],
    expectedGaps: 0,
  },
  {
    name: "external-only evidence urns require more evidence when verifier says weak",
    finding: { primary_resource_urn: "urn:external:okta:user:123" },
    evidence: [evidenceRow({ graph_root_urn: "urn:external:okta:user:123" })],
    verification: verification({ verdict: "weakly_supported", allowed_next_stage: "explain" }),
    expectedToolId: "autonomy.cerebro_finding_investigation",
    expectedNextTitle: "Collect missing evidence before recommendation",
    expectedSummaryIncludes: ["0 gap(s)", "Claim weakly_supported allows explain"],
    expectedGaps: 0,
  },
  {
    name: "single default runtime is assumed for a bare finding id",
    objective: "investigate finding finding-1",
    verification: verification({ verdict: "supported", allowed_next_stage: "recommend" }),
    expectedToolId: "autonomy.cerebro_finding_investigation",
    expectedNextTitle: "Write recommendation from verified evidence",
    expectedSummaryIncludes: ["Claim supported allows recommend"],
    expectedAssumptionIncludes: "Assumed runtime writer-okta",
    expectedGaps: 0,
  },
  {
    name: "multiple default runtimes keep a bare finding id in context mode",
    objective: "investigate finding finding-1",
    defaultRuntimeIds: ["writer-okta", "writer-github"],
    expectedToolId: "autonomy.cerebro_context_investigation",
    expectedNextTitle: "Build evidence ledger and related-entity scope",
    expectedSummaryIncludes: ["finding id detected without runtime"],
    expectedVerificationCount: 0,
    expectedPlanUpdated: false,
    expectedCallsInclude: ["health:writer-okta,writer-github", "reasonGraph"],
    expectedAssumptionIncludes: "Finding id was detected, but no runtime id was present",
  },
  {
    name: "no finding id uses context investigation across configured runtimes",
    objective: "investigate Okta posture drift today",
    defaultRuntimeIds: ["writer-okta", "writer-slack"],
    expectedToolId: "autonomy.cerebro_context_investigation",
    expectedNextTitle: "Build evidence ledger and related-entity scope",
    expectedSummaryIncludes: ["finding id not detected"],
    expectedVerificationCount: 0,
    expectedPlanUpdated: false,
    expectedCallsInclude: ["health:writer-okta,writer-slack", "findings:writer-okta:recent", "findings:writer-slack:recent", "reasonGraph"],
  },
  {
    name: "explicit runtime keeps context investigation scoped",
    objective: "investigate runtime writer-okta for new critical identity findings",
    defaultRuntimeIds: ["writer-okta", "writer-github"],
    expectedToolId: "autonomy.cerebro_context_investigation",
    expectedNextTitle: "Build evidence ledger and related-entity scope",
    expectedSummaryIncludes: ["1 runtime(s)", "finding id not detected"],
    expectedVerificationCount: 0,
    expectedPlanUpdated: false,
    expectedCallsInclude: ["health:writer-okta", "findings:writer-okta:recent", "reasonGraph"],
    expectedCallsExclude: ["findings:writer-github:recent"],
  },
];

for (const scenario of runnerEvals) {
  test(`synthetic autonomy runner eval: ${scenario.name}`, async () => {
    const result = await runRunnerEval(scenario);
    const lastRun = result.updated.toolRuns.at(-1);
    const details = result.updated.workLog.at(-1)?.details ?? "";

    assert.equal(result.advance.status, "advanced");
    assert.equal(result.updated.status, scenario.expectedStatus ?? "active");
    assert.equal(result.updated.currentPlan[0]?.status, "completed");
    assert.equal(result.updated.currentPlan[1]?.title, scenario.expectedNextTitle);
    assert.equal(lastRun?.toolId, scenario.expectedToolId);
    assert.equal(lastRun?.status, "completed");
    for (const expected of scenario.expectedSummaryIncludes) {
      assert.match(lastRun?.responseSummary ?? "", new RegExp(escapeRegExp(expected)));
    }
    if (scenario.expectedGaps !== undefined) {
      assert.match(lastRun?.responseSummary ?? "", new RegExp(`${scenario.expectedGaps} gap\\(s\\)`));
    }
    assert.equal(result.updated.toolRuns.some((run) => /approved_execution|approval_request|execute/.test(run.toolId)), false);
    assert.match(details, /read-only/i);

    const expectedVerificationCount = scenario.expectedVerificationCount ?? (scenario.expectedToolId === "autonomy.cerebro_finding_investigation" ? 1 : 0);
    assert.equal(result.verificationRequests.length, expectedVerificationCount);
    if (expectedVerificationCount > 0) {
      assert.equal(result.verificationRequests[0]?.claim_type, "finding_triage");
      assert.equal(result.verificationRequests[0]?.requested_action_stage, "recommend");
    }

    if (scenario.expectedPlanUpdated ?? scenario.expectedToolId === "autonomy.cerebro_finding_investigation") {
      assert.ok(result.updated.workLog.some((entry) => entry.kind === "plan_updated" && entry.summary.includes(scenario.expectedNextTitle)));
    } else {
      assert.equal(result.updated.workLog.some((entry) => entry.kind === "plan_updated"), false);
    }
    const expectedAssumption = scenario.expectedAssumptionIncludes;
    if (expectedAssumption) {
      assert.ok(result.updated.assumptions.some((assumption) => assumption.includes(expectedAssumption)));
    }
    for (const expected of scenario.expectedCallsInclude ?? []) {
      assert.ok(result.calls.includes(expected), `${scenario.name} expected call ${expected}; calls: ${result.calls.join(", ")}`);
    }
    for (const unexpected of scenario.expectedCallsExclude ?? []) {
      assert.equal(result.calls.includes(unexpected), false, `${scenario.name} did not expect call ${unexpected}; calls: ${result.calls.join(", ")}`);
    }
  });
}

function verification(overrides: VerificationOverride): ClaimVerification {
  return {
    claim: "Finding finding-1 is actionable.",
    verdict: overrides.verdict ?? "supported",
    allowed_next_stage: overrides.allowed_next_stage ?? "recommend",
    blockers: overrides.blockers ?? [],
    warnings: overrides.warnings ?? [],
    ...overrides,
  };
}

async function runRunnerEval(scenario: RunnerEval): Promise<{
  advance: Awaited<ReturnType<AutonomyRunner["advance"]>>;
  updated: AutonomousGoalRecord;
  calls: string[];
  verificationRequests: Array<Record<string, unknown>>;
}> {
  const now = () => NOW;
  const calls: string[] = [];
  const verificationRequests: Array<Record<string, unknown>> = [];
  const config = testConfig({
    autonomy: { runnerLeaseMs: 30_000 },
    cerebro: { defaultRuntimeIds: scenario.defaultRuntimeIds ?? [DEFAULT_RUNTIME] },
  });
  const store = new InMemoryAutonomyGoalStore(now);
  const service = new AutonomyGoalService(config, { store, now });
  const cerebro = {
    listFindings: async (runtimeId: string, input: { findingId?: string; ruleId?: string }) => {
      if (input.findingId) {
        calls.push(`findings:${runtimeId}:id:${input.findingId}`);
        if (scenario.finding === null) return [];
        return [findingRecord(scenario.finding)];
      }
      if (input.ruleId) {
        calls.push(`findings:${runtimeId}:rule:${input.ruleId}`);
        return scenario.relatedFindings ?? [findingRecord({ id: "related-1", title: "Related MFA finding" })];
      }
      calls.push(`findings:${runtimeId}:recent`);
      return scenario.recentFindings ?? [findingRecord({ id: `recent-${runtimeId}`, runtime_id: runtimeId })];
    },
    listFindingEvidence: async (_runtimeId: string, findingId: string) => {
      calls.push(`evidence:${findingId}`);
      if (scenario.findingEvidenceError) throw new Error(scenario.findingEvidenceError);
      return scenario.evidence ?? [evidenceRow()];
    },
    listRuntimeHealth: async (input: { runtimeId?: string; runtimeIds?: string[] }) => {
      calls.push(`health:${input.runtimeId ?? input.runtimeIds?.join(",") ?? "configured"}`);
      if (scenario.runtimeHealthError) throw new Error(scenario.runtimeHealthError);
      return scenario.health ?? [runtimeHealth(input.runtimeId ?? input.runtimeIds?.[0] ?? DEFAULT_RUNTIME)];
    },
    graphNeighborhood: async (urn: string) => {
      calls.push(`graph:${urn}`);
      if (scenario.graphError) throw new Error(scenario.graphError);
      return { root_urn: urn, neighbors: [] };
    },
    reasonGraph: async () => {
      calls.push("reasonGraph");
      return { answer: "Context graph reviewed.", confidence: "synthetic" };
    },
    verifyAgentClaim: async (request: Record<string, unknown>) => {
      calls.push("verifyClaim");
      verificationRequests.push(request);
      if (scenario.verificationError) throw new Error(scenario.verificationError);
      return verification({ claim: String(request.claim ?? ""), ...scenario.verification });
    },
  };
  const memory = {
    search: async () => [{
      id: "memory-1",
      kind: "investigation_note",
      topic: "Identity findings",
      summary: "Check claim verification before recommending action.",
      tags: ["synthetic"],
      createdAt: NOW.toISOString(),
    }],
  };
  const runner = new AutonomyRunner(config, service, {
    workerId: "synthetic-eval-worker",
    now,
    cerebro: cerebro as any,
    memory: memory as any,
  });
  const goal = await service.createFromText({
    text: scenario.objective ?? `investigate runtime ${DEFAULT_RUNTIME} finding ${FINDING_ID}`,
    actor: { slackUserId: "UUSER", actorId: "actor-1" },
    channelId: "CSEC",
  });
  assert.equal(goal.capabilityId, "investigation");

  const advance = await runner.advance(goal.id);
  const updated = await service.get(goal.id);
  if (!updated) throw new Error(`Goal ${goal.id} was not found after runner advance.`);
  return { advance, updated, calls, verificationRequests };
}

function findingRecord(overrides: Finding = {}): Finding {
  return {
    id: FINDING_ID,
    runtime_id: DEFAULT_RUNTIME,
    rule_id: "okta.mfa",
    title: "Privileged user missing MFA",
    summary: "An admin user has no enrolled MFA factor.",
    severity: "high",
    status: "open",
    risk_score: 91,
    primary_resource_urn: RESOURCE_URN,
    last_observed_at: "2026-06-26T19:50:00.000Z",
    ...overrides,
  };
}

function evidenceRow(overrides: FindingEvidence = {}): FindingEvidence {
  return {
    id: "ev-1",
    finding_id: FINDING_ID,
    rule_id: "okta.mfa",
    evidence_type: "identity",
    summary: "MFA factor missing.",
    graph_root_urn: RESOURCE_URN,
    observed_at: "2026-06-26T19:50:00.000Z",
    ...overrides,
  };
}

function runtimeHealth(runtimeId: string): RuntimeHealth {
  return {
    runtime_id: runtimeId,
    status: "healthy",
    sync_status: "fresh",
    graph_status: "fresh",
    finding_status: "fresh",
    last_observed_at: "2026-06-26T19:55:00.000Z",
  };
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
