import assert from "node:assert/strict";
import test from "node:test";
import { SecurityResearchState } from "../src/agent/research-state.js";

test("research state verifies required claims only against successful observed tools", () => {
  const state = new SecurityResearchState();
  state.setAvailableTools(["cerebro_findings", "cerebro_graph_cypher_investigate"]);
  const plan = state.establishPlan({
    decision: "Decide whether the finding is still active and exposed.",
    entities: ["finding-1", "resource-1"],
    source_candidates: ["cerebro_findings", "missing_tool"],
    claims: [
      { id: "finding-active", claim: "The finding is active.", source_candidates: ["cerebro_findings"] },
      { id: "resource-exposed", claim: "The resource is exposed.", source_candidates: ["cerebro_graph_cypher_investigate"] },
    ],
  }) as any;
  assert.deepEqual(plan.plan.source_candidates, ["cerebro_findings"]);
  assert.deepEqual(plan.plan.unknown_source_candidates, ["missing_tool"]);

  const observed = state.recordToolResult("cerebro_findings", { details: { findings: [{ id: "finding-1" }] } });
  assert.match(observed?.evidenceReceipt ?? "", /^evidence:cerebro_findings:/);
  state.recordToolResult("cerebro_graph_cypher_investigate", { details: { error: "service unavailable" } });
  const result = state.closeClaimLedger({
    claims: [
      { id: "finding-active", status: "supported", source_tools: ["cerebro_findings"], evidence_receipts: [observed?.evidenceReceipt ?? ""], evidence_refs: ["finding:finding-1"], source_scope: "tenant findings visible to the configured runtime", coverage: "one exact finding id", absence_meaning: "An empty result would prove only that this runtime returned no visible match." },
      { id: "resource-exposed", status: "supported", source_tools: ["cerebro_graph_cypher_investigate"] },
    ],
    answer_ready: true,
  }) as any;

  assert.equal(result.claim_ledger.coverage, 0.5);
  assert.equal(result.claim_ledger.answer_ready, false);
  assert.equal(result.claim_ledger.claims[0].verified, true);
  assert.equal(result.claim_ledger.claims[0].source_scope, "tenant findings visible to the configured runtime");
  assert.match(result.claim_ledger.claims[0].absence_meaning, /runtime returned no visible match/);
  assert.equal(result.claim_ledger.claims[1].status, "unverified");
  assert.deepEqual(result.claim_ledger.claims[1].source_tools, []);
  assert.deepEqual(state.telemetryAttributes(), {
    "assistant.research.plan_present": true,
    "assistant.research.claim_ledger_closed": true,
    "assistant.research.required_claim_count": 2,
    "assistant.research.verified_claim_count": 1,
    "assistant.research.claim_coverage": 0.5,
    "assistant.research.answer_ready": false,
    "assistant.research.evidence_tool_completed_count": 1,
    "assistant.research.evidence_tool_partial_count": 0,
    "assistant.research.evidence_tool_failed_count": 1,
    "assistant.research.evidence_receipt_count": 1,
    "assistant.research.source_candidate_count": 2,
    "assistant.research.source_cooldown_count": 0,
    "assistant.research.scope_failure_count": 0,
    "assistant.research.selected_tool_count": 0,
    "assistant.intelligence.world_fact_count": 0,
    "assistant.intelligence.verified_fact_count": 0,
    "assistant.intelligence.hypothesis_count": 0,
    "assistant.intelligence.open_hypothesis_count": 0,
    "assistant.intelligence.decision_count": 0,
    "assistant.intelligence.workflow_present": false,
    "assistant.intelligence.workflow_valid": false,
    "assistant.intelligence.simulation_ready": false,
    "assistant.intelligence.attention_recommendation": "unset",
  });
});

test("partial source facts remain bounded evidence without opening the failure circuit", () => {
  const state = new SecurityResearchState();
  state.setAvailableTools(["cerebro_graph_reason"]);
  state.establishPlan({
    decision: "Check the alert host and user in the graph.",
    claims: [{ id: "host-link", claim: "The host is linked to the rotated secret.", source_candidates: ["cerebro_graph_reason"] }],
  });

  const observed = state.recordToolResult("cerebro_graph_reason", { details: {
    success: false,
    status: "partial",
    facts: ["host:build-runner-14 is linked to the rotated CI secret."],
    records: [{ id: "host:build-runner-14", secret: "ci-signing" }],
    error: "The j.reyes lookup timed out.",
  } });

  assert.match(observed?.evidenceReceipt ?? "", /^evidence:cerebro_graph_reason:/);
  assert.equal(state.lastToolFailed("cerebro_graph_reason"), false);
  assert.equal(state.toolFailureCount("cerebro_graph_reason"), 0);
  assert.equal(state.sourceHealthSnapshot("cerebro_graph_reason").allowed, true);
  assert.equal(state.telemetryAttributes()["assistant.research.evidence_tool_partial_count"], 1);
  assert.equal((state.snapshot() as any).tool_runs[0].status, "partial");

  const result = state.closeClaimLedger({
    claims: [{
      id: "host-link",
      status: "supported",
      source_tools: ["cerebro_graph_reason"],
      evidence_receipts: [observed?.evidenceReceipt ?? ""],
    }],
  }) as any;
  assert.equal(result.claim_ledger.claims[0].verified, true);
});

test("scope failures do not cool down a reachable source", () => {
  const state = new SecurityResearchState();
  state.recordToolResult("cerebro_code_github_pr_status", {
    details: { error: "GitHub request failed with 404: repository not found or app not installed" },
  });
  state.recordToolResult("cerebro_code_github_pr_status", {
    details: { error: "repo not allowed for this installation scope" },
  });

  const snapshot = state.snapshot() as any;
  assert.deepEqual(snapshot.tool_runs.map((run: any) => run.failure_kind), ["scope", "scope"]);
  assert.equal(state.sourceHealthSnapshot("cerebro_code_github_pr_status").allowed, true);
  assert.equal(state.telemetryAttributes()["assistant.research.scope_failure_count"], 2);
});

test("staged research plans seed the same claim ledger used by the Pi runtime", () => {
  const state = new SecurityResearchState();
  state.setAvailableTools(["cerebro_companion_self_context"]);
  state.seedStagedPlan({
    user_intent: "Identify the running companion instance.",
    research_plan: ["Verify the configured runtime and deployment environment."],
    required_sources: ["cerebro_companion_self_context"],
    user_visible_work: ["Check companion runtime context"],
  });
  const observed = state.recordToolResult("cerebro_companion_self_context", { details: { deployment_environment: "sec-dev" } });
  assert.equal(state.completionIssue(), "claim_ledger_not_closed");
  const result = state.closeClaimLedger({
    claims: [{ id: "claim-1", status: "supported", source_tools: ["cerebro_companion_self_context"], evidence_receipts: [observed?.evidenceReceipt ?? ""] }],
    answer_ready: true,
  }) as any;

  assert.equal(result.claim_ledger.coverage, 1);
  assert.equal(result.claim_ledger.answer_ready, true);
  assert.equal(state.completionIssue(), undefined);
});

test("research state rejects a supported claim without an issued evidence receipt", () => {
  const state = new SecurityResearchState();
  state.setAvailableTools(["cerebro_findings"]);
  state.establishPlan({
    decision: "Check findings.",
    claims: [{ id: "finding-current", claim: "The finding is current." }],
  });
  const observed = state.recordToolResult("cerebro_findings", { details: { id: "finding-1" } });

  const missingReceipt = state.closeClaimLedger({
    claims: [{ id: "finding-current", status: "supported", source_tools: ["cerebro_findings"] }],
    answer_ready: true,
  }) as any;
  assert.equal(missingReceipt.claim_ledger.claims[0].status, "unverified");

  const inventedReceipt = state.closeClaimLedger({
    claims: [{ id: "finding-current", status: "supported", source_tools: ["cerebro_findings"], evidence_receipts: ["evidence:cerebro_findings:invented"] }],
    answer_ready: true,
  }) as any;
  assert.equal(inventedReceipt.claim_ledger.claims[0].status, "unverified");

  const exactReceipt = state.closeClaimLedger({
    claims: [{ id: "finding-current", status: "supported", source_tools: ["cerebro_findings"], evidence_receipts: [observed?.evidenceReceipt ?? ""] }],
    answer_ready: true,
  }) as any;
  assert.equal(exactReceipt.claim_ledger.claims[0].verified, true);
});

test("research state rejects empty plans after evidence tools run", () => {
  const state = new SecurityResearchState();
  state.setAvailableTools(["cerebro_findings"]);
  state.establishPlan({ decision: "Check findings.", claims: [] });
  state.recordToolResult("cerebro_findings", { details: { findings: [] } });

  assert.equal(state.completionIssue(), "research_plan_has_no_claims");
});

test("negative claims require scope, coverage, and absence semantics", () => {
  const state = new SecurityResearchState();
  state.setAvailableTools(["cerebro_findings"]);
  state.establishPlan({
    decision: "Check whether any findings are visible.",
    claims: [{ id: "no-findings", claim: "No findings are open.", source_candidates: ["cerebro_findings"] }],
  });
  const observed = state.recordToolResult("cerebro_findings", { details: { findings: [] } });
  const unsupported = state.closeClaimLedger({
    claims: [{ id: "no-findings", status: "supported", source_tools: ["cerebro_findings"], evidence_receipts: [observed?.evidenceReceipt ?? ""] }],
    answer_ready: true,
  }) as any;
  assert.equal(unsupported.claim_ledger.claims[0].verified, false);

  const scoped = state.closeClaimLedger({
    claims: [{
      id: "no-findings",
      status: "supported",
      source_tools: ["cerebro_findings"],
      evidence_receipts: [observed?.evidenceReceipt ?? ""],
      source_scope: "configured runtime writer-okta-user",
      coverage: "open findings returned by that runtime",
      absence_meaning: "The checked runtime returned no visible open findings; other runtimes were not checked.",
    }],
    answer_ready: true,
  }) as any;
  assert.equal(scoped.claim_ledger.claims[0].verified, true);
});

test("research evidence keeps finding URLs and runtime subjects bound to their source records", () => {
  const state = new SecurityResearchState();
  state.setAvailableTools(["cerebro_findings"]);
  state.establishPlan({
    decision: "Check the exact finding.",
    claims: [{ id: "finding-current", claim: "Finding f-17 is open.", source_candidates: ["cerebro_findings"] }],
  });
  const observed = state.recordToolResult("cerebro_findings", { details: {
    findings: [{ finding_id: "f-17", title: "Public login role", status: "open", web_url: "https://cerebro.example/findings/f-17", observed_at: "2026-07-15T12:00:00Z" }],
  } });
  state.closeClaimLedger({ claims: [{
    id: "finding-current",
    status: "supported",
    source_tools: ["cerebro_findings"],
    evidence_receipts: [observed?.evidenceReceipt ?? ""],
    evidence_refs: ["f-17"],
  }] });
  const answer = state.reconcileClaimEvidence({
    answer: "Finding f-17 is open.", messages: ["Finding f-17 is open."], keyPoints: [], evidence: ["Finding f-17 returned open."], actionsTaken: ["Checked the finding."], nextActions: [], research: [], memoryUpdates: [], source: "flue",
    claimEvidenceBindings: [{ claimId: "finding-current", claimText: "Finding f-17 is open.", temporalScope: "current", evidenceIds: [] }],
  });
  const evidence = answer.claimEvidence?.[0]?.evidence[0];
  assert.equal(evidence?.subjectId, "f-17");
  assert.equal(evidence?.subjectKind, "finding");
  assert.equal(evidence?.permalink, "https://cerebro.example/findings/f-17");
  assert.equal(answer.claimEvidence?.[0]?.verification, "verified");
});
