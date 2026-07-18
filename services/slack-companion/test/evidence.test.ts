import assert from "node:assert/strict";
import test from "node:test";
import {
  citationQualityMetrics,
  evidenceCandidatesFromToolResult,
  reconcileClaimEvidence,
  renderClaimEvidence,
  resolveClaimEvidencePermalinks,
} from "../src/agent/evidence.js";
import { SecurityResearchState } from "../src/agent/research-state.js";
import type { SecurityAssistantAnswer } from "../src/agent/security-assistant-types.js";

test("memory evidence keeps bounded provenance and enforces the trusted Slack audience", () => {
  const details = {
    memories: [{
      id: "memory-1",
      kind: "owner_context",
      topic: "Checkout service owner",
      channelId: "CSEC",
      sourceTs: "1782501562.693279",
      createdAt: "2026-07-12T10:30:00.000Z",
      verifiedAt: "2026-07-12T11:00:00.000Z",
      verifiedBy: ["slack_message_context"],
      sourceArtifacts: ["service-catalog:checkout"],
    }],
    diagnostics: {
      results: [{ id: "memory-1", quality: "source_verified", freshness: "current" }],
      conflicts: [{ recordIds: ["memory-1", "memory-2"] }],
    },
  };

  const allowed = evidenceCandidatesFromToolResult("security_memory_intelligence", details, "CSEC");
  const restricted = evidenceCandidatesFromToolResult("security_memory_intelligence", details, "CPRIVATE");

  assert.equal(allowed[0]?.access, "allowed");
  assert.equal(allowed[0]?.quality, "source_verified");
  assert.equal(allowed[0]?.freshness, "current");
  assert.equal(allowed[0]?.conflicted, true);
  assert.equal(restricted[0]?.access, "restricted");
  assert.deepEqual(evidenceCandidatesFromToolResult("cerebro_findings", details, "CSEC"), []);
});

test("company-library evidence exposes only records wholly visible to the current channel", () => {
  const records = [{
    id: "dossier-checkout",
    title: "Checkout operations",
    channelIds: ["CSEC"],
    sourceArtifacts: ["service-catalog:checkout"],
    claims: [{ basis: "conflicted" }],
    version: 4,
    updatedAt: "2026-07-14T10:00:00.000Z",
  }];
  const visible = evidenceCandidatesFromToolResult("company_library_search", { records }, "CSEC");
  const hidden = evidenceCandidatesFromToolResult("company_library_search", { records }, "COTHER");

  assert.equal(visible[0]?.id, "library:dossier-checkout");
  assert.equal(visible[0]?.access, "allowed");
  assert.equal(visible[0]?.version, 4);
  assert.equal(visible[0]?.conflicted, true);
  assert.equal(hidden[0]?.access, "restricted");
});

test("decision packet receipts become stable live evidence whose digest changes drive re-verification", () => {
  const first = evidenceCandidatesFromToolResult("cerebro_decision_packet", {
    decision_packet: {
      id: "dpr_11111111111111111111111111111111",
      generated_at: "2026-07-15T12:00:00.000Z",
      workflow: { id: "triage" },
      scope: { urn: "urn:cerebro:tenant-1:finding:1" },
      contradictions: [],
      provenance: { resolver_ids: ["finding"], evidence_digest: "sha256:evidence-1", coverage_digest: "sha256:coverage-1" },
    },
  });
  const next = evidenceCandidatesFromToolResult("cerebro_decision_packet", {
    decision_packet: {
      id: "dpr_22222222222222222222222222222222",
      generated_at: "2026-07-15T12:05:00.000Z",
      workflow: { id: "triage" },
      scope: { urn: "urn:cerebro:tenant-1:finding:1" },
      contradictions: [{ resolution_state: "unresolved" }],
      provenance: { resolver_ids: ["finding"], evidence_digest: "sha256:evidence-2", coverage_digest: "sha256:coverage-2" },
    },
  });

  assert.equal(first[0]?.sourceRef, next[0]?.sourceRef);
  assert.notEqual(first[0]?.version, next[0]?.version);
  assert.equal(first[0]?.basis, "live");
  assert.equal(next[0]?.conflicted, true);
  assert.deepEqual(next[0]?.sourceArtifacts, ["dpr_22222222222222222222222222222222", "sha256:evidence-2", "sha256:coverage-2"]);
});

test("claim reconciliation binds exact visible text to the closed ledger and current-run evidence", () => {
  const answer = reconcileClaimEvidence(baseAnswer({
    answer: "Checkout belongs to Payments.",
    messages: ["Checkout belongs to Payments."],
    claimEvidenceBindings: [{
      claimId: "owner",
      claimText: "Checkout belongs to Payments.",
      temporalScope: "current",
      evidenceIds: ["memory-1", "invented"],
    }],
  }), [{
    id: "memory-1",
    kind: "memory",
    title: "Checkout service owner",
    basis: "historical",
    access: "allowed",
    createdAt: "2026-07-12T10:30:00.000Z",
    verifiedBy: [],
    sourceArtifacts: [],
  }], [{
    id: "owner",
    status: "supported",
    source_tools: ["security_memory_intelligence"],
    evidence_receipts: ["evidence:security_memory_intelligence:one"],
    evidence_refs: [],
    verified: true,
  }]);

  assert.deepEqual(answer.claimEvidence?.[0]?.evidence.map((item) => item.id), ["memory-1"]);
  assert.equal(answer.claimEvidence?.[0]?.verification, "historical_only");
  assert.equal(answer.claimEvidence?.[0]?.visible, true);
  assert.doesNotMatch(answer.messages[0] ?? "", /\[\[memory:/);
});

test("live ledger evidence verifies a current claim and the host inserts its source marker", () => {
  const answer = reconcileClaimEvidence(baseAnswer({
    answer: "Checkout belongs to Payments.",
    messages: ["Checkout belongs to Payments. Review access quarterly."],
    claimEvidenceBindings: [{
      claimId: "owner",
      claimText: "Checkout belongs to Payments.",
      temporalScope: "current",
      evidenceIds: ["memory-1"],
    }],
  }), [{
    id: "memory-1",
    kind: "memory",
    title: "Checkout service owner",
    basis: "historical",
    access: "allowed",
    createdAt: "2026-07-12T10:30:00.000Z",
    verifiedBy: [],
    sourceArtifacts: [],
  }], [{
    id: "owner",
    status: "supported",
    source_tools: ["security_memory_intelligence", "cerebro_graph_reason"],
    evidence_receipts: ["evidence:security_memory_intelligence:one", "evidence:cerebro_graph_reason:two"],
    evidence_refs: ["resource:checkout"],
    verified: true,
  }]);
  const rendered = renderClaimEvidence(answer.messages, answer.claimEvidence);

  assert.equal(answer.claimEvidence?.[0]?.verification, "verified");
  assert.match(rendered[0] ?? "", /Checkout belongs to Payments\. \[1, 2\]/);
  assert.match(rendered[1] ?? "", /\*Sources\*/);
  assert.match(rendered[1] ?? "", /Checkout service owner/);
  assert.match(rendered[1] ?? "", /resource:checkout/);
});

test("claim reconciliation rejects unknown claim ids and evidence ids", () => {
  const answer = reconcileClaimEvidence(baseAnswer({
    claimEvidenceBindings: [{ claimId: "unknown", claimText: "Unknown claim.", temporalScope: "historical", evidenceIds: ["invented"] }],
  }), [], []);
  assert.deepEqual(answer.claimEvidence, []);
  assert.deepEqual(answer.memoryCitationIds, []);
});

test("Slack permalink resolution is current-channel only and best effort", async () => {
  const calls: unknown[] = [];
  const packets = await resolveClaimEvidencePermalinks({
    chat: {
      getPermalink: async (input: unknown) => {
        calls.push(input);
        return { permalink: "https://writer.slack.com/archives/CSEC/p1782501562693279" };
      },
    },
  }, [{
    claimId: "owner",
    claimText: "Checkout belongs to Payments.",
    temporalScope: "historical",
    verification: "verified",
    sourceTools: ["security_memory_intelligence"],
    evidenceReceipts: [],
    visible: true,
    evidence: [{
      id: "memory-1",
      kind: "memory",
      title: "Checkout service owner",
      basis: "historical",
      access: "allowed",
      channelId: "CSEC",
      sourceTs: "1782501562.693279",
      verifiedBy: [],
      sourceArtifacts: [],
    }],
  }], "CSEC");

  assert.deepEqual(calls, [{ channel: "CSEC", message_ts: "1782501562.693279" }]);
  assert.equal(packets[0]?.evidence[0]?.permalink, "https://writer.slack.com/archives/CSEC/p1782501562693279");
});

test("citation quality reports invisible, restricted, stale-current, and undisclosed conflicts", () => {
  const metrics = citationQualityMetrics(baseAnswer({
    claimEvidence: [{
      claimId: "owner",
      claimText: "Checkout belongs to Payments.",
      temporalScope: "current",
      verification: "contradicted",
      sourceTools: ["security_memory_intelligence"],
      evidenceReceipts: [],
      visible: false,
      evidence: [{
        id: "memory-1",
        kind: "memory",
        title: "Checkout service owner",
        basis: "historical",
        access: "restricted",
        conflicted: true,
        verifiedBy: [],
        sourceArtifacts: [],
      }],
    }],
  }));
  assert.deepEqual(metrics.blockers, [
    "citation_claim_not_visible",
    "citation_source_not_accessible",
    "evidence_conflict_not_disclosed",
  ]);
});

test("citation quality does not report source disagreement when live evidence refutes a claim", () => {
  const metrics = citationQualityMetrics(baseAnswer({
    claimEvidence: [{
      claimId: "github-coverage",
      claimText: "GitHub coverage is configured.",
      temporalScope: "current",
      verification: "contradicted",
      sourceTools: ["cerebro_source_query"],
      evidenceReceipts: ["receipt-github-coverage"],
      visible: true,
      evidence: [{
        id: "github-coverage-check",
        kind: "live_source",
        title: "GitHub runtime coverage check",
        basis: "live",
        access: "allowed",
        sourceTool: "cerebro_source_query",
        sourceRef: "runtime:writer-github-audit",
        verifiedBy: [],
        sourceArtifacts: [],
      }],
    }],
  }));
  assert.equal(metrics.conflictDisclosure, 1);
  assert.doesNotMatch(metrics.blockers.join(" "), /evidence_conflict_not_disclosed/);
});

test("research state binds evidence only after the claim ledger closes", () => {
  const state = new SecurityResearchState(undefined, "CSEC");
  state.setAvailableTools(["security_session_recall", "cerebro_graph_reason"]);
  state.establishPlan({
    claims: [{ id: "owner", claim: "Verify checkout ownership", source_candidates: ["security_session_recall", "cerebro_graph_reason"] }],
    source_candidates: ["security_session_recall", "cerebro_graph_reason"],
  });
  const memoryReceipt = state.recordToolResult("security_session_recall", { details: {
    memories: [{ id: "memory-1", topic: "Checkout service owner", createdAt: "2026-07-12T10:30:00.000Z" }],
  } })?.evidenceReceipt;
  const liveReceipt = state.recordToolResult("cerebro_graph_reason", { details: { owner: "Payments" } })?.evidenceReceipt;
  state.closeClaimLedger({ claims: [{
    id: "owner",
    status: "supported",
    source_tools: ["security_session_recall", "cerebro_graph_reason"],
    evidence_receipts: [memoryReceipt as string, liveReceipt as string],
    evidence_refs: ["resource:checkout"],
  }] });
  const answer = state.reconcileClaimEvidence(baseAnswer({
    answer: "Checkout belongs to Payments.",
    messages: ["Checkout belongs to Payments."],
    claimEvidenceBindings: [{ claimId: "owner", claimText: "Checkout belongs to Payments.", temporalScope: "current", evidenceIds: ["memory-1"] }],
  }));

  assert.equal(answer.claimEvidence?.[0]?.verification, "verified");
  assert.deepEqual(answer.claimEvidence?.[0]?.sourceTools, ["security_session_recall", "cerebro_graph_reason"]);
});

function baseAnswer(overrides: Partial<SecurityAssistantAnswer> = {}): SecurityAssistantAnswer {
  return {
    answer: "Bounded answer.",
    messages: ["Bounded answer."],
    keyPoints: [],
    evidence: [],
    actionsTaken: [],
    nextActions: [],
    research: [],
    memoryUpdates: [],
    source: "pi",
    ...overrides,
  };
}
