import assert from "node:assert/strict";
import test from "node:test";
import { EvidenceGovernanceService } from "../src/agent/evidence-governance.js";
import type { SecurityAssistantAnswer } from "../src/agent/security-assistant-types.js";
import { testConfig } from "./fixtures.js";

test("evidence governance creates deterministic redacted receipts with same-channel access", async () => {
  const now = new Date("2026-07-15T12:00:00.000Z");
  const service = new EvidenceGovernanceService(testConfig(), { now: () => now });
  const input = {
    answerId: "CSEC:1787000000.000001",
    channelId: "CSEC",
    threadTs: "1787000000.000000",
    answer: answer("Checkout belongs to Payments; token=ghp_abcdefghijklmnopqrstuvwxyz123456.", 1),
  };

  const first = await service.recordAnswer(input);
  const second = await service.recordAnswer(input);
  const visible = await service.receiptForAnswer(input.answerId, "CSEC");
  const hidden = await service.receiptForAnswer(input.answerId, "CPRIVATE");

  assert.equal(first?.receiptId, second?.receiptId);
  assert.equal(first?.manifestHash, second?.manifestHash);
  assert.equal(first?.secretValuesStored, false);
  assert.doesNotMatch(JSON.stringify(first), /ghp_abcdefghijklmnopqrstuvwxyz123456/);
  assert.equal(visible?.status, "current");
  assert.equal(hidden, undefined);
});

test("source version changes invalidate dependent claims and reach the original thread", async () => {
  let now = new Date("2026-07-15T12:00:00.000Z");
  const service = new EvidenceGovernanceService(testConfig(), { now: () => now });
  const originalId = "CSEC:1787000001.000001";
  await service.recordAnswer({ answerId: originalId, channelId: "CSEC", threadTs: "1787000001.000000", answer: answer("Checkout belongs to Payments.", 1) });
  now = new Date("2026-07-15T12:01:00.000Z");
  await service.recordAnswer({ answerId: "CSEC:1787000002.000001", channelId: "CSEC", threadTs: "1787000002.000000", answer: answer("Checkout belongs to Commerce.", 2) });

  const original = await service.receiptForAnswer(originalId, "CSEC");
  const prompt = await service.promptBlockForThread("CSEC", "1787000001.000000");

  assert.equal(original?.status, "needs_reverification");
  assert.match(prompt, /Do not reuse these claims as current facts/);
  assert.match(prompt, /Checkout belongs to Payments/);
  assert.match(prompt, /source_version_changed/);
});

test("source feedback requires two distinct reporters before invalidating evidence", async () => {
  const now = new Date("2026-07-15T12:00:00.000Z");
  const service = new EvidenceGovernanceService(testConfig(), { now: () => now, feedbackThreshold: 2 });
  const answerId = "CSEC:1787000003.000001";
  await service.recordAnswer({ answerId, channelId: "CSEC", threadTs: "1787000003.000000", answer: answer("Checkout belongs to Payments.", 1) });

  const first = await service.recordSourceFeedback({ answerId, audienceChannelId: "CSEC", evidenceId: "resource:checkout", reporterId: "U1", reason: "source_outdated" });
  const duplicate = await service.recordSourceFeedback({ answerId, audienceChannelId: "CSEC", evidenceId: "resource:checkout", reporterId: "U1", reason: "source_outdated" });
  const before = await service.receiptForAnswer(answerId, "CSEC");
  const second = await service.recordSourceFeedback({ answerId, audienceChannelId: "CSEC", evidenceId: "resource:checkout", reporterId: "U2", reason: "source_outdated" });
  const after = await service.receiptForAnswer(answerId, "CSEC");

  assert.deepEqual(first, { accepted: true, corroborated: false, affectedClaims: 0 });
  assert.equal(duplicate.corroborated, false);
  assert.equal(before?.status, "current");
  assert.equal(second.corroborated, true);
  assert.equal(second.affectedClaims, 1);
  assert.equal(after?.status, "needs_reverification");
});

test("live evidence receipts expire after the current-state validity window", async () => {
  let now = new Date("2026-07-15T12:00:00.000Z");
  const service = new EvidenceGovernanceService(testConfig(), { now: () => now });
  const answerId = "CSEC:1787000004.000001";
  await service.recordAnswer({ answerId, channelId: "CSEC", threadTs: "1787000004.000000", answer: answer("Checkout belongs to Payments.", 1) });
  now = new Date("2026-07-15T12:16:00.000Z");

  assert.equal((await service.receiptForAnswer(answerId, "CSEC"))?.status, "expired");
});

function answer(claimText: string, version: number): SecurityAssistantAnswer {
  return {
    answer: claimText,
    messages: [claimText],
    keyPoints: [],
    evidence: ["Checked the checkout resource."],
    actionsTaken: ["Checked the live source."],
    nextActions: [],
    research: ["cerebro_graph_reason: checked"],
    memoryUpdates: [],
    source: "flue",
    claimEvidence: [{
      claimId: "checkout-owner",
      claimText,
      temporalScope: "current",
      verification: "verified",
      sourceTools: ["cerebro_graph_reason"],
      evidenceReceipts: ["evidence:cerebro_graph_reason:one"],
      visible: true,
      evidence: [{
        id: "resource:checkout",
        kind: "live_source",
        title: "Checkout resource",
        basis: "live",
        access: "allowed",
        sourceTool: "cerebro_graph_reason",
        sourceRef: "resource:checkout",
        verifiedAt: "2026-07-15T12:00:00.000Z",
        version,
        verifiedBy: ["cerebro_graph_reason"],
        sourceArtifacts: ["resource:checkout"],
      }],
    }],
  };
}
