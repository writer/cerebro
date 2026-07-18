import assert from "node:assert/strict";
import test from "node:test";
import { runComplianceSyntheticEvals } from "../src/compliance/evals.js";
import { compliancePacketMemoryCandidates } from "../src/compliance/memory.js";
import { buildCompliancePacket } from "../src/compliance/work-packets.js";

test("runComplianceSyntheticEvals covers packet and memory scenarios", () => {
  const report = runComplianceSyntheticEvals(new Date("2026-06-28T12:00:00.000Z"));

  assert.equal(report.summary.fail, 0);
  assert.equal(report.summary.total, 6);
  assert.equal(report.groups.packet?.total, 5);
  assert.equal(report.groups.memory?.total, 1);
  assert.ok(report.scenarios.some((scenario) => scenario.name === "audit report redacts secrets"));
});

test("compliancePacketMemoryCandidates creates bounded non-secret memory write input", () => {
  const packet = buildCompliancePacket({
    packet_type: "control_evidence",
    control_id: "CC-6.1",
    framework: "SOC 2",
    period: "2026-Q2",
    owner: "security",
    policy_refs: ["policy:access"],
    system_refs: ["system:okta"],
    evidence_refs: ["evidencecas://cases/access/q2.json"],
    assertion: "token=should-not-leak appeared in raw evidence but should not be stored.",
  }) as any;

  const [memory] = compliancePacketMemoryCandidates(packet, {
    channelId: "CSEC",
    sourceTs: "1719590000.000000",
    now: new Date("2026-06-28T12:00:00.000Z"),
  });

  assert.ok(memory);
  assert.equal(memory.kind, "investigation_note");
  assert.equal(memory.promotionState, "candidate");
  assert.equal(memory.channelId, "CSEC");
  assert.equal(memory.sourceTs, "1719590000.000000");
  assert.equal(memory.verifiedAt, "2026-06-28T12:00:00.000Z");
  assert.ok(memory.sourceArtifacts?.includes(packet.packet_id));
  assert.ok(memory.entities?.includes("CC-6.1"));
  assert.doesNotMatch(JSON.stringify(memory), /should-not-leak/);
});
