import assert from "node:assert/strict";
import test from "node:test";
import { verifyDecisionPacketLifecycle } from "../src/cerebro/decision-packet-canary-main.js";
import type { DecisionPacket } from "../src/cerebro/types.js";

test("decision packet production canary builds, reopens, and rechecks stored inputs", async () => {
  const packets = new Map<string, DecisionPacket>();
  const requests: unknown[] = [];
  let sequence = 0;
  const client = {
    async listSourceRuntimes(): Promise<Record<string, unknown>> {
      return { runtimes: [{ id: "runtime-1" }] };
    },
    async buildDecisionPacket(request: unknown): Promise<DecisionPacket> {
      requests.push(request);
      sequence += 1;
      const packet = packetFixture(sequence);
      packets.set(packet.id, packet);
      return packet;
    },
    async getDecisionPacket(packetId: string): Promise<DecisionPacket> {
      const packet = packets.get(packetId);
      assert(packet);
      return packet;
    },
  };

  const receipt = await verifyDecisionPacketLifecycle(client, "writer");

  assert.equal(receipt.runtimeCount, 1);
  assert.equal(receipt.packetId, "dpr_11111111111111111111111111111111");
  assert.equal(receipt.recheckPacketId, "dpr_22222222222222222222222222222222");
  assert.deepEqual(requests[0], {
    workflow: "deployment_canary",
    question: "Can this tenant build and reopen a current decision receipt?",
    required_sources: ["deployment-canary"],
  });
  assert.deepEqual(requests[1], {
    workflow: "deployment_canary",
    question: "Can this tenant build and reopen a current decision receipt?",
    scope_urn: undefined,
    finding_ids: [],
    claim_ids: [],
    evidence_urns: [],
    audit_packet_ids: [],
    required_sources: ["deployment-canary"],
    requested_action: undefined,
  });
  assert.equal("tenant_id" in (requests[1] as Record<string, unknown>), false);
  assert.equal("actor_id" in (requests[1] as Record<string, unknown>), false);
});

test("decision packet production canary rejects mutable receipt digests", async () => {
  const original = packetFixture(1);
  const changed = { ...original, provenance: { ...original.provenance, evidence_digest: "sha256:changed" } };
  const client = {
    async listSourceRuntimes(): Promise<Record<string, unknown>> { return { items: [{ id: "runtime-1" }] }; },
    async buildDecisionPacket(): Promise<DecisionPacket> { return original; },
    async getDecisionPacket(): Promise<DecisionPacket> { return changed; },
  };

  await assert.rejects(
    verifyDecisionPacketLifecycle(client, "writer"),
    /changed an immutable decision receipt digest/,
  );
});

function packetFixture(sequence: number): DecisionPacket {
  const digit = String(sequence);
  return {
    schema_version: "2026-07-15",
    id: `dpr_${digit.repeat(32)}`,
    generated_at: `2026-07-15T12:00:0${sequence}.000Z`,
    workflow: { id: "deployment_canary", question: "Can this tenant build and reopen a current decision receipt?" },
    scope: { tenant_id: "writer", actor_id: "deployment-canary" },
    inputs: { finding_ids: [], claim_ids: [], evidence_urns: [], audit_packet_ids: [], required_sources: ["deployment-canary"] },
    decision: { state: "blocked", reasons: ["required coverage gap"] },
    confidence: { level: "low", basis: ["required coverage gap"] },
    freshness: { state: "unknown", required_stale: false },
    evidence: [], contradictions: [], coverage_gaps: [], affected: [], controls: [], audit_packets: [], actions: [],
    provenance: { resolver_ids: ["ports"], source_ids: [], evidence_digest: "sha256:evidence", coverage_digest: "sha256:coverage" },
  };
}
