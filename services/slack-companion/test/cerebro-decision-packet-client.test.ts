import assert from "node:assert/strict";
import test from "node:test";
import { CerebroClient } from "../src/cerebro/client.js";
import { testConfig } from "./fixtures.js";

test("decision packet client sends only resolver inputs and reopens the encoded receipt id", async () => {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    requests.push({ url: String(input), init });
    return new Response(JSON.stringify({
      schema_version: "2026-07-15",
      id: "dpr_11111111111111111111111111111111",
      generated_at: "2026-07-15T12:00:00.000Z",
      workflow: { id: "triage", question: "Is this finding actionable?" },
      scope: {}, inputs: { finding_ids: ["finding-1"], claim_ids: [], evidence_urns: [], audit_packet_ids: [], required_sources: [] },
      decision: { state: "supported", reasons: [] }, confidence: { level: "high", basis: [] },
      freshness: { state: "fresh", required_stale: false }, evidence: [], contradictions: [], coverage_gaps: [], affected: [], controls: [], audit_packets: [], actions: [],
      provenance: { resolver_ids: [], source_ids: [], evidence_digest: "sha256:evidence", coverage_digest: "sha256:coverage" }, limits: {},
    }), { status: init?.method === "POST" ? 201 : 200, headers: { "Content-Type": "application/json" } });
  };
  const client = new CerebroClient(testConfig(), { fetchImpl });

  await client.buildDecisionPacket({ workflow: "triage", question: "Is this finding actionable?", finding_ids: ["finding-1"] });
  await client.getDecisionPacket("dpr_11111111111111111111111111111111");

  const body = JSON.parse(String(requests[0]?.init?.body));
  assert.deepEqual(body, { workflow: "triage", question: "Is this finding actionable?", finding_ids: ["finding-1"] });
  assert.equal("tenant_id" in body, false);
  assert.equal("actor_id" in body, false);
  assert.equal("verdict" in body, false);
  assert.equal(requests[1]?.url.endsWith("/api/v1/platform/decision-packets/dpr_11111111111111111111111111111111"), true);
  const headers = new Headers(requests[0]?.init?.headers);
  assert.equal(headers.get("Authorization"), "Bearer read-key");
  assert.equal(headers.get("X-Cerebro-Tenant"), "writer");
});
