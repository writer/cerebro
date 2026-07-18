import assert from "node:assert/strict";
import test from "node:test";
import { CerebroClient } from "../src/cerebro/client.js";
import type { ComplianceWorkItemRecord } from "../src/cerebro/types.js";
import { testConfig } from "./fixtures.js";

test("Cerebro work-item reads carry tenant filters, pagination, and the read credential", async () => {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const client = new CerebroClient(testConfig({ cerebro: { apiKeys: { read: "read-key", findings: "findings-key" } } }), {
    fetchImpl: responseFetch(requests, { items: [], next_cursor: "cursor-2" }),
  });

  const page = await client.listComplianceWorkItems({
    state: "blocked",
    ownerId: "team-security",
    cursor: "cursor-1",
    limit: 25,
  });

  assert.equal(page.next_cursor, "cursor-2");
  assert.equal(requests.length, 1);
  const request = requests[0]!;
  const url = new URL(request.url);
  assert.equal(url.pathname, "/grc/work-items");
  assert.deepEqual(Object.fromEntries(url.searchParams), {
    tenant_id: "writer",
    state: "blocked",
    owner_id: "team-security",
    cursor: "cursor-1",
    limit: "25",
  });
  assert.equal(new Headers(request.init?.headers).get("Authorization"), "Bearer read-key");
});

test("Cerebro work-item get and command encode identity and preserve the versioned command", async () => {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const record = workItemRecord();
  const client = new CerebroClient(testConfig({ cerebro: { apiKeys: { read: "read-key", findings: "findings-key" } } }), {
    fetchImpl: responseFetch(requests, record),
  });

  await client.getComplianceWorkItem("work/item 1");
  await client.commandComplianceWorkItem("work/item 1", {
    operation: "action",
    expected_version: 7,
    action: "verify_assurance",
    assurance_decision_id: "decision-8",
    rationale: "Fresh evidence satisfies the control objective.",
  });

  assert.equal(new URL(requests[0]!.url).pathname, "/grc/work-items/work%2Fitem%201");
  assert.equal(new Headers(requests[0]!.init?.headers).get("Authorization"), "Bearer read-key");
  assert.equal(new URL(requests[1]!.url).pathname, "/grc/work-items/work%2Fitem%201/commands");
  assert.equal(new Headers(requests[1]!.init?.headers).get("Authorization"), "Bearer findings-key");
  assert.deepEqual(JSON.parse(String(requests[1]!.init?.body)), {
    operation: "action",
    expected_version: 7,
    action: "verify_assurance",
    assurance_decision_id: "decision-8",
    rationale: "Fresh evidence satisfies the control objective.",
  });
  await assert.rejects(client.getComplianceWorkItem("  "), /work item ID is required/);
});

function responseFetch(requests: Array<{ url: string; init?: RequestInit }>, body: unknown): typeof fetch {
  return async (input, init) => {
    requests.push({ url: String(input), init });
    return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
  };
}

function workItemRecord(): ComplianceWorkItemRecord {
  return {
    item: {
      id: "work/item 1",
      fingerprint_version: "v1",
      fingerprint: "sha256:1",
      basis: {
        tenant_id: "writer",
        program_id: "soc2",
        scope_revision_id: "scope-1",
        control_id: "CC6.1",
        objective_id: "objective-1",
        kind: "finding",
        subject_id: "aws:iam:user/operator",
        reason: "privileged access lacks current evidence",
        source_id: "aws",
      },
      state: "in_progress",
      owner_id: "team-security",
      due_at: "2026-07-20T00:00:00Z",
      priority: "high",
      verification_required: true,
      occurrences: [],
      version: 7,
      updated_at: "2026-07-15T00:00:00Z",
    },
    occurrences: [],
    actions: [],
  };
}
