import assert from "node:assert/strict";
import test from "node:test";

import { Client } from "../src/index.js";

test("compliance work item methods preserve canonical ids, filters, versions, and commands", async () => {
  const requests = [];
  const item = {
    id: "compliance-work-item-a",
    fingerprint_version: "compliance-work-fingerprint/v1",
    fingerprint: "sha256:a",
    basis: {
      tenant_id: "tenant-a",
      program_id: "program-a",
      scope_revision_id: "scope-a",
      control_id: "control-a",
      objective_id: "objective-a",
      kind: "remediate_finding",
      subject_id: "subject-a",
      reason: "active_finding",
      source_id: "runtime-a",
    },
    state: "in_progress",
    owner_id: "owner-a",
    due_at: "2026-07-16T00:00:00Z",
    priority: "high",
    verification_required: true,
    occurrences: [],
    version: 2,
    updated_at: "2026-07-15T00:00:00Z",
  };
  const record = { item, occurrences: [], actions: [] };
  const client = new Client({
    baseUrl: "https://cerebro.example.com/",
    fetchImpl: async (url, init = {}) => {
      requests.push({ url: String(url), method: init.method, body: init.body });
      const payload = String(url).includes("/commands") ? record : String(url).includes("compliance-work-item-a") ? record : { items: [item], next_cursor: "cursor-b" };
      return new Response(JSON.stringify(payload), { status: 200, headers: { "Content-Type": "application/json" } });
    },
  });

  const page = await client.listComplianceWorkItems({ tenantId: "tenant-a", state: "in_progress", ownerId: "owner-a", cursor: "cursor-a", limit: 25 });
  assert.equal(page.items[0].id, item.id);
  assert.equal(page.next_cursor, "cursor-b");
  const listURL = new URL(requests[0].url);
  assert.equal(listURL.pathname, "/grc/work-items");
  assert.deepEqual(Object.fromEntries(listURL.searchParams), {
    tenant_id: "tenant-a",
    state: "in_progress",
    owner_id: "owner-a",
    cursor: "cursor-a",
    limit: "25",
  });

  const fetched = await client.getComplianceWorkItem(item.id, "tenant-a");
  assert.equal(fetched.item.version, 2);
  const command = {
    operation: "action",
    expected_version: 2,
    action: "verify_assurance",
    assurance_decision_id: "assurance-decision-a",
    rationale: "Verify the post-change assessment.",
  };
  const updated = await client.commandComplianceWorkItem(item.id, command, "tenant-a");
  assert.equal(updated.item.id, item.id);
  assert.equal(requests[2].method, "POST");
  assert.deepEqual(JSON.parse(requests[2].body), command);
  assert.equal(new URL(requests[2].url).searchParams.get("tenant_id"), "tenant-a");
});
