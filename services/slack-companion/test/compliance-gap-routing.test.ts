import assert from "node:assert/strict";
import test from "node:test";
import { complianceGapJiraDraft } from "../src/compliance/gap-routing.js";
import { findingLifecyclePreflight } from "../src/compliance/lifecycle-preflight.js";
import { testConfig } from "./fixtures.js";

test("complianceGapJiraDraft turns packet gaps into a Jira draft with duplicate search", () => {
  const draft = complianceGapJiraDraft(testConfig({
    ticketing: { jira: { defaultProjectKey: "SEC" } },
  }), {
    packet_type: "control_evidence",
    control_id: "CC-6.1",
    framework: "SOC 2",
    period: "2026-Q2",
    owner: "security",
    policy_refs: ["policy:access"],
    system_refs: ["system:okta"],
    finding_refs: ["finding-1"],
    labels: ["Identity Access"],
  }) as any;

  assert.equal(draft.created, false);
  assert.equal(draft.ready_for_operator, true);
  assert.equal(draft.issue.project_key, "SEC");
  assert.match(draft.issue.summary, /Control evidence packet/);
  assert.match(draft.issue.description, /Gaps:\n- evidence_refs/);
  assert.match(draft.duplicate_search.jql, /project = SEC/);
  assert.ok(draft.issue.labels.includes("identity-access"));
  assert.equal(draft.packet.secret_values_stored, false);
});

test("complianceGapJiraDraft does not request Jira work for gap-free packets", () => {
  const draft = complianceGapJiraDraft(testConfig({
    ticketing: { jira: { defaultProjectKey: "SEC" } },
  }), {
    packet_type: "audit_safe_report",
    title: "Access review summary",
    scope: "Okta admins",
    audience: "internal audit",
    period: "2026-Q2",
    facts: ["Access reviews completed."],
    evidence_refs: ["evidencecas://cases/access/q2.json"],
  }) as any;

  assert.equal(draft.ready_for_operator, false);
  assert.deepEqual(draft.missing, ["packet_gaps"]);
  assert.match(draft.note, /No Jira gap ticket/);
});

test("findingLifecyclePreflight requires evidence, disposition, approval, dry-run, and rollback for terminal actions", () => {
  const blocked = findingLifecyclePreflight({
    runtime_id: "writer-okta-user",
    finding_id: "finding-1",
    action: "resolve",
    evidence_refs: ["evidencecas://cases/okta/finding-1.json"],
    ticket_refs: ["SEC-42"],
  }) as any;
  const ready = findingLifecyclePreflight({
    runtime_id: "writer-okta-user",
    finding_id: "finding-1",
    action: "suppress",
    evidence_refs: ["evidencecas://cases/okta/finding-1.json"],
    exception_refs: ["exception:accepted-risk:1"],
    approval_refs: ["approval:slack:123"],
    dry_run_refs: ["dry-run:impact:456"],
    rollback_plan: "Reopen the finding and remove the exception link.",
    execute: true,
    approved: true,
  }) as any;

  assert.equal(blocked.ready_for_execution, false);
  assert.deepEqual(blocked.missing, ["approval_ref", "dry_run_ref", "rollback_plan"]);
  assert.equal(blocked.decision, "dry_run_required");
  assert.equal(ready.ready_for_execution, true);
  assert.equal(ready.decision, "approval_ready");
  assert.equal(ready.guardrail_input.has_dry_run, true);
  assert.deepEqual(ready.audit_record_input.ticket_refs, ["exception:accepted-risk:1"]);
});
