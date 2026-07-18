import assert from "node:assert/strict";
import test from "node:test";
import { buildCompliancePacket } from "../src/compliance/work-packets.js";

test("control evidence packet maps controls to systems and blocks review on missing disposition", () => {
  const packet = buildCompliancePacket({
    packet_type: "control_evidence",
    control_id: "CC-6.1",
    framework: "SOC 2",
    period: "2026-Q2",
    owner: "security",
    policy_refs: ["policy:access-control"],
    system_refs: ["system:okta", "system:github"],
    evidence_refs: ["evidencecas://cases/access/q2.json"],
    finding_refs: ["finding-1"],
  }) as any;

  assert.equal(packet.packet_type, "control_evidence");
  assert.equal(packet.readiness, "needs_remediation");
  assert.equal(packet.ready_for_review, false);
  assert.deepEqual(packet.gaps, ["finding_disposition"]);
  assert.equal(packet.control_system_map.length, 2);
  assert.equal(packet.evidence_ledger[0].chain_of_custody_required, true);
  assert.match(packet.review_actions[0], /Link open findings/);
});

test("control evidence packet becomes review-ready with policy, system, evidence, and disposition refs", () => {
  const packet = buildCompliancePacket({
    packet_type: "control-evidence",
    control_id: "CC-6.1",
    framework: "SOC 2",
    period: "2026-Q2",
    owner: "security",
    assertion: "Okta and GitHub privileged access reviews completed.",
    policy_refs: ["policy:access-control"],
    system_refs: ["system:okta", "system:github"],
    evidence_refs: ["evidencecas://cases/access/q2.json"],
    ticket_refs: ["SEC-42"],
    finding_refs: ["finding-1"],
    evidence_age_days: 12,
  }) as any;

  assert.equal(packet.readiness, "ready");
  assert.equal(packet.ready_for_review, true);
  assert.deepEqual(packet.gaps, []);
  assert.match(packet.packet_id, /^control_evidence_[a-f0-9]{16}$/);
});

test("policy-system map reports missing source coverage and builds one row per control-system pair", () => {
  const packet = buildCompliancePacket({
    packet_type: "policy_system_map",
    title: "Access review map",
    owner: "security",
    policy_refs: ["policy:access-control"],
    control_ids: ["CC-6.1", "CC-6.2"],
    system_refs: ["system:okta", "system:github"],
  }) as any;

  assert.equal(packet.packet_type, "policy_system_map");
  assert.equal(packet.readiness, "needs_context");
  assert.deepEqual(packet.gaps, ["source_or_evidence_refs"]);
  assert.equal(packet.mappings.length, 4);
});

test("audit-safe report redacts secret-looking fields and lists excluded material", () => {
  const packet = buildCompliancePacket({
    packet_type: "audit_safe_report",
    title: "Privileged access summary",
    scope: "Okta and GitHub privileged access",
    audience: "external auditor",
    period: "2026-Q2",
    facts: [
      "All active admins have owner approval.",
      "token=should-not-leak was present in one raw log line.",
    ],
    evidence_refs: ["evidencecas://cases/access/q2.json"],
    ticket_refs: ["SEC-42"],
  }) as any;

  assert.equal(packet.ready_for_review, true);
  assert.deepEqual(packet.gaps, []);
  assert.match(packet.facts[1], /\[redacted_secret\]/);
  assert.doesNotMatch(JSON.stringify(packet), /should-not-leak/);
  assert.equal(packet.secret_values_stored, false);
  assert.ok(packet.excluded_from_report.includes("raw credentials"));
});

test("compliance packet rejects unknown packet types with allowed values", () => {
  const packet = buildCompliancePacket({ packet_type: "unknown" }) as any;

  assert.equal(packet.error, "invalid_packet_type");
  assert.deepEqual(packet.allowed_packet_types, [
    "control_evidence",
    "policy_system_map",
    "audit_safe_report",
    "finding_lifecycle",
    "exception_management",
    "triage_quality",
    "approval_remediation",
    "continuous_monitor",
  ]);
});

test("finding lifecycle packet requires approval and a disposition record for terminal states", () => {
  const packet = buildCompliancePacket({
    packet_type: "finding_lifecycle",
    runtime_id: "writer-okta-user",
    finding_id: "finding-1",
    owner: "identity",
    desired_state: "resolved",
    evidence_refs: ["evidencecas://cases/okta/finding-1.json"],
  }) as any;

  assert.equal(packet.packet_type, "finding_lifecycle");
  assert.equal(packet.readiness, "needs_remediation");
  assert.deepEqual(packet.gaps, ["ticket_or_exception_ref", "approval_ref"]);
  assert.equal(packet.lifecycle_plan[0].tool, "evidence_bundle_get");
  assert.equal(packet.lifecycle_plan[4].tool, "finding_update");
});

test("finding lifecycle packet is ready when terminal updates have evidence, ticket, and approval refs", () => {
  const packet = buildCompliancePacket({
    packet_type: "finding_lifecycle",
    runtime_id: "writer-okta-user",
    finding_id: "finding-1",
    owner: "identity",
    desired_state: "suppressed",
    action: "suppress",
    evidence_refs: ["evidencecas://cases/okta/finding-1.json"],
    ticket_refs: ["SEC-42"],
    approval_refs: ["approval:slack:123"],
  }) as any;

  assert.equal(packet.readiness, "ready");
  assert.equal(packet.ready_for_review, true);
  assert.deepEqual(packet.gaps, []);
});

test("exception management packet captures expiry, approval, and compensating controls", () => {
  const packet = buildCompliancePacket({
    packet_type: "exception_management",
    title: "Okta admin exception",
    owner: "identity",
    reviewer: "security",
    risk: "Temporary admin access until migration completes.",
    expires_at: "2026-07-31",
    finding_refs: ["finding-1"],
    evidence_refs: ["evidencecas://cases/okta/exception.json"],
    approval_refs: ["approval:slack:123"],
    compensating_controls: ["Daily admin activity review"],
  }) as any;

  assert.equal(packet.readiness, "ready");
  assert.equal(packet.exception_record.status, "ready_for_review");
  assert.equal(packet.exception_record.approval_required, true);
  assert.deepEqual(packet.compensating_controls, ["Daily admin activity review"]);
});

test("triage quality packet scores source-backed owner-routed disposition", () => {
  const packet = buildCompliancePacket({
    packet_type: "triage_quality",
    title: "Weekly identity triage sample",
    owner: "security",
    period: "2026-W27",
    finding_refs: ["finding-1", "finding-2"],
    evidence_refs: ["evidencecas://cases/okta/triage.json"],
    ticket_refs: ["SEC-42"],
    facts: ["Two identity findings were routed to owners."],
  }) as any;

  assert.equal(packet.ready_for_review, true);
  assert.equal(packet.quality_score, 1);
  assert.deepEqual(packet.gaps, []);
});

test("triage quality packet redacts secret-like facts and flags review", () => {
  const packet = buildCompliancePacket({
    packet_type: "triage_quality",
    owner: "security",
    finding_refs: ["finding-1"],
    evidence_refs: ["evidencecas://cases/okta/triage.json"],
    ticket_refs: ["SEC-42"],
    facts: ["token=should-not-leak appeared in a raw source row."],
  }) as any;

  assert.match(packet.facts[0], /\[redacted_secret\]/);
  assert.doesNotMatch(JSON.stringify(packet), /should-not-leak/);
  assert.ok(packet.gaps.includes("secret_redaction_review"));
});

test("approval remediation packet builds guardrail input and waits for dry run", () => {
  const packet = buildCompliancePacket({
    packet_type: "approval_remediation",
    owner: "identity",
    action: "resolve",
    runtime_id: "writer-okta-user",
    finding_id: "finding-1",
    evidence_refs: ["evidencecas://cases/okta/finding-1.json"],
    ticket_refs: ["SEC-42"],
    approval_refs: ["approval:slack:123"],
    rollback_plan: "Reopen finding and restore previous due date.",
  }) as any;

  assert.equal(packet.readiness, "needs_evidence");
  assert.deepEqual(packet.gaps, ["dry_run_ref"]);
  assert.equal(packet.guardrail_input.has_human_approval, true);
  assert.equal(packet.guardrail_input.has_dry_run, false);
  assert.equal(packet.execution_plan[0].tool, "operator_policy_guardrail_check");
});

test("approval remediation packet is ready when dry run, approval, ticket, evidence, and rollback are present", () => {
  const packet = buildCompliancePacket({
    packet_type: "approval_remediation",
    owner: "identity",
    action: "resolve",
    runtime_id: "writer-okta-user",
    finding_id: "finding-1",
    evidence_refs: ["evidencecas://cases/okta/finding-1.json"],
    ticket_refs: ["SEC-42"],
    approval_refs: ["approval:slack:123"],
    dry_run_refs: ["dry-run:impact-check:456"],
    rollback_plan: "Reopen finding and restore previous due date.",
  }) as any;

  assert.equal(packet.readiness, "ready");
  assert.equal(packet.ready_for_review, true);
  assert.deepEqual(packet.gaps, []);
  assert.equal(packet.guardrail_input.has_dry_run, true);
});

test("continuous monitor packet builds a scheduler-compatible draft with findings threshold trigger", () => {
  const packet = buildCompliancePacket({
    packet_type: "continuous_monitor",
    title: "Privileged access control monitor",
    owner: "security",
    control_ids: ["CC-6.1"],
    policy_refs: ["policy:access-control"],
    runtime_ids: ["writer-okta-user", "writer-github-audit"],
    source_refs: ["source:okta", "source:github"],
    cadence: "weekdays",
    hour: 8,
    minute: 30,
    time_zone: "America/Los_Angeles",
    threshold: 5,
    cooldown_minutes: 45,
    channel_id: "CSEC",
  }) as any;

  assert.equal(packet.packet_type, "continuous_monitor");
  assert.equal(packet.readiness, "ready");
  assert.equal(packet.ready_for_review, true);
  assert.equal(packet.schedule_draft.description, "Privileged access control monitor");
  assert.equal(packet.schedule_draft.schedule.kind, "weekdays");
  assert.deepEqual(packet.schedule_draft.schedule.timeOfDay, { hour: 8, minute: 30 });
  assert.equal(packet.schedule_draft.trigger.type, "findings_threshold");
  assert.equal(packet.schedule_draft.trigger.threshold, 5);
  assert.equal(packet.schedule_draft.trigger.cooldownMs, 45 * 60_000);
  assert.deepEqual(packet.schedule_draft.contextProviders, ["runtime_health_snapshot", "open_findings_snapshot", "companion_self_context"]);
  assert.deepEqual(packet.schedule_draft.steps[1].dependsOn, ["collect-control-context"]);
  assert.equal(packet.monitor_contract.no_write_actions, true);
});

test("continuous monitor packet defaults cadence and reports missing monitor inputs", () => {
  const packet = buildCompliancePacket({
    packet_type: "continuous_monitor",
    title: "Evidence freshness watch",
    control_id: "CC-7.2",
  }) as any;

  assert.equal(packet.readiness, "needs_evidence");
  assert.deepEqual(packet.gaps, ["owner", "evidence_sources"]);
  assert.equal(packet.schedule_draft.schedule.kind, "weekdays");
  assert.match(packet.warnings[0], /defaulted to weekdays/);
  assert.match(packet.review_actions.join("\n"), /source refs|runtime ids/);
});
