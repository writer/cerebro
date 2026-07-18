import { createHash } from "node:crypto";
import { redactSecurityText } from "../security/redaction.js";

export type CompliancePacketType =
  | "control_evidence"
  | "policy_system_map"
  | "audit_safe_report"
  | "finding_lifecycle"
  | "exception_management"
  | "triage_quality"
  | "approval_remediation"
  | "continuous_monitor";

export interface CompliancePacketInput {
  packet_type?: string;
  title?: string;
  control_id?: string;
  control_ids?: string[];
  framework?: string;
  period?: string;
  scope?: string;
  audience?: string;
  owner?: string;
  assertion?: string;
  runtime_id?: string;
  finding_id?: string;
  action?: string;
  current_state?: string;
  desired_state?: string;
  severity?: string;
  risk?: string;
  remediation?: string;
  reviewer?: string;
  due_at?: string;
  expires_at?: string;
  rollback_plan?: string;
  cadence?: string;
  time_zone?: string;
  channel_id?: string;
  runtime_ids?: string[];
  hour?: number;
  minute?: number;
  interval_minutes?: number;
  threshold?: number;
  cooldown_minutes?: number;
  policy_refs?: string[];
  system_refs?: string[];
  source_refs?: string[];
  evidence_refs?: string[];
  ticket_refs?: string[];
  finding_refs?: string[];
  exception_refs?: string[];
  approval_refs?: string[];
  dry_run_refs?: string[];
  compensating_controls?: string[];
  facts?: string[];
  caveats?: string[];
  evidence_age_days?: number;
}

export interface CompliancePacket {
  packet_type: CompliancePacketType;
  packet_id: string;
  ready_for_review: boolean;
  readiness: "ready" | "needs_context" | "needs_evidence" | "needs_remediation";
  title: string;
  gaps: string[];
  review_actions: string[];
  secret_values_stored: false;
  [key: string]: unknown;
}

export const compliancePacketTypes: CompliancePacketType[] = [
  "control_evidence",
  "policy_system_map",
  "audit_safe_report",
  "finding_lifecycle",
  "exception_management",
  "triage_quality",
  "approval_remediation",
  "continuous_monitor",
];

export function buildCompliancePacket(input: CompliancePacketInput): CompliancePacket | { error: string; allowed_packet_types: CompliancePacketType[] } {
  const packetType = normalizePacketType(input.packet_type);
  if (!packetType) {
    return {
      error: "invalid_packet_type",
      allowed_packet_types: compliancePacketTypes,
    };
  }
  switch (packetType) {
    case "control_evidence":
      return controlEvidencePacket(input);
    case "policy_system_map":
      return policySystemMapPacket(input);
    case "audit_safe_report":
      return auditSafeReportPacket(input);
    case "finding_lifecycle":
      return findingLifecyclePacket(input);
    case "exception_management":
      return exceptionManagementPacket(input);
    case "triage_quality":
      return triageQualityPacket(input);
    case "approval_remediation":
      return approvalRemediationPacket(input);
    case "continuous_monitor":
      return continuousMonitorPacket(input);
  }
}

function controlEvidencePacket(input: CompliancePacketInput): CompliancePacket {
  const controlId = clean(input.control_id);
  const framework = clean(input.framework);
  const period = clean(input.period);
  const owner = clean(input.owner);
  const policyRefs = cleanList(input.policy_refs);
  const systemRefs = cleanList(input.system_refs);
  const evidenceRefs = cleanList(input.evidence_refs);
  const ticketRefs = cleanList(input.ticket_refs);
  const findingRefs = cleanList(input.finding_refs);
  const exceptionRefs = cleanList(input.exception_refs);
  const sourceRefs = cleanList(input.source_refs);
  const assertion = redacted(input.assertion);
  const evidenceAgeDays = normalizedAge(input.evidence_age_days);
  const gaps = [
    controlId ? "" : "control_id",
    framework ? "" : "framework",
    period ? "" : "period",
    owner ? "" : "owner",
    policyRefs.length ? "" : "policy_refs",
    systemRefs.length ? "" : "system_refs",
    evidenceRefs.length ? "" : "evidence_refs",
    evidenceAgeDays !== undefined && evidenceAgeDays > 90 ? "fresh_evidence" : "",
    findingRefs.length && !ticketRefs.length && !exceptionRefs.length ? "finding_disposition" : "",
  ].filter(Boolean);
  const readiness = gaps.includes("evidence_refs") || gaps.includes("fresh_evidence")
    ? "needs_evidence"
    : gaps.includes("finding_disposition")
      ? "needs_remediation"
      : gaps.length
        ? "needs_context"
        : "ready";
  const title = clean(input.title) ?? `Control evidence packet${controlId ? `: ${controlId}` : ""}`;
  return {
    packet_type: "control_evidence",
    packet_id: packetId("control_evidence", [controlId, framework, period, owner, ...evidenceRefs]),
    title,
    control_id: controlId,
    framework,
    period,
    owner,
    assertion,
    readiness,
    ready_for_review: readiness === "ready",
    control_system_map: systemRefs.map((system_ref) => ({
      control_id: controlId,
      system_ref,
      policy_refs: policyRefs,
      source_refs: sourceRefs,
    })),
    evidence_ledger: evidenceRefs.map((evidence_ref) => ({
      evidence_ref,
      control_id: controlId,
      period,
      age_days: evidenceAgeDays,
      chain_of_custody_required: true,
    })),
    ticket_refs: ticketRefs,
    finding_refs: findingRefs,
    exception_refs: exceptionRefs,
    gaps,
    review_actions: reviewActions({
      gaps,
      evidenceRefs,
      ticketRefs,
      findingRefs,
      exceptionRefs,
      packetType: "control evidence",
    }),
    audit_safe_summary: redacted([
      title,
      framework ? `Framework: ${framework}` : "",
      period ? `Period: ${period}` : "",
      owner ? `Owner: ${owner}` : "",
      assertion ?? "",
    ].filter(Boolean).join("\n")),
    secret_values_stored: false,
  };
}

function policySystemMapPacket(input: CompliancePacketInput): CompliancePacket {
  const title = clean(input.title) ?? "Policy to system map";
  const policyRefs = cleanList(input.policy_refs);
  const controlIds = cleanList(input.control_ids);
  const systemRefs = cleanList(input.system_refs);
  const sourceRefs = cleanList(input.source_refs);
  const evidenceRefs = cleanList(input.evidence_refs);
  const owner = clean(input.owner);
  const gaps = [
    policyRefs.length ? "" : "policy_refs",
    controlIds.length ? "" : "control_ids",
    systemRefs.length ? "" : "system_refs",
    sourceRefs.length || evidenceRefs.length ? "" : "source_or_evidence_refs",
    owner ? "" : "owner",
  ].filter(Boolean);
  const mappings = controlIds.length && systemRefs.length
    ? controlIds.flatMap((control_id) => systemRefs.map((system_ref) => ({
      policy_refs: policyRefs,
      control_id,
      system_ref,
      evidence_refs: evidenceRefs,
      source_refs: sourceRefs,
    })))
    : [];
  return {
    packet_type: "policy_system_map",
    packet_id: packetId("policy_system_map", [title, owner, ...policyRefs, ...controlIds, ...systemRefs]),
    title,
    owner,
    readiness: gaps.length ? "needs_context" : "ready",
    ready_for_review: gaps.length === 0,
    policy_refs: policyRefs,
    control_ids: controlIds,
    system_refs: systemRefs,
    source_refs: sourceRefs,
    evidence_refs: evidenceRefs,
    mappings,
    gaps,
    review_actions: gaps.length
      ? gaps.map((gap) => `Add ${gap.replace(/_/g, " ")} before using this map as control evidence.`)
      : ["Review mapped controls against live tenant state before making current-state claims."],
    secret_values_stored: false,
  };
}

function auditSafeReportPacket(input: CompliancePacketInput): CompliancePacket {
  const title = clean(input.title) ?? "Audit-safe report";
  const scope = clean(input.scope);
  const audience = clean(input.audience);
  const period = clean(input.period);
  const rawFacts = cleanList(input.facts);
  const facts = rawFacts.map((value) => redactSecurityText(value));
  const caveats = redactedList(input.caveats);
  const evidenceRefs = cleanList(input.evidence_refs);
  const ticketRefs = cleanList(input.ticket_refs);
  const exceptionRefs = cleanList(input.exception_refs);
  const gaps = [
    scope ? "" : "scope",
    audience ? "" : "audience",
    period ? "" : "period",
    facts.length ? "" : "facts",
    evidenceRefs.length ? "" : "evidence_refs",
  ].filter(Boolean);
  return {
    packet_type: "audit_safe_report",
    packet_id: packetId("audit_safe_report", [title, scope, audience, period, ...evidenceRefs]),
    title,
    scope,
    audience,
    period,
    readiness: gaps.includes("evidence_refs") ? "needs_evidence" : gaps.length ? "needs_context" : "ready",
    ready_for_review: gaps.length === 0,
    facts,
    caveats,
    evidence_refs: evidenceRefs,
    ticket_refs: ticketRefs,
    exception_refs: exceptionRefs,
    excluded_from_report: [
      "secret values",
      "raw credentials",
      "private keys",
      "unsourced current-state claims",
      "hidden chain-of-thought",
    ],
    report_sections: [
      { heading: "Scope", content: scope },
      { heading: "Period", content: period },
      { heading: "Evidence", refs: evidenceRefs },
      { heading: "Findings and exceptions", refs: [...ticketRefs, ...exceptionRefs] },
      { heading: "Caveats", content: caveats },
    ],
    gaps,
    review_actions: gaps.length
      ? gaps.map((gap) => `Add ${gap.replace(/_/g, " ")} before sharing this report.`)
      : ["Verify every fact has a source reference before sharing outside the operator channel."],
    secret_values_stored: false,
  };
}

function findingLifecyclePacket(input: CompliancePacketInput): CompliancePacket {
  const findingId = clean(input.finding_id) ?? cleanList(input.finding_refs)[0];
  const runtimeId = clean(input.runtime_id);
  const owner = clean(input.owner);
  const currentState = clean(input.current_state) ?? "open";
  const desiredState = clean(input.desired_state);
  const severity = clean(input.severity);
  const evidenceRefs = cleanList(input.evidence_refs);
  const ticketRefs = cleanList(input.ticket_refs);
  const exceptionRefs = cleanList(input.exception_refs);
  const approvalRefs = cleanList(input.approval_refs);
  const action = clean(input.action);
  const dueAt = clean(input.due_at);
  const gaps = [
    findingId ? "" : "finding_id",
    runtimeId ? "" : "runtime_id",
    owner ? "" : "owner",
    evidenceRefs.length ? "" : "evidence_refs",
    desiredState ? "" : "desired_state",
    terminalFindingState(desiredState) && !ticketRefs.length && !exceptionRefs.length ? "ticket_or_exception_ref" : "",
    terminalFindingState(desiredState) && !approvalRefs.length ? "approval_ref" : "",
  ].filter(Boolean);
  return {
    packet_type: "finding_lifecycle",
    packet_id: packetId("finding_lifecycle", [runtimeId, findingId, desiredState, owner, ...ticketRefs, ...exceptionRefs]),
    title: clean(input.title) ?? `Finding lifecycle packet${findingId ? `: ${findingId}` : ""}`,
    runtime_id: runtimeId,
    finding_id: findingId,
    owner,
    severity,
    current_state: currentState,
    desired_state: desiredState,
    action,
    due_at: dueAt,
    readiness: lifecycleReadiness(gaps),
    ready_for_review: gaps.length === 0,
    evidence_refs: evidenceRefs,
    ticket_refs: ticketRefs,
    exception_refs: exceptionRefs,
    approval_refs: approvalRefs,
    lifecycle_plan: [
      { order: 1, tool: "evidence_bundle_get", input: { runtime_id: runtimeId, finding_id: findingId } },
      { order: 2, tool: "owner_resolve", input: { runtime_id: runtimeId, finding_id: findingId } },
      { order: 3, tool: "jira_issue_search", input: { query: findingId } },
      { order: 4, tool: "operator_policy_guardrail_check", input: { action: action ?? "finding update", target_system: "cerebro", changes_production: terminalFindingState(desiredState) } },
      { order: 5, tool: "finding_update", input: { finding_id: findingId, action: action ?? desiredState } },
      { order: 6, tool: "operator_action_audit_log", input: { action: action ?? "finding lifecycle", target_system: "cerebro", target_id: findingId } },
    ],
    gaps,
    review_actions: gaps.length
      ? gaps.map((gap) => lifecycleGapAction(gap))
      : ["Review evidence, owner, ticket or exception refs, and approval before any finding update."],
    secret_values_stored: false,
  };
}

function exceptionManagementPacket(input: CompliancePacketInput): CompliancePacket {
  const title = clean(input.title) ?? "Exception management packet";
  const owner = clean(input.owner);
  const reviewer = clean(input.reviewer);
  const risk = redacted(input.risk);
  const expiresAt = clean(input.expires_at);
  const controlId = clean(input.control_id);
  const findingRefs = cleanList(input.finding_refs);
  const exceptionRefs = cleanList(input.exception_refs);
  const evidenceRefs = cleanList(input.evidence_refs);
  const ticketRefs = cleanList(input.ticket_refs);
  const approvalRefs = cleanList(input.approval_refs);
  const compensatingControls = redactedList(input.compensating_controls);
  const gaps = [
    owner ? "" : "owner",
    reviewer ? "" : "reviewer",
    risk ? "" : "risk",
    expiresAt ? "" : "expires_at",
    controlId || findingRefs.length ? "" : "control_or_finding_ref",
    evidenceRefs.length ? "" : "evidence_refs",
    approvalRefs.length ? "" : "approval_ref",
    compensatingControls.length ? "" : "compensating_controls",
  ].filter(Boolean);
  return {
    packet_type: "exception_management",
    packet_id: packetId("exception_management", [title, owner, reviewer, expiresAt, controlId, ...findingRefs, ...exceptionRefs]),
    title,
    owner,
    reviewer,
    control_id: controlId,
    finding_refs: findingRefs,
    exception_refs: exceptionRefs,
    evidence_refs: evidenceRefs,
    ticket_refs: ticketRefs,
    approval_refs: approvalRefs,
    risk,
    expires_at: expiresAt,
    compensating_controls: compensatingControls,
    readiness: gaps.includes("evidence_refs") ? "needs_evidence" : gaps.length ? "needs_context" : "ready",
    ready_for_review: gaps.length === 0,
    exception_record: {
      status: gaps.length ? "draft" : "ready_for_review",
      renewal_required: Boolean(expiresAt),
      evidence_required: true,
      approval_required: true,
    },
    gaps,
    review_actions: gaps.length
      ? gaps.map((gap) => `Add ${gap.replace(/_/g, " ")} before relying on this exception.`)
      : ["Review expiry, risk, compensating controls, and approval before linking the exception to a finding or control."],
    secret_values_stored: false,
  };
}

function triageQualityPacket(input: CompliancePacketInput): CompliancePacket {
  const title = clean(input.title) ?? "Triage quality packet";
  const owner = clean(input.owner);
  const period = clean(input.period);
  const rawFacts = cleanList(input.facts);
  const facts = rawFacts.map((value) => redactSecurityText(value));
  const caveats = redactedList(input.caveats);
  const evidenceRefs = cleanList(input.evidence_refs);
  const ticketRefs = cleanList(input.ticket_refs);
  const findingRefs = cleanList(input.finding_refs);
  const secretSafe = rawFacts.every((fact) => redactSecurityText(fact) === fact);
  const qualityChecks = [
    { check: "source_backed", passed: evidenceRefs.length > 0, missing: evidenceRefs.length ? [] : ["evidence_refs"] },
    { check: "owner_routed", passed: Boolean(owner), missing: owner ? [] : ["owner"] },
    { check: "disposition_recorded", passed: ticketRefs.length > 0 || caveats.some((item) => /\bfalse positive|accepted risk|duplicate|no action\b/i.test(item)), missing: ticketRefs.length ? [] : ["ticket_refs_or_disposition_caveat"] },
    { check: "finding_scope_named", passed: findingRefs.length > 0, missing: findingRefs.length ? [] : ["finding_refs"] },
    { check: "secret_safe", passed: secretSafe, missing: secretSafe ? [] : ["secret_redaction_review"] },
  ];
  const gaps = [...new Set(qualityChecks.flatMap((check) => check.passed ? [] : check.missing))];
  return {
    packet_type: "triage_quality",
    packet_id: packetId("triage_quality", [title, owner, period, ...findingRefs, ...evidenceRefs]),
    title,
    owner,
    period,
    readiness: gaps.includes("evidence_refs") ? "needs_evidence" : gaps.length ? "needs_context" : "ready",
    ready_for_review: gaps.length === 0,
    finding_refs: findingRefs,
    evidence_refs: evidenceRefs,
    ticket_refs: ticketRefs,
    facts,
    caveats,
    quality_checks: qualityChecks,
    quality_score: qualityChecks.filter((check) => check.passed).length / qualityChecks.length,
    gaps,
    review_actions: gaps.length
      ? gaps.map((gap) => `Add ${gap.replace(/_/g, " ")} to close the triage quality gap.`)
      : ["Use the packet as reviewer evidence for triage quality; re-check live finding state before reporting trends."],
    secret_values_stored: false,
  };
}

function approvalRemediationPacket(input: CompliancePacketInput): CompliancePacket {
  const title = clean(input.title) ?? "Approval-backed remediation packet";
  const owner = clean(input.owner);
  const action = redacted(input.action);
  const remediation = redacted(input.remediation);
  const runtimeId = clean(input.runtime_id);
  const findingId = clean(input.finding_id) ?? cleanList(input.finding_refs)[0];
  const systemRefs = cleanList(input.system_refs);
  const evidenceRefs = cleanList(input.evidence_refs);
  const ticketRefs = cleanList(input.ticket_refs);
  const approvalRefs = cleanList(input.approval_refs);
  const dryRunRefs = cleanList(input.dry_run_refs);
  const rollbackPlan = redacted(input.rollback_plan);
  const gaps = [
    owner ? "" : "owner",
    action || remediation ? "" : "action_or_remediation",
    runtimeId || systemRefs.length ? "" : "target_system",
    evidenceRefs.length ? "" : "evidence_refs",
    dryRunRefs.length ? "" : "dry_run_ref",
    ticketRefs.length ? "" : "ticket_ref",
    approvalRefs.length ? "" : "approval_ref",
    rollbackPlan ? "" : "rollback_plan",
  ].filter(Boolean);
  return {
    packet_type: "approval_remediation",
    packet_id: packetId("approval_remediation", [title, owner, action, remediation, runtimeId, findingId, ...ticketRefs, ...approvalRefs]),
    title,
    owner,
    action,
    remediation,
    runtime_id: runtimeId,
    finding_id: findingId,
    system_refs: systemRefs,
    evidence_refs: evidenceRefs,
    ticket_refs: ticketRefs,
    approval_refs: approvalRefs,
    dry_run_refs: dryRunRefs,
    rollback_plan: rollbackPlan,
    readiness: remediationReadiness(gaps),
    ready_for_review: gaps.length === 0,
    guardrail_input: {
      action: action ?? remediation,
      target_system: runtimeId ?? systemRefs[0] ?? "unspecified",
      changes_production: true,
      has_dry_run: dryRunRefs.length > 0,
      has_human_approval: approvalRefs.length > 0,
      evidence_refs: evidenceRefs,
      ticket_refs: ticketRefs,
    },
    execution_plan: [
      { order: 1, tool: "operator_policy_guardrail_check", input: { action: action ?? remediation, target_system: runtimeId ?? systemRefs[0], changes_production: true } },
      { order: 2, tool: "operator_action_audit_log", input: { action: action ?? remediation, target_system: runtimeId ?? systemRefs[0] ?? "cerebro", target_id: findingId, status: "planned" } },
      { order: 3, tool: "finding_update", input: findingId ? { finding_id: findingId, action: action ?? "note" } : undefined },
    ].filter((step) => step.input),
    gaps,
    review_actions: gaps.length
      ? gaps.map((gap) => remediationGapAction(gap))
      : ["Run the guardrail check, verify approval scope, then execute only through the dedicated approved write tool."],
    secret_values_stored: false,
  };
}

function continuousMonitorPacket(input: CompliancePacketInput): CompliancePacket {
  const title = clean(input.title) ?? "Continuous compliance monitor";
  const owner = clean(input.owner);
  const controlIds = uniqueStrings([clean(input.control_id), ...cleanList(input.control_ids)]);
  const policyRefs = cleanList(input.policy_refs);
  const runtimeIds = cleanList(input.runtime_ids);
  const systemRefs = cleanList(input.system_refs);
  const sourceRefs = cleanList(input.source_refs);
  const evidenceRefs = cleanList(input.evidence_refs);
  const findingRefs = cleanList(input.finding_refs);
  const threshold = positiveInteger(input.threshold);
  const cooldownMinutes = positiveInteger(input.cooldown_minutes) ?? 60;
  const timeZone = clean(input.time_zone) ?? "America/Los_Angeles";
  const monitorTargetPresent = controlIds.length > 0 || policyRefs.length > 0 || runtimeIds.length > 0 || systemRefs.length > 0 || findingRefs.length > 0 || clean(input.scope);
  const evidenceSourcePresent = sourceRefs.length > 0 || evidenceRefs.length > 0 || runtimeIds.length > 0;
  const schedule = monitorSchedule(input, timeZone);
  const warnings = schedule.warning ? [schedule.warning] : [];
  const trigger = threshold && runtimeIds.length
    ? {
      type: "findings_threshold",
      runtimeIds,
      threshold,
      cooldownMs: cooldownMinutes * 60_000,
    }
    : undefined;
  const gaps = [
    owner ? "" : "owner",
    monitorTargetPresent ? "" : "monitor_target",
    evidenceSourcePresent ? "" : "evidence_sources",
    threshold && !runtimeIds.length ? "runtime_ids_for_threshold" : "",
  ].filter(Boolean);
  const scheduleDraft = {
    description: title,
    schedule: schedule.value,
    trigger,
    steps: [
      {
        id: "collect-control-context",
        title: "Collect control context",
        prompt: [
          "Read compliance source context and live Cerebro state for the monitor target.",
          monitorTargetLine(controlIds, policyRefs, runtimeIds, systemRefs, findingRefs, input.scope),
        ].filter(Boolean).join("\n"),
        dependsOn: [],
      },
      {
        id: "build-evidence-packet",
        title: "Build evidence packet",
        prompt: "Use cerebro_compliance_packet with control_evidence or audit_safe_report fields for the current run. Include evidence refs, policy refs, open findings, exceptions, and gaps.",
        dependsOn: ["collect-control-context"],
      },
      {
        id: "route-gaps",
        title: "Route gaps",
        prompt: "Summarize monitor status, new gaps, stale evidence, exception expirations, finding count changes, and the next ticket or approval action.",
        dependsOn: ["build-evidence-packet"],
      },
    ],
    contextProviders: uniqueStrings([
      "runtime_health_snapshot",
      "open_findings_snapshot",
      "companion_self_context",
    ]),
    channelId: clean(input.channel_id),
    warnings,
  };
  return {
    packet_type: "continuous_monitor",
    packet_id: packetId("continuous_monitor", [title, owner, ...controlIds, ...policyRefs, ...runtimeIds, ...systemRefs]),
    title,
    owner,
    scope: clean(input.scope),
    control_ids: controlIds,
    policy_refs: policyRefs,
    runtime_ids: runtimeIds,
    system_refs: systemRefs,
    source_refs: sourceRefs,
    evidence_refs: evidenceRefs,
    finding_refs: findingRefs,
    readiness: gaps.includes("evidence_sources") ? "needs_evidence" : gaps.length ? "needs_context" : "ready",
    ready_for_review: gaps.length === 0,
    schedule_draft: scheduleDraft,
    monitor_contract: {
      status: gaps.length ? "draft" : "ready_for_review",
      owner,
      escalation: "Create or update a ticket for repeated gaps, expired exceptions, stale evidence, or finding thresholds.",
      no_write_actions: true,
      approval_required_for_remediation: true,
    },
    gaps,
    warnings,
    review_actions: gaps.length
      ? gaps.map((gap) => monitorGapAction(gap))
      : ["Review the schedule, channel, owner, and threshold before creating the scheduled job."],
    secret_values_stored: false,
  };
}

function reviewActions(input: {
  gaps: string[];
  evidenceRefs: string[];
  ticketRefs: string[];
  findingRefs: string[];
  exceptionRefs: string[];
  packetType: string;
}): string[] {
  if (!input.gaps.length) {
    return [
      `Review the ${input.packetType} packet against live Cerebro state.`,
      "Attach the packet to the audit or ticket record after approval.",
    ];
  }
  return input.gaps.map((gap) => {
    switch (gap) {
      case "evidence_refs":
        return "Collect EvidenceCAS, Cerebro evidence, or source-system references for the control period.";
      case "fresh_evidence":
        return "Refresh stale evidence or mark the period with an explicit freshness caveat.";
      case "finding_disposition":
        return "Link open findings to a ticket or approved exception before marking the control ready.";
      default:
        return `Add ${gap.replace(/_/g, " ")} to complete the packet.`;
    }
  });
}

function terminalFindingState(value: string | undefined): boolean {
  return Boolean(value && /\b(resolve|resolved|suppress|suppressed|accept|accepted|close|closed)\b/i.test(value));
}

function lifecycleReadiness(gaps: string[]): CompliancePacket["readiness"] {
  if (gaps.includes("evidence_refs")) return "needs_evidence";
  if (gaps.includes("ticket_or_exception_ref") || gaps.includes("approval_ref")) return "needs_remediation";
  return gaps.length ? "needs_context" : "ready";
}

function remediationReadiness(gaps: string[]): CompliancePacket["readiness"] {
  if (gaps.includes("evidence_refs") || gaps.includes("dry_run_ref")) return "needs_evidence";
  if (gaps.includes("approval_ref") || gaps.includes("ticket_ref") || gaps.includes("rollback_plan")) return "needs_remediation";
  return gaps.length ? "needs_context" : "ready";
}

function lifecycleGapAction(gap: string): string {
  switch (gap) {
    case "evidence_refs":
      return "Build an evidence bundle before changing the finding lifecycle.";
    case "ticket_or_exception_ref":
      return "Link a ticket or approved exception before closing or suppressing the finding.";
    case "approval_ref":
      return "Capture reviewed approval before preparing the lifecycle update.";
    default:
      return `Add ${gap.replace(/_/g, " ")} to complete the lifecycle packet.`;
  }
}

function remediationGapAction(gap: string): string {
  switch (gap) {
    case "dry_run_ref":
      return "Attach a dry-run or impact-check reference before approval.";
    case "approval_ref":
      return "Capture reviewed approval before execution.";
    case "rollback_plan":
      return "Add rollback steps or a no-rollback rationale before execution.";
    case "ticket_ref":
      return "Link the remediation ticket or audit record.";
    default:
      return `Add ${gap.replace(/_/g, " ")} to complete the remediation packet.`;
  }
}

function monitorSchedule(input: CompliancePacketInput, timeZone: string): { value: Record<string, unknown>; warning?: string } {
  const cadence = clean(input.cadence)?.toLowerCase().replace(/[-\s]+/g, "_");
  const hour = boundedInteger(input.hour, 0, 23) ?? 9;
  const minute = boundedInteger(input.minute, 0, 59) ?? 0;
  if (cadence === "interval") {
    return {
      value: {
        kind: "interval",
        everyMs: (positiveInteger(input.interval_minutes) ?? 120) * 60_000,
        timeZone,
      },
    };
  }
  if (cadence === "daily") {
    return { value: { kind: "daily", timeOfDay: { hour, minute }, timeZone } };
  }
  if (cadence === "weekly") {
    return { value: { kind: "weekly", daysOfWeek: [1], timeOfDay: { hour, minute }, timeZone } };
  }
  if (cadence === "weekdays") {
    return { value: { kind: "weekdays", timeOfDay: { hour, minute }, timeZone } };
  }
  return {
    value: { kind: "weekdays", timeOfDay: { hour, minute }, timeZone },
    warning: "No cadence supplied; defaulted to weekdays at 09:00.",
  };
}

function monitorTargetLine(
  controlIds: string[],
  policyRefs: string[],
  runtimeIds: string[],
  systemRefs: string[],
  findingRefs: string[],
  scope: string | undefined,
): string {
  return [
    scope ? `Scope: ${scope}` : "",
    controlIds.length ? `Controls: ${controlIds.join(", ")}` : "",
    policyRefs.length ? `Policies: ${policyRefs.join(", ")}` : "",
    runtimeIds.length ? `Runtimes: ${runtimeIds.join(", ")}` : "",
    systemRefs.length ? `Systems: ${systemRefs.join(", ")}` : "",
    findingRefs.length ? `Findings: ${findingRefs.join(", ")}` : "",
  ].filter(Boolean).join("\n");
}

function monitorGapAction(gap: string): string {
  switch (gap) {
    case "evidence_sources":
      return "Add source refs, evidence refs, or runtime ids so each run can collect evidence.";
    case "runtime_ids_for_threshold":
      return "Add runtime ids for the finding threshold trigger.";
    default:
      return `Add ${gap.replace(/_/g, " ")} before creating the monitor.`;
  }
}

function normalizePacketType(value: string | undefined): CompliancePacketType | undefined {
  const normalized = value?.trim().toLowerCase().replace(/[-\s]+/g, "_");
  return compliancePacketTypes.includes(normalized as CompliancePacketType) ? normalized as CompliancePacketType : undefined;
}

function clean(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function cleanList(values: string[] | undefined): string[] {
  return [...new Set((values ?? []).map(clean).filter((value): value is string => Boolean(value)))];
}

function redacted(value: string | undefined): string | undefined {
  return value ? redactSecurityText(value) : undefined;
}

function redactedList(values: string[] | undefined): string[] {
  return cleanList(values).map((value) => redactSecurityText(value));
}

function normalizedAge(value: number | undefined): number | undefined {
  if (value === undefined || Number.isNaN(value)) return undefined;
  return Math.max(0, Math.floor(value));
}

function positiveInteger(value: number | undefined): number | undefined {
  if (value === undefined || Number.isNaN(value)) return undefined;
  const normalized = Math.floor(value);
  return normalized > 0 ? normalized : undefined;
}

function boundedInteger(value: number | undefined, min: number, max: number): number | undefined {
  if (value === undefined || Number.isNaN(value)) return undefined;
  const normalized = Math.floor(value);
  return normalized >= min && normalized <= max ? normalized : undefined;
}

function packetId(type: CompliancePacketType, parts: Array<string | undefined>): string {
  return `${type}_${createHash("sha256").update(parts.filter(Boolean).join("\u0000")).digest("hex").slice(0, 16)}`;
}

function uniqueStrings(values: Array<string | undefined>): string[] {
  return [...new Set(values.filter((value): value is string => Boolean(value)))];
}
