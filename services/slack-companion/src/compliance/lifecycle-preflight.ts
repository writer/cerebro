export interface FindingLifecyclePreflightInput {
  runtime_id?: string;
  finding_id?: string;
  action?: string;
  desired_state?: string;
  reason?: string;
  evidence_refs?: string[];
  ticket_refs?: string[];
  exception_refs?: string[];
  approval_refs?: string[];
  dry_run_refs?: string[];
  rollback_plan?: string;
  execute?: boolean;
  approved?: boolean;
}

export function findingLifecyclePreflight(input: FindingLifecyclePreflightInput): Record<string, unknown> {
  const runtimeId = clean(input.runtime_id);
  const findingId = clean(input.finding_id);
  const action = clean(input.action);
  const desiredState = clean(input.desired_state) ?? action;
  const evidenceRefs = cleanList(input.evidence_refs);
  const ticketRefs = cleanList(input.ticket_refs);
  const exceptionRefs = cleanList(input.exception_refs);
  const approvalRefs = cleanList(input.approval_refs);
  const dryRunRefs = cleanList(input.dry_run_refs);
  const rollbackPlan = clean(input.rollback_plan);
  const terminal = terminalFindingState(desiredState);
  const missing = [
    findingId ? "" : "finding_id",
    action || desiredState ? "" : "action_or_desired_state",
    terminal && !runtimeId ? "runtime_id" : "",
    terminal && !evidenceRefs.length ? "evidence_refs" : "",
    terminal && !ticketRefs.length && !exceptionRefs.length ? "ticket_or_exception_ref" : "",
    terminal && !approvalRefs.length && input.approved !== true ? "approval_ref" : "",
    terminal && !dryRunRefs.length ? "dry_run_ref" : "",
    terminal && !rollbackPlan ? "rollback_plan" : "",
  ].filter(Boolean);
  const decision = preflightDecision(terminal, missing);
  return {
    decision,
    ready_for_execution: terminal ? missing.length === 0 : missing.length === 0,
    terminal_action: terminal,
    execute_requested: input.execute === true,
    approved: input.approved === true,
    runtime_id: runtimeId,
    finding_id: findingId,
    action,
    desired_state: desiredState,
    missing,
    evidence_refs: evidenceRefs,
    ticket_refs: ticketRefs,
    exception_refs: exceptionRefs,
    approval_refs: approvalRefs,
    dry_run_refs: dryRunRefs,
    rollback_plan: rollbackPlan,
    guardrail_input: {
      action: action ?? desiredState,
      target_system: runtimeId ?? "cerebro",
      changes_production: terminal,
      has_dry_run: dryRunRefs.length > 0,
      has_human_approval: approvalRefs.length > 0 || input.approved === true,
      evidence_refs: evidenceRefs,
      ticket_refs: [...ticketRefs, ...exceptionRefs],
    },
    finding_update_input: {
      finding_id: findingId,
      action: action ?? desiredState,
      reason: clean(input.reason),
      execute: input.execute === true,
      approved: input.approved === true,
    },
    audit_record_input: {
      action: action ?? desiredState ?? "finding lifecycle",
      target_system: runtimeId ?? "cerebro",
      target_id: findingId,
      status: missing.length ? "blocked" : "approval_ready",
      evidence_refs: evidenceRefs,
      ticket_refs: [...ticketRefs, ...exceptionRefs],
      decision,
    },
    next_step: nextStep(terminal, missing),
    secret_values_stored: false,
  };
}

function preflightDecision(terminal: boolean, missing: string[]): string {
  if (!missing.length) return terminal ? "approval_ready" : "ready";
  if (missing.includes("evidence_refs")) return "needs_evidence";
  if (missing.includes("dry_run_ref")) return "dry_run_required";
  if (missing.includes("approval_ref")) return "approval_required";
  return "needs_context";
}

function nextStep(terminal: boolean, missing: string[]): string {
  if (!missing.length) return terminal
    ? "Run the approved finding update, then write an audit record with the result."
    : "Use the planned finding update path; terminal lifecycle evidence is not required for this action.";
  if (missing.includes("ticket_or_exception_ref")) return "Create or link a Jira ticket or exception before closing the finding.";
  if (missing.includes("dry_run_ref")) return "Run a dry-run or impact check and attach its reference before execution.";
  if (missing.includes("approval_ref")) return "Capture reviewed human approval that names the finding, action, and evidence.";
  return `Add ${missing[0]?.replace(/_/g, " ")} before execution.`;
}

function terminalFindingState(value: string | undefined): boolean {
  return /\b(resolve|resolved|suppress|suppressed|close|closed|false_positive|accepted_risk)\b/i.test(value ?? "");
}

function cleanList(values: string[] | undefined): string[] {
  return unique((values ?? []).map(clean).filter((value): value is string => Boolean(value)));
}

function clean(value: string | undefined): string | undefined {
  const trimmed = value?.replace(/\s+/g, " ").trim();
  return trimmed || undefined;
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}
