import type {
  CanonicalWorkCoordinator,
  DurableCanonicalWorkCasePort,
} from "@writer/cerebro-slack-companion";
import type { ComplianceWorkCommand, ComplianceWorkItemState } from "@writer/cerebro-sdk";
import { CANONICAL_WORK_TOOL_POLICIES } from "./policy.js";
import type {
  CanonicalWorkApprovalPort,
  CanonicalWorkEvidencePort,
  CanonicalWorkGoalPort,
  CanonicalWorkHostContext,
  CanonicalWorkHostTool,
} from "./types.js";

export interface CanonicalWorkToolDependencies {
  approvals: CanonicalWorkApprovalPort;
  clock: { now(): Date };
  coordinator: CanonicalWorkCoordinator;
  evidence: CanonicalWorkEvidencePort;
  goals: CanonicalWorkGoalPort;
  store: DurableCanonicalWorkCasePort;
}

export function createCanonicalWorkHostTools(
  deps: CanonicalWorkToolDependencies,
): CanonicalWorkHostTool[] {
  return [
    {
      name: "operator_security_case_open_work_item",
      description: "Open or resume one durable Slack case for an existing canonical Cerebro work item.",
      policy: CANONICAL_WORK_TOOL_POLICIES.operator_security_case_open_work_item,
      execute: (input, context) => openCase(deps, input, context),
    },
    {
      name: "operator_security_case_command",
      description: "Plan one version-checked canonical work-item command and request approval for its exact digest.",
      policy: CANONICAL_WORK_TOOL_POLICIES.operator_security_case_command,
      execute: (input, context) => planCommand(deps, input, context),
    },
    {
      name: "operator_security_case_execute_command",
      description: "Execute one approved canonical work-item command and reconcile an unknown result before retrying.",
      policy: CANONICAL_WORK_TOOL_POLICIES.operator_security_case_execute_command,
      execute: (input, context) => executeCommand(deps, input, context),
    },
    {
      name: "operator_security_case_work_item_status",
      description: "Refresh one Slack case from the canonical Cerebro work item without changing canonical state.",
      policy: CANONICAL_WORK_TOOL_POLICIES.operator_security_case_work_item_status,
      execute: (input, context) => readStatus(deps, input, context),
    },
    {
      name: "operator_security_case_list",
      description: "List the canonical Cerebro work queue with state, owner, cursor, and limit filters.",
      policy: CANONICAL_WORK_TOOL_POLICIES.operator_security_case_list,
      execute: (input) => listWork(deps, input),
    },
  ];
}

async function openCase(
  deps: CanonicalWorkToolDependencies,
  input: Record<string, unknown>,
  context: CanonicalWorkHostContext,
) {
  const opened = await deps.coordinator.open({
    title: optionalString(input.title),
    work_item_id: requiredString(input.work_item_id, "work_item_id"),
  });
  const goal = await deps.goals.syncCase(opened.case, context);
  await deps.evidence.record({
    case_ref: caseRef(opened.case.case_id),
    kind: "case_durable",
    occurred_at: deps.clock.now().toISOString(),
    receipt_ref: requestReceipt(context.request_ref),
    request_ref: context.request_ref,
  });
  await recordGoalEvidence(deps, opened.case.case_id, goal.goal_receipt_ref, context);
  return { case: opened.case, created: opened.created };
}

async function planCommand(
  deps: CanonicalWorkToolDependencies,
  input: Record<string, unknown>,
  context: CanonicalWorkHostContext,
) {
  const caseId = requiredString(input.case_id, "case_id");
  const planned = await deps.coordinator.planCommand(caseId, commandFromInput(input));
  const approval = await deps.approvals.request({
    actor_ref: requiredString(context.actor_ref, "actor_ref"),
    case_id: caseId,
    channel_ref: context.channel_ref,
    command_digest: planned.intent.command_digest,
    intent_id: planned.intent.intent_id,
    request_ref: requiredString(context.request_ref, "request_ref"),
    summary: commandSummary(planned.intent.command),
    thread_ref: context.thread_ref,
  });
  const goal = await deps.goals.recordIntent(planned.intent, approval.approval_ref, context);
  await deps.evidence.record({
    case_ref: caseRef(caseId),
    intent_ref: intentRef(planned.intent.intent_id),
    kind: "approval_requested",
    occurred_at: deps.clock.now().toISOString(),
    receipt_ref: requiredString(approval.approval_ref, "approval_ref"),
    request_ref: context.request_ref,
  });
  await recordGoalEvidence(deps, caseId, goal.goal_receipt_ref, context);
  return {
    approval_ref: approval.approval_ref,
    approval_required: true,
    created: planned.created,
    intent: planned.intent,
  };
}

async function executeCommand(
  deps: CanonicalWorkToolDependencies,
  input: Record<string, unknown>,
  context: CanonicalWorkHostContext,
) {
  const intentId = requiredString(input.intent_id, "intent_id");
  const approvalRef = requiredString(input.approval_ref, "approval_ref");
  const intent = await deps.store.readIntent(intentId);
  if (intent === undefined) throw new Error("Canonical work command intent does not exist.");
  const approval = await deps.approvals.approvedReceipt(approvalRef, {
    command_digest: intent.command_digest,
    intent_id: intent.intent_id,
  });
  const result = await deps.coordinator.executeApproved(intent.intent_id, approval);
  const goal = await deps.goals.syncCase(result.case, context);
  await deps.evidence.record({
    case_ref: caseRef(result.case.case_id),
    intent_ref: intentRef(result.intent.intent_id),
    kind: "command_finished",
    occurred_at: deps.clock.now().toISOString(),
    outcome: result.intent.status,
    receipt_ref: approval.approval_ref,
    request_ref: context.request_ref,
  });
  await recordGoalEvidence(deps, result.case.case_id, goal.goal_receipt_ref, context);
  return result;
}

async function readStatus(
  deps: CanonicalWorkToolDependencies,
  input: Record<string, unknown>,
  context: CanonicalWorkHostContext,
) {
  const refreshed = await deps.coordinator.refresh(requiredString(input.case_id, "case_id"));
  const goal = await deps.goals.syncCase(refreshed, context);
  await recordGoalEvidence(deps, refreshed.case_id, goal.goal_receipt_ref, context);
  return { case: refreshed, found: true };
}

function listWork(deps: CanonicalWorkToolDependencies, input: Record<string, unknown>) {
  return deps.coordinator.list({
    cursor: optionalString(input.cursor),
    limit: optionalPositiveInteger(input.limit),
    owner_id: optionalString(input.owner_id),
    state: optionalString(input.work_state) as ComplianceWorkItemState | undefined,
  });
}

function commandFromInput(input: Record<string, unknown>): ComplianceWorkCommand {
  const expectedVersion = optionalPositiveInteger(input.expected_version);
  if (expectedVersion === undefined) throw new Error("expected_version must be a positive integer");
  const operation = optionalString(input.operation) ?? "action";
  const command: ComplianceWorkCommand = {
    expected_version: expectedVersion,
    operation: operation as ComplianceWorkCommand["operation"],
  };
  assignString(command, "action", input.action);
  assignString(command, "assurance_decision_id", input.assurance_decision_id);
  assignString(command, "blocker_reason", input.blocker_reason);
  assignString(command, "due_at", input.due_at);
  assignString(command, "owner_id", input.owner_id);
  assignString(command, "rationale", input.rationale);
  assignString(command, "snooze_until", input.snooze_until);
  assignString(command, "source_ref", input.source_ref);
  assignString(command, "trigger", input.trigger);
  if (input.evidence_ids !== undefined) {
    if (!Array.isArray(input.evidence_ids) || input.evidence_ids.some((value) => typeof value !== "string")) {
      throw new Error("evidence_ids must contain strings");
    }
    command.evidence_ids = input.evidence_ids.map((value) => value.trim());
  }
  return command;
}

function assignString(
  command: ComplianceWorkCommand,
  key: keyof ComplianceWorkCommand,
  value: unknown,
): void {
  const normalized = optionalString(value);
  if (normalized !== undefined) (command as Record<string, unknown>)[key] = normalized;
}

function commandSummary(command: ComplianceWorkCommand): string {
  const action = command.operation === "invalidate" ? "invalidate" : command.action;
  return `Apply ${action ?? "the planned update"} to the canonical work item at version ${command.expected_version}.`;
}

function requiredString(value: unknown, field: string): string {
  const normalized = optionalString(value);
  if (normalized === undefined) throw new Error(`${field} is required`);
  return normalized;
}

function optionalString(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") throw new Error("Expected a string value");
  const normalized = value.trim();
  if (!normalized || normalized.length > 2_048) throw new Error("String value is empty or too long");
  return normalized;
}

function optionalPositiveInteger(value: unknown): number | undefined {
  if (value === undefined || value === null) return undefined;
  if (!Number.isSafeInteger(value) || Number(value) < 1) return undefined;
  return Number(value);
}

function caseRef(caseId: string): string {
  return `case://canonical-work/${encodeURIComponent(caseId)}`;
}

function intentRef(intentId: string): string {
  return `intent://canonical-work/${encodeURIComponent(intentId)}`;
}

function requestReceipt(requestRef: string): string {
  return `receipt://slack-request/${encodeURIComponent(requiredString(requestRef, "request_ref"))}`;
}

async function recordGoalEvidence(
  deps: CanonicalWorkToolDependencies,
  caseId: string,
  goalReceiptRef: string,
  context: CanonicalWorkHostContext,
): Promise<void> {
  await deps.evidence.record({
    case_ref: caseRef(caseId),
    kind: "goal_synced",
    occurred_at: deps.clock.now().toISOString(),
    receipt_ref: requiredString(goalReceiptRef, "goal_receipt_ref"),
    request_ref: context.request_ref,
  });
}
