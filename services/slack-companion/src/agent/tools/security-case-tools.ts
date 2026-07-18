import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import type { AutonomousGoalRecord } from "../../autonomy/goals.js";
import type { ComplianceWorkCommand, ComplianceWorkItemRecord, ComplianceWorkItemState } from "../../cerebro/types.js";
import {
  attachGithubSecurityCaseFix,
  createCerebroWorkItemSecurityCase,
  createGithubSecurityCase,
  securityCaseView,
  syncCerebroWorkItemCase,
} from "../../security-cases/security-case.js";
import { safeToolResult } from "./tool-result.js";
import type { SecurityToolDeps } from "./types.js";

export function createSecurityCaseTools(deps: SecurityToolDeps): AgentTool[] {
  return [
    {
      name: "operator_security_case_start",
      label: "Start security case",
      description: "Start one durable GitHub security-alert case after Cerebro identifies the runtime, finding, repository, and alert reference. The case begins with current finding investigation and keeps existing commands and goals unchanged.",
      parameters: Type.Object({
        title: Type.String(),
        alert_ref: Type.String(),
        repository: Type.String(),
        runtime_id: Type.String(),
        finding_id: Type.String(),
        owner: Type.Optional(Type.String()),
        channel_id: Type.Optional(Type.String()),
        thread_ts: Type.Optional(Type.String()),
        requested_by_slack_user_id: Type.Optional(Type.String()),
        requested_by_display_name: Type.Optional(Type.String()),
      }),
      execute: async (_toolCallId, params) => safeToolResult(async () => startSecurityCase(deps, params as StartCaseArgs)),
    },
    {
      name: "operator_security_case_open_work_item",
      label: "Open work item case",
      description: "Open a durable operator case for one canonical Cerebro compliance work item. Repeated calls return the existing case instead of creating another queue entry.",
      parameters: Type.Object({
        work_item_id: Type.String(),
        title: Type.Optional(Type.String()),
        channel_id: Type.Optional(Type.String()),
        thread_ts: Type.Optional(Type.String()),
        requested_by_slack_user_id: Type.Optional(Type.String()),
        requested_by_display_name: Type.Optional(Type.String()),
      }),
      execute: async (_toolCallId, params) => safeToolResult(async () => openWorkItemCase(deps, params as OpenWorkItemCaseArgs)),
    },
    {
      name: "operator_security_case_attach_fix",
      label: "Attach security case fix",
      description: "Attach a bounded reviewable code fix to an existing GitHub security-alert case. The durable run opens a draft pull request, waits for merge, requests approval for fresh finding evaluation, and verifies the finding is resolved.",
      parameters: Type.Object({
        case_id: Type.String(),
        title: Type.String(),
        body: Type.Optional(Type.String()),
        files: Type.Array(Type.Object({ path: Type.String(), content: Type.String() }), { minItems: 1, maxItems: 12 }),
        branch: Type.Optional(Type.String()),
        base: Type.Optional(Type.String()),
        draft: Type.Optional(Type.Boolean()),
      }),
      execute: async (_toolCallId, params) => safeToolResult(async () => attachSecurityCaseFix(deps, params as AttachFixArgs)),
    },
    {
      name: "operator_security_case_command",
      label: "Plan canonical work update",
      description: "Add one version-checked canonical Cerebro work-item command to the durable case. The autonomy runner records approval before executing it. Remediation and assurance verification remain separate commands.",
      parameters: Type.Object({
        case_id: Type.String(),
        expected_version: Type.Number(),
        action: Type.String(),
        rationale: Type.Optional(Type.String()),
        owner_id: Type.Optional(Type.String()),
        blocker_reason: Type.Optional(Type.String()),
        snooze_until: Type.Optional(Type.String()),
        due_at: Type.Optional(Type.String()),
        evidence_ids: Type.Optional(Type.Array(Type.String(), { maxItems: 100 })),
        assurance_decision_id: Type.Optional(Type.String()),
        trigger: Type.Optional(Type.String()),
        source_ref: Type.Optional(Type.String()),
      }),
      execute: async (_toolCallId, params) => safeToolResult(async () => planWorkItemCaseCommand(deps, params as CommandWorkItemCaseArgs)),
    },
    {
      name: "operator_security_case_execute_command",
      label: "Execute canonical work update",
      description: "Execute the exact canonical Cerebro work-item command attached to an approved durable case step. Calls without a matching approved step are rejected.",
      parameters: Type.Object({
        case_id: Type.String(),
        expected_version: Type.Number(),
        action: Type.String(),
        rationale: Type.Optional(Type.String()),
        owner_id: Type.Optional(Type.String()),
        blocker_reason: Type.Optional(Type.String()),
        snooze_until: Type.Optional(Type.String()),
        due_at: Type.Optional(Type.String()),
        evidence_ids: Type.Optional(Type.Array(Type.String(), { maxItems: 100 })),
        assurance_decision_id: Type.Optional(Type.String()),
        trigger: Type.Optional(Type.String()),
        source_ref: Type.Optional(Type.String()),
      }),
      execute: async (_toolCallId, params) => safeToolResult(async () => executeWorkItemCaseCommand(deps, params as CommandWorkItemCaseArgs)),
    },
    {
      name: "operator_security_case_status",
      label: "Security case status",
      description: "Read one security case with its current state, owner, next action, blockers, artifacts, approvals, and verification record. Canonical work-item cases refresh from Cerebro before returning.",
      parameters: Type.Object({ case_id: Type.String() }),
      execute: async (_toolCallId, params) => safeToolResult(async () => readSecurityCase(deps, String((params as Record<string, unknown>).case_id))),
    },
    {
      name: "operator_security_case_work_item_status",
      label: "Canonical work item status",
      description: "Read the current canonical Cerebro work item for one durable case without changing the case record.",
      parameters: Type.Object({ case_id: Type.String() }),
      execute: async (_toolCallId, params) => safeToolResult(async () => readCanonicalWorkItem(deps, String((params as Record<string, unknown>).case_id))),
    },
    {
      name: "operator_security_case_list",
      label: "Security work queue",
      description: "List durable operator cases and the canonical Cerebro compliance work queue. Use work_state, owner_id, cursor, and limit for canonical queue pagination; state filters local case views.",
      parameters: Type.Object({
        state: Type.Optional(Type.String()),
        work_state: Type.Optional(Type.String()),
        owner_id: Type.Optional(Type.String()),
        cursor: Type.Optional(Type.String()),
        limit: Type.Optional(Type.Number()),
      }),
      execute: async (_toolCallId, params) => safeToolResult(async () => listSecurityCases(deps, params as ListSecurityCasesArgs)),
    },
  ];
}

interface StartCaseArgs {
  title: string;
  alert_ref: string;
  repository: string;
  runtime_id: string;
  finding_id: string;
  owner?: string;
  channel_id?: string;
  thread_ts?: string;
  requested_by_slack_user_id?: string;
  requested_by_display_name?: string;
}

interface OpenWorkItemCaseArgs {
  work_item_id: string;
  title?: string;
  channel_id?: string;
  thread_ts?: string;
  requested_by_slack_user_id?: string;
  requested_by_display_name?: string;
}

interface AttachFixArgs {
  case_id: string;
  title: string;
  body?: string;
  files: Array<{ path: string; content: string }>;
  branch?: string;
  base?: string;
  draft?: boolean;
}

interface CommandWorkItemCaseArgs {
  case_id: string;
  expected_version: number;
  action: NonNullable<ComplianceWorkCommand["action"]>;
  rationale?: string;
  owner_id?: string;
  blocker_reason?: string;
  snooze_until?: string;
  due_at?: string;
  evidence_ids?: string[];
  assurance_decision_id?: string;
  trigger?: ComplianceWorkCommand["trigger"];
  source_ref?: string;
}

interface ListSecurityCasesArgs {
  state?: string;
  work_state?: ComplianceWorkItemState;
  owner_id?: string;
  cursor?: string;
  limit?: number;
}

async function startSecurityCase(deps: SecurityToolDeps, args: StartCaseArgs): Promise<Record<string, unknown>> {
  const goals = deps.autonomyGoals;
  if (!goals?.createFromPlan) return { created: false, error: "security_case_store_unavailable" };
  const prepared = createGithubSecurityCase({
    title: args.title,
    alertRef: args.alert_ref,
    repository: args.repository,
    runtimeId: args.runtime_id,
    findingId: args.finding_id,
    owner: args.owner,
  });
  const goal = await goals.createFromPlan({
    objective: `Handle GitHub security alert ${args.alert_ref} for ${args.repository}; verify Cerebro finding ${args.finding_id} is resolved.`,
    actor: requestedActor(args),
    channelId: stringValue(args.channel_id),
    threadTs: stringValue(args.thread_ts),
    capabilityId: "remediation",
    plan: prepared.plan,
    resourceRefs: prepared.resourceRefs,
    acceptanceCriteria: prepared.acceptanceCriteria,
    securityCase: prepared.context,
  });
  deps.researchState?.recordCreatedGoal(goal.id);
  return { created: true, case: securityCaseView(goal) };
}

async function openWorkItemCase(deps: SecurityToolDeps, args: OpenWorkItemCaseArgs): Promise<Record<string, unknown>> {
  const goals = deps.autonomyGoals;
  if (!goals?.createFromPlan) return { created: false, error: "security_case_store_unavailable" };
  const workItemId = requiredString(args.work_item_id, "work_item_id");
  const existing = await findWorkItemCase(deps, workItemId);
  if (existing) {
    const refreshed = await refreshCanonicalCase(deps, existing);
    return { created: false, case: securityCaseView(refreshed.goal), work_item: refreshed.record };
  }
  const record = await deps.cerebro.getComplianceWorkItem(workItemId);
  const prepared = createCerebroWorkItemSecurityCase(record.item, stringValue(args.title));
  const goal = await goals.createFromPlan({
    objective: `Resolve canonical Cerebro work item ${record.item.id} with recorded remediation and fresh post-change assurance.`,
    actor: requestedActor(args),
    channelId: stringValue(args.channel_id),
    threadTs: stringValue(args.thread_ts),
    capabilityId: "remediation",
    plan: prepared.plan,
    resourceRefs: prepared.resourceRefs,
    acceptanceCriteria: prepared.acceptanceCriteria,
    securityCase: prepared.context,
  });
  deps.researchState?.recordCreatedGoal(goal.id);
  return { created: true, case: securityCaseView(goal), work_item: record };
}

async function attachSecurityCaseFix(deps: SecurityToolDeps, args: AttachFixArgs): Promise<Record<string, unknown>> {
  const goals = deps.autonomyGoals;
  if (!goals?.replacePlan || !goals.update) return { attached: false, error: "security_case_update_unavailable" };
  const goal = await findSecurityCase(deps, args.case_id);
  if (!goal) return { attached: false, error: "security_case_not_found" };
  if (goal.securityCase?.kind !== "github_security_alert") return { attached: false, error: "github_security_case_required" };
  const plan = attachGithubSecurityCaseFix(goal, {
    title: args.title,
    body: args.body,
    files: args.files,
    branch: args.branch,
    base: args.base,
    draft: args.draft,
  });
  await goals.replacePlan(goal.id, plan);
  const updated = await goals.update(goal.id, {
    status: "active",
    activeStepId: null,
    nextWakeAt: new Date().toISOString(),
  });
  return { attached: true, case: securityCaseView(updated) };
}

async function planWorkItemCaseCommand(deps: SecurityToolDeps, args: CommandWorkItemCaseArgs): Promise<Record<string, unknown>> {
  const goals = deps.autonomyGoals;
  if (!goals?.update) return { scheduled: false, error: "security_case_update_unavailable" };
  const goal = await findSecurityCase(deps, args.case_id);
  if (!goal) return { scheduled: false, error: "security_case_not_found" };
  if (goal.securityCase?.kind !== "cerebro_work_item") return { scheduled: false, error: "cerebro_work_item_case_required" };
  const command = workItemCommand(args);
  const stepId = commandStepId(command);
  const execution = {
    toolName: "operator_security_case_execute_command",
    arguments: commandToolArguments(args),
    verificationToolName: "operator_security_case_work_item_status",
    verificationArguments: { case_id: args.case_id },
    approvalRequired: true,
    idempotencyKey: `${goal.securityCase.workItemId}:${command.expected_version}:${command.action}`,
    rollback: "No rollback command is issued automatically. Refresh the canonical work item and submit a new version-checked command if the approved action must be superseded.",
    maxAttempts: 1,
    attempts: 0,
  };
  let found = false;
  const plan = goal.currentPlan.map((step) => {
    if (step.id !== stepId) return step;
    found = true;
    return {
      ...step,
      status: "pending" as const,
      execution,
      acceptanceCriteriaIds: commandCriteria(command.action),
      summary: undefined,
    };
  });
  if (!found) {
    plan.push({
      id: stepId,
      title: commandStepTitle(command.action),
      status: "pending",
      dependsOn: ["inspect-work-item"],
      execution,
      acceptanceCriteriaIds: commandCriteria(command.action),
    });
  }
  const updated = await goals.update(goal.id, {
    currentPlan: plan,
    activeStepId: null,
    status: "active",
    nextWakeAt: new Date().toISOString(),
  });
  return { scheduled: true, approval_required: true, case: securityCaseView(updated), command };
}

async function executeWorkItemCaseCommand(deps: SecurityToolDeps, args: CommandWorkItemCaseArgs): Promise<Record<string, unknown>> {
  const goal = await findSecurityCase(deps, args.case_id);
  if (!goal) return { updated: false, error: "security_case_not_found" };
  if (goal.securityCase?.kind !== "cerebro_work_item") return { updated: false, error: "cerebro_work_item_case_required" };
  const command = workItemCommand(args);
  const approvedStep = goal.currentPlan.find((step) => step.execution?.toolName === "operator_security_case_execute_command"
    && step.execution.arguments.case_id === args.case_id
    && step.execution.arguments.expected_version === args.expected_version
    && step.execution.arguments.action === args.action);
  const approval = approvedStep && goal.approvals.find((candidate) => candidate.stepId === approvedStep.id
    && candidate.toolName === "operator_security_case_execute_command"
    && candidate.status === "approved");
  if (!approval) {
    return {
      updated: false,
      approval_required: true,
      error: "approved_goal_step_required",
      message: "The exact canonical work-item command must be approved on its durable case before execution.",
    };
  }
  const record = await deps.cerebro.commandComplianceWorkItem(goal.securityCase.workItemId, command);
  const updated = await syncCanonicalGoal(
    deps,
    goal,
    record,
    args.action === "verify_assurance" ? stringValue(args.assurance_decision_id) : undefined,
  );
  return { updated: true, case: securityCaseView(updated), work_item: record };
}

async function readSecurityCase(deps: SecurityToolDeps, caseId: string): Promise<Record<string, unknown>> {
  const goal = await findSecurityCase(deps, caseId);
  if (!goal) return { found: false, error: "security_case_not_found" };
  if (goal.securityCase?.kind !== "cerebro_work_item") return { found: true, case: securityCaseView(goal) };
  const refreshed = await refreshCanonicalCase(deps, goal);
  return { found: true, case: securityCaseView(refreshed.goal), work_item: refreshed.record };
}

async function readCanonicalWorkItem(deps: SecurityToolDeps, caseId: string): Promise<Record<string, unknown>> {
  const goal = await findSecurityCase(deps, caseId);
  if (!goal) return { found: false, error: "security_case_not_found" };
  if (goal.securityCase?.kind !== "cerebro_work_item") return { found: false, error: "cerebro_work_item_case_required" };
  const record = await deps.cerebro.getComplianceWorkItem(goal.securityCase.workItemId);
  return { found: true, work_item: record };
}

async function listSecurityCases(deps: SecurityToolDeps, args: ListSecurityCasesArgs): Promise<Record<string, unknown>> {
  if (!deps.autonomyGoals?.list) return { cases: [], work_items: [], error: "security_case_store_unavailable" };
  const cases = (await deps.autonomyGoals.list())
    .map(securityCaseView)
    .filter((item): item is NonNullable<typeof item> => Boolean(item))
    .filter((item) => !args.state || item.state === args.state)
    .slice(0, 50);
  const listWorkItems = (deps.cerebro as Partial<SecurityToolDeps["cerebro"]>).listComplianceWorkItems;
  if (typeof listWorkItems !== "function") return { cases, count: cases.length, work_items: [] };
  const page = await deps.cerebro.listComplianceWorkItems({
    state: args.work_state,
    ownerId: stringValue(args.owner_id),
    cursor: stringValue(args.cursor),
    limit: boundedLimit(args.limit),
  });
  return { cases, count: cases.length, work_items: page.items, next_cursor: page.next_cursor };
}

async function refreshCanonicalCase(
  deps: SecurityToolDeps,
  goal: AutonomousGoalRecord,
): Promise<{ goal: AutonomousGoalRecord; record: ComplianceWorkItemRecord }> {
  if (goal.securityCase?.kind !== "cerebro_work_item") throw new Error("Canonical work-item case required.");
  const record = await deps.cerebro.getComplianceWorkItem(goal.securityCase.workItemId);
  return { goal: await syncCanonicalGoal(deps, goal, record), record };
}

async function syncCanonicalGoal(
  deps: SecurityToolDeps,
  goal: AutonomousGoalRecord,
  record: ComplianceWorkItemRecord,
  assuranceDecisionId?: string,
): Promise<AutonomousGoalRecord> {
  if (goal.securityCase?.kind !== "cerebro_work_item") throw new Error("Canonical work-item case required.");
  const synced = syncCerebroWorkItemCase(goal.securityCase, record.item, assuranceDecisionId);
  if (!deps.autonomyGoals?.update) return { ...goal, securityCase: synced.context, currentPlan: synced.plan, resourceRefs: synced.resourceRefs };
  return deps.autonomyGoals.update(goal.id, {
    securityCase: synced.context,
    currentPlan: synced.plan,
    resourceRefs: synced.resourceRefs,
  });
}

async function findWorkItemCase(deps: SecurityToolDeps, workItemId: string): Promise<AutonomousGoalRecord | undefined> {
  const goals = await deps.autonomyGoals?.list?.();
  return goals?.find((goal) => goal.securityCase?.kind === "cerebro_work_item" && goal.securityCase.workItemId === workItemId);
}

async function findSecurityCase(deps: SecurityToolDeps, caseId: string): Promise<AutonomousGoalRecord | undefined> {
  const direct = await deps.autonomyGoals?.get?.(caseId);
  if (direct?.securityCase) return direct;
  const goals = await deps.autonomyGoals?.list?.();
  return goals?.find((goal) => goal.securityCase?.id === caseId);
}

function requestedActor(args: {
  requested_by_slack_user_id?: string;
  requested_by_display_name?: string;
}): { slackUserId: string; actorId: string; displayName?: string } {
  const slackUserId = stringValue(args.requested_by_slack_user_id) ?? "unknown";
  return {
    slackUserId,
    actorId: slackUserId === "unknown" ? "slack:unknown" : `slack:${slackUserId}`,
    displayName: stringValue(args.requested_by_display_name),
  };
}

function boundedLimit(value: number | undefined): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isInteger(value) || value < 1 || value > 200) throw new Error("limit must be an integer from 1 through 200.");
  return value;
}

const workItemActions = new Set<NonNullable<ComplianceWorkCommand["action"]>>([
  "assign",
  "request_evidence",
  "block",
  "snooze",
  "accept",
  "remediate",
  "verify",
  "verify_assurance",
  "close",
  "supersede",
]);

type ComplianceWorkActionCommand = ComplianceWorkCommand & { action: NonNullable<ComplianceWorkCommand["action"]> };

function workItemCommand(args: CommandWorkItemCaseArgs): ComplianceWorkActionCommand {
  if (!Number.isInteger(args.expected_version) || args.expected_version < 1) {
    throw new Error("expected_version must be a positive integer.");
  }
  if (!workItemActions.has(args.action)) throw new Error(`Unsupported canonical work-item action: ${String(args.action)}.`);
  return {
    operation: "action",
    expected_version: args.expected_version,
    action: args.action,
    owner_id: stringValue(args.owner_id),
    rationale: stringValue(args.rationale),
    blocker_reason: stringValue(args.blocker_reason),
    snooze_until: stringValue(args.snooze_until),
    due_at: stringValue(args.due_at),
    evidence_ids: args.evidence_ids,
    assurance_decision_id: stringValue(args.assurance_decision_id),
    trigger: args.trigger,
    source_ref: stringValue(args.source_ref),
  };
}

function commandToolArguments(args: CommandWorkItemCaseArgs): Record<string, unknown> {
  return withoutUndefined({
    case_id: args.case_id,
    expected_version: args.expected_version,
    action: args.action,
    rationale: stringValue(args.rationale),
    owner_id: stringValue(args.owner_id),
    blocker_reason: stringValue(args.blocker_reason),
    snooze_until: stringValue(args.snooze_until),
    due_at: stringValue(args.due_at),
    evidence_ids: args.evidence_ids,
    assurance_decision_id: stringValue(args.assurance_decision_id),
    trigger: args.trigger,
    source_ref: stringValue(args.source_ref),
  });
}

function commandStepId(command: ComplianceWorkActionCommand): string {
  if (command.action === "remediate") return "record-remediation";
  if (command.action === "verify_assurance") return "record-post-change-assurance";
  return `apply-canonical-${command.action}-${command.expected_version}`;
}

function commandStepTitle(action: NonNullable<ComplianceWorkCommand["action"]>): string {
  const titles: Record<NonNullable<ComplianceWorkCommand["action"]>, string> = {
    assign: "Assign the canonical work item",
    request_evidence: "Request evidence for the canonical work item",
    block: "Block the canonical work item",
    snooze: "Snooze the canonical work item",
    accept: "Accept the canonical work item",
    remediate: "Record the completed remediation",
    verify: "Record verification evidence",
    verify_assurance: "Verify with a fresh assurance decision",
    close: "Close the canonical work item",
    supersede: "Supersede the canonical work item",
  };
  return titles[action];
}

function commandCriteria(action: NonNullable<ComplianceWorkCommand["action"]>): string[] {
  if (action === "remediate") return ["remediation-recorded"];
  if (action === "verify_assurance") return ["assurance-decision-recorded", "canonical-work-resolved"];
  return [];
}

function withoutUndefined(input: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(input).filter(([, value]) => value !== undefined));
}

function requiredString(value: unknown, label: string): string {
  const normalized = stringValue(value);
  if (!normalized) throw new Error(`${label} is required.`);
  return normalized;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}
