import { randomUUID } from "node:crypto";
import { canonicalResourceRef, type AgentAcceptanceCriterion, type AgentResourceRef } from "../autonomy/agent-run.js";
import type { AutonomyPlanStep, AutonomousGoalRecord } from "../autonomy/goals.js";
import type { ComplianceWorkItem } from "../cerebro/types.js";
import {
  securityCaseContextSchema,
  githubSecurityCaseContextSchema,
  type CerebroWorkItemCaseContext,
  type GithubSecurityCaseContext,
  type SecurityCaseContext,
  type SecurityCaseState,
} from "./types.js";

export interface GithubSecurityCaseInput {
  title: string;
  alertRef: string;
  repository: string;
  runtimeId: string;
  findingId: string;
  owner?: string;
}

export interface GithubSecurityCaseFixInput {
  title: string;
  body?: string;
  files: Array<{ path: string; content: string }>;
  branch?: string;
  base?: string;
  draft?: boolean;
}

export interface SecurityCaseView {
  id: string;
  kind: SecurityCaseContext["kind"];
  title: string;
  state: SecurityCaseState;
  owner?: string;
  nextAction?: string;
  alertRef?: string;
  repository?: string;
  runtimeId?: string;
  findingId?: string;
  workItemId?: string;
  workItemVersion?: number;
  workItemState?: ComplianceWorkItem["state"];
  assuranceDecisionId?: string;
  goalId: string;
  goalStatus: AutonomousGoalRecord["status"];
  blockers: string[];
  resources: AutonomousGoalRecord["resourceRefs"];
  artifacts: AutonomousGoalRecord["artifacts"];
  approvals: AutonomousGoalRecord["approvals"];
  verification: AutonomousGoalRecord["completionReceipt"];
  updatedAt: string;
}

export function createCerebroWorkItemSecurityCase(item: ComplianceWorkItem, title?: string): {
  context: CerebroWorkItemCaseContext;
  plan: AutonomyPlanStep[];
  resourceRefs: AgentResourceRef[];
  acceptanceCriteria: AgentAcceptanceCriterion[];
} {
  const context = cerebroWorkItemCaseContext(item, title);
  return {
    context,
    plan: cerebroWorkItemCasePlan(item),
    resourceRefs: cerebroWorkItemCaseResources(item),
    acceptanceCriteria: cerebroWorkItemCaseCriteria(item),
  };
}

export function syncCerebroWorkItemCase(
  current: CerebroWorkItemCaseContext,
  item: ComplianceWorkItem,
  assuranceDecisionId?: string,
): { context: CerebroWorkItemCaseContext; plan: AutonomyPlanStep[]; resourceRefs: AgentResourceRef[] } {
  if (current.workItemId !== item.id) throw new Error("Canonical work item does not match this security case.");
  return {
    context: cerebroWorkItemCaseContext(item, current.title, assuranceDecisionId ?? current.assuranceDecisionId),
    plan: cerebroWorkItemCasePlan(item),
    resourceRefs: cerebroWorkItemCaseResources(item),
  };
}

export function createGithubSecurityCase(input: GithubSecurityCaseInput): {
  context: GithubSecurityCaseContext;
  plan: AutonomyPlanStep[];
  resourceRefs: AgentResourceRef[];
  acceptanceCriteria: AgentAcceptanceCriterion[];
} {
  const context = githubSecurityCaseContextSchema.parse({
    id: `case-${randomUUID()}`,
    kind: "github_security_alert",
    title: input.title,
    alertRef: input.alertRef,
    repository: input.repository,
    runtimeId: input.runtimeId,
    findingId: input.findingId,
    owner: input.owner,
    desiredOutcome: "The finding is resolved in Cerebro after the fix merges and fresh source evaluation completes.",
  });
  return {
    context,
    plan: initialGithubSecurityCasePlan(context),
    resourceRefs: githubSecurityCaseResources(context),
    acceptanceCriteria: githubSecurityCaseCriteria(),
  };
}

export function attachGithubSecurityCaseFix(
  goal: AutonomousGoalRecord,
  fix: GithubSecurityCaseFixInput,
): AutonomyPlanStep[] {
  const context = requiredGithubSecurityCase(goal);
  if (fix.files.length === 0) throw new Error("At least one changed file is required before a reviewable fix can be attached.");
  const existing = new Map(goal.currentPlan.map((step) => [step.id, step]));
  const initial = initialGithubSecurityCasePlan(context);
  const investigate = existing.get("investigate-finding") ?? requiredPlanStep(initial, "investigate-finding");
  const prepare = existing.get("prepare-reviewable-fix") ?? requiredPlanStep(initial, "prepare-reviewable-fix");
  const prepared = prepare.status === "completed" ? prepare : { ...prepare, status: "completed" as const, summary: "Reviewable fix attached to the case." };

  return [
    investigate,
    prepared,
    {
      id: "open-reviewable-pr",
      title: "Open the reviewable fix",
      status: "pending",
      dependsOn: ["prepare-reviewable-fix"],
      execution: {
        toolName: "cerebro_code_github_pr",
        arguments: withoutUndefined({
          repo: context.repository,
          title: fix.title,
          body: fix.body,
          files: fix.files,
          branch: fix.branch,
          base: fix.base,
          draft: fix.draft ?? true,
        }),
        verificationToolName: "cerebro_code_github_pr_status",
        verificationArguments: {
          repo: context.repository,
          pull_number: "$result.pull_request.number",
          include_checks: true,
        },
        approvalRequired: false,
        maxAttempts: 1,
        attempts: 0,
      },
      acceptanceCriteriaIds: ["reviewable-pr-created"],
    },
    {
      id: "monitor-github-merge",
      title: "Wait for the pull request to merge",
      status: "pending",
      dependsOn: ["open-reviewable-pr"],
    },
    {
      id: "reevaluate-finding",
      title: "Run a fresh finding evaluation",
      status: "pending",
      dependsOn: ["monitor-github-merge"],
      execution: {
        toolName: "source_run_trigger",
        arguments: {
          runtime_id: context.runtimeId,
          action: "finding_evaluate",
          reason: `Verify ${context.id} after the reviewable fix merged.`,
          execute: true,
          approved: true,
        },
        verificationToolName: "source_run_status",
        verificationArguments: { runtime_id: context.runtimeId },
        approvalRequired: true,
        idempotencyKey: `${context.id}:finding-evaluate`,
        rollback: "No source data is mutated. If evaluation fails, keep the case open and rerun after the runtime recovers.",
        maxAttempts: 3,
        attempts: 0,
      },
      acceptanceCriteriaIds: ["finding-reevaluated"],
    },
    {
      id: "verify-finding-resolved",
      title: "Verify the finding is resolved",
      status: "pending",
      dependsOn: ["reevaluate-finding"],
      execution: {
        toolName: "finding_lookup",
        arguments: {
          runtime_id: context.runtimeId,
          finding_id: context.findingId,
          limit: 1,
        },
        verificationArguments: {},
        approvalRequired: false,
        maxAttempts: 3,
        attempts: 0,
      },
      acceptanceCriteriaIds: ["finding-resolved"],
    },
  ];
}

export function securityCaseView(goal: AutonomousGoalRecord): SecurityCaseView | undefined {
  const context = goal.securityCase;
  if (!context) return undefined;
  const next = nextCaseStep(goal);
  const shared = {
    id: context.id,
    kind: context.kind,
    title: context.title,
    state: securityCaseState(goal, next),
    owner: context.owner,
    nextAction: next?.title,
    goalId: goal.id,
    goalStatus: goal.status,
    blockers: [...goal.blockers],
    resources: goal.resourceRefs,
    artifacts: goal.artifacts,
    approvals: goal.approvals,
    verification: goal.completionReceipt,
    updatedAt: goal.updatedAt,
  };
  return context.kind === "github_security_alert"
    ? {
        ...shared,
        alertRef: context.alertRef,
        repository: context.repository,
        runtimeId: context.runtimeId,
        findingId: context.findingId,
      }
    : {
        ...shared,
        workItemId: context.workItemId,
        workItemVersion: context.workItemVersion,
        workItemState: context.workItemState,
        assuranceDecisionId: context.assuranceDecisionId,
      };
}

function initialGithubSecurityCasePlan(context: GithubSecurityCaseContext): AutonomyPlanStep[] {
  return [
    {
      id: "investigate-finding",
      title: "Investigate the finding and affected resources",
      status: "pending",
      dependsOn: [],
      execution: {
        toolName: "cerebro_finding_investigation",
        arguments: {
          runtime_id: context.runtimeId,
          finding_id: context.findingId,
          include_graph: true,
        },
        verificationArguments: {},
        approvalRequired: false,
        maxAttempts: 3,
        attempts: 0,
      },
      acceptanceCriteriaIds: ["finding-investigated"],
    },
    {
      id: "prepare-reviewable-fix",
      title: "Prepare the reviewable fix",
      status: "pending",
      dependsOn: ["investigate-finding"],
    },
  ];
}

function githubSecurityCaseResources(context: GithubSecurityCaseContext): AgentResourceRef[] {
  return [
    canonicalResourceRef({ kind: "github", id: context.alertRef, source: "github_security_alert", label: context.title }),
    canonicalResourceRef({ kind: "github", id: context.repository, source: "github", label: context.repository }),
    canonicalResourceRef({ kind: "cerebro", id: `${context.runtimeId}/findings/${context.findingId}`, source: "cerebro_findings", label: context.findingId }),
  ];
}

function githubSecurityCaseCriteria(): AgentAcceptanceCriterion[] {
  return [
    criterion("finding-investigated", "The current finding and affected resources were inspected.", "field_equals", "finding_found", true),
    criterion("reviewable-pr-created", "A reviewable pull request exists.", "field_present", "pull_request.url"),
    criterion("finding-reevaluated", "A fresh finding evaluation completed.", "tool_success"),
    criterion("finding-resolved", "A fresh finding read reports resolved.", "field_equals", "findings.0.status", "resolved"),
  ];
}

function cerebroWorkItemCaseContext(
  item: ComplianceWorkItem,
  title?: string,
  assuranceDecisionId?: string,
): CerebroWorkItemCaseContext {
  return securityCaseContextSchema.parse({
    id: item.id,
    kind: "cerebro_work_item",
    title: (title?.trim() || `${item.basis.control_id}: ${item.basis.subject_id}`).slice(0, 300),
    owner: item.owner_id || undefined,
    desiredOutcome: "Record remediation, evaluate fresh evidence, and resolve the canonical Cerebro work item.",
    workItemId: item.id,
    workItemVersion: item.version,
    workItemState: item.state,
    programId: item.basis.program_id,
    scopeRevisionId: item.basis.scope_revision_id,
    controlId: item.basis.control_id,
    objectiveId: item.basis.objective_id,
    subjectId: item.basis.subject_id,
    sourceId: item.basis.source_id,
    findingIds: workItemFindingIds(item),
    assuranceDecisionId: assuranceDecisionId ?? item.verification?.assurance_decision_id,
  }) as CerebroWorkItemCaseContext;
}

function cerebroWorkItemCasePlan(item: ComplianceWorkItem): AutonomyPlanStep[] {
  const remediated = Boolean(item.last_remediated_at || item.verification);
  const verified = Boolean(item.verification);
  return [
    {
      id: "inspect-work-item",
      title: "Inspect the canonical work item",
      status: "completed",
      dependsOn: [],
    },
    {
      id: "record-remediation",
      title: "Record the completed remediation",
      status: remediated ? "completed" : "pending",
      dependsOn: ["inspect-work-item"],
    },
    {
      id: "record-post-change-assurance",
      title: "Record a fresh post-change assurance decision",
      status: verified ? "completed" : "pending",
      dependsOn: ["record-remediation"],
    },
    {
      id: "verify-canonical-work",
      title: "Verify and resolve the canonical work item",
      status: verified && item.state === "resolved" ? "completed" : "pending",
      dependsOn: ["record-post-change-assurance"],
    },
  ];
}

function cerebroWorkItemCaseResources(item: ComplianceWorkItem): AgentResourceRef[] {
  return [
    canonicalResourceRef({ kind: "cerebro", id: `grc/work-items/${item.id}`, source: "cerebro_compliance_work", label: item.id }),
    canonicalResourceRef({ kind: "generic", id: item.basis.subject_id, source: item.basis.source_id, label: item.basis.subject_id }),
    ...workItemFindingIds(item).map((findingId) => canonicalResourceRef({
      kind: "cerebro",
      id: `findings/${findingId}`,
      source: "cerebro_findings",
      label: findingId,
    })),
  ];
}

function cerebroWorkItemCaseCriteria(item: ComplianceWorkItem): AgentAcceptanceCriterion[] {
  return [
    {
      ...criterion("canonical-work-loaded", "The current canonical work item was loaded from Cerebro.", "tool_success"),
      status: "passed",
      checkedAt: item.updated_at,
      result: "The canonical work item was loaded from Cerebro.",
    },
    criterion("remediation-recorded", "Cerebro records the completed remediation and its actor.", "field_present", "work_item.item.last_remediated_at"),
    criterion("assurance-decision-recorded", "The work item references a fresh post-change assurance decision.", "field_present", "work_item.item.verification.assurance_decision_id"),
    criterion("canonical-work-resolved", "Cerebro reports the canonical work item as resolved.", "field_equals", "work_item.item.state", "resolved"),
  ];
}

function workItemFindingIds(item: ComplianceWorkItem): string[] {
  return [...new Set(item.occurrences.flatMap((occurrence) => occurrence.finding_ids ?? []))].slice(0, 100);
}

function criterion(
  id: string,
  description: string,
  kind: AgentAcceptanceCriterion["kind"],
  field?: string,
  expected?: string | number | boolean,
): AgentAcceptanceCriterion {
  return { id, description, kind, field, expected, status: "pending", evidenceRefs: [] };
}

function requiredGithubSecurityCase(goal: AutonomousGoalRecord): GithubSecurityCaseContext {
  if (!goal.securityCase) throw new Error("Security case not found on this durable run.");
  if (goal.securityCase.kind !== "github_security_alert") throw new Error("This action requires a GitHub security-alert case.");
  return goal.securityCase;
}

function requiredPlanStep(plan: AutonomyPlanStep[], stepId: string): AutonomyPlanStep {
  const step = plan.find((item) => item.id === stepId);
  if (!step) throw new Error(`Security case plan step ${stepId} is missing.`);
  return step;
}

function nextCaseStep(goal: AutonomousGoalRecord): AutonomyPlanStep | undefined {
  return goal.currentPlan.find((step) => step.id === goal.activeStepId)
    ?? goal.currentPlan.find((step) => step.status === "waiting")
    ?? goal.currentPlan.find((step) => step.status === "active")
    ?? goal.currentPlan.find((step) => step.status === "pending");
}

function securityCaseState(goal: AutonomousGoalRecord, next: AutonomyPlanStep | undefined): SecurityCaseState {
  if (goal.securityCase?.kind === "cerebro_work_item") {
    switch (goal.securityCase.workItemState) {
      case "resolved":
      case "accepted":
      case "superseded":
        return "closed";
      case "blocked":
        return "blocked";
      case "snoozed":
        return "waiting_on_owner";
      case "in_progress":
        return goal.securityCase.assuranceDecisionId ? "verifying" : "needs_evidence";
      case "open":
        return "ready_to_act";
    }
  }
  if (goal.status === "completed" && goal.completionReceipt?.status === "complete") return "closed";
  if (goal.status === "blocked" || goal.status === "cancelled") return "blocked";
  if (goal.status === "approval_needed") return "needs_decision";
  if (!next) return goal.status === "waiting" ? "needs_evidence" : "investigating";
  if (next.id === "verify-finding-resolved" || next.id === "reevaluate-finding") return "verifying";
  if (next.id === "monitor-github-merge") return "waiting_on_owner";
  if (next.id === "prepare-reviewable-fix" || next.id === "open-reviewable-pr") return "ready_to_act";
  return "investigating";
}

function withoutUndefined(input: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(input).filter(([, value]) => value !== undefined));
}
