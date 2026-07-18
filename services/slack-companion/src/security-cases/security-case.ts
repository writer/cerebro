import { randomUUID } from "node:crypto";
import { canonicalResourceRef, type AgentAcceptanceCriterion, type AgentResourceRef } from "../autonomy/agent-run.js";
import type { AutonomyPlanStep, AutonomousGoalRecord } from "../autonomy/goals.js";
import { securityCaseContextSchema, type SecurityCaseContext, type SecurityCaseState } from "./types.js";

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
  alertRef: string;
  repository: string;
  runtimeId: string;
  findingId: string;
  goalId: string;
  goalStatus: AutonomousGoalRecord["status"];
  blockers: string[];
  resources: AutonomousGoalRecord["resourceRefs"];
  artifacts: AutonomousGoalRecord["artifacts"];
  approvals: AutonomousGoalRecord["approvals"];
  verification: AutonomousGoalRecord["completionReceipt"];
  updatedAt: string;
}

export function createGithubSecurityCase(input: GithubSecurityCaseInput): {
  context: SecurityCaseContext;
  plan: AutonomyPlanStep[];
  resourceRefs: AgentResourceRef[];
  acceptanceCriteria: AgentAcceptanceCriterion[];
} {
  const context = securityCaseContextSchema.parse({
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
  const context = requiredSecurityCase(goal);
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
  return {
    id: context.id,
    kind: context.kind,
    title: context.title,
    state: securityCaseState(goal, next),
    owner: context.owner,
    nextAction: next?.title,
    alertRef: context.alertRef,
    repository: context.repository,
    runtimeId: context.runtimeId,
    findingId: context.findingId,
    goalId: goal.id,
    goalStatus: goal.status,
    blockers: [...goal.blockers],
    resources: goal.resourceRefs,
    artifacts: goal.artifacts,
    approvals: goal.approvals,
    verification: goal.completionReceipt,
    updatedAt: goal.updatedAt,
  };
}

function initialGithubSecurityCasePlan(context: SecurityCaseContext): AutonomyPlanStep[] {
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

function githubSecurityCaseResources(context: SecurityCaseContext): AgentResourceRef[] {
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

function criterion(
  id: string,
  description: string,
  kind: AgentAcceptanceCriterion["kind"],
  field?: string,
  expected?: string | number | boolean,
): AgentAcceptanceCriterion {
  return { id, description, kind, field, expected, status: "pending", evidenceRefs: [] };
}

function requiredSecurityCase(goal: AutonomousGoalRecord): SecurityCaseContext {
  if (!goal.securityCase) throw new Error("Security case not found on this durable run.");
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
