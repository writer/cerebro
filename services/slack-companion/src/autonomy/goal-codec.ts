import { randomUUID } from "node:crypto";
import { z } from "zod";
import { isClaimVerificationActionStage } from "../cerebro/types.js";
import { redactSecurityText } from "../security/redaction.js";
import {
  agentAcceptanceCriteriaSchema,
  agentArtifactsSchema,
  agentCompletionReceiptSchema,
  agentCorrectionsSchema,
  agentResourceRefsSchema,
  agentStepExecutionSchema,
} from "./agent-run.js";
import type {
  AutonomyApprovalRecord,
  AutonomyApprovalStatus,
  AutonomyCapabilityId,
  AutonomyExecutionContract,
  AutonomyExecutionContractSource,
  AutonomyGoalClaim,
  AutonomyGoalStatus,
  AutonomyPlanStep,
  AutonomyToolRunRecord,
  AutonomyToolRunStatus,
  AutonomyWorkLogEntry,
  AutonomyWorkLogKind,
  AutonomousGoalRecord,
  CreateAutonomyGoalInput,
  UpdateAutonomyGoalInput,
} from "./goal-types.js";
import { securityCaseContextSchema } from "../security-cases/types.js";
import { securityMissionReceiptSchema, securityMissionStepReceiptSchema } from "./mission-types.js";

const autonomyPlanStepSchema = z.object({
  id: z.string().trim().min(1).max(160),
  title: z.string().trim().min(1).max(500),
  status: z.enum(["pending", "active", "waiting", "completed", "failed", "skipped"]),
  dependsOn: z.array(z.string().trim().min(1).max(160)).max(40).default([]),
  summary: z.string().trim().min(1).max(1200).optional(),
  execution: agentStepExecutionSchema.optional(),
  acceptanceCriteriaIds: z.array(z.string().trim().min(1).max(160)).max(40).optional(),
  mission: securityMissionStepReceiptSchema.optional(),
});

const autonomyPlanSchema = z.array(autonomyPlanStepSchema).max(80);

export function cleanText(value: string, field: string): string {
  const trimmed = redactSecurityText(value).replace(/\s+/g, " ").trim();
  if (!trimmed) throw new Error(`${field} is required`);
  return trimmed.slice(0, 1200);
}

export function createGoalRecord(input: CreateAutonomyGoalInput, nowDate: Date): AutonomousGoalRecord {
  const now = nowDate.toISOString();
  const objective = cleanText(input.objective, "objective");
  return {
    id: `goal-${randomUUID()}`,
    status: "active",
    capabilityId: input.capabilityId ?? "planner",
    objective,
    channelId: input.channelId,
    threadTs: input.threadTs,
    createdBy: { ...input.createdBy },
    createdAt: now,
    updatedAt: now,
    currentPlan: clonePlan(input.plan ?? []),
    assumptions: [...(input.assumptions ?? [])],
    blockers: [],
    artifactUrls: [],
    resourceRefs: agentResourceRefsSchema.parse(input.resourceRefs ?? []),
    artifacts: agentArtifactsSchema.parse(input.artifacts ?? []),
    acceptanceCriteria: agentAcceptanceCriteriaSchema.parse(input.acceptanceCriteria ?? []),
    corrections: agentCorrectionsSchema.parse(input.corrections ?? []),
    securityCase: input.securityCase ? securityCaseContextSchema.parse(input.securityCase) : undefined,
    nextWakeAt: input.nextWakeAt,
    executionContract: cloneExecutionContract(input.executionContract),
    mission: cloneMission(input.mission),
    toolRuns: [],
    approvals: [],
    workLog: [{
      id: `log-${randomUUID()}`,
      kind: "goal_created",
      createdAt: now,
      summary: `Goal created: ${objective}`,
    }],
  };
}

export function applyGoalUpdate(goal: AutonomousGoalRecord, input: UpdateAutonomyGoalInput, nowDate: Date): AutonomousGoalRecord {
  return {
    ...goal,
    status: input.status ?? goal.status,
    capabilityId: input.capabilityId ?? goal.capabilityId,
    currentPlan: input.currentPlan ? clonePlan(input.currentPlan) : goal.currentPlan,
    activeStepId: input.activeStepId === undefined ? goal.activeStepId : input.activeStepId ?? undefined,
    assumptions: input.assumptions ? [...input.assumptions] : goal.assumptions,
    blockers: input.blockers ? [...input.blockers] : goal.blockers,
    artifactUrls: input.artifactUrls ? [...input.artifactUrls] : goal.artifactUrls,
    nextWakeAt: input.nextWakeAt === undefined ? goal.nextWakeAt : input.nextWakeAt ?? undefined,
    completionSummary: input.completionSummary === undefined ? goal.completionSummary : input.completionSummary ?? undefined,
    claim: input.claim === undefined ? goal.claim : input.claim ?? undefined,
    executionContract: input.executionContract === undefined ? goal.executionContract : cloneExecutionContract(input.executionContract ?? undefined),
    mission: input.mission === undefined ? goal.mission : cloneMission(input.mission ?? undefined),
    toolRuns: input.toolRuns ? cloneToolRuns(input.toolRuns) : goal.toolRuns,
    approvals: input.approvals ? cloneApprovals(input.approvals) : goal.approvals,
    resourceRefs: input.resourceRefs ? agentResourceRefsSchema.parse(input.resourceRefs) : goal.resourceRefs,
    artifacts: input.artifacts ? agentArtifactsSchema.parse(input.artifacts) : goal.artifacts,
    acceptanceCriteria: input.acceptanceCriteria ? agentAcceptanceCriteriaSchema.parse(input.acceptanceCriteria) : goal.acceptanceCriteria,
    corrections: input.corrections ? agentCorrectionsSchema.parse(input.corrections) : goal.corrections,
    completionReceipt: input.completionReceipt === undefined
      ? goal.completionReceipt
      : input.completionReceipt === null ? undefined : agentCompletionReceiptSchema.parse(input.completionReceipt),
    securityCase: input.securityCase === undefined
      ? goal.securityCase
      : input.securityCase === null ? undefined : securityCaseContextSchema.parse(input.securityCase),
    updatedAt: nowDate.toISOString(),
  };
}

export function appendGoalLog(
  goal: AutonomousGoalRecord,
  entry: Omit<AutonomyWorkLogEntry, "id" | "createdAt">,
  nowDate: Date,
): AutonomousGoalRecord {
  const now = nowDate.toISOString();
  return {
    ...goal,
    updatedAt: now,
    workLog: [
      ...goal.workLog,
      {
        id: `log-${randomUUID()}`,
        createdAt: now,
        ...entry,
        summary: cleanText(entry.summary, "summary"),
      },
    ],
  };
}

export function compareGoals(left: AutonomousGoalRecord, right: AutonomousGoalRecord): number {
  return right.updatedAt.localeCompare(left.updatedAt);
}

export function cloneGoal(goal: AutonomousGoalRecord): AutonomousGoalRecord {
  return {
    ...goal,
    createdBy: { ...goal.createdBy },
    currentPlan: clonePlan(goal.currentPlan),
    assumptions: [...goal.assumptions],
    blockers: [...goal.blockers],
    artifactUrls: [...goal.artifactUrls],
    resourceRefs: goal.resourceRefs.map((item) => ({ ...item, links: item.links.map((link) => ({ ...link })) })),
    artifacts: goal.artifacts.map((item) => ({ ...item, sourceRefs: [...item.sourceRefs] })),
    acceptanceCriteria: goal.acceptanceCriteria.map((item) => ({ ...item, evidenceRefs: [...item.evidenceRefs] })),
    corrections: goal.corrections.map((item) => ({ ...item, sourceRefs: [...item.sourceRefs] })),
    completionReceipt: goal.completionReceipt ? {
      ...goal.completionReceipt,
      criteriaPassed: [...goal.completionReceipt.criteriaPassed],
      criteriaFailed: [...goal.completionReceipt.criteriaFailed],
      evidenceRefs: [...goal.completionReceipt.evidenceRefs],
    } : undefined,
    securityCase: goal.securityCase ? securityCaseContextSchema.parse(goal.securityCase) : undefined,
    claim: goal.claim ? { ...goal.claim } : undefined,
    executionContract: cloneExecutionContract(goal.executionContract),
    mission: cloneMission(goal.mission),
    toolRuns: cloneToolRuns(goal.toolRuns),
    approvals: cloneApprovals(goal.approvals),
    workLog: goal.workLog.map((entry) => ({ ...entry })),
  };
}

export function toAutonomousGoalRecord(item: Record<string, unknown>): AutonomousGoalRecord | undefined {
  if (
    typeof item.id !== "string"
    || !isAutonomyGoalStatus(item.status)
    || typeof item.objective !== "string"
    || typeof item.createdAt !== "string"
    || typeof item.updatedAt !== "string"
    || !Array.isArray(item.currentPlan)
    || !Array.isArray(item.workLog)
  ) {
    return undefined;
  }
  const createdBy = objectValue(item.createdBy) ?? {};
  return {
    id: item.id,
    status: item.status,
    capabilityId: isAutonomyCapabilityId(item.capabilityId) ? item.capabilityId : "planner",
    objective: item.objective,
    channelId: typeof item.channelId === "string" ? item.channelId : undefined,
    threadTs: typeof item.threadTs === "string" ? item.threadTs : undefined,
    createdBy: {
      slackUserId: typeof createdBy.slackUserId === "string" ? createdBy.slackUserId : undefined,
      actorId: typeof createdBy.actorId === "string" ? createdBy.actorId : undefined,
      displayName: typeof createdBy.displayName === "string" ? createdBy.displayName : undefined,
    },
    createdAt: item.createdAt,
    updatedAt: item.updatedAt,
    currentPlan: item.currentPlan.map(toPlanStep).filter(isPlanStep),
    activeStepId: typeof item.activeStepId === "string" ? item.activeStepId : undefined,
    assumptions: Array.isArray(item.assumptions) ? item.assumptions.map(String) : [],
    blockers: Array.isArray(item.blockers) ? item.blockers.map(String) : [],
    artifactUrls: Array.isArray(item.artifactUrls) ? item.artifactUrls.map(String) : [],
    resourceRefs: parsedArray(agentResourceRefsSchema, item.resourceRefs),
    artifacts: parsedArray(agentArtifactsSchema, item.artifacts),
    acceptanceCriteria: parsedArray(agentAcceptanceCriteriaSchema, item.acceptanceCriteria),
    corrections: parsedArray(agentCorrectionsSchema, item.corrections),
    completionReceipt: parsedValue(agentCompletionReceiptSchema, item.completionReceipt),
    securityCase: parsedValue(securityCaseContextSchema, item.securityCase),
    nextWakeAt: typeof item.nextWakeAt === "string" ? item.nextWakeAt : undefined,
    completionSummary: typeof item.completionSummary === "string" ? item.completionSummary : undefined,
    claim: toGoalClaim(item.claim),
    executionContract: toExecutionContract(item.executionContract),
    mission: parsedValue(securityMissionReceiptSchema, item.mission),
    toolRuns: Array.isArray(item.toolRuns) ? item.toolRuns.map(toToolRun).filter(isToolRun) : [],
    approvals: Array.isArray(item.approvals) ? item.approvals.map(toApproval).filter(isApproval) : [],
    workLog: item.workLog.map(toWorkLogEntry).filter(isWorkLogEntry),
  };
}

export function isAutonomousGoalRecord(value: AutonomousGoalRecord | undefined): value is AutonomousGoalRecord {
  return Boolean(value);
}

export function isAutonomyGoalStatus(value: unknown): value is AutonomyGoalStatus {
  return value === "active"
    || value === "waiting"
    || value === "approval_needed"
    || value === "blocked"
    || value === "paused"
    || value === "completed"
    || value === "cancelled";
}

export function isAutonomyCapabilityId(value: unknown): value is AutonomyCapabilityId {
  return value === "triage"
    || value === "investigation"
    || value === "planner"
    || value === "executor"
    || value === "remediation"
    || value === "identity_response"
    || value === "detection_response"
    || value === "self_repair";
}

function clonePlan(plan: AutonomyPlanStep[]): AutonomyPlanStep[] {
  const parsed = autonomyPlanSchema.parse(plan);
  validatePlanGraph(parsed);
  return parsed.map((step) => ({
    ...step,
    title: cleanText(step.title, "plan title").slice(0, 500),
    ...(step.summary ? { summary: cleanText(step.summary, "plan summary") } : {}),
    dependsOn: [...step.dependsOn],
    ...(step.acceptanceCriteriaIds ? { acceptanceCriteriaIds: [...step.acceptanceCriteriaIds] } : {}),
    ...(step.mission ? { mission: cloneMissionStep(step.mission) } : {}),
    ...(step.execution ? {
      execution: {
        ...step.execution,
        arguments: { ...step.execution.arguments },
        verificationArguments: { ...step.execution.verificationArguments },
      },
    } : {}),
  }));
}

function cloneToolRuns(toolRuns: AutonomyToolRunRecord[] | undefined): AutonomyToolRunRecord[] {
  return (toolRuns ?? []).map((run) => ({ ...run }));
}

function cloneApprovals(approvals: AutonomyApprovalRecord[] | undefined): AutonomyApprovalRecord[] {
  return (approvals ?? []).map((approval) => ({
    ...approval,
    decidedBy: approval.decidedBy ? { ...approval.decidedBy } : undefined,
  }));
}

function cloneExecutionContract(contract: AutonomyExecutionContract | undefined): AutonomyExecutionContract | undefined {
  return contract
    ? {
        ...contract,
        requiredVerifierIds: [...contract.requiredVerifierIds],
      }
    : undefined;
}

function cloneMission(mission: AutonomousGoalRecord["mission"]): AutonomousGoalRecord["mission"] {
  if (!mission) return undefined;
  const parsed = securityMissionReceiptSchema.parse(mission);
  return {
    ...parsed,
    bindings: parsed.bindings.map((binding) => ({ ...binding })),
    missingInputIds: [...parsed.missingInputIds],
    requiredEvidence: [...parsed.requiredEvidence],
    acceptanceCriteriaIds: [...parsed.acceptanceCriteriaIds],
    actionStepIds: [...parsed.actionStepIds],
    serviceLevel: { ...parsed.serviceLevel },
  };
}

function cloneMissionStep(mission: NonNullable<AutonomyPlanStep["mission"]>): NonNullable<AutonomyPlanStep["mission"]> {
  const parsed = securityMissionStepReceiptSchema.parse(mission);
  return {
    ...parsed,
    requiredInputIds: [...parsed.requiredInputIds],
    toolSelector: {
      names: [...parsed.toolSelector.names],
      prefixes: [...parsed.toolSelector.prefixes],
      families: [...parsed.toolSelector.families],
      authorities: [...parsed.toolSelector.authorities],
    },
  };
}

function toPlanStep(value: unknown): AutonomyPlanStep | undefined {
  const parsed = autonomyPlanStepSchema.safeParse(value);
  if (!parsed.success) return undefined;
  const item = parsed.data;
  return {
    id: item.id,
    title: cleanText(item.title, "plan title").slice(0, 500),
    status: item.status,
    dependsOn: [...item.dependsOn],
    ...(item.summary ? { summary: cleanText(item.summary, "plan summary") } : {}),
    execution: item.execution ? { ...item.execution, arguments: { ...item.execution.arguments }, verificationArguments: { ...item.execution.verificationArguments } } : undefined,
    acceptanceCriteriaIds: item.acceptanceCriteriaIds ? [...item.acceptanceCriteriaIds] : undefined,
    mission: item.mission ? cloneMissionStep(item.mission) : undefined,
  };
}

function validatePlanGraph(plan: AutonomyPlanStep[]): void {
  const ids = new Set<string>();
  for (const step of plan) {
    if (ids.has(step.id)) throw new Error(`Duplicate autonomy plan step ${step.id}.`);
    ids.add(step.id);
  }
  for (const step of plan) {
    const unknown = step.dependsOn.filter((dependency) => !ids.has(dependency));
    if (unknown.length > 0) throw new Error(`Autonomy plan step ${step.id} has unknown dependencies: ${unknown.join(", ")}.`);
  }
  const visiting = new Set<string>();
  const visited = new Set<string>();
  const byId = new Map(plan.map((step) => [step.id, step]));
  const visit = (id: string): void => {
    if (visiting.has(id)) throw new Error("Autonomy plan contains a dependency cycle.");
    if (visited.has(id)) return;
    visiting.add(id);
    for (const dependency of byId.get(id)?.dependsOn ?? []) visit(dependency);
    visiting.delete(id);
    visited.add(id);
  };
  for (const step of plan) visit(step.id);
}

function parsedArray<T>(schema: { safeParse(value: unknown): { success: boolean; data?: T } }, value: unknown): T {
  const parsed = schema.safeParse(value ?? []);
  return parsed.success ? parsed.data as T : [] as T;
}

function parsedValue<T>(schema: { safeParse(value: unknown): { success: boolean; data?: T } }, value: unknown): T | undefined {
  if (value === undefined || value === null) return undefined;
  const parsed = schema.safeParse(value);
  return parsed.success ? parsed.data : undefined;
}

function toWorkLogEntry(value: unknown): AutonomyWorkLogEntry | undefined {
  const item = objectValue(value);
  if (!item || typeof item.id !== "string" || !isWorkLogKind(item.kind) || typeof item.createdAt !== "string" || typeof item.summary !== "string") {
    return undefined;
  }
  return {
    id: item.id,
    kind: item.kind,
    createdAt: item.createdAt,
    summary: item.summary,
    details: typeof item.details === "string" ? item.details : undefined,
    artifactUrl: typeof item.artifactUrl === "string" ? item.artifactUrl : undefined,
  };
}

function toToolRun(value: unknown): AutonomyToolRunRecord | undefined {
  const item = objectValue(value);
  if (!item || typeof item.id !== "string" || typeof item.toolId !== "string" || !isToolRunStatus(item.status) || typeof item.startedAt !== "string") {
    return undefined;
  }
  return {
    id: item.id,
    toolId: item.toolId,
    toolName: typeof item.toolName === "string" ? item.toolName : undefined,
    status: item.status,
    requestSummary: typeof item.requestSummary === "string" ? item.requestSummary : undefined,
    responseSummary: typeof item.responseSummary === "string" ? item.responseSummary : undefined,
    reason: typeof item.reason === "string" ? item.reason : undefined,
    error: typeof item.error === "string" ? item.error : undefined,
    artifactUrl: typeof item.artifactUrl === "string" ? item.artifactUrl : undefined,
    startedAt: item.startedAt,
    completedAt: typeof item.completedAt === "string" ? item.completedAt : undefined,
  };
}

function toApproval(value: unknown): AutonomyApprovalRecord | undefined {
  const item = objectValue(value);
  if (
    !item
    || typeof item.id !== "string"
    || !isApprovalStatus(item.status)
    || typeof item.toolId !== "string"
    || typeof item.actionSummary !== "string"
    || typeof item.reason !== "string"
    || typeof item.risk !== "string"
    || typeof item.createdAt !== "string"
  ) {
    return undefined;
  }
  const decidedBy = objectValue(item.decidedBy);
  return {
    id: item.id,
    status: item.status,
    stepId: typeof item.stepId === "string" ? item.stepId : undefined,
    toolId: item.toolId,
    toolName: typeof item.toolName === "string" ? item.toolName : undefined,
    actionSummary: item.actionSummary,
    reason: item.reason,
    risk: item.risk,
    requestSummary: typeof item.requestSummary === "string" ? item.requestSummary : undefined,
    createdAt: item.createdAt,
    decidedAt: typeof item.decidedAt === "string" ? item.decidedAt : undefined,
    decidedBy: decidedBy
      ? {
          slackUserId: typeof decidedBy.slackUserId === "string" ? decidedBy.slackUserId : undefined,
          actorId: typeof decidedBy.actorId === "string" ? decidedBy.actorId : undefined,
          displayName: typeof decidedBy.displayName === "string" ? decidedBy.displayName : undefined,
        }
      : undefined,
    resultSummary: typeof item.resultSummary === "string" ? item.resultSummary : undefined,
    error: typeof item.error === "string" ? item.error : undefined,
  };
}

function toGoalClaim(value: unknown): AutonomyGoalClaim | undefined {
  const item = objectValue(value);
  if (!item || typeof item.workerId !== "string" || typeof item.claimedAt !== "string" || typeof item.leaseExpiresAt !== "string") {
    return undefined;
  }
  return {
    workerId: item.workerId,
    claimedAt: item.claimedAt,
    leaseExpiresAt: item.leaseExpiresAt,
    attempt: typeof item.attempt === "number" ? item.attempt : 1,
  };
}

function toExecutionContract(value: unknown): AutonomyExecutionContract | undefined {
  const item = objectValue(value);
  if (
    !item
    || !isExecutionContractSource(item.source)
    || typeof item.version !== "string"
    || !isAutonomyCapabilityId(item.capabilityId)
    || typeof item.profileId !== "string"
    || !isClaimVerificationActionStage(item.maxActionStage)
    || !isClaimVerificationActionStage(item.requestedActionStage)
    || typeof item.selectedAt !== "string"
  ) {
    return undefined;
  }
  return {
    source: item.source,
    version: item.version,
    capabilityId: item.capabilityId,
    profileId: item.profileId,
    maxActionStage: item.maxActionStage,
    requestedActionStage: item.requestedActionStage,
    requiredVerifierIds: Array.isArray(item.requiredVerifierIds) ? item.requiredVerifierIds.map(String) : [],
    selectedAt: item.selectedAt,
  };
}

function isPlanStep(value: AutonomyPlanStep | undefined): value is AutonomyPlanStep {
  return Boolean(value);
}

function isWorkLogEntry(value: AutonomyWorkLogEntry | undefined): value is AutonomyWorkLogEntry {
  return Boolean(value);
}

function isToolRun(value: AutonomyToolRunRecord | undefined): value is AutonomyToolRunRecord {
  return Boolean(value);
}

function isToolRunStatus(value: unknown): value is AutonomyToolRunStatus {
  return value === "planned" || value === "completed" || value === "failed" || value === "skipped" || value === "approval_requested";
}

function isApproval(value: AutonomyApprovalRecord | undefined): value is AutonomyApprovalRecord {
  return Boolean(value);
}

function isApprovalStatus(value: unknown): value is AutonomyApprovalStatus {
  return value === "pending" || value === "approved" || value === "rejected" || value === "executed" || value === "failed" || value === "cancelled";
}

function isExecutionContractSource(value: unknown): value is AutonomyExecutionContractSource {
  return value === "cerebro" || value === "local_default";
}

function isWorkLogKind(value: unknown): value is AutonomyWorkLogKind {
  return value === "goal_created"
    || value === "plan_updated"
    || value === "step_started"
    || value === "tool_called"
    || value === "artifact_changed"
    || value === "check_result"
    || value === "assumption_made"
    || value === "blocker_found"
    || value === "approval_requested"
    || value === "decision_made"
    || value === "step_completed"
    || value === "goal_completed";
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}
