import { randomUUID } from "node:crypto";
import type { SlackActor } from "../auth.js";
import type { CerebroClient } from "../cerebro/client.js";
import type { AppConfig } from "../config/index.js";
import { redactSecurityText } from "../security/redaction.js";
import { inferAutonomyCapability } from "./capabilities.js";
import { autonomyExecutionContractFromControlPlane, localAutonomyExecutionContract } from "./execution-contract.js";
import {
  createAutonomyGoalStore,
  type AutonomyGoalLedgerEvent,
  type AutonomyApprovalRecord,
  type AutonomyCapabilityId,
  type AutonomyExecutionContract,
  type AutonomyGoalStatus,
  type AutonomyGoalStore,
  type AutonomyPlanStep,
  type AutonomyToolRunRecord,
  type AutonomousGoalRecord,
  type UpdateAutonomyGoalInput,
} from "./goals.js";
import { defaultAutonomyPlan } from "./plans.js";
import { compileSecurityMission, missionToolMatches } from "./mission-compiler.js";
import { securityMissionPack } from "./mission-packs.js";
import type { SecurityMissionInputId, SecurityMissionPackId } from "./mission-types.js";
import {
  agentStepExecutionSchema,
  agentArtifactSchema,
  agentCorrectionSchema,
  agentResourceRefsSchema,
  createAgentArtifact,
  mergeResourceRefs,
  sanitizeAgentAcceptanceCriteria,
  type AgentAcceptanceCriterion,
  type AgentArtifact,
  type AgentCompletionReceipt,
  type AgentCorrection,
  type AgentResourceRef,
  type AgentStepExecution,
} from "./agent-run.js";
import type { SecurityCaseContext } from "../security-cases/types.js";

interface CommandSender {
  send(command: unknown): Promise<unknown>;
}

interface AutonomyGoalServiceOptions {
  store?: AutonomyGoalStore;
  dynamo?: CommandSender;
  now?: () => Date;
  cerebro?: Pick<CerebroClient, "getAgentControlPlane">;
}

export interface AutonomyGoalServiceStats {
  enabled: boolean;
  store: "dynamodb" | "memory";
  total: number;
  active: number;
  waiting: number;
  approvalNeeded: number;
  blocked: number;
  paused: number;
  completed: number;
  cancelled: number;
  dueCount: number;
  oldestDueAgeMs: number;
  claimed: number;
  staleClaims: number;
}

export class AutonomyGoalService {
  private readonly store: AutonomyGoalStore;
  private readonly now: () => Date;
  private readonly cerebro?: Pick<CerebroClient, "getAgentControlPlane">;

  constructor(
    private readonly config: AppConfig,
    options: AutonomyGoalServiceOptions = {},
  ) {
    this.now = options.now ?? (() => new Date());
    this.cerebro = options.cerebro;
    this.store = options.store ?? createAutonomyGoalStore(config, { dynamo: options.dynamo, now: options.now });
  }

  async createFromText(input: {
    text: string;
    actor: SlackActor;
    channelId?: string;
    threadTs?: string;
    missionPackId?: SecurityMissionPackId;
    missionBindings?: Partial<Record<SecurityMissionInputId, string>>;
    resourceRefs?: AgentResourceRef[];
    acceptanceCriteria?: AgentAcceptanceCriterion[];
    assumptions?: string[];
  }): Promise<AutonomousGoalRecord> {
    this.assertEnabled();
    const now = this.now().toISOString();
    const resourceRefs = agentResourceRefsSchema.parse(input.resourceRefs ?? []);
    const mission = compileSecurityMission({
      objective: input.text,
      requestedPackId: input.missionPackId,
      bindings: input.missionBindings,
      resourceRefs,
      now: new Date(now),
    });
    const capabilityId = mission?.pack.capabilityId ?? inferAutonomyCapability(input.text);
    const executionContract = await this.executionContractFor(capabilityId, now);
    return this.store.create({
      objective: input.text,
      capabilityId,
      channelId: input.channelId,
      threadTs: input.threadTs,
      createdBy: input.actor,
      nextWakeAt: now,
      plan: mission?.plan ?? defaultAutonomyPlan(capabilityId),
      executionContract,
      mission: mission?.receipt,
      resourceRefs,
      acceptanceCriteria: mergeAcceptanceCriteria(mission?.acceptanceCriteria ?? [], input.acceptanceCriteria ?? []),
      assumptions: input.assumptions,
    });
  }

  async createFromPlan(input: {
    objective: string;
    actor: SlackActor;
    channelId?: string;
    threadTs?: string;
    capabilityId?: AutonomyCapabilityId;
    plan: AutonomyPlanStep[];
    resourceRefs?: AgentResourceRef[];
    acceptanceCriteria?: AgentAcceptanceCriterion[];
    assumptions?: string[];
    securityCase?: SecurityCaseContext;
  }): Promise<AutonomousGoalRecord> {
    this.assertEnabled();
    const now = this.now().toISOString();
    const resourceRefs = agentResourceRefsSchema.parse(input.resourceRefs ?? []);
    const capabilityId = input.capabilityId ?? inferAutonomyCapability(input.objective);
    return this.store.create({
      objective: input.objective,
      capabilityId,
      channelId: input.channelId,
      threadTs: input.threadTs,
      createdBy: input.actor,
      nextWakeAt: now,
      plan: input.plan,
      assumptions: input.assumptions,
      executionContract: await this.executionContractFor(capabilityId, now),
      resourceRefs,
      acceptanceCriteria: sanitizeAgentAcceptanceCriteria(input.acceptanceCriteria ?? []),
      securityCase: input.securityCase,
    });
  }

  async list(status?: AutonomyGoalStatus): Promise<AutonomousGoalRecord[]> {
    this.assertEnabled();
    return (await this.store.list(status)).slice(0, this.config.autonomy.maxListedGoals);
  }

  async due(now: Date = new Date()): Promise<AutonomousGoalRecord[]> {
    this.assertEnabled();
    return this.store.listDue(now, this.config.autonomy.maxListedGoals);
  }

  async listEvents(goalId: string, limit = 100): Promise<AutonomyGoalLedgerEvent[]> {
    this.assertEnabled();
    return this.store.listEvents(goalId, limit);
  }

  async stats(): Promise<AutonomyGoalServiceStats> {
    if (!this.config.autonomy.goalsEnabled) {
      return emptyStats(false, this.goalStoreMode());
    }
    const now = this.now();
    const goals = await this.store.list();
    const dueAges = goals
      .filter((goal) => goal.status === "active")
      .map((goal) => goal.nextWakeAt ? now.getTime() - Date.parse(goal.nextWakeAt) : 0)
      .filter((age) => Number.isFinite(age) && age >= 0);
    return {
      enabled: true,
      store: this.goalStoreMode(),
      total: goals.length,
      active: goals.filter((goal) => goal.status === "active").length,
      waiting: goals.filter((goal) => goal.status === "waiting").length,
      approvalNeeded: goals.filter((goal) => goal.status === "approval_needed").length,
      blocked: goals.filter((goal) => goal.status === "blocked").length,
      paused: goals.filter((goal) => goal.status === "paused").length,
      completed: goals.filter((goal) => goal.status === "completed").length,
      cancelled: goals.filter((goal) => goal.status === "cancelled").length,
      dueCount: dueAges.length,
      oldestDueAgeMs: dueAges.length > 0 ? Math.max(...dueAges) : 0,
      claimed: goals.filter((goal) => Boolean(goal.claim)).length,
      staleClaims: goals.filter((goal) => goal.claim && Date.parse(goal.claim.leaseExpiresAt) <= now.getTime()).length,
    };
  }

  async get(goalId: string): Promise<AutonomousGoalRecord | undefined> {
    this.assertEnabled();
    return this.store.get(goalId);
  }

  async revision(goalId: string): Promise<number | undefined> {
    this.assertEnabled();
    return this.store.getRevision(goalId);
  }

  async setStatus(input: {
    goalId: string;
    status: AutonomyGoalStatus;
    actor: SlackActor;
    reason?: string;
  }): Promise<AutonomousGoalRecord> {
    this.assertEnabled();
    const goal = await this.requiredGoal(input.goalId);
    const updated = await this.store.update(goal.id, {
      status: input.status,
      completionSummary: input.status === "completed" ? input.reason : undefined,
    });
    return this.store.appendLog(updated.id, {
      kind: input.status === "completed" ? "goal_completed" : "decision_made",
      summary: `${statusVerb(input.status)} by ${actorLabel(input.actor)}.`,
      details: input.reason,
    });
  }

  async update(goalId: string, input: UpdateAutonomyGoalInput): Promise<AutonomousGoalRecord> {
    this.assertEnabled();
    return this.store.update(goalId, input);
  }

  async appendLog(goalId: string, entry: Parameters<AutonomyGoalStore["appendLog"]>[1]): Promise<AutonomousGoalRecord> {
    this.assertEnabled();
    return this.store.appendLog(goalId, entry);
  }

  async claim(goalId: string, workerId: string, leaseMs: number, expectedRevision?: number): Promise<AutonomousGoalRecord | undefined> {
    this.assertEnabled();
    return this.store.tryClaim(goalId, {
      workerId,
      leaseExpiresAt: new Date(this.now().getTime() + leaseMs).toISOString(),
      expectedRevision,
    });
  }

  async release(goalId: string, workerId: string): Promise<AutonomousGoalRecord> {
    this.assertEnabled();
    return this.store.releaseClaim(goalId, workerId);
  }

  async replacePlan(goalId: string, plan: AutonomyPlanStep[], activeStepId?: string): Promise<AutonomousGoalRecord> {
    this.assertEnabled();
    const updated = await this.store.update(goalId, { currentPlan: plan, activeStepId });
    return this.store.appendLog(updated.id, {
      kind: "plan_updated",
      summary: `Plan updated with ${plan.length} step(s).`,
    });
  }

  async bindMissionStep(input: {
    goalId: string;
    stepId: string;
    execution: AgentStepExecution;
    toolMetadata: { name: string; family: string; authority: string };
    acceptanceCriteriaIds?: string[];
    missionBindings?: Partial<Record<SecurityMissionInputId, string>>;
  }): Promise<AutonomousGoalRecord> {
    this.assertEnabled();
    const goal = await this.requiredGoal(input.goalId);
    if (!goal.mission) throw new Error(`Goal ${goal.id} is not a compiled security mission.`);
    const step = goal.currentPlan.find((candidate) => candidate.id === input.stepId);
    if (!step?.mission) throw new Error(`No mission step matched ${input.stepId}.`);
    if (step.mission.bindingState === "operator_decision") throw new Error(`Mission step ${step.id} requires a recorded decision, not a tool binding.`);
    const execution = agentStepExecutionSchema.parse(input.execution);
    if (input.toolMetadata.name !== execution.toolName || !missionToolMatches(step.mission.toolSelector, input.toolMetadata)) {
      throw new Error(`Tool ${execution.toolName} is outside the selector for mission step ${step.id}.`);
    }
    const mergedBindings = new Map(goal.mission.bindings.map((binding) => [binding.id, binding]));
    const allowedBindingIds = new Set(securityMissionPack(goal.mission.packId).inputs.map((definition) => definition.id));
    for (const [id, value] of Object.entries(input.missionBindings ?? {}) as Array<[SecurityMissionInputId, string | undefined]>) {
      if (!allowedBindingIds.has(id)) throw new Error(`Mission pack ${goal.mission.packId} does not accept input ${id}.`);
      if (value?.trim()) {
        const cleaned = value.trim().slice(0, 500);
        if (redactSecurityText(cleaned) !== cleaned) throw new Error(`Mission input ${id} contains secret-like data.`);
        mergedBindings.set(id, { id, value: cleaned, source: "explicit" as const });
      }
    }
    const unresolvedInputs = step.mission.requiredInputIds.filter((id) => !mergedBindings.has(id));
    if (unresolvedInputs.length > 0) throw new Error(`Mission step ${step.id} still needs inputs: ${unresolvedInputs.join(", ")}.`);
    if (step.mission.approvalRequired && !execution.approvalRequired) throw new Error(`Mission step ${step.id} requires reviewed approval.`);
    if (step.mission.verificationRequired && !execution.verificationToolName) throw new Error(`Mission step ${step.id} requires an independent verification tool.`);
    if (step.mission.rollback && !execution.rollback) throw new Error(`Mission step ${step.id} requires a rollback plan.`);
    const acceptanceCriteriaIds = input.acceptanceCriteriaIds ?? step.acceptanceCriteriaIds ?? [];
    const knownCriteria = new Set(goal.acceptanceCriteria.map((criterion) => criterion.id));
    const unknownCriteria = acceptanceCriteriaIds.filter((id) => !knownCriteria.has(id));
    if (unknownCriteria.length > 0) throw new Error(`Mission step ${step.id} has unknown acceptance criteria: ${unknownCriteria.join(", ")}.`);
    if (acceptanceCriteriaIds.length === 0) throw new Error(`Mission step ${step.id} needs at least one acceptance criterion.`);
    const plan = goal.currentPlan.map((candidate): AutonomyPlanStep => candidate.id === step.id ? {
      ...candidate,
      status: "pending",
      summary: "Executable tool bound to mission step.",
      execution,
      acceptanceCriteriaIds: [...acceptanceCriteriaIds],
      mission: { ...candidate.mission!, bindingState: "bound" },
    } : candidate);
    const missingInputIds = goal.mission.missingInputIds.filter((id) => !mergedBindings.has(id));
    const mission = {
      ...goal.mission,
      bindings: [...mergedBindings.values()],
      missingInputIds,
      status: missingInputIds.length > 0
        ? "needs_input" as const
        : plan.some((candidate) => candidate.mission?.bindingState === "needs_tool") ? "needs_tool" as const : "ready" as const,
    };
    const updated = await this.store.update(goal.id, {
      currentPlan: plan,
      activeStepId: null,
      status: "active",
      nextWakeAt: this.now().toISOString(),
      blockers: goal.blockers.filter((blocker) => !blocker.startsWith(missionBlockerPrefix(step.id))),
      mission,
    });
    return this.store.appendLog(updated.id, {
      kind: "plan_updated",
      summary: `Bound ${execution.toolName} to ${step.title}.`,
      details: `Mission: ${goal.mission.packId}@${goal.mission.packVersion}.`,
    });
  }

  async recordMissionDecision(input: {
    goalId: string;
    stepId: string;
    summary: string;
    evidenceRefs: string[];
    approvalId?: string;
  }): Promise<AutonomousGoalRecord> {
    this.assertEnabled();
    const goal = await this.requiredGoal(input.goalId);
    const step = goal.currentPlan.find((candidate) => candidate.id === input.stepId);
    if (!goal.mission || !step?.mission || step.mission.kind !== "decide") throw new Error(`No decision step matched ${input.stepId}.`);
    if (step.status !== "waiting" && step.status !== "active") throw new Error(`Mission decision ${step.id} is not ready.`);
    const completedStepIds = new Set(goal.currentPlan.filter((candidate) => candidate.status === "completed" || candidate.status === "skipped").map((candidate) => candidate.id));
    const incompleteDependencies = step.dependsOn.filter((dependency) => !completedStepIds.has(dependency));
    if (incompleteDependencies.length > 0) throw new Error(`Mission decision ${step.id} is waiting on: ${incompleteDependencies.join(", ")}.`);
    const evidenceRefs = [...new Set(input.evidenceRefs.map((ref) => ref.trim()).filter(Boolean))].slice(0, 24);
    if (evidenceRefs.length === 0) throw new Error(`Mission decision ${step.id} needs at least one evidence reference.`);
    let approvals = goal.approvals;
    if (step.mission.approvalRequired) {
      const approval = goal.approvals.find((candidate) => candidate.stepId === step.id && candidate.status === "approved"
        && (!input.approvalId || candidate.id === input.approvalId || candidate.id.endsWith(input.approvalId)));
      if (!approval) throw new Error(`Mission decision ${step.id} needs reviewed approval.`);
      approvals = goal.approvals.map((candidate) => candidate.id === approval.id
        ? { ...candidate, status: "executed" as const, resultSummary: input.summary }
        : candidate);
      evidenceRefs.push(approval.id);
    }
    const checkedAt = this.now().toISOString();
    const criterionIds = new Set(step.acceptanceCriteriaIds ?? []);
    const acceptanceCriteria = goal.acceptanceCriteria.map((criterion) => criterionIds.has(criterion.id) ? {
      ...criterion,
      status: "passed" as const,
      checkedAt,
      result: input.summary,
      evidenceRefs: [...new Set([...criterion.evidenceRefs, ...evidenceRefs])].slice(0, 24),
    } : criterion);
    const currentPlan = goal.currentPlan.map((candidate): AutonomyPlanStep => candidate.id === step.id
      ? { ...candidate, status: "completed", summary: input.summary }
      : candidate);
    const hasPending = currentPlan.some((candidate) => candidate.status === "pending");
    const updated = await this.store.update(goal.id, {
      currentPlan,
      acceptanceCriteria,
      approvals,
      activeStepId: null,
      status: hasPending ? "active" : "waiting",
      nextWakeAt: hasPending ? checkedAt : null,
      blockers: goal.blockers.filter((blocker) => !blocker.startsWith(missionBlockerPrefix(step.id))),
    });
    return this.store.appendLog(updated.id, {
      kind: "decision_made",
      summary: input.summary,
      details: `Mission step: ${step.id}; evidence: ${evidenceRefs.join(", ")}.`,
    });
  }

  async appendToolRun(goalId: string, run: Omit<AutonomyToolRunRecord, "id">): Promise<AutonomousGoalRecord> {
    this.assertEnabled();
    const goal = await this.requiredGoal(goalId);
    const record: AutonomyToolRunRecord = {
      id: `toolrun-${randomUUID()}`,
      ...run,
    };
    const updated = await this.store.update(goal.id, {
      toolRuns: [...goal.toolRuns, record],
    });
    return this.store.appendLog(updated.id, {
      kind: record.status === "failed" ? "blocker_found" : record.status === "approval_requested" ? "approval_requested" : "tool_called",
      summary: `${record.toolName || record.toolId}: ${record.status}.`,
      details: record.responseSummary ?? record.error ?? record.reason,
      artifactUrl: record.artifactUrl,
    });
  }

  async appendResourceRefs(goalId: string, additions: AgentResourceRef[]): Promise<AutonomousGoalRecord> {
    this.assertEnabled();
    const goal = await this.requiredGoal(goalId);
    return this.store.update(goal.id, {
      resourceRefs: mergeResourceRefs(goal.resourceRefs, agentResourceRefsSchema.parse(additions)),
    });
  }

  async appendArtifact(goalId: string, artifact: Omit<AgentArtifact, "id" | "createdAt"> | AgentArtifact): Promise<AutonomousGoalRecord> {
    this.assertEnabled();
    const goal = await this.requiredGoal(goalId);
    const parsed = "id" in artifact
      ? agentArtifactSchema.parse(artifact)
      : createAgentArtifact(artifact, this.now());
    const artifacts = [...goal.artifacts.filter((item) => item.id !== parsed.id), parsed].slice(-80);
    const urls = [...new Set([...goal.artifactUrls, parsed.url].filter((value): value is string => Boolean(value)))].slice(-80);
    const updated = await this.store.update(goal.id, { artifacts, artifactUrls: urls });
    return this.store.appendLog(updated.id, {
      kind: "artifact_changed",
      summary: `Artifact recorded: ${parsed.title}.`,
      artifactUrl: parsed.url,
    });
  }

  async updateAcceptanceCriteria(goalId: string, criteria: AgentAcceptanceCriterion[]): Promise<AutonomousGoalRecord> {
    this.assertEnabled();
    return this.store.update(goalId, { acceptanceCriteria: sanitizeAgentAcceptanceCriteria(criteria) });
  }

  async appendCorrection(goalId: string, correction: AgentCorrection): Promise<AutonomousGoalRecord> {
    this.assertEnabled();
    const goal = await this.requiredGoal(goalId);
    const parsed = agentCorrectionSchema.parse(correction);
    const updated = await this.store.update(goal.id, { corrections: [...goal.corrections, parsed].slice(-40) });
    return this.store.appendLog(updated.id, {
      kind: "decision_made",
      summary: `Correction recorded: ${parsed.replacement}`,
      details: parsed.reason,
    });
  }

  async recordCompletionReceipt(goalId: string, receipt: AgentCompletionReceipt): Promise<AutonomousGoalRecord> {
    this.assertEnabled();
    const updated = await this.store.update(goalId, {
      completionReceipt: receipt,
      completionSummary: receipt.summary,
      status: receipt.status === "complete" ? "completed" : receipt.status === "blocked" ? "blocked" : "waiting",
      nextWakeAt: null,
    });
    return this.store.appendLog(updated.id, {
      kind: receipt.status === "complete" ? "goal_completed" : "check_result",
      summary: receipt.summary,
      details: `Verifier: ${receipt.verifier}; passed: ${receipt.criteriaPassed.length}; failed: ${receipt.criteriaFailed.length}.`,
    });
  }

  async requestApproval(goalId: string, approval: Omit<AutonomyApprovalRecord, "id" | "status" | "createdAt">): Promise<AutonomousGoalRecord> {
    this.assertEnabled();
    const goal = await this.requiredGoal(goalId);
    const now = this.now().toISOString();
    const record: AutonomyApprovalRecord = {
      id: `approval-${randomUUID()}`,
      status: "pending",
      createdAt: now,
      ...approval,
    };
    const updated = await this.store.update(goal.id, {
      status: "approval_needed",
      approvals: [...goal.approvals, record],
      nextWakeAt: null,
    });
    return this.store.appendLog(updated.id, {
      kind: "approval_requested",
      summary: `Approval requested: ${record.actionSummary}.`,
      details: record.reason,
    });
  }

  async decideApproval(input: {
    goalId: string;
    approvalId: string;
    decision: "approved" | "rejected";
    actor: SlackActor;
  }): Promise<AutonomousGoalRecord> {
    this.assertEnabled();
    const goal = await this.requiredGoal(input.goalId);
    const index = goal.approvals.findIndex((approval) => approval.id === input.approvalId || approval.id.endsWith(input.approvalId));
    if (index < 0) throw new Error(`No approval matched ${input.approvalId}.`);
    const approval = goal.approvals[index]!;
    if (approval.status !== "pending") throw new Error(`Approval ${approval.id} is already ${approval.status}.`);
    const decided: AutonomyApprovalRecord = {
      ...approval,
      status: input.decision,
      decidedAt: this.now().toISOString(),
      decidedBy: input.actor,
    };
    const approvals = [...goal.approvals];
    approvals[index] = decided;
    const updated = await this.store.update(goal.id, {
      approvals,
      status: input.decision === "approved" ? "active" : "blocked",
      blockers: input.decision === "rejected" ? [...goal.blockers, `Approval rejected: ${approval.actionSummary}`] : goal.blockers,
      nextWakeAt: input.decision === "approved" ? this.now().toISOString() : null,
    });
    return this.store.appendLog(updated.id, {
      kind: "decision_made",
      summary: `${input.decision === "approved" ? "Approved" : "Rejected"} ${approval.actionSummary} by ${actorLabel(input.actor)}.`,
      details: approval.reason,
    });
  }

  private async requiredGoal(goalId: string): Promise<AutonomousGoalRecord> {
    const goal = await this.store.get(goalId);
    if (!goal) throw new Error(`No autonomy goal matched ${goalId}.`);
    return goal;
  }

  private assertEnabled(): void {
    if (!this.config.autonomy.goalsEnabled) {
      throw new Error("Autonomy goals are disabled.");
    }
  }

  private goalStoreMode(): "dynamodb" | "memory" {
    return this.config.autonomy.goalsTableName || this.config.learning.tableName ? "dynamodb" : "memory";
  }

  private async executionContractFor(capabilityId: AutonomyCapabilityId, selectedAt: string): Promise<AutonomyExecutionContract> {
    if (!this.cerebro) return localAutonomyExecutionContract(capabilityId, selectedAt);
    const controlPlane = await this.cerebro.getAgentControlPlane().catch(() => undefined);
    return controlPlane
      ? autonomyExecutionContractFromControlPlane(capabilityId, controlPlane, selectedAt)
      : localAutonomyExecutionContract(capabilityId, selectedAt);
  }
}

export function missionBlockerPrefix(stepId: string): string {
  return `[mission:${stepId}]`;
}

function emptyStats(enabled: boolean, store: "dynamodb" | "memory"): AutonomyGoalServiceStats {
  return {
    enabled,
    store,
    total: 0,
    active: 0,
    waiting: 0,
    approvalNeeded: 0,
    blocked: 0,
    paused: 0,
    completed: 0,
    cancelled: 0,
    dueCount: 0,
    oldestDueAgeMs: 0,
    claimed: 0,
    staleClaims: 0,
  };
}

function statusVerb(status: AutonomyGoalStatus): string {
  switch (status) {
    case "active":
      return "Resumed";
    case "paused":
      return "Paused";
    case "cancelled":
      return "Cancelled";
    case "completed":
      return "Completed";
    case "blocked":
      return "Marked blocked";
    case "waiting":
      return "Marked waiting";
    case "approval_needed":
      return "Marked approval needed";
  }
}

function actorLabel(actor: SlackActor): string {
  return actor.displayName || actor.actorId || actor.slackUserId || "operator";
}

function mergeAcceptanceCriteria(primary: AgentAcceptanceCriterion[], additions: AgentAcceptanceCriterion[]): AgentAcceptanceCriterion[] {
  const byId = new Map(primary.map((criterion) => [criterion.id, criterion]));
  for (const criterion of additions) byId.set(criterion.id, criterion);
  return [...byId.values()].slice(0, 80);
}
