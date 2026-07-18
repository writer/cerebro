import { z } from "zod";
import { redactSecurityText } from "../security/redaction.js";

export type TeammateCommitmentStatus = "planned" | "in_progress" | "completed" | "blocked" | "cancelled";
export type TeammateGoalStatus = "active" | "waiting" | "approval_needed" | "blocked" | "paused" | "completed" | "cancelled";
export type TeammateWorkOwner = "cerebro" | "user" | "external";

export interface TeammateCommitment {
  id: string;
  summary: string;
  status: TeammateCommitmentStatus;
  nextAction?: string;
  blocker?: string;
  artifactRefs: string[];
  goalId?: string;
  goalStatus?: TeammateGoalStatus;
  acceptanceCriteria?: string[];
  nextWakeAt?: string;
  verification?: string;
}

export interface TeammateOpenLoop {
  id: string;
  summary: string;
  owner: TeammateWorkOwner;
  nextAction?: string;
  blockedBy?: string;
}

export interface TeammateDecisionRequest {
  required: boolean;
  question?: string;
  reason?: string;
}

export interface AssistantTeammateUpdate {
  objective?: string;
  desiredOutcome?: string;
  resolvedScope: string[];
  scopeAssumptions: string[];
  commitments: TeammateCommitment[];
  openLoops: TeammateOpenLoop[];
  userDecision?: TeammateDecisionRequest;
}

export interface AssistantTeammateState extends AssistantTeammateUpdate {
  updatedAt?: string;
}

const rawCommitmentSchema = z.object({
  id: z.string(),
  summary: z.string(),
  status: z.enum(["planned", "in_progress", "completed", "blocked", "cancelled"]),
  next_action: z.string().optional(),
  nextAction: z.string().optional(),
  blocker: z.string().optional(),
  artifact_refs: z.array(z.string()).default([]),
  artifactRefs: z.array(z.string()).default([]),
  goal_id: z.string().optional(),
  goalId: z.string().optional(),
  goal_status: z.enum(["active", "waiting", "approval_needed", "blocked", "paused", "completed", "cancelled"]).optional(),
  goalStatus: z.enum(["active", "waiting", "approval_needed", "blocked", "paused", "completed", "cancelled"]).optional(),
  acceptance_criteria: z.array(z.string()).default([]),
  acceptanceCriteria: z.array(z.string()).default([]),
  next_wake_at: z.string().optional(),
  nextWakeAt: z.string().optional(),
  verification: z.string().optional(),
});

const rawOpenLoopSchema = z.object({
  id: z.string(),
  summary: z.string(),
  owner: z.enum(["cerebro", "user", "external"]),
  next_action: z.string().optional(),
  nextAction: z.string().optional(),
  blocked_by: z.string().optional(),
  blockedBy: z.string().optional(),
});

const rawDecisionSchema = z.object({
  required: z.boolean(),
  question: z.string().optional(),
  reason: z.string().optional(),
});

const rawTeammateUpdateSchema = z.object({
  objective: z.string().optional(),
  desired_outcome: z.string().optional(),
  desiredOutcome: z.string().optional(),
  resolved_scope: z.array(z.string()).default([]),
  resolvedScope: z.array(z.string()).default([]),
  scope_assumptions: z.array(z.string()).default([]),
  scopeAssumptions: z.array(z.string()).default([]),
  commitments: z.array(rawCommitmentSchema).default([]),
  open_loops: z.array(rawOpenLoopSchema).default([]),
  openLoops: z.array(rawOpenLoopSchema).default([]),
  user_decision: rawDecisionSchema.optional(),
  userDecision: rawDecisionSchema.optional(),
  updated_at: z.string().optional(),
  updatedAt: z.string().optional(),
});

export function parseAssistantTeammateUpdate(value: unknown): AssistantTeammateUpdate | undefined {
  const parsed = rawTeammateUpdateSchema.safeParse(value);
  if (!parsed.success) return undefined;
  const data = parsed.data;
  const commitments = data.commitments.flatMap((item) => {
    const id = cleanId(item.id);
    const summary = cleanText(item.summary, 500);
    if (!id || !summary) return [];
    const nextAction = cleanText(item.next_action ?? item.nextAction, 500) || undefined;
    const blocker = cleanText(item.blocker, 500) || undefined;
    return [{
      id,
      summary,
      status: item.status,
      nextAction,
      blocker,
      artifactRefs: unique([...(item.artifact_refs ?? []), ...(item.artifactRefs ?? [])], 12, 320),
      goalId: cleanId(item.goal_id ?? item.goalId ?? "") || undefined,
      goalStatus: item.goal_status ?? item.goalStatus,
      acceptanceCriteria: unique([...(item.acceptance_criteria ?? []), ...(item.acceptanceCriteria ?? [])], 24, 500),
      nextWakeAt: cleanText(item.next_wake_at ?? item.nextWakeAt, 80) || undefined,
      verification: cleanText(item.verification, 500) || undefined,
    }];
  }).slice(0, 16);
  const rawOpenLoops = data.open_loops.length > 0 ? data.open_loops : data.openLoops;
  const openLoops = rawOpenLoops.flatMap((item) => {
    const id = cleanId(item.id);
    const summary = cleanText(item.summary, 500);
    if (!id || !summary) return [];
    return [{
      id,
      summary,
      owner: item.owner,
      nextAction: cleanText(item.next_action ?? item.nextAction, 500) || undefined,
      blockedBy: cleanText(item.blocked_by ?? item.blockedBy, 500) || undefined,
    }];
  }).slice(0, 16);
  const rawDecision = data.user_decision ?? data.userDecision;
  const userDecision = rawDecision ? {
    required: rawDecision.required,
    question: cleanText(rawDecision.question, 500) || undefined,
    reason: cleanText(rawDecision.reason, 500) || undefined,
  } : { required: false };
  return {
    objective: cleanText(data.objective, 800) || undefined,
    desiredOutcome: cleanText(data.desired_outcome ?? data.desiredOutcome, 800) || undefined,
    resolvedScope: unique(data.resolved_scope.length > 0 ? data.resolved_scope : data.resolvedScope, 24, 500),
    scopeAssumptions: unique(data.scope_assumptions.length > 0 ? data.scope_assumptions : data.scopeAssumptions, 12, 500),
    commitments,
    openLoops,
    userDecision,
  };
}

export function parseAssistantTeammateState(value: unknown): AssistantTeammateState | undefined {
  const update = parseAssistantTeammateUpdate(value);
  const parsed = rawTeammateUpdateSchema.safeParse(value);
  if (!update || !parsed.success) return undefined;
  return {
    ...update,
    updatedAt: cleanText(parsed.data.updated_at ?? parsed.data.updatedAt, 80) || undefined,
  };
}

export function emptyAssistantTeammateState(): AssistantTeammateState {
  return { resolvedScope: [], scopeAssumptions: [], commitments: [], openLoops: [] };
}

export function mergeAssistantTeammateState(
  current: AssistantTeammateState | undefined,
  update: AssistantTeammateUpdate | undefined,
  fallbackObjective: string | undefined,
  updatedAt: string,
): AssistantTeammateState {
  const base = current ?? emptyAssistantTeammateState();
  if (!update) {
    return {
      ...base,
      objective: base.objective ?? (cleanText(fallbackObjective, 800) || undefined),
      updatedAt,
    };
  }
  const commitments = mergeById(base.commitments, update.commitments, 16);
  const closedIds = new Set(commitments
    .filter((item) => item.status === "completed" || item.status === "cancelled")
    .map((item) => item.id));
  return {
    objective: update.objective ?? base.objective ?? (cleanText(fallbackObjective, 800) || undefined),
    desiredOutcome: update.desiredOutcome ?? base.desiredOutcome,
    resolvedScope: unique([...update.resolvedScope, ...base.resolvedScope], 24, 500),
    scopeAssumptions: unique([...update.scopeAssumptions, ...base.scopeAssumptions], 12, 500),
    commitments,
    openLoops: mergeById(base.openLoops, update.openLoops, 16).filter((item) => !closedIds.has(item.id)),
    userDecision: update.userDecision ?? base.userDecision,
    updatedAt,
  };
}

export function teammateStatePromptValue(state: AssistantTeammateState): Record<string, unknown> {
  return {
    objective: state.objective,
    desired_outcome: state.desiredOutcome,
    resolved_scope: state.resolvedScope,
    scope_assumptions: state.scopeAssumptions,
    commitments: state.commitments.map((item) => ({
      id: item.id,
      summary: item.summary,
      status: item.status,
      next_action: item.nextAction,
      blocker: item.blocker,
      artifact_refs: item.artifactRefs,
      goal_id: item.goalId,
      goal_status: item.goalStatus,
      acceptance_criteria: item.acceptanceCriteria ?? [],
      next_wake_at: item.nextWakeAt,
      verification: item.verification,
    })),
    open_loops: state.openLoops.map((item) => ({
      id: item.id,
      summary: item.summary,
      owner: item.owner,
      next_action: item.nextAction,
      blocked_by: item.blockedBy,
    })),
    user_decision: state.userDecision,
  };
}

function mergeById<T extends { id: string }>(current: T[], updates: T[], limit: number): T[] {
  const merged = new Map(current.map((item) => [item.id, item]));
  for (const item of updates) merged.set(item.id, item);
  return [...updates.map((item) => item.id), ...current.map((item) => item.id)]
    .filter((id, index, values) => values.indexOf(id) === index)
    .flatMap((id) => merged.get(id) ?? [])
    .slice(0, limit);
}

function cleanId(value: string): string {
  return value.replace(/[^A-Za-z0-9_.:-]/g, "").slice(0, 160);
}

function cleanText(value: unknown, max: number): string {
  return typeof value === "string" ? redactSecurityText(value).replace(/\s+/g, " ").trim().slice(0, max) : "";
}

function unique(values: string[], limit: number, max: number): string[] {
  return [...new Set(values.map((value) => cleanText(value, max)).filter(Boolean))].slice(0, limit);
}
