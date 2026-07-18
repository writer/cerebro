import { z } from "zod";
import type { AppConfig } from "../config/index.js";
import type { AutonomyGoalLedgerEvent, AutonomousGoalRecord } from "./goal-types.js";
import { missionShard } from "./goal-store-dynamo-model.js";

export const MISSION_WORK_INDEX = "mission-work-index";
export const MISSION_TASK_SCHEMA_VERSION = "2026-07-16.1";

const autonomyCapabilityIdSchema = z.enum([
  "triage",
  "investigation",
  "planner",
  "executor",
  "remediation",
  "identity_response",
  "detection_response",
  "self_repair",
]);

export const missionTaskEnvelopeSchema = z.object({
  schemaVersion: z.literal(MISSION_TASK_SCHEMA_VERSION),
  taskId: z.string().trim().min(1).max(240),
  tenantId: z.string().trim().min(1).max(160),
  goalId: z.string().trim().startsWith("goal-").max(200),
  revision: z.number().int().positive(),
  capabilityId: autonomyCapabilityIdSchema,
  stepId: z.string().trim().min(1).max(200).optional(),
  availableAt: z.string().datetime(),
  enqueuedAt: z.string().datetime(),
  execution: z.object({
    contractVersion: z.string().trim().min(1).max(120).optional(),
    profileId: z.string().trim().min(1).max(160).optional(),
    missionPackId: z.string().trim().min(1).max(160).optional(),
    missionPackVersion: z.string().trim().min(1).max(120).optional(),
    compilerVersion: z.string().trim().min(1).max(120).optional(),
    planDigest: z.string().trim().min(1).max(160).optional(),
  }).optional(),
}).strict();

export type MissionTaskEnvelope = z.infer<typeof missionTaskEnvelopeSchema>;

export interface MissionWorkOutboxRecord {
  pk: string;
  sk: string;
  task: MissionTaskEnvelope;
}

export function missionWorkOutboxItem(
  config: AppConfig,
  goal: AutonomousGoalRecord,
  event: AutonomyGoalLedgerEvent,
  revision: number,
): Record<string, unknown> | undefined {
  if (!shouldEnqueueMissionWork(goal, event)) return undefined;
  const task = createMissionTaskEnvelope(config, goal, event.occurredAt, revision);
  const key = missionWorkOutboxKey(config, goal.id, revision);
  return {
    ...key,
    record_type: "autonomy_mission_work_v1",
    mission_work_scope: missionWorkScope(config, Number(missionShard(goal.id))),
    mission_work_available_at: missionWorkSortKey(task),
    publication_attempts: 0,
    task,
  };
}

export function missionWorkOutboxFromItem(item: Record<string, unknown>): MissionWorkOutboxRecord | undefined {
  if (
    item.record_type !== "autonomy_mission_work_v1"
    || typeof item.pk !== "string"
    || typeof item.sk !== "string"
  ) return undefined;
  const task = missionTaskEnvelopeSchema.safeParse(item.task);
  return task.success ? { pk: item.pk, sk: item.sk, task: task.data } : undefined;
}

export function missionWorkOutboxKey(config: AppConfig, goalId: string, revision: number): { pk: string; sk: string } {
  return {
    pk: `tenant#${config.cerebro.tenantId}#mission#${goalId}`,
    sk: `work#${formatRevision(revision)}`,
  };
}

export function missionWorkScope(config: AppConfig, shard: number): string {
  return `tenant#${config.cerebro.tenantId}#mission-work#shard#${String(shard).padStart(2, "0")}`;
}

export function missionWorkSortKey(task: MissionTaskEnvelope, availableAt = task.availableAt): string {
  return `${availableAt}#${task.goalId}#${formatRevision(task.revision)}`;
}

function createMissionTaskEnvelope(
  config: AppConfig,
  goal: AutonomousGoalRecord,
  enqueuedAt: string,
  revision: number,
): MissionTaskEnvelope {
  const availableAt = validIso(goal.nextWakeAt) ?? validIso(goal.updatedAt) ?? enqueuedAt;
  const stepId = goal.activeStepId ?? goal.currentPlan.find((step) => step.status === "active" || step.status === "pending")?.id;
  const execution = compactExecution({
    contractVersion: goal.executionContract?.version,
    profileId: goal.executionContract?.profileId,
    missionPackId: goal.mission?.packId,
    missionPackVersion: goal.mission?.packVersion,
    compilerVersion: goal.mission?.compilerVersion,
    planDigest: goal.mission?.planDigest,
  });
  return missionTaskEnvelopeSchema.parse({
    schemaVersion: MISSION_TASK_SCHEMA_VERSION,
    taskId: `${goal.id}:${revision}`,
    tenantId: config.cerebro.tenantId,
    goalId: goal.id,
    revision,
    capabilityId: goal.capabilityId,
    stepId,
    availableAt,
    enqueuedAt,
    execution,
  });
}

function shouldEnqueueMissionWork(goal: AutonomousGoalRecord, event: AutonomyGoalLedgerEvent): boolean {
  if (goal.status !== "active") return false;
  if (event.type === "goal_created") return true;
  if (event.type === "claim_released") return true;
  if (event.type !== "goal_updated") return false;
  const schedulingFields = new Set(["status", "currentPlan", "activeStepId", "nextWakeAt", "approvals", "executionContract", "mission"]);
  return event.changedFields?.some((field) => schedulingFields.has(field)) ?? false;
}

function compactExecution(value: NonNullable<MissionTaskEnvelope["execution"]>): MissionTaskEnvelope["execution"] {
  const entries = Object.entries(value).filter(([, item]) => item !== undefined);
  return entries.length > 0 ? Object.fromEntries(entries) : undefined;
}

function formatRevision(revision: number): string {
  return String(revision).padStart(16, "0");
}

function validIso(value: string | undefined): string | undefined {
  return value && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : undefined;
}
