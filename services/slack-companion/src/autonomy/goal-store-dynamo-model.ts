import { compactGoalProjection, cloneGoalLedgerEvent } from "./goal-ledger.js";
import { isAutonomousGoalRecord, toAutonomousGoalRecord } from "./goal-codec.js";
import type { AppConfig } from "../config/index.js";
import type { AutonomyGoalLedgerEvent, AutonomousGoalRecord } from "./goal-types.js";

export const MISSION_DUE_INDEX = "mission-due-index";
export const MISSION_RECENT_INDEX = "mission-recent-index";
export const MISSION_STATUS_INDEX = "mission-status-index";
export const MISSION_INDEX_SHARDS = 16;

export interface StoredAutonomyGoal {
  goal: AutonomousGoalRecord;
  revision: number;
  source: "mission_v2" | "legacy";
}

export function missionSnapshotKey(config: AppConfig, goalId: string): { pk: string; sk: string } {
  return { pk: missionPartitionKey(config, goalId), sk: "snapshot" };
}

export function missionLookupPartitionKey(config: AppConfig, shortId: string): string {
  return `tenant#${config.cerebro.tenantId}#mission-lookup#${shortId}`;
}

export function missionSnapshotItem(config: AppConfig, goal: AutonomousGoalRecord, revision: number): Record<string, unknown> {
  const projected = compactGoalProjection(goal);
  const shard = missionShard(goal.id);
  const item: Record<string, unknown> = {
    ...missionSnapshotKey(config, goal.id),
    record_type: "autonomy_mission_snapshot_v2",
    revision,
    mission_recent_scope: `tenant#${config.cerebro.tenantId}#shard#${shard}`,
    mission_status_scope: `tenant#${config.cerebro.tenantId}#status#${goal.status}#shard#${shard}`,
    mission_updated_at: `${goal.updatedAt}#${goal.id}`,
    ...projected,
  };
  if (goal.status === "active") {
    item.mission_due_scope = `tenant#${config.cerebro.tenantId}#shard#${shard}`;
    item.mission_due_at = `${validIso(goal.nextWakeAt) ?? goal.updatedAt}#${goal.id}`;
  }
  return withoutUndefinedValues(item);
}

export function missionLookupItem(config: AppConfig, goalId: string): Record<string, unknown> {
  return {
    pk: missionLookupPartitionKey(config, shortGoalId(goalId)),
    sk: `goal#${goalId}`,
    record_type: "autonomy_mission_lookup_v2",
    goal_id: goalId,
  };
}

export function missionEventItem(config: AppConfig, event: AutonomyGoalLedgerEvent): Record<string, unknown> {
  return withoutUndefinedValues({
    pk: missionPartitionKey(config, event.goalId),
    sk: `event#${String(event.revision).padStart(16, "0")}#${event.id}`,
    record_type: "autonomy_mission_event_v2",
    ...cloneGoalLedgerEvent(event),
  });
}

export function storedGoalFromItem(item: Record<string, unknown> | undefined, source: StoredAutonomyGoal["source"]): StoredAutonomyGoal | undefined {
  if (!item) return undefined;
  const goal = toAutonomousGoalRecord(item);
  if (!isAutonomousGoalRecord(goal)) return undefined;
  return {
    goal: compactGoalProjection(goal),
    revision: source === "mission_v2" && Number.isInteger(item.revision) ? Number(item.revision) : 0,
    source,
  };
}

export function goalLedgerEventFromItem(item: Record<string, unknown>): AutonomyGoalLedgerEvent | undefined {
  if (
    item.record_type !== "autonomy_mission_event_v2"
    || typeof item.id !== "string"
    || typeof item.goalId !== "string"
    || !isEventType(item.type)
    || typeof item.occurredAt !== "string"
    || !Number.isInteger(item.revision)
  ) return undefined;
  return cloneGoalLedgerEvent({
    id: item.id,
    goalId: item.goalId,
    type: item.type,
    occurredAt: item.occurredAt,
    revision: Number(item.revision),
    previousRevision: Number.isInteger(item.previousRevision) ? Number(item.previousRevision) : undefined,
    changedFields: Array.isArray(item.changedFields) ? item.changedFields.map(String) : undefined,
    workLog: isWorkLog(item.workLog) ? { ...item.workLog } : undefined,
    workerId: typeof item.workerId === "string" ? item.workerId : undefined,
  });
}

export function missionRecentScope(config: AppConfig, shard: number): string {
  return `tenant#${config.cerebro.tenantId}#shard#${formatShard(shard)}`;
}

export function missionStatusScope(config: AppConfig, status: string, shard: number): string {
  return `tenant#${config.cerebro.tenantId}#status#${status}#shard#${formatShard(shard)}`;
}

export function legacyGoalPartitionKey(config: AppConfig): string {
  return `tenant#${config.cerebro.tenantId}#autonomy-goals`;
}

export function shortGoalId(goalId: string): string {
  return goalId.slice(-8);
}

export function isFullGoalId(goalId: string): boolean {
  return goalId.startsWith("goal-") && goalId.length > 8;
}

function missionPartitionKey(config: AppConfig, goalId: string): string {
  return `tenant#${config.cerebro.tenantId}#mission#${goalId}`;
}

export function missionShard(goalId: string): string {
  let hash = 2166136261;
  for (const char of goalId) {
    hash ^= char.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return formatShard((hash >>> 0) % MISSION_INDEX_SHARDS);
}

function formatShard(shard: number): string {
  return String(shard).padStart(2, "0");
}

function validIso(value: string | undefined): string | undefined {
  return value && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : undefined;
}

function withoutUndefinedValues<T extends object>(value: T): T {
  return compactValue(value) as T;
}

function compactValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.filter((item) => item !== undefined).map(compactValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value)
      .filter(([, item]) => item !== undefined)
      .map(([key, item]) => [key, compactValue(item)]));
  }
  return value;
}

function isEventType(value: unknown): value is AutonomyGoalLedgerEvent["type"] {
  return value === "goal_created"
    || value === "goal_updated"
    || value === "work_log_appended"
    || value === "claim_acquired"
    || value === "claim_released";
}

function isWorkLog(value: unknown): value is NonNullable<AutonomyGoalLedgerEvent["workLog"]> {
  if (!value || typeof value !== "object") return false;
  const item = value as Record<string, unknown>;
  return typeof item.id === "string"
    && typeof item.kind === "string"
    && typeof item.createdAt === "string"
    && typeof item.summary === "string";
}
