import { randomUUID } from "node:crypto";
import { cloneGoal } from "./goal-codec.js";
import type {
  AutonomyGoalLedgerEvent,
  AutonomyGoalLedgerEventType,
  AutonomyWorkLogEntry,
  AutonomousGoalRecord,
} from "./goal-types.js";

export const AUTONOMY_GOAL_LOG_PROJECTION_LIMIT = 100;

export function compareDueGoals(left: AutonomousGoalRecord, right: AutonomousGoalRecord): number {
  return goalDueAt(left).localeCompare(goalDueAt(right));
}

export function goalDueAt(goal: AutonomousGoalRecord): string {
  return goal.nextWakeAt && Number.isFinite(Date.parse(goal.nextWakeAt))
    ? new Date(goal.nextWakeAt).toISOString()
    : goal.updatedAt;
}

export function compactGoalProjection(goal: AutonomousGoalRecord): AutonomousGoalRecord {
  const compacted = cloneGoal(goal);
  compacted.workLog = compacted.workLog.slice(-AUTONOMY_GOAL_LOG_PROJECTION_LIMIT);
  return compacted;
}

export function createGoalLedgerEvent(input: {
  goalId: string;
  type: AutonomyGoalLedgerEventType;
  occurredAt: string;
  revision: number;
  previousRevision?: number;
  changedFields?: string[];
  workLog?: AutonomyWorkLogEntry;
  workerId?: string;
}): AutonomyGoalLedgerEvent {
  return {
    id: `event-${randomUUID()}`,
    goalId: input.goalId,
    type: input.type,
    occurredAt: input.occurredAt,
    revision: input.revision,
    previousRevision: input.previousRevision,
    changedFields: input.changedFields ? [...input.changedFields].sort() : undefined,
    workLog: input.workLog ? { ...input.workLog } : undefined,
    workerId: input.workerId,
  };
}

export function cloneGoalLedgerEvent(event: AutonomyGoalLedgerEvent): AutonomyGoalLedgerEvent {
  return {
    ...event,
    changedFields: event.changedFields ? [...event.changedFields] : undefined,
    workLog: event.workLog ? { ...event.workLog } : undefined,
  };
}
