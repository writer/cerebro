import { appendGoalLog, applyGoalUpdate, cleanText, cloneGoal, compareGoals, createGoalRecord } from "./goal-codec.js";
import { cloneGoalLedgerEvent, compactGoalProjection, compareDueGoals, createGoalLedgerEvent } from "./goal-ledger.js";
import type {
  AutonomyGoalLedgerEvent,
  AutonomyGoalStatus,
  AutonomyGoalStore,
  AutonomyWorkLogEntry,
  AutonomousGoalRecord,
  CreateAutonomyGoalInput,
  UpdateAutonomyGoalInput,
} from "./goal-types.js";

export class InMemoryAutonomyGoalStore implements AutonomyGoalStore {
  private readonly goals = new Map<string, AutonomousGoalRecord>();
  private readonly events = new Map<string, AutonomyGoalLedgerEvent[]>();

  constructor(private readonly now: () => Date = () => new Date()) {}

  async create(input: CreateAutonomyGoalInput): Promise<AutonomousGoalRecord> {
    const goal = compactGoalProjection(createGoalRecord(input, this.now()));
    this.goals.set(goal.id, cloneGoal(goal));
    const initialLog = goal.workLog[0];
    this.appendEvent(goal.id, createGoalLedgerEvent({
      goalId: goal.id,
      type: "goal_created",
      occurredAt: goal.createdAt,
      revision: 1,
      workLog: initialLog,
    }));
    return cloneGoal(goal);
  }

  async get(goalId: string): Promise<AutonomousGoalRecord | undefined> {
    const goal = this.findGoal(goalId);
    return goal ? cloneGoal(goal) : undefined;
  }

  async getRevision(goalId: string): Promise<number | undefined> {
    const goal = this.findGoal(goalId);
    return goal ? this.currentRevision(goal.id) : undefined;
  }

  async list(status?: AutonomyGoalStatus): Promise<AutonomousGoalRecord[]> {
    return [...this.goals.values()]
      .filter((goal) => !status || goal.status === status)
      .sort(compareGoals)
      .map(cloneGoal);
  }

  async listDue(now: Date, limit: number): Promise<AutonomousGoalRecord[]> {
    return [...this.goals.values()]
      .filter((goal) => goal.status === "active" && (!goal.nextWakeAt || Date.parse(goal.nextWakeAt) <= now.getTime()))
      .sort(compareDueGoals)
      .slice(0, limit)
      .map(cloneGoal);
  }

  async listEvents(goalId: string, limit = 100): Promise<AutonomyGoalLedgerEvent[]> {
    const goal = this.requiredGoal(goalId);
    return (this.events.get(goal.id) ?? [])
      .slice(-Math.max(1, limit))
      .reverse()
      .map(cloneGoalLedgerEvent);
  }

  async update(goalId: string, input: UpdateAutonomyGoalInput): Promise<AutonomousGoalRecord> {
    const current = this.requiredGoal(goalId);
    const updated = compactGoalProjection(applyGoalUpdate(current, input, this.now()));
    this.goals.set(current.id, cloneGoal(updated));
    this.appendEvent(current.id, createGoalLedgerEvent({
      goalId: current.id,
      type: "goal_updated",
      occurredAt: updated.updatedAt,
      revision: this.nextRevision(current.id),
      previousRevision: this.currentRevision(current.id),
      changedFields: Object.keys(input),
    }));
    return cloneGoal(updated);
  }

  async appendLog(goalId: string, entry: Omit<AutonomyWorkLogEntry, "id" | "createdAt">): Promise<AutonomousGoalRecord> {
    const current = this.requiredGoal(goalId);
    const updated = compactGoalProjection(appendGoalLog(current, entry, this.now()));
    this.goals.set(current.id, cloneGoal(updated));
    this.appendEvent(current.id, createGoalLedgerEvent({
      goalId: current.id,
      type: "work_log_appended",
      occurredAt: updated.updatedAt,
      revision: this.nextRevision(current.id),
      previousRevision: this.currentRevision(current.id),
      workLog: updated.workLog.at(-1),
    }));
    return cloneGoal(updated);
  }

  async tryClaim(goalId: string, input: { workerId: string; leaseExpiresAt: string; expectedRevision?: number }): Promise<AutonomousGoalRecord | undefined> {
    const current = this.findGoal(goalId);
    if (!current) return undefined;
    if (input.expectedRevision !== undefined && this.currentRevision(current.id) !== input.expectedRevision) return undefined;
    const now = this.now();
    if (current.claim && current.claim.workerId !== input.workerId && Date.parse(current.claim.leaseExpiresAt) > now.getTime()) {
      return undefined;
    }
    const updated = compactGoalProjection(applyGoalUpdate(current, {
      claim: {
        workerId: cleanText(input.workerId, "worker id"),
        claimedAt: now.toISOString(),
        leaseExpiresAt: input.leaseExpiresAt,
        attempt: (current.claim?.attempt ?? 0) + 1,
      },
    }, now));
    this.goals.set(current.id, cloneGoal(updated));
    this.appendEvent(current.id, createGoalLedgerEvent({
      goalId: current.id,
      type: "claim_acquired",
      occurredAt: updated.updatedAt,
      revision: this.nextRevision(current.id),
      previousRevision: this.currentRevision(current.id),
      workerId: updated.claim?.workerId,
    }));
    return cloneGoal(updated);
  }

  async releaseClaim(goalId: string, workerId: string): Promise<AutonomousGoalRecord> {
    const current = this.requiredGoal(goalId);
    if (current.claim && current.claim.workerId !== workerId && Date.parse(current.claim.leaseExpiresAt) > this.now().getTime()) {
      throw new Error(`Autonomy goal ${current.id} is claimed by another worker.`);
    }
    const updated = compactGoalProjection(applyGoalUpdate(current, { claim: null }, this.now()));
    this.goals.set(current.id, cloneGoal(updated));
    this.appendEvent(current.id, createGoalLedgerEvent({
      goalId: current.id,
      type: "claim_released",
      occurredAt: updated.updatedAt,
      revision: this.nextRevision(current.id),
      previousRevision: this.currentRevision(current.id),
      workerId,
    }));
    return cloneGoal(updated);
  }

  private appendEvent(goalId: string, event: AutonomyGoalLedgerEvent): void {
    this.events.set(goalId, [...(this.events.get(goalId) ?? []), cloneGoalLedgerEvent(event)]);
  }

  private currentRevision(goalId: string): number {
    return this.events.get(goalId)?.at(-1)?.revision ?? 0;
  }

  private nextRevision(goalId: string): number {
    return this.currentRevision(goalId) + 1;
  }

  private requiredGoal(goalId: string): AutonomousGoalRecord {
    const goal = this.findGoal(goalId);
    if (!goal) throw new Error(`No autonomy goal matched ${goalId}.`);
    return cloneGoal(goal);
  }

  private findGoal(goalId: string): AutonomousGoalRecord | undefined {
    return this.goals.get(goalId) ?? [...this.goals.values()].find((goal) => goal.id.endsWith(goalId));
  }
}
