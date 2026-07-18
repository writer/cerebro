import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { BatchGetCommand, DynamoDBDocumentClient, GetCommand, QueryCommand, TransactWriteCommand } from "@aws-sdk/lib-dynamodb";
import { appendGoalLog, applyGoalUpdate, cleanText, cloneGoal, compareGoals, createGoalRecord } from "./goal-codec.js";
import { compactGoalProjection, compareDueGoals, createGoalLedgerEvent } from "./goal-ledger.js";
import {
  MISSION_DUE_INDEX,
  MISSION_INDEX_SHARDS,
  MISSION_RECENT_INDEX,
  MISSION_STATUS_INDEX,
  goalLedgerEventFromItem,
  isFullGoalId,
  legacyGoalPartitionKey,
  missionEventItem,
  missionLookupItem,
  missionLookupPartitionKey,
  missionRecentScope,
  missionSnapshotItem,
  missionSnapshotKey,
  missionStatusScope,
  shortGoalId,
  storedGoalFromItem,
  type StoredAutonomyGoal,
} from "./goal-store-dynamo-model.js";
import type {
  AutonomyGoalLedgerEvent,
  AutonomyGoalStatus,
  AutonomyGoalStore,
  AutonomyGoalStoreOptions,
  AutonomyWorkLogEntry,
  AutonomousGoalRecord,
  CommandSender,
  CreateAutonomyGoalInput,
  UpdateAutonomyGoalInput,
} from "./goal-types.js";
import type { AppConfig } from "../config/index.js";
import { missionWorkOutboxItem } from "./mission-work-model.js";

export class AutonomyGoalConflictError extends Error {
  constructor(goalId: string) {
    super(`Autonomy goal ${goalId} changed while this update was being committed.`);
    this.name = "AutonomyGoalConflictError";
  }
}

export class DynamoAutonomyGoalStore implements AutonomyGoalStore {
  private readonly dynamo: CommandSender;
  private readonly now: () => Date;

  constructor(
    private readonly config: AppConfig,
    private readonly tableName: string,
    options: AutonomyGoalStoreOptions = {},
  ) {
    this.now = options.now ?? (() => new Date());
    this.dynamo = options.dynamo ?? DynamoDBDocumentClient.from(new DynamoDBClient({}), {
      marshallOptions: { removeUndefinedValues: true },
    });
  }

  async create(input: CreateAutonomyGoalInput): Promise<AutonomousGoalRecord> {
    const goal = compactGoalProjection(createGoalRecord(input, this.now()));
    const event = createGoalLedgerEvent({
      goalId: goal.id,
      type: "goal_created",
      occurredAt: goal.createdAt,
      revision: 1,
      workLog: goal.workLog[0],
    });
    await this.transact(goal, event, 1, {
      ConditionExpression: "attribute_not_exists(pk)",
    }, true);
    return cloneGoal(goal);
  }

  async get(goalId: string): Promise<AutonomousGoalRecord | undefined> {
    return cloneStoredGoal(await this.findStoredGoal(goalId));
  }

  async getRevision(goalId: string): Promise<number | undefined> {
    return (await this.findStoredGoal(goalId))?.revision;
  }

  async list(status?: AutonomyGoalStatus): Promise<AutonomousGoalRecord[]> {
    const limit = this.config.autonomy.maxListedGoals;
    const current = status
      ? await this.queryShards(MISSION_STATUS_INDEX, "mission_status_scope", "mission_updated_at", (shard) => missionStatusScope(this.config, status, shard), limit, false)
      : await this.queryShards(MISSION_RECENT_INDEX, "mission_recent_scope", "mission_updated_at", (shard) => missionRecentScope(this.config, shard), limit, false);
    const legacy = await this.listLegacy(status);
    return mergeGoals(status ? current.filter((goal) => goal.status === status) : current, legacy).slice(0, limit);
  }

  async listDue(now: Date, limit: number): Promise<AutonomousGoalRecord[]> {
    const current = await this.queryShards(
      MISSION_DUE_INDEX,
      "mission_due_scope",
      "mission_due_at",
      (shard) => missionRecentScope(this.config, shard),
      limit,
      true,
      `${now.toISOString()}#\uffff`,
    );
    const legacy = (await this.listLegacy("active"))
      .filter((goal) => !goal.nextWakeAt || Date.parse(goal.nextWakeAt) <= now.getTime());
    return mergeGoals(current, legacy)
      .filter((goal) => goal.status === "active" && (!goal.nextWakeAt || Date.parse(goal.nextWakeAt) <= now.getTime()))
      .sort(compareDueGoals)
      .slice(0, Math.max(1, limit));
  }

  async listEvents(goalId: string, limit = 100): Promise<AutonomyGoalLedgerEvent[]> {
    const stored = await this.requiredStoredGoal(goalId);
    if (stored.source === "legacy") {
      return stored.goal.workLog.slice(-Math.max(1, limit)).reverse().map((workLog, index) => ({
        id: `legacy-${workLog.id}`,
        goalId: stored.goal.id,
        type: workLog.kind === "goal_created" ? "goal_created" : "work_log_appended",
        occurredAt: workLog.createdAt,
        revision: Math.max(1, stored.goal.workLog.length - index),
        workLog: { ...workLog },
      }));
    }
    const response = await this.dynamo.send(new QueryCommand({
      TableName: this.tableName,
      KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
      ExpressionAttributeValues: { ":pk": missionSnapshotKey(this.config, stored.goal.id).pk, ":prefix": "event#" },
      ConsistentRead: true,
      ScanIndexForward: false,
      Limit: Math.max(1, limit),
    })) as { Items?: Record<string, unknown>[] };
    return (response.Items ?? []).map(goalLedgerEventFromItem).filter(isLedgerEvent);
  }

  async update(goalId: string, input: UpdateAutonomyGoalInput): Promise<AutonomousGoalRecord> {
    const current = await this.requiredStoredGoal(goalId);
    const updated = compactGoalProjection(applyGoalUpdate(current.goal, input, this.now()));
    const event = createGoalLedgerEvent({
      goalId: current.goal.id,
      type: "goal_updated",
      occurredAt: updated.updatedAt,
      revision: current.revision + 1,
      previousRevision: current.revision,
      changedFields: Object.keys(input),
    });
    await this.commitTransition(current, updated, event);
    return cloneGoal(updated);
  }

  async appendLog(goalId: string, entry: Omit<AutonomyWorkLogEntry, "id" | "createdAt">): Promise<AutonomousGoalRecord> {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const current = await this.requiredStoredGoal(goalId);
      const updated = compactGoalProjection(appendGoalLog(current.goal, entry, this.now()));
      const event = createGoalLedgerEvent({
        goalId: current.goal.id,
        type: "work_log_appended",
        occurredAt: updated.updatedAt,
        revision: current.revision + 1,
        previousRevision: current.revision,
        workLog: updated.workLog.at(-1),
      });
      try {
        await this.commitTransition(current, updated, event);
        return cloneGoal(updated);
      } catch (error) {
        if (!(error instanceof AutonomyGoalConflictError) || attempt === 2) throw error;
      }
    }
    throw new AutonomyGoalConflictError(goalId);
  }

  async tryClaim(goalId: string, input: { workerId: string; leaseExpiresAt: string; expectedRevision?: number }): Promise<AutonomousGoalRecord | undefined> {
    const current = await this.findStoredGoal(goalId);
    if (!current) return undefined;
    if (input.expectedRevision !== undefined && current.revision !== input.expectedRevision) return undefined;
    const now = this.now();
    const workerId = cleanText(input.workerId, "worker id");
    if (current.goal.claim && current.goal.claim.workerId !== workerId && Date.parse(current.goal.claim.leaseExpiresAt) > now.getTime()) return undefined;
    const updated = compactGoalProjection(applyGoalUpdate(current.goal, {
      claim: {
        workerId,
        claimedAt: now.toISOString(),
        leaseExpiresAt: input.leaseExpiresAt,
        attempt: (current.goal.claim?.attempt ?? 0) + 1,
      },
    }, now));
    const event = createGoalLedgerEvent({
      goalId: current.goal.id,
      type: "claim_acquired",
      occurredAt: updated.updatedAt,
      revision: current.revision + 1,
      previousRevision: current.revision,
      workerId: updated.claim?.workerId,
    });
    try {
      await this.commitTransition(current, updated, event, claimCondition(current, workerId, now));
      return cloneGoal(updated);
    } catch (error) {
      if (error instanceof AutonomyGoalConflictError) return undefined;
      throw error;
    }
  }

  async releaseClaim(goalId: string, workerId: string): Promise<AutonomousGoalRecord> {
    const current = await this.requiredStoredGoal(goalId);
    if (current.goal.claim && current.goal.claim.workerId !== workerId && Date.parse(current.goal.claim.leaseExpiresAt) > this.now().getTime()) {
      throw new Error(`Autonomy goal ${current.goal.id} is claimed by another worker.`);
    }
    const updated = compactGoalProjection(applyGoalUpdate(current.goal, { claim: null }, this.now()));
    const event = createGoalLedgerEvent({
      goalId: current.goal.id,
      type: "claim_released",
      occurredAt: updated.updatedAt,
      revision: current.revision + 1,
      previousRevision: current.revision,
      workerId,
    });
    await this.commitTransition(current, updated, event);
    return cloneGoal(updated);
  }

  private async findStoredGoal(goalId: string): Promise<StoredAutonomyGoal | undefined> {
    if (isFullGoalId(goalId)) {
      const current = await this.getCurrent(goalId);
      if (current) return current;
    } else if (goalId.length === 8) {
      const lookup = await this.dynamo.send(new QueryCommand({
        TableName: this.tableName,
        KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues: { ":pk": missionLookupPartitionKey(this.config, goalId), ":prefix": "goal#" },
        ConsistentRead: true,
        Limit: 2,
      })) as { Items?: Record<string, unknown>[] };
      if ((lookup.Items?.length ?? 0) > 1) return undefined;
      if (lookup.Items?.length === 1 && typeof lookup.Items[0]?.goal_id === "string") {
        const current = await this.getCurrent(lookup.Items[0].goal_id);
        if (current) return current;
      }
    }
    const legacy = await this.listLegacy();
    const matchedLegacy = legacy.find((goal) => goal.id === goalId || goal.id.endsWith(goalId));
    if (matchedLegacy) return { goal: matchedLegacy, revision: 0, source: "legacy" };
    if (!isFullGoalId(goalId)) {
      const current = (await this.list()).find((goal) => goal.id.endsWith(goalId));
      if (current) return this.getCurrent(current.id);
    }
    return undefined;
  }

  private async getCurrent(goalId: string): Promise<StoredAutonomyGoal | undefined> {
    const response = await this.dynamo.send(new GetCommand({
      TableName: this.tableName,
      Key: missionSnapshotKey(this.config, goalId),
      ConsistentRead: true,
    })) as { Item?: Record<string, unknown> };
    return storedGoalFromItem(response.Item, "mission_v2");
  }

  private async requiredStoredGoal(goalId: string): Promise<StoredAutonomyGoal> {
    const goal = await this.findStoredGoal(goalId);
    if (!goal) throw new Error(`No autonomy goal matched ${goalId}.`);
    return goal;
  }

  private async commitTransition(
    current: StoredAutonomyGoal,
    updated: AutonomousGoalRecord,
    event: AutonomyGoalLedgerEvent,
    condition = revisionCondition(current),
  ): Promise<void> {
    try {
      await this.transact(updated, event, current.revision + 1, condition, false);
    } catch (error) {
      if (conditionalCheckFailed(error)) throw new AutonomyGoalConflictError(current.goal.id);
      throw error;
    }
  }

  private async transact(
    goal: AutonomousGoalRecord,
    event: AutonomyGoalLedgerEvent,
    revision: number,
    condition: Record<string, unknown>,
    create: boolean,
  ): Promise<void> {
    const work = missionWorkOutboxItem(this.config, goal, event, revision);
    await this.dynamo.send(new TransactWriteCommand({
      TransactItems: [
        { Put: { TableName: this.tableName, Item: missionSnapshotItem(this.config, goal, revision), ...condition } },
        { Put: { TableName: this.tableName, Item: missionEventItem(this.config, event), ConditionExpression: "attribute_not_exists(pk)" } },
        { Put: {
          TableName: this.tableName,
          Item: missionLookupItem(this.config, goal.id),
          ...(create ? { ConditionExpression: "attribute_not_exists(pk)" } : {}),
        } },
        ...(work ? [{ Put: { TableName: this.tableName, Item: work, ConditionExpression: "attribute_not_exists(pk)" } }] : []),
      ],
    }));
  }

  private async queryShards(
    indexName: string,
    scopeName: string,
    sortName: string,
    scope: (shard: number) => string,
    limit: number,
    ascending: boolean,
    upperBound?: string,
  ): Promise<AutonomousGoalRecord[]> {
    const shardLimit = Math.max(1, limit);
    const responses = await Promise.all(Array.from({ length: MISSION_INDEX_SHARDS }, async (_, shard) => this.dynamo.send(new QueryCommand({
      TableName: this.tableName,
      IndexName: indexName,
      KeyConditionExpression: upperBound ? "#scope = :scope AND #sort <= :upperBound" : "#scope = :scope",
      ExpressionAttributeNames: { "#scope": scopeName, ...(upperBound ? { "#sort": sortName } : {}) },
      ExpressionAttributeValues: { ":scope": scope(shard), ...(upperBound ? { ":upperBound": upperBound } : {}) },
      ScanIndexForward: ascending,
      Limit: shardLimit,
    })) as Promise<{ Items?: Record<string, unknown>[] }>));
    const keys = responses.flatMap((response) => response.Items ?? []).map((item) => ({ pk: item.pk, sk: item.sk }));
    if (keys.length === 0) return [];
    const snapshots = await this.batchGetSnapshots(keys);
    return snapshots
      .map((item) => storedGoalFromItem(item, "mission_v2")?.goal)
      .filter(isGoal)
      .sort(ascending ? compareDueGoals : compareGoals)
      .slice(0, shardLimit);
  }

  private async listLegacy(status?: AutonomyGoalStatus): Promise<AutonomousGoalRecord[]> {
    const legacyTableName = this.config.autonomy.legacyGoalsTableName;
    if (!legacyTableName || legacyTableName === this.tableName) return [];
    const response = await this.dynamo.send(new QueryCommand({
      TableName: legacyTableName,
      KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
      ExpressionAttributeValues: { ":pk": legacyGoalPartitionKey(this.config), ":prefix": "goal#" },
      ConsistentRead: true,
    })) as { Items?: Record<string, unknown>[] };
    return (response.Items ?? [])
      .map((item) => storedGoalFromItem(item, "legacy")?.goal)
      .filter(isGoal)
      .filter((goal) => !status || goal.status === status)
      .sort(compareGoals);
  }

  private async batchGetSnapshots(keys: Array<{ pk: unknown; sk: unknown }>): Promise<Record<string, unknown>[]> {
    const unique = new Map<string, { pk: string; sk: string }>();
    for (const key of keys) {
      if (typeof key.pk === "string" && typeof key.sk === "string") unique.set(`${key.pk}\0${key.sk}`, { pk: key.pk, sk: key.sk });
    }
    const batches = chunk([...unique.values()], 100);
    const responses = await Promise.all(batches.map((batch) => this.batchGetSnapshotBatch(batch)));
    return responses.flat();
  }

  private async batchGetSnapshotBatch(keys: Array<{ pk: string; sk: string }>): Promise<Record<string, unknown>[]> {
    const items: Record<string, unknown>[] = [];
    let pending = keys;
    for (let attempt = 0; pending.length > 0 && attempt < 3; attempt += 1) {
      const response = await this.dynamo.send(new BatchGetCommand({
        RequestItems: { [this.tableName]: { Keys: pending, ConsistentRead: true } },
      })) as {
        Responses?: Record<string, Record<string, unknown>[]>;
        UnprocessedKeys?: Record<string, { Keys?: Array<{ pk: string; sk: string }> }>;
      };
      items.push(...(response.Responses?.[this.tableName] ?? []));
      pending = response.UnprocessedKeys?.[this.tableName]?.Keys ?? [];
    }
    if (pending.length > 0) throw new Error(`Mission snapshot read left ${pending.length} unprocessed key(s).`);
    return items;
  }
}

function revisionCondition(current: StoredAutonomyGoal): Record<string, unknown> {
  if (current.source === "legacy") {
    return { ConditionExpression: "attribute_not_exists(#revision)", ExpressionAttributeNames: { "#revision": "revision" } };
  }
  return {
    ConditionExpression: "#revision = :expectedRevision",
    ExpressionAttributeNames: { "#revision": "revision" },
    ExpressionAttributeValues: { ":expectedRevision": current.revision },
  };
}

function claimCondition(current: StoredAutonomyGoal, workerId: string, now: Date): Record<string, unknown> {
  if (current.source === "legacy") return revisionCondition(current);
  return {
    ConditionExpression: "#revision = :expectedRevision AND (attribute_not_exists(#claim) OR #claim.#workerId = :workerId OR #claim.#leaseExpiresAt <= :now)",
    ExpressionAttributeNames: { "#revision": "revision", "#claim": "claim", "#workerId": "workerId", "#leaseExpiresAt": "leaseExpiresAt" },
    ExpressionAttributeValues: { ":expectedRevision": current.revision, ":workerId": workerId, ":now": now.toISOString() },
  };
}

function cloneStoredGoal(stored: StoredAutonomyGoal | undefined): AutonomousGoalRecord | undefined {
  return stored ? cloneGoal(stored.goal) : undefined;
}

function mergeGoals(current: AutonomousGoalRecord[], legacy: AutonomousGoalRecord[]): AutonomousGoalRecord[] {
  const byId = new Map(legacy.map((goal) => [goal.id, goal]));
  for (const goal of current) byId.set(goal.id, goal);
  return [...byId.values()].sort(compareGoals).map(cloneGoal);
}

function conditionalCheckFailed(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  if (error.name === "ConditionalCheckFailedException") return true;
  if (error.name !== "TransactionCanceledException") return false;
  const reasons = (error as Error & { CancellationReasons?: Array<{ Code?: string }> }).CancellationReasons ?? [];
  return reasons.length === 0 || reasons.some((reason) => reason.Code === "ConditionalCheckFailed");
}

function isGoal(value: AutonomousGoalRecord | undefined): value is AutonomousGoalRecord {
  return Boolean(value);
}

function isLedgerEvent(value: AutonomyGoalLedgerEvent | undefined): value is AutonomyGoalLedgerEvent {
  return Boolean(value);
}

function chunk<T>(items: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let index = 0; index < items.length; index += size) chunks.push(items.slice(index, index + size));
  return chunks;
}
