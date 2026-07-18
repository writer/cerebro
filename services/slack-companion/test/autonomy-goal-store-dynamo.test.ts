import assert from "node:assert/strict";
import test from "node:test";
import { AutonomyGoalConflictError, DynamoAutonomyGoalStore } from "../src/autonomy/goal-store-dynamo.js";
import { AUTONOMY_GOAL_LOG_PROJECTION_LIMIT } from "../src/autonomy/goal-ledger.js";
import type { AutonomousGoalRecord } from "../src/autonomy/goals.js";
import { testConfig } from "./fixtures.js";

const NOW = "2026-07-14T12:00:00.000Z";

test("Dynamo autonomy goals persist a compact snapshot, lookup, and immutable creation event", async () => {
  const dynamo = new FakeMissionDynamo();
  const store = createStore(dynamo);

  const goal = await store.create({
    objective: "Keep the deployment repair moving.",
    createdBy: { actorId: "operator-1" },
  });

  const snapshot = dynamo.item("goals", `tenant#writer#mission#${goal.id}`, "snapshot");
  assert.ok(snapshot);
  assert.equal(snapshot.record_type, "autonomy_mission_snapshot_v2");
  assert.equal(snapshot.revision, 1);
  assert.match(String(snapshot.mission_recent_scope), /#shard#\d{2}$/);
  assert.equal(containsUndefined(snapshot), false);
  assert.equal(snapshot.channelId, undefined);
  assert.equal(dynamo.itemsByType("autonomy_mission_event_v2").length, 1);
  assert.equal(dynamo.itemsByType("autonomy_mission_lookup_v2")[0]?.goal_id, goal.id);
  const work = dynamo.itemsByType("autonomy_mission_work_v1")[0];
  assert.equal((work?.task as any)?.goalId, goal.id);
  assert.equal((work?.task as any)?.revision, 1);
  assert.match(String(work?.mission_work_scope), /#mission-work#shard#\d{2}$/);
});

test("Dynamo autonomy goals use direct reads for full and short mission ids", async () => {
  const dynamo = new FakeMissionDynamo();
  const store = createStore(dynamo);
  const goal = await store.create({ objective: "Read one mission directly", createdBy: {} });
  dynamo.commands.length = 0;

  assert.equal((await store.get(goal.id))?.id, goal.id);
  assert.deepEqual(dynamo.commands.map((command) => command.name), ["GetCommand"]);

  dynamo.commands.length = 0;
  assert.equal((await store.get(goal.id.slice(-8)))?.id, goal.id);
  assert.deepEqual(dynamo.commands.map((command) => command.name), ["QueryCommand", "GetCommand"]);
});

test("Dynamo autonomy goals query sharded due work without scanning mission snapshots", async () => {
  const dynamo = new FakeMissionDynamo();
  const times = [
    new Date("2026-07-14T11:00:00.000Z"),
    new Date("2026-07-14T11:01:00.000Z"),
    new Date("2026-07-14T11:02:00.000Z"),
  ];
  const store = createStore(dynamo, () => times.shift() ?? new Date(NOW));
  const due = await store.create({ objective: "Due", createdBy: {}, nextWakeAt: "2026-07-14T11:30:00.000Z" });
  await store.create({ objective: "Later", createdBy: {}, nextWakeAt: "2026-07-14T13:00:00.000Z" });
  dynamo.commands.length = 0;

  const selected = await store.listDue(new Date(NOW), 5);

  assert.deepEqual(selected.map((goal) => goal.id), [due.id]);
  assert.equal(dynamo.commands.filter((command) => command.name === "QueryCommand").length, 16);
  assert.equal(dynamo.commands.filter((command) => command.name === "BatchGetCommand").length, 1);
  assert.ok(dynamo.commands.filter((command) => command.name === "QueryCommand").every((command) => command.input.IndexName === "mission-due-index"));
});

test("Dynamo autonomy goal transitions reject a stale revision", async () => {
  const dynamo = new FakeMissionDynamo();
  const store = createStore(dynamo);
  const goal = await store.create({ objective: "Protect concurrent writes", createdBy: {} });
  dynamo.failNextTransaction = true;

  await assert.rejects(store.update(goal.id, { status: "waiting" }), AutonomyGoalConflictError);
  assert.equal((await store.get(goal.id))?.status, "active");
});

test("Dynamo autonomy goals fence claims to the queued revision", async () => {
  const dynamo = new FakeMissionDynamo();
  const store = createStore(dynamo);
  const goal = await store.create({ objective: "Execute only the queued revision", createdBy: {} });

  assert.equal(await store.tryClaim(goal.id, {
    workerId: "worker-stale",
    leaseExpiresAt: "2026-07-14T12:05:00.000Z",
    expectedRevision: 2,
  }), undefined);
  const claimed = await store.tryClaim(goal.id, {
    workerId: "worker-current",
    leaseExpiresAt: "2026-07-14T12:05:00.000Z",
    expectedRevision: 1,
  });
  assert.equal(claimed?.claim?.workerId, "worker-current");
  await store.releaseClaim(goal.id, "worker-current");
  assert.deepEqual(
    dynamo.itemsByType("autonomy_mission_work_v1").map((item) => (item.task as any).revision).sort((left, right) => left - right),
    [1, 3],
  );
});

test("Dynamo autonomy goals keep a bounded snapshot projection and complete ledger", async () => {
  const dynamo = new FakeMissionDynamo();
  let tick = 0;
  const store = createStore(dynamo, () => new Date(Date.parse(NOW) + tick++));
  const goal = await store.create({ objective: "Retain mission history", createdBy: {} });

  for (let index = 0; index < AUTONOMY_GOAL_LOG_PROJECTION_LIMIT + 5; index += 1) {
    await store.appendLog(goal.id, { kind: "check_result", summary: `Check ${index} passed.` });
  }

  assert.equal((await store.get(goal.id))?.workLog.length, AUTONOMY_GOAL_LOG_PROJECTION_LIMIT);
  const events = await store.listEvents(goal.id, 200);
  assert.equal(events.length, AUTONOMY_GOAL_LOG_PROJECTION_LIMIT + 6);
  assert.equal(events[0]?.workLog?.summary, `Check ${AUTONOMY_GOAL_LOG_PROJECTION_LIMIT + 4} passed.`);
});

test("Dynamo autonomy goals promote a legacy record on its first transition", async () => {
  const dynamo = new FakeMissionDynamo();
  const legacy = legacyGoal("goal-00000000-0000-4000-8000-123456789abc");
  dynamo.put("legacy-goals", { pk: "tenant#writer#autonomy-goals", sk: `goal#${legacy.id}`, ...legacy });
  const store = createStore(dynamo, undefined, "legacy-goals");

  const updated = await store.update(legacy.id, { status: "waiting" });

  assert.equal(updated.status, "waiting");
  assert.equal(dynamo.item("goals", `tenant#writer#mission#${legacy.id}`, "snapshot")?.revision, 1);
  assert.equal((await store.get(legacy.id))?.status, "waiting");
});

function createStore(dynamo: FakeMissionDynamo, now: (() => Date) | undefined = undefined, legacyGoalsTableName?: string): DynamoAutonomyGoalStore {
  return new DynamoAutonomyGoalStore(
    testConfig({ autonomy: { goalsTableName: "goals", legacyGoalsTableName, maxListedGoals: 10 } }),
    "goals",
    { dynamo, now: now ?? (() => new Date(NOW)) },
  );
}

class FakeMissionDynamo {
  readonly commands: Array<{ name: string; input: any }> = [];
  readonly items = new Map<string, Record<string, unknown>>();
  failNextTransaction = false;

  async send(command: any): Promise<unknown> {
    const name = command.constructor.name;
    const input = command.input;
    this.commands.push({ name, input });
    if (name === "GetCommand") return { Item: this.item(input.TableName, input.Key.pk, input.Key.sk) };
    if (name === "BatchGetCommand") return this.batchGet(input.RequestItems);
    if (name === "TransactWriteCommand") return this.transact(input.TransactItems);
    if (name === "QueryCommand") return this.query(input);
    throw new Error(`Unexpected command ${name}`);
  }

  put(tableName: string, item: Record<string, unknown>): void {
    this.items.set(this.key(tableName, String(item.pk), String(item.sk)), structuredClone(item));
  }

  item(tableName: string, pk: string, sk: string): Record<string, unknown> | undefined {
    const item = this.items.get(this.key(tableName, pk, sk));
    return item ? structuredClone(item) : undefined;
  }

  itemsByType(recordType: string): Record<string, unknown>[] {
    return [...this.items.values()].filter((item) => item.record_type === recordType).map((item) => structuredClone(item));
  }

  private transact(transactItems: Array<{ Put: any }>): Record<string, never> {
    if (this.failNextTransaction) {
      this.failNextTransaction = false;
      throw transactionConflict();
    }
    for (const { Put } of transactItems) this.assertCondition(Put);
    for (const { Put } of transactItems) this.put(Put.TableName, Put.Item);
    return {};
  }

  private assertCondition(input: any): void {
    const current = this.item(input.TableName, input.Item.pk, input.Item.sk);
    const condition = String(input.ConditionExpression ?? "");
    if (condition === "attribute_not_exists(pk)" && current) throw transactionConflict();
    if (condition.includes("attribute_not_exists(#revision)") && current?.revision !== undefined) throw transactionConflict();
    if (condition.includes("#revision = :expectedRevision") && current?.revision !== input.ExpressionAttributeValues?.[":expectedRevision"]) {
      throw transactionConflict();
    }
  }

  private query(input: any): { Items: Record<string, unknown>[] } {
    let items = [...this.items.entries()]
      .filter(([key]) => key.startsWith(`${input.TableName}|`))
      .map(([, item]) => structuredClone(item));
    if (input.IndexName) {
      const scopeName = input.ExpressionAttributeNames["#scope"];
      const sortName = input.ExpressionAttributeNames["#sort"];
      items = items.filter((item) => item[scopeName] === input.ExpressionAttributeValues[":scope"]);
      if (sortName) items = items.filter((item) => String(item[sortName]) <= input.ExpressionAttributeValues[":upperBound"]);
      const orderName = sortName ?? (input.IndexName === "mission-status-index" || input.IndexName === "mission-recent-index" ? "mission_updated_at" : "mission_due_at");
      items.sort((left, right) => String(left[orderName]).localeCompare(String(right[orderName])));
      if (input.ScanIndexForward === false) items.reverse();
    } else {
      items = items.filter((item) => item.pk === input.ExpressionAttributeValues[":pk"] && String(item.sk).startsWith(input.ExpressionAttributeValues[":prefix"]));
      items.sort((left, right) => String(left.sk).localeCompare(String(right.sk)));
      if (input.ScanIndexForward === false) items.reverse();
    }
    const limited = items.slice(0, input.Limit ?? items.length);
    return { Items: input.IndexName ? limited.map((item) => ({ pk: item.pk, sk: item.sk })) : limited };
  }

  private batchGet(requestItems: Record<string, { Keys: Array<{ pk: string; sk: string }> }>): { Responses: Record<string, Record<string, unknown>[]> } {
    return {
      Responses: Object.fromEntries(Object.entries(requestItems).map(([tableName, request]) => [
        tableName,
        request.Keys.map((key) => this.item(tableName, key.pk, key.sk)).filter((item): item is Record<string, unknown> => Boolean(item)),
      ])),
    };
  }

  private key(tableName: string, pk: string, sk: string): string {
    return `${tableName}|${pk}|${sk}`;
  }
}

function transactionConflict(): Error {
  const error = new Error("transaction cancelled") as Error & { CancellationReasons: Array<{ Code: string }> };
  error.name = "TransactionCanceledException";
  error.CancellationReasons = [{ Code: "ConditionalCheckFailed" }];
  return error;
}

function legacyGoal(id: string): AutonomousGoalRecord {
  return {
    id,
    status: "active",
    capabilityId: "planner",
    objective: "Promote this mission",
    createdBy: {},
    createdAt: NOW,
    updatedAt: NOW,
    currentPlan: [],
    assumptions: [],
    blockers: [],
    artifactUrls: [],
    resourceRefs: [],
    artifacts: [],
    acceptanceCriteria: [],
    corrections: [],
    toolRuns: [],
    approvals: [],
    workLog: [{ id: "log-legacy", kind: "goal_created", createdAt: NOW, summary: "Goal created." }],
  };
}

function containsUndefined(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(containsUndefined);
  if (!value || typeof value !== "object") return value === undefined;
  return Object.values(value).some((item) => item === undefined || containsUndefined(item));
}
