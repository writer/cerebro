import assert from "node:assert/strict";
import test from "node:test";
import { recordRunnerAdvanceFailure } from "../src/autonomy/runner-retry.js";
import type { AutonomousGoalRecord } from "../src/autonomy/goals.js";
import { testConfig } from "./fixtures.js";

test("runner failure handling backs off and blocks after three equivalent failures", async () => {
  let now = new Date("2026-07-14T12:00:00.000Z");
  let goal = goalRecord();
  const goals = {
    update: async (_goalId: string, input: any) => {
      goal = {
        ...goal,
        ...input,
        nextWakeAt: input.nextWakeAt === null ? undefined : input.nextWakeAt ?? goal.nextWakeAt,
      };
      return goal;
    },
    appendLog: async (_goalId: string, input: any) => {
      goal = {
        ...goal,
        workLog: [...goal.workLog, {
          id: `log-${goal.workLog.length + 1}`,
          createdAt: now.toISOString(),
          ...input,
        }],
      };
      return goal;
    },
  };
  const config = testConfig({ autonomy: { runnerPollIntervalMs: 10_000 } });

  await recordRunnerAdvanceFailure({ config, goals: goals as any, goal, error: new Error("Dynamo serialization failed"), now: () => now });
  assert.equal(goal.status, "active");
  assert.equal(goal.nextWakeAt, "2026-07-14T12:00:10.000Z");

  now = new Date("2026-07-14T12:00:10.000Z");
  await recordRunnerAdvanceFailure({ config, goals: goals as any, goal, error: new Error("Dynamo serialization failed"), now: () => now });
  assert.equal(goal.nextWakeAt, "2026-07-14T12:00:30.000Z");

  now = new Date("2026-07-14T12:00:30.000Z");
  const summary = await recordRunnerAdvanceFailure({ config, goals: goals as any, goal, error: new Error("Dynamo serialization failed"), now: () => now });
  assert.equal(goal.status, "blocked");
  assert.equal(goal.nextWakeAt, undefined);
  assert.match(summary, /blocked after 3 equivalent failures/i);
  assert.match(goal.blockers.at(-1) ?? "", /resume the goal after the cause is fixed/i);
  assert.equal(goal.workLog.at(-1)?.summary, "Runner stopped after 3 equivalent failures.");
});

function goalRecord(): AutonomousGoalRecord {
  return {
    id: "goal-1",
    status: "active",
    capabilityId: "planner",
    objective: "Keep the deployment repair moving.",
    createdBy: { actorId: "operator-1", displayName: "Operator" },
    createdAt: "2026-07-14T11:00:00.000Z",
    updatedAt: "2026-07-14T11:00:00.000Z",
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
    workLog: [],
  };
}
