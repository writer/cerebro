import assert from "node:assert/strict";
import test from "node:test";
import { Authorization } from "../src/auth.js";
import { handleOperator } from "../src/slack/commands/operator.js";
import { testConfig } from "./fixtures.js";

test("operator command identifies the configured Slack operator", async () => {
  const posts: any[] = [];
  const config = testConfig({
    slack: {
      operatorUserIds: new Set(["UOWNER"]),
      sourceWriteUserIds: new Set(["UOWNER"]),
      graphActionUserIds: new Set(["UOWNER"]),
    },
    cerebro: {
      slackUsers: new Map([["UOWNER", {
        actorId: "jonathan.haas@writer.com",
        displayName: "Jonathan Haas",
      }]]),
    },
  });
  const auth = new Authorization(config);

  await handleOperator({
    deps: deps(config, auth),
    command: { user_id: "UOWNER", channel_id: "CSEC" },
    respond: async (message: any) => posts.push(message),
    client: {},
    actor: auth.actorFor("UOWNER"),
    parsed: { name: "operator", action: "whoami" },
  });

  const text = posts[0].blocks[0].text.text;
  assert.match(text, /Jonathan Haas \(jonathan\.haas@writer\.com\)/);
  assert.match(text, /Slack user: UOWNER/);
  assert.match(text, /Operator commands: allowed/);
  assert.match(text, /source, graphActions/);
});

test("operator command blocks non-operators", async () => {
  const config = testConfig({
    slack: { operatorUserIds: new Set(["UOWNER"]) },
  });
  const auth = new Authorization(config);

  await assert.rejects(() => handleOperator({
    deps: deps(config, auth),
    command: { user_id: "UOTHER", channel_id: "CSEC" },
    respond: async () => undefined,
    client: {},
    actor: auth.actorFor("UOTHER"),
    parsed: { name: "operator", action: "whoami" },
  }), /Only configured Cerebro operators/);
});

test("operator deploy command reports auto-deploy policy", async () => {
  const posts: any[] = [];
  const config = testConfig({
    slack: { operatorUserIds: new Set(["UOWNER"]) },
    coordination: { deploymentFenceEnabled: true },
  });
  const auth = new Authorization(config);

  await handleOperator({
    deps: deps(config, auth),
    command: { user_id: "UOWNER", channel_id: "CSEC" },
    respond: async (message: any) => posts.push(message),
    client: {},
    actor: auth.actorFor("UOWNER"),
    parsed: { name: "operator", action: "deploy" },
  });

  const text = posts[0].blocks[0].text.text;
  assert.match(text, /Auto-deploy is enabled for main/);
  assert.match(text, /CI runs on every push to main/);
  assert.match(text, /direct ECS image deploy/);
  assert.match(text, /Infra program\/config changes run Pulumi/);
  assert.match(text, /workflow-only changes skip ECS/);
  assert.match(text, /latest main SHA/);
  assert.match(text, /ECS deployment fence: enabled/);
});

test("operator health command reports queue, policy, and audit state", async () => {
  const posts: any[] = [];
  const config = testConfig({
    slack: {
      operatorUserIds: new Set(["UOWNER"]),
      assistantBotUserIds: new Set(["BHELPER"]),
      assistantBotMaxHandoffsPerThread: 2,
      assistantBotHandoffWindowSeconds: 3_600,
    },
  });
  const auth = new Authorization(config);

  await handleOperator({
    deps: {
      ...deps(config, auth),
      workLoop: {
        stats: () => ({ queued: 1, active: 1, activeThreads: 1, oldestQueuedAgeMs: 2_500 }),
      },
      coordinator: {
        botHandoffStats: () => ({
          globalAllowedIds: 1,
          channelPolicies: 0,
          cooldownSeconds: 600,
          maxHandoffsPerThread: 2,
          windowSeconds: 3_600,
          activeWindows: 1,
        }),
        serviceSnapshot: async () => ({
          desiredCount: 2,
          runningCount: 2,
          pendingCount: 0,
          primaryRunningCount: 2,
        }),
        isCurrentTask: async () => ({ current: true, reason: "disabled" }),
      },
      scheduler: {
        stats: async () => ({
          enabled: true,
          store: "dynamodb",
          total: 2,
          active: 1,
          paused: 0,
          completed: 0,
          blocked: 1,
          dueCount: 1,
          oldestDueAgeMs: 61_000,
          triggerOnlyCount: 0,
          activeRuns: 1,
          maxConcurrent: 2,
          lastTickAt: "2026-07-02T12:00:00.000Z",
          lastTickStatus: "completed",
        }),
      },
      goals: {
        stats: async () => ({
          enabled: true,
          store: "dynamodb",
          total: 3,
          active: 1,
          waiting: 1,
          approvalNeeded: 0,
          blocked: 1,
          paused: 0,
          completed: 0,
          cancelled: 0,
          dueCount: 1,
          oldestDueAgeMs: 125_000,
          claimed: 1,
          staleClaims: 0,
        }),
      },
    } as any,
    command: { user_id: "UOWNER", channel_id: "CSEC" },
    respond: async (message: any) => posts.push(message),
    client: {},
    actor: auth.actorFor("UOWNER"),
    parsed: { name: "operator", action: "health" },
  });

  const text = posts[0].blocks[0].text.text;
  assert.match(text, /Cerebro operator health/);
  assert.match(text, /Work queue: 1 queued, 1 active, 1 active thread, oldest queued 3s/);
  assert.match(text, /Scheduled checks: 2 total, 1 active, 1 due, oldest due 61s, 1 blocked/);
  assert.match(text, /Autonomy goals: 3 total, 1 active, 1 due, oldest due 125s, 1 blocked, 1 claimed/);
  assert.match(text, /Deployment fence: ok, disabled desired 2, running 2, pending 0/);
  assert.doesNotMatch(text, /xoxb-test|xapp-test|read-key/);
});

function deps(config: ReturnType<typeof testConfig>, auth: Authorization): any {
  return {
    config,
    auth,
    cerebro: {},
    notes: { record: async () => undefined },
    skills: {},
    scheduler: {
      stats: async () => ({
        enabled: false,
        store: "memory",
        total: 0,
        active: 0,
        paused: 0,
        completed: 0,
        blocked: 0,
        dueCount: 0,
        oldestDueAgeMs: 0,
        triggerOnlyCount: 0,
        activeRuns: 0,
        maxConcurrent: 0,
      }),
    },
    goals: {
      stats: async () => ({
        enabled: false,
        store: "memory",
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
      }),
    },
  };
}
