import assert from "node:assert/strict";
import test from "node:test";
import {
  collectRuntimeHealth,
  renderRuntimeHealth,
  runtimeHealthHttpStatus,
  runtimeHealthSlackText,
} from "../src/runtime/health.js";
import { testConfig } from "./fixtures.js";

test("runtime health reports ready when durable stores and dependencies are wired", async () => {
  const config = testConfig({
    slack: { assistantBotUserIds: new Set(["BHELPER"]) },
    learning: { tableName: "learning-table" },
    schedules: { tableName: "schedule-table" },
    telemetry: { metricsEnabled: true },
  });
  const snapshot = await collectRuntimeHealth({
    config,
    coordinator: {
      isCurrentTask: async () => ({ current: true, reason: "current" }),
      serviceSnapshot: async () => ({ desiredCount: 2, runningCount: 2, pendingCount: 0, primaryRunningCount: 2 }),
      botHandoffStats: () => ({ globalAllowedIds: 0, channelPolicies: 0, cooldownSeconds: 600, maxHandoffsPerThread: 2, windowSeconds: 3600, activeWindows: 0 }),
    },
    scheduler: {
      stats: async () => ({
        enabled: true,
        store: "dynamodb",
        total: 1,
        active: 1,
        paused: 0,
        completed: 0,
        blocked: 0,
        dueCount: 0,
        oldestDueAgeMs: 0,
        triggerOnlyCount: 0,
        activeRuns: 0,
        maxConcurrent: 1,
      }),
    },
    goals: {
      stats: async () => ({
        enabled: true,
        store: "dynamodb",
        total: 1,
        active: 1,
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
    workLoop: {
      stats: () => ({ queued: 0, active: 0, activeThreads: 0, oldestQueuedAgeMs: 0 }),
    },
  } as any);

  assert.equal(snapshot.status, "ready");
  assert.equal(runtimeHealthHttpStatus(snapshot), 200);
  assert.match(renderRuntimeHealth(snapshot), /status=ready/);
  assert.match(runtimeHealthSlackText(snapshot), /Scheduled checks: 1 total, 1 active, 0 due/);
});

test("runtime health fails readiness when durable Slack claims are misconfigured", async () => {
  const snapshot = await collectRuntimeHealth({
    config: testConfig({
      learning: { tableName: undefined },
      telemetry: { metricsEnabled: true },
    }),
    scheduler: {
      stats: async () => ({
        enabled: true,
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
        maxConcurrent: 1,
      }),
    },
    goals: {
      stats: async () => ({
        enabled: true,
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
  } as any);

  assert.equal(snapshot.status, "not_ready");
  assert.equal(runtimeHealthHttpStatus(snapshot), 503);
  assert.match(renderRuntimeHealth(snapshot), /check\.config\.coordination\.event_dedupe=fail/);
  assert.match(runtimeHealthSlackText(snapshot), /Slack event claims are enabled without a DynamoDB table/);
});
