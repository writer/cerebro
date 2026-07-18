import assert from "node:assert/strict";
import test from "node:test";
import { ScheduledJobService } from "../src/schedules/scheduled-jobs/index.js";
import { finalizeSchedulePlan, type SchedulePlan } from "../src/schedules/schedule-parser.js";
import { testConfig } from "./fixtures.js";

test("ScheduledJobService creates and runs an LLM-planned job", async () => {
  let now = new Date("2026-06-26T16:00:00.000Z");
  const posts: any[] = [];
  const prompts: string[] = [];
  const service = new ScheduledJobService({
    config: testConfig({ schedules: { defaultChannelId: "CSEC" } }),
    cerebro: {
      listRuntimeHealth: async () => [{
        runtime_id: "writer-okta",
        source_id: "okta",
        status: "healthy",
        sync_status: "completed",
        graph_status: "completed",
        finding_status: "completed",
        open_finding_count: 1,
      }],
      listFindings: async (runtimeId: string) => [{
        id: `${runtimeId}-finding-1`,
        runtime_id: runtimeId,
        title: "Privileged identity needs review",
        severity: "high",
        risk_score: 91,
        status: "open",
      }],
    } as any,
    notes: { record: async () => undefined } as any,
    skills: {
      runPrompt: async (input: any) => {
        prompts.push(input.prompt);
        return {
          answer: "Login posture has one finding to review.",
          messages: ["Login posture has one finding to review."],
          keyPoints: [],
          evidence: [],
          actionsTaken: [],
          nextActions: [],
          research: [],
          memoryUpdates: [],
          source: "pi",
        };
      },
    } as any,
  }, {
    now: () => now,
    planner: fakePlanner({
      description: "Weekday login posture",
      schedule: {
        kind: "weekdays",
        timeOfDay: { hour: 9, minute: 0 },
        timeZone: "America/Los_Angeles",
      },
      steps: [{ id: "login", title: "Login posture", skillId: "login-posture", prompt: "Check login posture.", dependsOn: [] }],
      contextProviders: ["runtime_health_snapshot", "open_findings_snapshot"],
    }, () => now),
  });
  service.setSlackClient({
    chat: {
      postMessage: async (message: any) => {
        posts.push(message);
      },
    },
  });

  const job = await service.createFromText({
    text: "every weekday at 9am run login posture",
    actor: { slackUserId: "U1", actorId: "slack:U1" },
    channelId: "CSEC",
  });

  assert.equal(job.status, "active");
  assert.equal((await service.list()).length, 1);

  now = new Date(Date.parse(job.nextRunAt ?? "") + 1000);
  await service.tick();

  const updated = await service.get(job.id);
  assert.equal(updated?.lastStatus, "completed");
  assert.equal(posts.length, 1);
  assert.match(posts[0].text, /Scheduled check/);
  assert.match(posts[0].text, /Context: Runtime health snapshot completed; Open findings snapshot completed/);
  assert.match(prompts[0] ?? "", /Run security skill/);
  assert.match(prompts[0] ?? "", /Pre-run context gathered/);
  assert.match(prompts[0] ?? "", /writer-okta-finding-1/);
});

test("ScheduledJobService can run trigger-created jobs manually", async () => {
  const service = new ScheduledJobService({
    config: testConfig(),
    cerebro: {} as any,
    notes: { record: async () => undefined } as any,
    skills: {
      runPrompt: async () => ({
        answer: "Runtime health was checked.",
        messages: ["Runtime health was checked."],
        keyPoints: [],
        evidence: [],
        actionsTaken: [],
        nextActions: [],
        research: [],
        memoryUpdates: [],
        source: "pi",
      }),
    } as any,
  }, {
    now: () => new Date("2026-06-26T16:00:00.000Z"),
    planner: fakePlanner({
      description: "Runtime recovery check",
      trigger: {
        type: "runtime_health",
        runtimeId: "writer-okta",
        unhealthyOnly: true,
        cooldownMs: 3_600_000,
      },
      steps: [
        { id: "runtime", title: "Runtime health", skillId: "runtime-health", prompt: "Check runtime health.", dependsOn: [] },
        { id: "login", title: "Login posture", skillId: "login-posture", prompt: "Review login posture.", dependsOn: ["runtime"] },
      ],
    }),
  });

  const job = await service.createFromText({
    text: "when writer-okta is unhealthy run runtime health then login posture",
    actor: { slackUserId: "U1", actorId: "slack:U1" },
    channelId: "CSEC",
  });
  const result = await service.runNow(job.id);

  assert.equal(result.status, "completed");
  assert.equal(result.stepResults.length, 2);
  assert.deepEqual(job.steps[1]?.dependsOn, ["runtime"]);
});

test("ScheduledJobService creates reviewed draft jobs without planner calls", async () => {
  let planned = false;
  const service = new ScheduledJobService({
    config: testConfig(),
    cerebro: {} as any,
    notes: { record: async () => undefined } as any,
    skills: { runPrompt: async () => ({}) } as any,
  }, {
    now: () => new Date("2026-06-26T16:00:00.000Z"),
    planner: {
      plan: async () => {
        planned = true;
        throw new Error("planner should not run");
      },
    },
  });

  const job = await service.createFromDraft({
    actor: { slackUserId: "U1", actorId: "slack:U1" },
    draft: {
      description: "Privileged access control monitor",
      schedule: {
        kind: "weekdays",
        timeOfDay: { hour: 8, minute: 30 },
        timeZone: "America/Los_Angeles",
      },
      steps: [{ id: "evidence", title: "Build evidence packet", prompt: "Build packet.", dependsOn: [] }],
      contextProviders: ["runtime_health_snapshot", "unknown" as any],
      channelId: "CSEC",
      warnings: ["review threshold"],
    },
  });

  assert.equal(planned, false);
  assert.equal(job.status, "active");
  assert.equal(job.description, "Privileged access control monitor");
  assert.equal(job.nextRunAt, "2026-06-29T15:30:00.000Z");
  assert.deepEqual(job.contextProviders, ["runtime_health_snapshot"]);
  assert.deepEqual(job.warnings, ["review threshold"]);
});

test("ScheduledJobService blocks a scheduled check after repeated failed runs", async () => {
  let now = new Date("2026-06-26T16:00:00.000Z");
  const service = new ScheduledJobService({
    config: testConfig(),
    cerebro: {} as any,
    notes: { record: async () => undefined } as any,
    skills: {
      runPrompt: async () => {
        throw new Error("model timeout");
      },
    } as any,
  }, {
    now: () => now,
    planner: fakePlanner({
      description: "Runtime health check",
      schedule: { kind: "interval", everyMs: 60_000, timeZone: "America/Los_Angeles" },
      steps: [{ id: "runtime", title: "Runtime health", skillId: "runtime-health", prompt: "Check runtime health.", dependsOn: [] }],
    }, () => now),
  });

  const job = await service.createFromText({
    text: "check runtime health every minute",
    actor: { slackUserId: "U1", actorId: "slack:U1" },
    channelId: "CSEC",
  });

  await service.runNow(job.id);
  now = new Date(now.getTime() + 60_000);
  await service.runNow(job.id);
  now = new Date(now.getTime() + 60_000);
  await service.runNow(job.id);

  const updated = await service.get(job.id);
  const stats = await service.stats();
  assert.equal(updated?.status, "blocked");
  assert.equal(updated?.consecutiveFailures, 3);
  assert.match(updated?.lastError ?? "", /failed 1 step/);
  assert.equal(stats.blocked, 1);
  assert.equal(stats.dueCount, 0);
});

function fakePlanner(plan: SchedulePlan, now: () => Date = () => new Date("2026-06-26T16:00:00.000Z")) {
  return {
    plan: async (input: { text: string; channelId?: string; now?: Date }) => finalizeSchedulePlan(plan, {
      now: input.now ?? now(),
      timeZone: "America/Los_Angeles",
      defaultChannelId: input.channelId ?? "CSEC",
      defaultRuntimeIds: ["writer-okta"],
      sourceText: input.text,
    }),
  };
}
