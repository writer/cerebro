import assert from "node:assert/strict";
import test from "node:test";
import { contextProviderSummary, finalizeSchedulePlan, nextRunAtFor, scheduleSummary, triggerSummary } from "../src/schedules/schedule-parser.js";

const baseOptions = {
  now: new Date("2026-06-26T16:00:00.000Z"),
  timeZone: "America/Los_Angeles",
  defaultChannelId: "CSEC",
  defaultRuntimeIds: ["writer-okta", "writer-github"],
};

test("finalizeSchedulePlan accepts an LLM-planned weekday DAG", () => {
  const draft = finalizeSchedulePlan({
    description: "Weekday security posture check",
    schedule: {
      kind: "weekdays",
      timeOfDay: { hour: 9, minute: 0 },
      timeZone: "America/Los_Angeles",
    },
    steps: [
      { id: "login", title: "Login posture", skillId: "login-posture", prompt: "Check identity posture.", dependsOn: [] },
      { id: "runtime", title: "Runtime health", skillId: "runtime-health", prompt: "Check runtime health.", dependsOn: [] },
      { id: "findings", title: "High-risk findings", skillId: "scary-findings", prompt: "Rank high-risk findings.", dependsOn: ["login", "runtime"] },
    ],
    contextProviders: ["health", "open-findings", "unknown-provider"],
    channelId: "CSEC",
  }, baseOptions);

  assert.equal(draft.schedule?.kind, "weekdays");
  assert.equal(draft.channelId, "CSEC");
  assert.equal(draft.steps.length, 3);
  assert.deepEqual(draft.steps.slice(0, 2).map((step) => step.dependsOn), [[], []]);
  assert.deepEqual(draft.steps[2]?.dependsOn, ["login", "runtime"]);
  assert.deepEqual(draft.contextProviders, ["runtime_health_snapshot", "open_findings_snapshot"]);
  assert.match(contextProviderSummary(draft.contextProviders), /Runtime health snapshot/);
  assert.match(draft.warnings.join("\n"), /unknown-provider/);
  assert.match(scheduleSummary(draft.schedule), /Weekdays at 09:00/);
  assert.match(draft.steps[0]?.prompt ?? "", /Run security skill/);
});

test("finalizeSchedulePlan accepts runtime health triggers", () => {
  const draft = finalizeSchedulePlan({
    description: "Runtime recovery check",
    trigger: {
      type: "runtime_health",
      runtimeId: "writer-okta",
      unhealthyOnly: true,
      cooldownMs: 3_600_000,
    },
    steps: [
      { id: "runtime", title: "Runtime health", skillId: "runtime-health", prompt: "Check the unhealthy runtime.", dependsOn: [] },
      { id: "login", title: "Login posture", skillId: "login-posture", prompt: "Review identity impact.", dependsOn: ["runtime"] },
    ],
  }, baseOptions);

  assert.equal(draft.trigger?.type, "runtime_health");
  assert.equal(draft.schedule, undefined);
  assert.equal(draft.nextRunAt, undefined);
  assert.match(triggerSummary(draft.trigger), /writer-okta/);
  assert.equal(draft.steps.length, 2);
  assert.deepEqual(draft.steps[1]?.dependsOn, ["runtime"]);
});

test("finalizeSchedulePlan accepts interval schedules and Slack channel ids", () => {
  const draft = finalizeSchedulePlan({
    description: "High-risk finding watch",
    schedule: {
      kind: "interval",
      everyMs: 7_200_000,
      timeZone: "America/Los_Angeles",
    },
    steps: [{ id: "findings", title: "High-risk findings", skillId: "scary-findings", prompt: "Find high-risk open findings.", dependsOn: [] }],
    channelId: "COPS",
  }, baseOptions);

  assert.equal(draft.schedule?.kind, "interval");
  assert.equal(draft.channelId, "COPS");
  assert.match(scheduleSummary(draft.schedule), /2 hour/);
});

test("finalizeSchedulePlan rejects plans without a schedule or trigger", () => {
  assert.throws(() => finalizeSchedulePlan({
    description: "Login posture",
    steps: [{ id: "login", title: "Login posture", skillId: "login-posture", prompt: "Check login posture.", dependsOn: [] }],
  }, baseOptions), /schedule or trigger/);
});

test("nextRunAtFor advances past elapsed daily time", () => {
  const next = nextRunAtFor({
    kind: "daily",
    timeOfDay: { hour: 8, minute: 0 },
    timeZone: "America/Los_Angeles",
  }, new Date("2026-06-26T16:00:00.000Z"));

  assert.equal(next, "2026-06-27T15:00:00.000Z");
});
