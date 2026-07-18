import assert from "node:assert/strict";
import test from "node:test";
import { parsePlannerOutput, SchedulePlannerService } from "../src/schedules/schedule-planner.js";
import { testConfig } from "./fixtures.js";

test("parsePlannerOutput accepts fenced JSON from the LLM", () => {
  const plan = parsePlannerOutput([
    "```json",
    JSON.stringify({
      description: "Weekday login posture",
      schedule: {
        kind: "weekdays",
        timeOfDay: { hour: 9, minute: 0 },
        timeZone: "America/Los_Angeles",
      },
      trigger: null,
      steps: [
        { id: "login", title: "Login posture", skill_id: "login-posture", prompt: "Check identity posture.", depends_on: [] },
      ],
      context_providers: ["runtime_health_snapshot"],
      warnings: "Used default channel.",
    }),
    "```",
  ].join("\n"));

  assert.equal(plan?.description, "Weekday login posture");
  assert.equal(plan?.schedule?.kind, "weekdays");
  assert.equal(plan?.steps[0]?.skillId, "login-posture");
  assert.deepEqual(plan?.contextProviders, ["runtime_health_snapshot"]);
  assert.deepEqual(plan?.warnings, ["Used default channel."]);
});

test("SchedulePlannerService finalizes a fake LLM plan", async () => {
  const service = new SchedulePlannerService(testConfig({ schedules: { defaultChannelId: "CSEC" } }), {
    complete: async ({ systemPrompt, userPrompt }) => {
      assert.match(systemPrompt, /Available pre-run context providers/);
      assert.match(userPrompt, /Operator text/);
      return JSON.stringify({
        description: "High-risk findings watch",
        schedule: {
          kind: "interval",
          everyMs: 7_200_000,
          timeZone: "America/Los_Angeles",
        },
        steps: [
          { id: "findings", title: "High-risk findings", skillId: "scary-findings", prompt: "Find high-risk open findings.", dependsOn: [] },
        ],
        contextProviders: ["open_findings_snapshot"],
        channelId: "CSEC",
        warnings: [],
      });
    },
  });

  const draft = await service.plan({
    text: "keep an eye on scary findings every couple hours",
    channelId: "CSEC",
    now: new Date("2026-06-26T16:00:00.000Z"),
  });

  assert.equal(draft.description, "High-risk findings watch");
  assert.equal(draft.schedule?.kind, "interval");
  assert.equal(draft.nextRunAt, "2026-06-26T18:00:00.000Z");
  assert.deepEqual(draft.contextProviders, ["open_findings_snapshot"]);
  assert.match(draft.steps[0]?.prompt ?? "", /Run security skill/);
});
