import assert from "node:assert/strict";
import test from "node:test";
import { DailyNotesService } from "../src/learning/daily-notes.js";
import { testConfig } from "./fixtures.js";

test("daily notes stay private until the Pacific overnight consolidation window", async () => {
  let now = new Date("2026-06-26T19:00:00.000Z");
  const writes: any[] = [];
  let hygieneRuns = 0;
  const service = new DailyNotesService(
    testConfig({ learning: { tableName: undefined } }),
    {
      remember: async (input: any) => {
        writes.push(input);
        return { id: `memory-${writes.length}`, createdAt: now.toISOString(), tags: input.tags ?? [], ...input };
      },
      runHygiene: async () => {
        hygieneRuns += 1;
        return { checked: 0, expired: 0, duplicateExpired: 0, staleTransientExpired: 0, dryRun: false };
      },
    } as any,
    { now: () => now },
  );

  const note = await service.record({
    kind: "assistant_answer",
    title: "Slack question: login security",
    summary: "Checked Okta and GitHub posture for login security.",
    details: "Evidence: Okta MFA runtime healthy. Next: review GitHub findings.",
    tags: ["slack-question", "login"],
    channelId: "CSEC",
    sourceTs: "1.1",
    outcome: "answered",
    senderKind: "human",
    trafficKind: "human_request",
  });

  assert.equal(note?.localDate, "2026-06-26");
  assert.deepEqual(await service.consolidateIfDue(), { status: "outside_window" });
  assert.equal(writes.length, 0);
  assert.equal(hygieneRuns, 0);
});

test("daily notes consolidate yesterday into durable memory during Pacific night", async () => {
  let now = new Date("2026-06-26T19:00:00.000Z");
  const writes: any[] = [];
  let hygieneRuns = 0;
  const service = new DailyNotesService(
    testConfig({ learning: { tableName: undefined } }),
    {
      remember: async (input: any) => {
        writes.push(input);
        return { id: `memory-${writes.length}`, createdAt: now.toISOString(), tags: input.tags ?? [], ...input };
      },
      runHygiene: async () => {
        hygieneRuns += 1;
        return { checked: 2, expired: 1, duplicateExpired: 0, staleTransientExpired: 1, dryRun: false };
      },
    } as any,
    { now: () => now },
  );

  await service.record({
    kind: "assistant_answer",
    title: "Slack question: login security",
    summary: "Checked Okta and GitHub posture for login security.",
    details: "Evidence: Okta MFA runtime healthy. Next: review GitHub findings.",
    tags: ["slack-question", "login"],
    channelId: "CSEC",
    sourceTs: "1.1",
    outcome: "answered",
    senderKind: "human",
    trafficKind: "human_request",
  });
  await service.record({
    kind: "safety_refusal",
    title: "Refused Slack mention",
    summary: "The request asked Cerebro to delete the graph.",
    details: "Category: destructive_infrastructure",
    tags: ["safety-refusal", "destructive_infrastructure"],
    channelId: "CSEC",
    sourceTs: "1.2",
    outcome: "refused",
  });

  now = new Date("2026-06-27T09:45:00.000Z");
  const result = await service.consolidateIfDue();

  assert.equal(result.status, "consolidated");
  assert.equal(result.targetDate, "2026-06-26");
  assert.equal(result.noteCount, 2);
  assert.equal(writes.length, 2);
  assert.equal(writes[0].kind, "investigation_note");
  assert.equal(writes[0].topic, "Cerebro daily notes 2026-06-26");
  assert.match(writes[0].summary, /processed 2 noted event/);
  assert.match(writes[0].details, /assistant_answer/);
  assert.match(writes[0].details, /human_request=1/);
  assert.equal(writes[1].kind, "runbook_note");
  assert.match(writes[1].summary, /unsafe request/);
  assert.equal(hygieneRuns, 1);

  const second = await service.consolidateIfDue();
  assert.equal(second.status, "already_done");
  assert.equal(hygieneRuns, 1);
});
