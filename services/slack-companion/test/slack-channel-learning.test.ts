import assert from "node:assert/strict";
import test from "node:test";
import { SlackChannelLearningService } from "../src/learning/slack-channel-learning.js";
import { SecurityMemoryCurator } from "../src/learning/security-memory-curator.js";
import { SecurityMemoryStore } from "../src/learning/security-memory/index.js";
import { testConfig } from "./fixtures.js";

test("joined channel learning sends only a redacted bounded batch to required curation", async () => {
  const writes: any[] = [];
  const service = new SlackChannelLearningService(
    testConfig({ learning: { channelLearningBatchSize: 2 } }),
    {
      rememberWithRequiredCuration: async (input: any) => {
        writes.push(input);
        return { id: "memory-1" } as any;
      },
    },
  );

  const first = service.observe({
    channelId: "GTEAM",
    ts: "1.1",
    text: "<@U123> owns the deploy token=xoxb-demo",
  });
  const second = service.observe({
    channelId: "GTEAM",
    ts: "1.2",
    text: "The release check is the service task definition, not the one-off task.",
  });
  await service.flushAll();

  assert.equal(first.accepted, true);
  assert.equal(second.accepted, true);
  assert.equal(writes.length, 1);
  assert.equal(writes[0].sourceKind, "slack_channel");
  assert.equal(writes[0].channelId, "GTEAM");
  assert.match(writes[0].details, /@participant/);
  assert.match(writes[0].details, /\[redacted_(?:slack_token|secret)\]/);
  assert.doesNotMatch(writes[0].details, /U123|xoxb-demo/);
  assert.deepEqual(writes[0].sourceArtifacts, ["slack:GTEAM:1.1", "slack:GTEAM:1.2"]);
});

test("joined channel learning ignores DMs and configured excluded channels", async () => {
  const writes: any[] = [];
  const service = new SlackChannelLearningService(
    testConfig({ learning: { channelLearningExcludedChannelIds: new Set(["CPRIVATE"]) } }),
    { rememberWithRequiredCuration: async (input: any) => writes.push(input) as any },
  );

  const directMessage = service.observe({ channelId: "DUSER", ts: "2.1", text: "private context" });
  const excluded = service.observe({ channelId: "CPRIVATE", ts: "2.2", text: "excluded context" });
  await service.flushAll();

  assert.equal(directMessage.reason, "unsupported_conversation");
  assert.equal(excluded.reason, "excluded_channel");
  assert.equal(writes.length, 0);
});

test("required curation fails closed when a memory store has no curator", async () => {
  const memory = new SecurityMemoryStore(testConfig());

  const record = await memory.rememberWithRequiredCuration({
    kind: "team_context",
    topic: "Uncurated passive Slack batch",
    summary: "This raw candidate must not be stored.",
    details: "Message 1: raw conversation",
    sourceKind: "slack_channel",
  });

  assert.equal(record, undefined);
  assert.deepEqual(await memory.search("raw conversation", 3), []);
});

test("required curation stores the curator result instead of the passive batch", async () => {
  let candidate: any;
  const memory = new SecurityMemoryStore(testConfig(), {
    curator: {
      curateWrite: async (input: any) => {
        candidate = input.candidate;
        return {
          shouldStore: true,
          reason: "Reusable release verification rule.",
          kind: "runbook_note",
          topic: "Release verification",
          summary: "Verify the running service task definition before reporting a release complete.",
          details: "Message 1: raw conversation that the curator tried to preserve",
          tags: ["release", "verification"],
          sourceKind: "slack_channel",
          sourceArtifacts: ["invented-ref"],
          verifiedBy: ["invented-verifier"],
          verifiedAt: "2026-07-14T00:00:00.000Z",
          confidence: 0.99,
          stalenessPolicy: "durable",
          promotionState: "promoted",
        };
      },
      curateRecall: async () => ({ queryIntent: "release", selections: [], rejected: [] }),
      curateHygiene: async () => ({ expire: [], keep: [] }),
    },
  });

  const stored = await memory.rememberWithRequiredCuration({
    kind: "team_context",
    topic: "Joined Slack channel context from CTEAM",
    summary: "Review this passive channel batch for reusable team or security context.",
    details: "Message 1: raw conversation that must not become durable memory",
    channelId: "CTEAM",
    sourceTs: "3.1",
    sourceKind: "slack_channel",
    sourceArtifacts: ["slack:CTEAM:3.1"],
  });

  assert.match(candidate.details, /raw conversation/);
  assert.equal(stored?.topic, "Release verification");
  assert.equal(stored?.summary, "Verify the running service task definition before reporting a release complete.");
  assert.equal(stored?.details, undefined);
  assert.deepEqual(stored?.sourceArtifacts, ["slack:CTEAM:3.1"]);
  assert.equal(stored?.verifiedBy, undefined);
  assert.equal(stored?.verifiedAt, undefined);
  assert.equal(stored?.confidence, 0.85);
  assert.equal(stored?.stalenessPolicy, "until_reverified");
  assert.equal(stored?.promotionState, "candidate");
});

test("joined channel learning extracts multiple source-backed memories from one batch", async () => {
  const calls: any[] = [];
  const curator = new SecurityMemoryCurator(testConfig(), {
    complete: async (input) => {
      calls.push(input);
      return JSON.stringify({
        reason: "The batch contains an owner rule and a release verification rule.",
        rejection_category: null,
        memories: [{
        should_store: true,
        reason: "Reusable ownership context.",
        kind: "owner_context",
        topic: "Release ownership",
        summary: "The release owner verifies the running service after deployment.",
        tags: ["release", "owner"],
        confidence: 0.8,
        source_kind: "slack_channel",
        source_artifacts: [],
        staleness_policy: "until_reverified",
        promotion_state: "candidate",
      }, {
        should_store: true,
        reason: "Reusable verification procedure.",
        kind: "runbook_note",
        topic: "Release verification",
        summary: "Check the running service task definition before reporting deployment complete.",
        tags: ["release", "verification"],
        confidence: 0.9,
        source_kind: "slack_channel",
        source_artifacts: [],
        staleness_policy: "until_reverified",
        promotion_state: "candidate",
        }],
      });
    },
  });
  const memory = new SecurityMemoryStore(testConfig(), { curator });
  const service = new SlackChannelLearningService(testConfig({ learning: { channelLearningBatchSize: 2 } }), memory);

  const result = await service.learnBatch("CTEAM", [
    { channelId: "CTEAM", ts: "4.1", text: "The release owner verifies the running service." },
    { channelId: "CTEAM", ts: "4.2", text: "Use the service task definition before calling the deploy complete." },
  ]);
  const stored = await memory.recordsBySourceKind("slack_channel");

  assert.equal(result.reason, "stored");
  assert.equal(result.recordsStored, 2);
  assert.equal(result.recordIds?.length, 2);
  assert.equal(stored.length, 2);
  assert.deepEqual(stored.map((record) => record.topic).sort(), ["Release ownership", "Release verification"]);
  assert.ok(stored.every((record) => record.details === undefined));
  assert.ok(stored.every((record) => record.promotionState === "candidate"));
  assert.ok(stored.every((record) => record.stalenessPolicy === "until_reverified"));
  assert.ok(stored.every((record) => record.confidence === 0.8 || record.confidence === 0.85));
  assert.ok(stored.every((record) => record.sourceArtifacts?.join(",") === "slack:CTEAM:4.1,slack:CTEAM:4.2"));
  assert.equal(calls[0]?.modelLane, "orchestrator");
  assert.match(calls[0]?.systemPrompt ?? "", /every distinct durable fact/);
  assert.match(calls[0]?.systemPrompt ?? "", /duplicate_only/);
});

test("joined channel learning records why a batch produced no reusable memory", async () => {
  const curator = new SecurityMemoryCurator(testConfig(), {
    complete: async () => JSON.stringify({
      reason: "The messages are social coordination with no reusable operating fact.",
      rejection_category: "social_chatter",
      memories: [],
    }),
  });
  const memory = new SecurityMemoryStore(testConfig(), { curator });
  const service = new SlackChannelLearningService(testConfig(), memory);

  const result = await service.learnBatch("CTEAM", [
    { channelId: "CTEAM", ts: "5.1", text: "Thanks, sounds good." },
  ]);

  assert.equal(result.reason, "rejected");
  assert.equal(result.recordsStored, 0);
  assert.equal(result.rejectionCategory, "social_chatter");
});

test("passive Slack curation uses the configured orchestrator model lane", async () => {
  const calls: any[] = [];
  const curator = new SecurityMemoryCurator(testConfig(), {
    complete: async (input) => {
      calls.push(input);
      return JSON.stringify({ should_store: false, reason: "No reusable context." });
    },
  });

  await curator.curateWrite({
    candidate: {
      kind: "team_context",
      topic: "Joined Slack channel context from CTEAM",
      summary: "Review this passive channel batch.",
      sourceKind: "slack_channel",
    },
    now: new Date("2026-07-14T00:00:00.000Z"),
    recent: [],
  });

  assert.equal(calls[0]?.modelLane, "orchestrator");
  assert.match(calls[0]?.systemPrompt ?? "", /company work reusable value/);
  assert.match(calls[0]?.systemPrompt ?? "", /store the disagreement/);
});

test("joined-channel learning refuses a non-Opus orchestrator", async () => {
  const curator = new SecurityMemoryCurator(testConfig({ triage: { pi: { model: "baseline-model" } } }), {
    complete: async () => JSON.stringify({ should_store: false, reason: "No reusable context." }),
  });

  await assert.rejects(curator.curateWrite({
    candidate: {
      kind: "team_context",
      topic: "Joined Slack channel context from CTEAM",
      summary: "Review this passive channel batch.",
      sourceKind: "slack_channel",
    },
    now: new Date("2026-07-14T00:00:00.000Z"),
    recent: [],
  }), /requires a configured Opus model/);
});
