import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import type { Logger } from "../src/logger.js";
import { SlackChannelBackfillService } from "../src/learning/slack-channel-backfill.js";
import { SlackChannelBackfillStore } from "../src/learning/slack-channel-backfill-store.js";
import { SLACK_CHANNEL_CURATION_VERSION, SlackChannelLearningService } from "../src/learning/slack-channel-learning.js";
import type { SlackChannelHistoryReader } from "../src/slack/channel-history.js";
import type { SlackMessage } from "../src/slack/research/types.js";
import { testConfig } from "./fixtures.js";

const quietLogger: Logger = { info() {}, warn() {}, error() {} };

test("historical learning keeps human channel context and drops machine content", async () => {
  const config = testConfig({ learning: { channelLearningBatchSize: 3 } });
  const writes: any[] = [];
  const learning = new SlackChannelLearningService(config, {
    rememberWithRequiredCuration: async (input: any) => {
      writes.push(input);
      return { id: `memory-${writes.length}` } as any;
    },
  });
  const history = historyReader({
    roots: [
      { ts: "90", bot_id: "BAPP", text: "machine digest", reply_count: 3 },
      { ts: "80", user: "UHUMAN", text: "Verify the running service before closing the deploy." },
      { ts: "70", app_id: "AAPP", text: "machine status" },
      { ts: "60", user: "UHUMAN", subtype: "message_changed", text: "edited" },
    ],
    replies: {
      "90": [
        { ts: "90", bot_id: "BAPP", text: "machine digest", reply_count: 3 },
        { ts: "91", thread_ts: "90", user: "UHUMAN", text: "<@UOWNER> owns the release verification." },
        { ts: "92", thread_ts: "90", bot_id: "BAPP", text: "automated follow-up" },
        { ts: "93", thread_ts: "90", user: "UHUMAN", text: "<@UCEREBRO> inspect this" },
      ],
    },
  });
  const store = new SlackChannelBackfillStore(config);
  const service = new SlackChannelBackfillService({ history, learning, store, logger: quietLogger, sleep: async () => {} });

  const first = await service.run(backfillOptions(3));

  assert.equal(first.channelsDiscovered, 1);
  assert.equal(first.channelsProcessed, 1);
  assert.equal(first.rootsScanned, 4);
  assert.equal(first.threadMessagesScanned, 3);
  assert.equal(first.humanMessages, 2);
  assert.equal(first.machineMessages, 3);
  assert.equal(first.subtypeMessages, 1);
  assert.equal(first.directMentions, 1);
  assert.equal(first.recordsStored, 1);
  assert.equal(writes.length, 1);
  assert.match(writes[0].details, /@participant owns the release verification/);
  assert.match(writes[0].details, /Verify the running service/);
  assert.doesNotMatch(writes[0].details, /machine digest|machine status|automated follow-up|inspect this|UOWNER|UCEREBRO/);
  assert.deepEqual(writes[0].sourceArtifacts, ["slack:CTEAM:80", "slack:CTEAM:91"]);

  const second = await service.run(backfillOptions(3));
  assert.equal(second.channelsSkipped, 1);
  assert.equal(second.recordsStored, 1);
  assert.equal(writes.length, 1);
});

test("historical learning resumes a failed page without repeating a completed batch", async () => {
  const config = testConfig({ learning: { channelLearningBatchSize: 2 } });
  const roots: SlackMessage[] = [
    { ts: "9", user: "U1", text: "first" },
    { ts: "8", user: "U2", text: "second" },
    { ts: "7", user: "U3", text: "third" },
    { ts: "6", user: "U4", text: "fourth" },
  ];
  const history = historyReader({ roots, replies: {} });
  const store = new SlackChannelBackfillStore(config);
  const failedService = new SlackChannelBackfillService({
    history,
    store,
    logger: quietLogger,
    sleep: async () => {},
    learning: {
      learnBatch: async (_channelId, batch) => {
        if (batch[0]?.ts === "6") throw new Error("transient curation failure");
        return { accepted: true, reason: "stored", messageCount: batch.length, recordId: "first" };
      },
    },
  });

  await assert.rejects(() => failedService.run(backfillOptions(2)), /transient curation failure/);
  assert.equal((await store.checkpoint("CTEAM"))?.status, "failed");
  assert.equal((await store.checkpoint("CTEAM"))?.rootsScanned, 0);

  const learned: string[][] = [];
  const resumedService = new SlackChannelBackfillService({
    history,
    store,
    logger: quietLogger,
    sleep: async () => {},
    learning: {
      learnBatch: async (_channelId, batch) => {
        learned.push(batch.map((message) => message.ts));
        return { accepted: true, reason: "stored", messageCount: batch.length, recordId: "resumed" };
      },
    },
  });
  const receipt = await resumedService.run(backfillOptions(2));

  assert.deepEqual(learned, [["6", "7"]]);
  assert.equal(receipt.humanMessages, 4);
  assert.equal(receipt.batchesProcessed, 2);
  assert.equal(receipt.batchesSkipped, 1);
  assert.equal(receipt.recordsStored, 2);
  assert.equal((await store.checkpoint("CTEAM"))?.status, "completed");
});

test("historical learning retries a transiently failed page in the same run", async () => {
  const config = testConfig({ learning: { channelLearningBatchSize: 2 } });
  const roots: SlackMessage[] = [
    { ts: "9", user: "U1", text: "first" },
    { ts: "8", user: "U2", text: "second" },
    { ts: "7", user: "U3", text: "third" },
    { ts: "6", user: "U4", text: "fourth" },
  ];
  const store = new SlackChannelBackfillStore(config);
  const learned: string[][] = [];
  let transientFailures = 0;
  const service = new SlackChannelBackfillService({
    history: historyReader({ roots, replies: {} }),
    store,
    logger: quietLogger,
    sleep: async () => {},
    learning: {
      learnBatch: async (_channelId, batch) => {
        const timestamps = batch.map((message) => message.ts);
        learned.push(timestamps);
        if (timestamps[0] === "6" && transientFailures < 3) {
          transientFailures += 1;
          throw new Error("transient curation failure");
        }
        return {
          accepted: true,
          reason: "stored",
          messageCount: batch.length,
          recordId: "learned",
          recordsStored: timestamps[0] === "8" ? 2 : 3,
        };
      },
    },
  });

  const receipt = await service.run(backfillOptions(2));

  assert.deepEqual(learned, [["8", "9"], ["6", "7"], ["6", "7"], ["6", "7"], ["6", "7"]]);
  assert.equal(receipt.status, "completed");
  assert.equal(receipt.rootsScanned, 4);
  assert.equal(receipt.batchesProcessed, 2);
  assert.equal(receipt.batchesSkipped, 1);
  assert.equal(receipt.recordsStored, 5);
  assert.equal((await store.checkpoint("CTEAM"))?.status, "completed");
});

test("a new curation version replays legacy checkpoints and batch markers", async () => {
  const config = testConfig({ learning: { channelLearningBatchSize: 2 } });
  const store = new SlackChannelBackfillStore(config);
  await store.saveCheckpoint({
    channelId: "CTEAM",
    status: "completed",
    targetOldestTs: "1",
    snapshotTs: "200",
    nextLatestTs: "1",
    runId: "legacy-run",
    updatedAt: "2026-07-14T00:00:00.000Z",
    rootsScanned: 2,
    threadMessagesScanned: 0,
    threadErrors: 0,
    humanMessages: 2,
    machineMessages: 0,
    subtypeMessages: 0,
    missingUserMessages: 0,
    missingTimestampMessages: 0,
    emptyMessages: 0,
    directMentions: 0,
    batchesProcessed: 1,
    batchesSkipped: 0,
    recordsStored: 0,
    recordsRejected: 1,
  });
  const fingerprint = createHash("sha256").update("CTEAM|8|9").digest("hex").slice(0, 24);
  await store.markBatch({
    fingerprint,
    channelId: "CTEAM",
    messageCount: 2,
    result: "rejected",
    processedAt: "2026-07-14T00:00:00.000Z",
  });
  let calls = 0;
  const service = new SlackChannelBackfillService({
    history: historyReader({
      roots: [
        { ts: "9", user: "U1", text: "first" },
        { ts: "8", user: "U2", text: "second" },
      ],
      replies: {},
    }),
    store,
    logger: quietLogger,
    sleep: async () => {},
    learning: {
      learnBatch: async (_channelId, batch) => {
        calls += 1;
        return { accepted: true, reason: "stored", messageCount: batch.length, recordsStored: 2 };
      },
    },
  });

  const receipt = await service.run(backfillOptions(2));

  assert.equal(calls, 1);
  assert.equal(receipt.batchesSkipped, 0);
  assert.equal(receipt.recordsStored, 2);
  assert.equal((await store.checkpoint("CTEAM"))?.curationVersion, SLACK_CHANNEL_CURATION_VERSION);
  assert.equal((await store.batchMarker("CTEAM", fingerprint))?.curationVersion, SLACK_CHANNEL_CURATION_VERSION);
});

function historyReader(input: { roots: SlackMessage[]; replies: Record<string, SlackMessage[]> }): SlackChannelHistoryReader {
  return {
    botUserId: async () => "UCEREBRO",
    joinedChannels: async () => [{ id: "CTEAM", name: "team", isPrivate: true }],
    historyPage: async () => ({ messages: input.roots, hasMore: false }),
    threadReplies: async (_channelId, threadTs) => input.replies[threadTs] ?? [],
  };
}

function backfillOptions(batchSize: number) {
  return { targetOldestTs: "1", snapshotTs: "200", batchSize, maxChannels: 10, maxRootsPerChannel: 100 };
}
