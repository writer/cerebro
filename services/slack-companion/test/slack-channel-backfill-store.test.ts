import assert from "node:assert/strict";
import test from "node:test";
import { SlackChannelBackfillStore, type SlackChannelBackfillCheckpoint } from "../src/learning/slack-channel-backfill-store.js";
import { testConfig } from "./fixtures.js";

test("backfill state round-trips checkpoints and metadata-only batch markers", async () => {
  const store = new SlackChannelBackfillStore(testConfig());
  const checkpoint: SlackChannelBackfillCheckpoint = {
    channelId: "CTEAM",
    status: "running",
    targetOldestTs: "1",
    snapshotTs: "10",
    nextLatestTs: "7",
    runId: "run-1",
    updatedAt: "2026-07-15T00:00:00.000Z",
    rootsScanned: 3,
    threadMessagesScanned: 2,
    threadErrors: 0,
    humanMessages: 4,
    machineMessages: 1,
    subtypeMessages: 0,
    missingUserMessages: 0,
    missingTimestampMessages: 0,
    emptyMessages: 0,
    directMentions: 0,
    batchesProcessed: 1,
    batchesSkipped: 0,
    recordsStored: 1,
    recordsRejected: 0,
  };
  await store.saveCheckpoint(checkpoint);
  await store.markBatch({ fingerprint: "fingerprint", channelId: "CTEAM", messageCount: 4, result: "stored", processedAt: checkpoint.updatedAt });

  assert.deepEqual(await store.checkpoint("CTEAM"), checkpoint);
  assert.deepEqual(await store.batchMarker("CTEAM", "fingerprint"), {
    fingerprint: "fingerprint",
    channelId: "CTEAM",
    messageCount: 4,
    result: "stored",
    processedAt: checkpoint.updatedAt,
  });
  assert.equal(await store.batchMarker("CTEAM", "missing"), undefined);
});
