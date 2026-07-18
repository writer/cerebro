import assert from "node:assert/strict";
import test from "node:test";
import { InMemoryImprovementArtifactStore } from "../src/improvement/artifacts.js";
import { ImprovementControlPlane } from "../src/improvement/control-plane.js";
import { SlackImprovementHumanAssistancePublisher } from "../src/improvement/human-assistance.js";
import { InMemoryImprovementJobQueue } from "../src/improvement/queue.js";
import { InMemoryImprovementRunStore } from "../src/improvement/store.js";
import type { ImprovementSignal } from "../src/improvement/types.js";
import { SlackDeliveryOutbox } from "../src/slack/delivery-outbox.js";
import { InMemorySlackDeliveryOutboxStore } from "../src/slack/delivery-outbox-store.js";
import { testConfig } from "./fixtures.js";

const now = () => new Date("2026-07-14T18:00:00.000Z");
const candidate = { repo: "WriterInternal/cerebro-slack-companion", baseRef: "main" };
const assistance = { humanAssistance: { channelId: "CSEC", intendedUserId: "UUSER" } };

test("a threshold-crossing improvement queues one exact-user assistance initiative without copying private context", async () => {
  const runStore = new InMemoryImprovementRunStore();
  const artifacts = new InMemoryImprovementArtifactStore();
  const queue = new InMemoryImprovementJobQueue();
  const deliveryStore = new InMemorySlackDeliveryOutboxStore();
  const outbox = new SlackDeliveryOutbox(testConfig(), { store: deliveryStore, now });
  const controlPlane = new ImprovementControlPlane({
    store: runStore,
    artifacts,
    queue,
    signalThreshold: 2,
    cooldownHours: 168,
    humanAssistance: new SlackImprovementHumanAssistancePublisher(outbox, { now }),
    now,
  });

  const first = await controlPlane.observe(signal("Private customer question one"), candidate, assistance);
  assert.equal(first?.status, "observed");
  assert.equal((await deliveryStore.listDue("9999-12-31T23:59:59.999Z", 10)).length, 0);

  const crossingSignal = signal("Private customer question two", "2026-07-14T18:01:00.000Z");
  const queued = await controlPlane.observe(crossingSignal, candidate, assistance);
  await controlPlane.observe(crossingSignal, candidate, assistance);

  const deliveries = await deliveryStore.listDue("9999-12-31T23:59:59.999Z", 10);
  assert.equal(queued?.status, "queued");
  assert.equal(queue.jobs.length, 1);
  assert.equal(deliveries.length, 1);
  const delivery = deliveries[0]!;
  assert.match(delivery.text, /^<@UUSER> I recorded 2 feedback did not act signals in self improvement and queued work to author a draft repair\./);
  assert.match(delivery.text, /What exact outcome should its regression test prove\?$/);
  assert.doesNotMatch(delivery.text, /Private customer question/);
  assert.deepEqual(delivery.receiptContext, {
    kind: "assistant_initiative",
    refId: `improvement-assistance:${queued!.id}`,
    assistantInitiative: {
      intendedUserId: "UUSER",
      expiresAt: "2026-07-17T18:00:00.000Z",
      goalId: queued!.id,
    },
  });
  assert.equal(delivery.text.match(/<@/g)?.length, 1);
  assert.doesNotMatch(delivery.text, /<!here>|<!channel>|<!everyone>/);
  assert.doesNotMatch(JSON.stringify(queue.jobs), /CSEC|UUSER|Private customer question/);
  assert.doesNotMatch(JSON.stringify([...artifacts.values.values()]), /CSEC|UUSER/);
});

test("assistance enqueue retries after the durable queued transition without requeueing or duplicate delivery", async () => {
  const runStore = new InMemoryImprovementRunStore();
  const queue = new InMemoryImprovementJobQueue();
  const deliveryStore = new InMemorySlackDeliveryOutboxStore();
  const outbox = new SlackDeliveryOutbox(testConfig(), { store: deliveryStore, now });
  let shouldFail = true;
  const publisher = new SlackImprovementHumanAssistancePublisher({
    enqueue: async (input) => {
      if (shouldFail) {
        shouldFail = false;
        throw new Error("delivery store unavailable");
      }
      return outbox.enqueue(input);
    },
  }, { now });
  const controlPlane = new ImprovementControlPlane({
    store: runStore,
    artifacts: new InMemoryImprovementArtifactStore(),
    queue,
    signalThreshold: 1,
    cooldownHours: 168,
    humanAssistance: publisher,
    now,
  });
  const crossingSignal = signal("Private customer question");

  await assert.rejects(controlPlane.observe(crossingSignal, candidate, assistance), /delivery store unavailable/);
  assert.equal([...runStore.runs.values()][0]?.status, "queued");
  assert.equal(queue.jobs.length, 1);

  await controlPlane.reconcilePending();
  assert.equal((await deliveryStore.listDue("9999-12-31T23:59:59.999Z", 10)).length, 1);
  await controlPlane.reconcilePending();

  assert.equal(queue.jobs.length, 1);
  assert.equal(runStore.events.filter((event) => event.type === "author_requested").length, 1);
  assert.equal((await deliveryStore.listDue("9999-12-31T23:59:59.999Z", 10)).length, 1);
});

test("an exact human reply records one redacted run-bound outcome and rejects a conflicting reply", async () => {
  const runStore = new InMemoryImprovementRunStore();
  const artifacts = new InMemoryImprovementArtifactStore();
  const queue = new InMemoryImprovementJobQueue();
  const controlPlane = new ImprovementControlPlane({
    store: runStore,
    artifacts,
    queue,
    signalThreshold: 1,
    cooldownHours: 168,
    now,
  });
  const queued = await controlPlane.observe(signal("Private customer question"), candidate, assistance);
  assert.ok(queued);

  assert.equal(await controlPlane.recordHumanAssistanceOutcome({
    runId: queued.id,
    channelId: "CSEC",
    intendedUserId: "UOTHER",
    outcome: "wrong user",
  }), undefined);
  assert.equal(await controlPlane.recordHumanAssistanceOutcome({
    runId: `improvement-${"f".repeat(24)}`,
    channelId: "CSEC",
    intendedUserId: "UUSER",
    outcome: "wrong run",
  }), undefined);

  const rawOutcome = "Prove a retry succeeds without token=abc123, <@U09GFTUDY1Y>, C0BJ7JD5L3A, or 1784183855.454569.";
  const refined = await controlPlane.recordHumanAssistanceOutcome({
    runId: queued.id,
    channelId: "CSEC",
    intendedUserId: "UUSER",
    outcome: rawOutcome,
  });
  assert.equal(refined?.status, "queued");
  assert.equal(refined?.assistance?.deliveryStatus, "answered");
  assert.equal(refined?.assistance?.refinementStatus, "pending");
  assert.equal(queue.jobs.length, 2);
  assert.doesNotMatch(JSON.stringify(queue.jobs), /abc123|U09GFTUDY1Y|C0BJ7JD5L3A|1784183855/);
  const storedOutcome = [...artifacts.values.values()].find((value: any) => value?.reason === "human-regression-outcome");
  assert.match(JSON.stringify(storedOutcome), /Required regression outcome/);
  assert.doesNotMatch(JSON.stringify(storedOutcome), /abc123|U09GFTUDY1Y|C0BJ7JD5L3A|1784183855/);

  const duplicate = await controlPlane.recordHumanAssistanceOutcome({
    runId: queued.id,
    channelId: "CSEC",
    intendedUserId: "UUSER",
    outcome: rawOutcome,
  });
  assert.equal(duplicate?.assistance?.outcomeArtifact?.sha256, refined?.assistance?.outcomeArtifact?.sha256);
  assert.equal(queue.jobs.length, 2);
  await assert.rejects(controlPlane.recordHumanAssistanceOutcome({
    runId: queued.id,
    channelId: "CSEC",
    intendedUserId: "UUSER",
    outcome: "Prove a different behavior.",
  }), /different human regression outcome/);
});

test("a DM recipient is persisted and enqueued without changing its delivery fingerprint", async () => {
  const runStore = new InMemoryImprovementRunStore();
  const deliveryStore = new InMemorySlackDeliveryOutboxStore();
  const outbox = new SlackDeliveryOutbox(testConfig(), { store: deliveryStore, now });
  const controlPlane = new ImprovementControlPlane({
    store: runStore,
    artifacts: new InMemoryImprovementArtifactStore(),
    queue: new InMemoryImprovementJobQueue(),
    signalThreshold: 1,
    cooldownHours: 168,
    humanAssistance: new SlackImprovementHumanAssistancePublisher(outbox, { now }),
    now,
  });
  const queued = await controlPlane.observe(signal("Private customer question"), candidate, {
    humanAssistance: { channelId: "DSEC", intendedUserId: "UUSER" },
  });
  const deliveries = await deliveryStore.listDue("9999-12-31T23:59:59.999Z", 10);
  assert.equal(queued?.assistance?.channelId, "DSEC");
  assert.equal(deliveries[0]?.channelId, "DSEC");
  assert.equal(deliveries.length, 1);
});

function signal(question: string, occurredAt = "2026-07-14T18:00:00.000Z"): ImprovementSignal {
  return {
    signature: "self-repair:self-improvement:feedback-did-not-act",
    source: "feedback_downvote",
    issueKind: "feedback-did-not-act",
    skillId: "self-improvement",
    occurredAt,
    channelHash: "0123456789abcdef",
    question,
    answer: "Private assistant answer",
    toolNames: [],
    evidenceCount: 0,
    actionCount: 0,
    commitmentStates: [],
  };
}
