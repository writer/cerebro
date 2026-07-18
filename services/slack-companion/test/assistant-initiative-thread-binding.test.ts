import assert from "node:assert/strict";
import test from "node:test";
import { SlackDeliveryOutbox } from "../src/slack/delivery-outbox.js";
import { InMemorySlackDeliveryOutboxStore } from "../src/slack/delivery-outbox-store.js";
import { SlackThreadSessionStateStore } from "../src/triage/slack-thread-state.js";
import { testConfig } from "./fixtures.js";

test("outbox receipt recovery binds the actual Slack thread without posting twice", async () => {
  const deliveryStore = new InMemorySlackDeliveryOutboxStore();
  let now = new Date("2026-07-16T12:00:00.000Z");
  const threadState = new SlackThreadSessionStateStore(testConfig(), { now: () => now });
  let hookAttempts = 0;
  const outbox = new SlackDeliveryOutbox(testConfig(), {
    store: deliveryStore,
    now: () => now,
    workerId: "worker-a",
    retryBaseMs: 100,
    maxRetryMs: 100,
    beforeCompletePosted: async ({ delivery, postedTs }) => {
      hookAttempts += 1;
      if (hookAttempts === 1) throw new Error("binding store unavailable");
      await threadState.bindAssistantInitiativeReceipt({
        deliveryId: delivery.id,
        channelId: delivery.channelId,
        threadTs: delivery.threadTs ?? postedTs,
        receiptContext: delivery.receiptContext,
      });
    },
  });
  const queued = await outbox.enqueue({
    idempotencyKey: "initiative:source-loop:jonathan",
    channelId: "CSEC",
    text: "I found a concrete source-loop gap. Reply here if you want me to open the repair PR.",
    receiptContext: {
      kind: "assistant_initiative",
      refId: "initiative-source-loop",
      assistantInitiative: {
        intendedUserId: "UUSER",
        expiresAt: "2026-07-17T12:00:00.000Z",
        goalId: "goal-source-loop",
      },
    },
  });
  const posted: string[] = [];
  const client = {
    chat: {
      postMessage: async ({ client_msg_id }: { client_msg_id: string }) => {
        posted.push(client_msg_id);
        return { ts: "1784201000.000100" };
      },
    },
  };

  assert.equal((await outbox.tick(client))[0]?.status, "retry");
  now = new Date(now.getTime() + 100);
  assert.equal((await outbox.tick(client))[0]?.status, "posted");

  const binding = await threadState.getAssistantInitiativeBinding("CSEC", "1784201000.000100");
  assert.equal(binding?.initiativeId, "initiative-source-loop");
  assert.equal(binding?.deliveryId, queued.id);
  assert.equal(binding?.intendedUserId, "UUSER");
  assert.equal(binding?.goalId, "goal-source-loop");
  assert.equal(binding?.status, "open");
  assert.equal(hookAttempts, 2);
  assert.deepEqual(posted, [queued.clientMessageId]);
});

test("assistant initiative bindings expire and close fail-closed", async () => {
  let now = new Date("2026-07-16T12:00:00.000Z");
  const threadState = new SlackThreadSessionStateStore(testConfig(), { now: () => now });
  await threadState.bindAssistantInitiativeReceipt({
    deliveryId: "delivery-1",
    channelId: "CSEC",
    threadTs: "1784201000.000200",
    receiptContext: {
      kind: "assistant_initiative",
      refId: "initiative-expiry",
      assistantInitiative: {
        intendedUserId: "UUSER",
        expiresAt: "2026-07-16T12:01:00.000Z",
      },
    },
  });

  assert.equal((await threadState.matchAssistantInitiativeReply({
    channelId: "CSEC",
    threadTs: "1784201000.000200",
    userId: "UOTHER",
  })), undefined);
  assert.equal((await threadState.matchAssistantInitiativeReply({
    channelId: "CSEC",
    threadTs: "1784201000.000201",
    userId: "UUSER",
  })), undefined);
  assert.equal((await threadState.matchAssistantInitiativeReply({
    channelId: "COTHER",
    threadTs: "1784201000.000200",
    userId: "UUSER",
  })), undefined);
  assert.equal((await threadState.matchAssistantInitiativeReply({
    channelId: "CSEC",
    threadTs: "1784201000.000200",
    userId: "UUSER",
  }))?.initiativeId, "initiative-expiry");

  now = new Date("2026-07-16T12:01:00.000Z");
  assert.equal((await threadState.matchAssistantInitiativeReply({
    channelId: "CSEC",
    threadTs: "1784201000.000200",
    userId: "UUSER",
  })), undefined);
  const expired = await threadState.getAssistantInitiativeBinding("CSEC", "1784201000.000200");
  assert.equal(expired?.status, "closed");
  assert.equal(expired?.closeReason, "expired");
});

test("assistant initiative bindings preserve exact-user matching in DMs", async () => {
  const threadState = new SlackThreadSessionStateStore(testConfig(), { now: () => new Date("2026-07-16T12:00:00.000Z") });
  await threadState.bindAssistantInitiativeReceipt({
    deliveryId: "delivery-dm",
    channelId: "DSEC",
    threadTs: "1784201000.000250",
    receiptContext: {
      kind: "assistant_initiative",
      refId: "initiative-dm",
      assistantInitiative: {
        intendedUserId: "UUSER",
        expiresAt: "2026-07-17T12:00:00.000Z",
        goalId: `improvement-${"b".repeat(24)}`,
      },
    },
  });

  assert.equal(await threadState.matchAssistantInitiativeReply({
    channelId: "DSEC",
    threadTs: "1784201000.000250",
    userId: "UOTHER",
  }), undefined);
  assert.equal((await threadState.matchAssistantInitiativeReply({
    channelId: "DSEC",
    threadTs: "1784201000.000250",
    userId: "UUSER",
  }))?.goalId, `improvement-${"b".repeat(24)}`);
});

test("Dynamo bindings use one exact thread item and a consistent reply lookup", async () => {
  const dynamo = new RecordingInitiativeDynamo();
  const config = testConfig({ triage: { threadStateTableName: "learning" } });
  const threadState = new SlackThreadSessionStateStore(config, {
    dynamo,
    now: () => new Date("2026-07-16T12:00:00.000Z"),
  });

  await threadState.bindAssistantInitiativeReceipt({
    deliveryId: "delivery-dynamo",
    channelId: "CSEC",
    threadTs: "1784201000.000500",
    receiptContext: {
      kind: "assistant_initiative",
      refId: "initiative-dynamo",
      assistantInitiative: { intendedUserId: "UUSER" },
    },
  });
  const restored = await threadState.getAssistantInitiativeBinding("CSEC", "1784201000.000500");

  assert.equal(restored?.initiativeId, "initiative-dynamo");
  const update = dynamo.commands.find((command) => command.name === "UpdateCommand")!.input;
  assert.deepEqual(update.Key, {
    pk: "tenant#writer#slack-thread-sessions",
    sk: "assistant-initiative#CSEC#1784201000.000500",
  });
  assert.match(update.UpdateExpression, /if_not_exists\(intendedUserId/);
  assert.match(update.ConditionExpression, /initiativeId = :initiativeId/);
  assert.match(update.ConditionExpression, /intendedUserId = :intendedUserId/);
  const get = dynamo.commands.find((command) => command.name === "GetCommand")!.input;
  assert.deepEqual(get.Key, update.Key);
  assert.equal(get.ConsistentRead, true);
});

class RecordingInitiativeDynamo {
  readonly commands: Array<{ name: string; input: any }> = [];
  private item?: Record<string, unknown>;

  async send(command: any): Promise<unknown> {
    const name = command.constructor.name;
    const input = command.input;
    this.commands.push({ name, input });
    if (name === "UpdateCommand") {
      const values = input.ExpressionAttributeValues;
      this.item = {
        ...input.Key,
        initiativeId: values[":initiativeId"],
        deliveryId: values[":deliveryId"],
        channelId: values[":channelId"],
        threadTs: values[":threadTs"],
        intendedUserId: values[":intendedUserId"],
        status: values[":open"],
        expiresAt: values[":expiresAt"],
        createdAt: values[":createdAt"],
        updatedAt: values[":updatedAt"],
      };
      return { Attributes: this.item };
    }
    if (name === "GetCommand") return { Item: this.item };
    throw new Error(`Unexpected command ${name}`);
  }
}
