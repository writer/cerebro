import assert from "node:assert/strict";
import test from "node:test";
import {
  DynamoSharedRateLimitStore,
  InMemorySharedRateLimitStore,
  SharedRateLimitCoordinator,
  isRateLimitError,
} from "../src/a2a/index.js";

const options = { maxConcurrent: 2, leaseMs: 10_000, waitMs: 0 };

test("shared rate limiter caps concurrent leases across Cerebro instances", async () => {
  const store = new InMemorySharedRateLimitStore();
  const first = new SharedRateLimitCoordinator(store, "cerebro-1", () => 1_000);
  const second = new SharedRateLimitCoordinator(store, "cerebro-2", () => 1_000);

  const leaseOne = await first.acquire("model:opus", options);
  const leaseTwo = await second.acquire("model:opus", options);
  await assert.rejects(() => second.acquire("model:opus", options), /capacity unavailable/);

  await leaseOne.release();
  const replacement = await second.acquire("model:opus", options);
  assert.equal(replacement.slot, leaseOne.slot);
  await Promise.all([leaseTwo.release(), replacement.release()]);
});

test("expired leases are reclaimed when a Cerebro disappears", async () => {
  const store = new InMemorySharedRateLimitStore();
  let now = 1_000;
  const first = new SharedRateLimitCoordinator(store, "cerebro-1", () => now);
  const second = new SharedRateLimitCoordinator(store, "cerebro-2", () => now);

  await first.acquire("source:slack", { ...options, maxConcurrent: 1, leaseMs: 1_000 });
  now = 2_001;
  const replacement = await second.acquire("source:slack", { ...options, maxConcurrent: 1 });
  assert.equal(replacement.slot, 0);
  await replacement.release();
});

test("rate-limit cooldown is shared across Cerebros", async () => {
  const store = new InMemorySharedRateLimitStore();
  let now = 5_000;
  const first = new SharedRateLimitCoordinator(store, "cerebro-1", () => now);
  const second = new SharedRateLimitCoordinator(store, "cerebro-2", () => now);

  await first.recordRateLimit("source:cerebro", 10_000);
  await assert.rejects(() => second.acquire("source:cerebro", options), /capacity unavailable/);
  now = 15_001;
  const lease = await second.acquire("source:cerebro", options);
  await lease.release();
});

test("rate-limit detection recognizes provider status and throttling errors", () => {
  assert.equal(isRateLimitError({ $metadata: { httpStatusCode: 429 } }), true);
  assert.equal(isRateLimitError(new Error("ThrottlingException: too many requests")), true);
  assert.equal(isRateLimitError(new Error("validation failed")), false);
});

test("nested model stages reuse the owning workflow lease", async () => {
  const coordinator = new SharedRateLimitCoordinator(new InMemorySharedRateLimitStore(), "cerebro-1", () => 1_000);
  const result = await coordinator.withPermit("model:opus", { ...options, maxConcurrent: 1 }, () =>
    coordinator.withPermit("model:opus", { ...options, maxConcurrent: 1 }, async () => "completed"));
  assert.equal(result, "completed");
});

test("lease cleanup failure does not replace completed model work", async () => {
  class FailingReleaseStore extends InMemorySharedRateLimitStore {
    override async releaseSlot(): Promise<void> {
      throw new Error("lease cleanup unavailable");
    }
  }
  const coordinator = new SharedRateLimitCoordinator(new FailingReleaseStore(), "cerebro-1", () => 1_000);
  const result = await coordinator.withPermit("model:opus", { ...options, maxConcurrent: 1 }, async () => "ignored");
  assert.equal(result, "ignored");
});

test("Dynamo leases compare milliseconds while TTL records epoch seconds", async () => {
  const commands: Array<{ input?: Record<string, unknown> }> = [];
  const dynamo = { async send(command: unknown) { commands.push(command as { input?: Record<string, unknown> }); return {}; } };
  const store = new DynamoSharedRateLimitStore("learning", "writer", dynamo);

  assert.equal(await store.claimSlot("model:opus", 0, "owner-1", 121_000, 1_000), true);
  await store.setCooldown("model:opus", 181_000);
  await store.releaseSlot("model:opus", 0, "owner-1");

  const lease = commands[0]?.input as { Item?: Record<string, unknown>; ConditionExpression?: string };
  assert.equal(lease.Item?.lease_until, 121_000);
  assert.equal(lease.Item?.expires_at, 121);
  assert.match(lease.ConditionExpression ?? "", /lease_until/);
  const cooldown = commands[1]?.input as { ExpressionAttributeValues?: Record<string, unknown> };
  assert.equal(cooldown.ExpressionAttributeValues?.[":until"], 181_000);
  assert.equal(cooldown.ExpressionAttributeValues?.[":expires"], 181);
  const release = commands[2]?.input as {
    ConditionExpression?: string;
    ExpressionAttributeNames?: Record<string, unknown>;
    ExpressionAttributeValues?: Record<string, unknown>;
  };
  assert.equal(release.ConditionExpression, "#owner = :owner");
  assert.deepEqual(release.ExpressionAttributeNames, { "#owner": "owner" });
  assert.equal(release.ExpressionAttributeValues?.[":owner"], "owner-1");
});
