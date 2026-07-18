import assert from "node:assert/strict";
import test from "node:test";
import { SourceHealthRegistry } from "../src/agent/source-health.js";

test("source health cools down repeated failures and recovers after a successful probe", () => {
  let now = 1_000;
  const registry = new SourceHealthRegistry({ failureThreshold: 2, cooldownMs: 5_000, now: () => now });

  registry.recordFailure("cerebro_findings", 100);
  assert.deepEqual(registry.snapshot("cerebro_findings"), {
    source: "cerebro_findings",
    status: "degraded",
    allowed: true,
    attempts: 1,
    consecutive_failures: 1,
    success_rate: 0,
    average_latency_ms: 100,
    slow: false,
  });

  registry.recordFailure("cerebro_findings", 300);
  const cooledDown = registry.snapshot("cerebro_findings");
  assert.equal(cooledDown.status, "cooldown");
  assert.equal(cooledDown.allowed, false);
  assert.equal(cooledDown.retry_after_ms, 5_000);

  now += 5_001;
  assert.equal(registry.snapshot("cerebro_findings").allowed, true);
  registry.recordSuccess("cerebro_findings", 200);
  const recovered = registry.snapshot("cerebro_findings");
  assert.equal(recovered.status, "healthy");
  assert.equal(recovered.consecutive_failures, 0);
  assert.equal(recovered.success_rate, 1 / 3);
  assert.equal(recovered.average_latency_ms, 200);
});

test("source health marks consistently slow sources degraded", () => {
  const registry = new SourceHealthRegistry({ slowThresholdMs: 30_000 });
  registry.recordSuccess("slow_source", 45_000);

  const snapshot = registry.snapshot("slow_source");
  assert.equal(snapshot.status, "degraded");
  assert.equal(snapshot.allowed, true);
  assert.equal(snapshot.slow, true);
});

test("source health ranks healthy sources ahead of degraded and cooled-down sources", () => {
  const registry = new SourceHealthRegistry({ failureThreshold: 2 });
  registry.recordFailure("degraded");
  registry.recordFailure("cooldown");
  registry.recordFailure("cooldown");

  assert.deepEqual(registry.rank(["cooldown", "degraded", "healthy"]), ["healthy", "degraded", "cooldown"]);
});
