import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  emptySourceHealthState,
  rankSourceHealth,
  recordSourceHealthObservation,
  snapshotSourceHealth,
  SourceHealthObservationConflictError,
  SourceHealthPolicyInvariantError,
  type SourceHealthSnapshotV1,
} from "../src/execution/source-health-policy.js";

const policy = {
  cooldown_ms: 5 * 60 * 1_000,
  failure_policy: {
    block_after_consecutive_failures: 2,
    observation_receipt_limit: 8,
  },
  slow_threshold_ms: 30_000,
} as const;

function observe(
  state: ReturnType<typeof emptySourceHealthState>,
  input: {
    idempotency_key: string;
    kind: "failure" | "success";
    latency_ms: number;
    observed_at: string;
  },
) {
  return recordSourceHealthObservation({
    observation: input,
    policy,
    state,
  });
}

describe("source health policy", () => {
  test("opens cooldown, permits a later probe, and recovers on success", () => {
    const initial = emptySourceHealthState("source:alpha", policy);
    const first = observe(initial, {
      idempotency_key: "observation-1",
      kind: "failure",
      latency_ms: 100,
      observed_at: "2026-07-18T10:00:00.000Z",
    });
    const second = observe(first.state, {
      idempotency_key: "observation-2",
      kind: "failure",
      latency_ms: 200,
      observed_at: "2026-07-18T10:01:00.000Z",
    });

    assert.deepEqual(second.state.cooldown, {
      cooldown_key:
        "source-health:12:source:alpha:observation-2",
      cooldown_until: "2026-07-18T10:06:00.000Z",
      observed_at: "2026-07-18T10:01:00.000Z",
      resource_ref: "source:alpha",
      schema_version: "capacity-cooldown/v1",
    });
    assert.deepEqual(
      snapshotSourceHealth({
        observed_at: "2026-07-18T10:02:00.000Z",
        policy,
        state: second.state,
      }),
      {
        allowed: false,
        attempts: 2,
        average_latency_ms: 150,
        consecutive_failures: 2,
        retry_after_ms: 240_000,
        schema_version: "source-health-snapshot/v1",
        slow: false,
        source_ref: "source:alpha",
        status: "cooldown",
        success_rate: 0,
      },
    );

    const probe = snapshotSourceHealth({
      observed_at: "2026-07-18T10:06:00.000Z",
      policy,
      state: second.state,
    });
    assert.equal(probe.allowed, true);
    assert.equal(probe.status, "degraded");
    assert.equal(probe.retry_after_ms, undefined);

    const recovered = observe(second.state, {
      idempotency_key: "observation-3",
      kind: "success",
      latency_ms: 300,
      observed_at: "2026-07-18T10:06:01.000Z",
    });
    assert.equal(recovered.state.cooldown, undefined);
    assert.deepEqual(
      snapshotSourceHealth({
        observed_at: "2026-07-18T10:06:01.000Z",
        policy,
        state: recovered.state,
      }),
      {
        allowed: true,
        attempts: 3,
        average_latency_ms: 200,
        consecutive_failures: 0,
        retry_after_ms: undefined,
        schema_version: "source-health-snapshot/v1",
        slow: false,
        source_ref: "source:alpha",
        status: "healthy",
        success_rate: 1 / 3,
      },
    );
  });

  test("replays only an exact observation without double counting", () => {
    const first = observe(emptySourceHealthState("source:alpha", policy), {
      idempotency_key: "observation-1",
      kind: "failure",
      latency_ms: 100,
      observed_at: "2026-07-18T10:00:00.000Z",
    });
    const replay = observe(first.state, {
      idempotency_key: "observation-1",
      kind: "failure",
      latency_ms: 100,
      observed_at: "2026-07-18T10:00:00.000Z",
    });

    assert.equal(replay.replayed, true);
    assert.equal(replay.state, first.state);
    assert.equal(replay.state.observation_receipts.length, 1);
    assert.throws(
      () =>
        observe(first.state, {
          idempotency_key: "observation-1",
          kind: "failure",
          latency_ms: 101,
          observed_at: "2026-07-18T10:00:00.000Z",
        }),
      SourceHealthObservationConflictError,
    );
  });

  test("keeps a successful slow source available but degraded", () => {
    const slow = observe(emptySourceHealthState("source:slow", policy), {
      idempotency_key: "observation-1",
      kind: "success",
      latency_ms: 30_000,
      observed_at: "2026-07-18T10:00:00.000Z",
    });
    const snapshot = snapshotSourceHealth({
      observed_at: "2026-07-18T10:00:01.000Z",
      policy,
      state: slow.state,
    });

    assert.equal(snapshot.allowed, true);
    assert.equal(snapshot.slow, true);
    assert.equal(snapshot.status, "degraded");
  });

  test("ranks available and healthy sources first with stable ties", () => {
    const snapshots: SourceHealthSnapshotV1[] = [
      snapshot("source:tie-a", "degraded", true, 0.5, 200),
      snapshot("source:cooldown", "cooldown", false, 1, 1),
      snapshot("source:healthy", "healthy", true, 0.2, 400),
      snapshot("source:fast", "degraded", true, 0.8, 100),
      snapshot("source:tie-b", "degraded", true, 0.5, 200),
    ];
    const original = [...snapshots];

    assert.deepEqual(
      rankSourceHealth(snapshots).map((candidate) => candidate.source_ref),
      [
        "source:healthy",
        "source:fast",
        "source:tie-a",
        "source:tie-b",
        "source:cooldown",
      ],
    );
    assert.deepEqual(snapshots, original);
  });

  test("rejects caller-owned state that no longer matches its receipts", () => {
    const first = observe(emptySourceHealthState("source:alpha", policy), {
      idempotency_key: "observation-1",
      kind: "failure",
      latency_ms: 100,
      observed_at: "2026-07-18T10:00:00.000Z",
    });
    const tampered = structuredClone(first.state);
    tampered.failure_state.consecutive_failures = 0;

    assert.throws(
      () =>
        snapshotSourceHealth({
          observed_at: "2026-07-18T10:00:01.000Z",
          policy,
          state: tampered,
        }),
      SourceHealthPolicyInvariantError,
    );
  });
});

function snapshot(
  sourceRef: string,
  status: SourceHealthSnapshotV1["status"],
  allowed: boolean,
  successRate: number,
  averageLatency: number,
): SourceHealthSnapshotV1 {
  return {
    allowed,
    attempts: 2,
    average_latency_ms: averageLatency,
    consecutive_failures: status === "cooldown" ? 2 : 0,
    retry_after_ms: status === "cooldown" ? 1_000 : undefined,
    schema_version: "source-health-snapshot/v1",
    slow: status === "degraded",
    source_ref: sourceRef,
    status,
    success_rate: successRate,
  };
}
