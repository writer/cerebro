import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  decideRunFailure,
  DependencyCircuitOpenError,
  emptyConsecutiveFailureState,
  FailurePolicyIdempotencyConflictError,
  recordConsecutiveFailure,
  resetConsecutiveFailures,
  TurnDependencyCircuit,
} from "../src/execution/repeated-failure-policy.js";

const policy = { block_after_consecutive_failures: 3 } as const;

describe("consecutive failure policy", () => {
  test("resets the active fingerprint and count after success", () => {
    const failed = recordConsecutiveFailure({
      failure_fingerprint: "timeout",
      idempotency_key: "observation-1",
      policy,
      state: emptyConsecutiveFailureState(),
    });
    const reset = resetConsecutiveFailures({
      idempotency_key: "observation-2",
      state: failed.state,
    });

    assert.equal(reset.status, "reset");
    assert.equal(reset.state.consecutive_failures, 0);
    assert.equal(reset.state.failure_fingerprint, undefined);
  });

  test("uses lifecycle-valid degradation, pause, and block transitions", () => {
    const first = decideRunFailure({
      current_run_state: "running",
      current_service_state: "ready",
      failure_fingerprint: "timeout",
      idempotency_key: "observation-1",
      policy,
      state: emptyConsecutiveFailureState(),
    });
    assert.equal(first.status, "degraded");
    assert.equal(first.run_state, "paused");
    assert.deepEqual(first.run_transitions, [
      { from: "running", to: "paused" },
    ]);
    assert.deepEqual(first.service_transition, {
      from: "ready",
      to: "degraded",
    });

    const second = decideRunFailure({
      current_run_state: "paused",
      current_service_state: "degraded",
      failure_fingerprint: "timeout",
      idempotency_key: "observation-2",
      policy,
      state: first.state,
    });
    const third = decideRunFailure({
      current_run_state: "paused",
      current_service_state: "degraded",
      failure_fingerprint: "timeout",
      idempotency_key: "observation-3",
      policy,
      state: second.state,
    });

    assert.equal(second.status, "degraded");
    assert.equal(third.status, "blocked");
    assert.equal(third.run_state, "blocked");
    assert.deepEqual(third.run_transitions, [
      { from: "paused", to: "blocked" },
    ]);
    assert.equal(third.service_transition, undefined);
  });

  test("replays an exact observation without consuming the budget twice", () => {
    const first = recordConsecutiveFailure({
      failure_fingerprint: "timeout",
      idempotency_key: "observation-1",
      policy,
      state: emptyConsecutiveFailureState(),
    });
    const replay = recordConsecutiveFailure({
      failure_fingerprint: "timeout",
      idempotency_key: "observation-1",
      policy,
      state: first.state,
    });

    assert.equal(replay.replayed, true);
    assert.equal(replay.state.consecutive_failures, 1);
    assert.throws(
      () =>
        recordConsecutiveFailure({
          failure_fingerprint: "unavailable",
          idempotency_key: "observation-1",
          policy,
          state: first.state,
        }),
      FailurePolicyIdempotencyConflictError,
    );
  });

  test("starts a new streak when the fingerprinted failure kind changes", () => {
    const first = recordConsecutiveFailure({
      failure_fingerprint: "timeout",
      idempotency_key: "observation-1",
      policy,
      state: emptyConsecutiveFailureState(),
    });
    const second = recordConsecutiveFailure({
      failure_fingerprint: "timeout",
      idempotency_key: "observation-2",
      policy,
      state: first.state,
    });
    const changed = recordConsecutiveFailure({
      failure_fingerprint: "unavailable",
      idempotency_key: "observation-3",
      policy,
      state: second.state,
    });

    assert.equal(changed.state.consecutive_failures, 1);
    assert.equal(changed.state.failure_fingerprint, "unavailable");
    assert.equal(changed.status, "degraded");
  });
});

describe("per-turn dependency circuit", () => {
  test("stops repeated calls and replays an invocation idempotently", async () => {
    const circuit = new TurnDependencyCircuit({
      block_after_consecutive_failures: 2,
      failure_fingerprint: (error) =>
        error instanceof Error ? error.message : String(error),
    });
    let calls = 0;
    const invoke = (idempotencyKey: string) =>
      circuit.execute(
        {
          dependency_ref: "dependency://lookup",
          idempotency_key: idempotencyKey,
          input_fingerprint: `input-${idempotencyKey}`,
        },
        () => {
          calls += 1;
          throw new Error("timeout");
        },
      );

    await assert.rejects(invoke("call-1"), /timeout/);
    await assert.rejects(invoke("call-1"), /timeout/);
    assert.equal(calls, 1);

    await assert.rejects(invoke("call-2"), /timeout/);
    await assert.rejects(invoke("call-3"), DependencyCircuitOpenError);
    assert.equal(calls, 2);
    assert.deepEqual(circuit.snapshot("dependency://lookup"), {
      consecutive_failures: 2,
      failure_fingerprint: "timeout",
      open: true,
    });
  });

  test("a successful dependency call resets the turn-local streak", async () => {
    const circuit = new TurnDependencyCircuit({
      block_after_consecutive_failures: 2,
      failure_fingerprint: () => "timeout",
    });
    const invocation = (idempotencyKey: string) => ({
      dependency_ref: "dependency://lookup",
      idempotency_key: idempotencyKey,
      input_fingerprint: `input-${idempotencyKey}`,
    });

    await assert.rejects(
      circuit.execute(invocation("call-1"), () => {
        throw new Error("timeout");
      }),
      /timeout/,
    );
    assert.equal(
      await circuit.execute(invocation("call-2"), () => "completed"),
      "completed",
    );
    await assert.rejects(
      circuit.execute(invocation("call-3"), () => {
        throw new Error("timeout");
      }),
      /timeout/,
    );

    assert.deepEqual(circuit.snapshot("dependency://lookup"), {
      consecutive_failures: 1,
      failure_fingerprint: "timeout",
      open: false,
    });
  });
});
