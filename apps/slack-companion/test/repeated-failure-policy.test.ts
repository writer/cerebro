import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  decideRunFailure,
  DependencyCircuitOpenError,
  emptyConsecutiveFailureState,
  FailureObservationLimitError,
  FailurePolicyIdempotencyConflictError,
  recordConsecutiveFailure,
  resetConsecutiveFailures,
  TurnDependencyCircuit,
} from "../src/execution/repeated-failure-policy.js";

const policy = {
  block_after_consecutive_failures: 3,
  observation_receipt_limit: 8,
} as const;

describe("consecutive failure policy", () => {
  test("resets the active fingerprint and count after success", () => {
    const failed = recordConsecutiveFailure({
      failure_fingerprint: "timeout",
      idempotency_key: "obs-1",
      policy,
      state: emptyConsecutiveFailureState(policy),
    });
    const reset = resetConsecutiveFailures({
      idempotency_key: "obs-2",
      policy,
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
      idempotency_key: "obs-1",
      policy,
      state: emptyConsecutiveFailureState(policy),
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
      idempotency_key: "obs-2",
      policy,
      state: first.state,
    });
    const third = decideRunFailure({
      current_run_state: "paused",
      current_service_state: "degraded",
      failure_fingerprint: "timeout",
      idempotency_key: "obs-3",
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
      idempotency_key: "obs-1",
      policy,
      state: emptyConsecutiveFailureState(policy),
    });
    const replay = recordConsecutiveFailure({
      failure_fingerprint: "timeout",
      idempotency_key: "obs-1",
      policy,
      state: first.state,
    });

    assert.equal(replay.replayed, true);
    assert.equal(replay.state.consecutive_failures, 1);
    assert.throws(
      () =>
        recordConsecutiveFailure({
          failure_fingerprint: "unavailable",
          idempotency_key: "obs-1",
          policy,
          state: first.state,
        }),
      FailurePolicyIdempotencyConflictError,
    );
  });

  test("starts a new streak when the fingerprinted failure kind changes", () => {
    const first = recordConsecutiveFailure({
      failure_fingerprint: "timeout",
      idempotency_key: "obs-1",
      policy,
      state: emptyConsecutiveFailureState(policy),
    });
    const second = recordConsecutiveFailure({
      failure_fingerprint: "timeout",
      idempotency_key: "obs-2",
      policy,
      state: first.state,
    });
    const changed = recordConsecutiveFailure({
      failure_fingerprint: "unavailable",
      idempotency_key: "obs-3",
      policy,
      state: second.state,
    });

    assert.equal(changed.state.consecutive_failures, 1);
    assert.equal(changed.state.failure_fingerprint, "unavailable");
    assert.equal(changed.status, "degraded");
  });

  test("replays retained observations after intervening outcomes", () => {
    const first = recordConsecutiveFailure({
      failure_fingerprint: "timeout",
      idempotency_key: "obs-1",
      policy,
      state: emptyConsecutiveFailureState(policy),
    });
    const success = resetConsecutiveFailures({
      idempotency_key: "obs-2",
      policy,
      state: first.state,
    });
    const changed = recordConsecutiveFailure({
      failure_fingerprint: "unavailable",
      idempotency_key: "obs-3",
      policy,
      state: success.state,
    });

    const oldFailure = recordConsecutiveFailure({
      failure_fingerprint: "timeout",
      idempotency_key: "obs-1",
      policy,
      state: changed.state,
    });
    assert.equal(oldFailure.replayed, true);
    assert.equal(oldFailure.receipt.consecutive_failures, 1);
    assert.equal(oldFailure.state, changed.state);
    assert.equal(oldFailure.state.consecutive_failures, 1);
    assert.equal(oldFailure.state.failure_fingerprint, "unavailable");

    const oldSuccess = resetConsecutiveFailures({
      idempotency_key: "obs-2",
      policy,
      state: changed.state,
    });
    assert.equal(oldSuccess.replayed, true);
    assert.equal(oldSuccess.state, changed.state);
    assert.equal(oldSuccess.state.consecutive_failures, 1);
    assert.equal(oldSuccess.state.failure_fingerprint, "unavailable");
  });

  test("fails closed when the bounded receipt window is exhausted", () => {
    const boundedPolicy = {
      block_after_consecutive_failures: 3,
      observation_receipt_limit: 3,
    } as const;
    const first = recordConsecutiveFailure({
      failure_fingerprint: "timeout",
      idempotency_key: "obs-1",
      policy: boundedPolicy,
      state: emptyConsecutiveFailureState(boundedPolicy),
    });
    const reset = resetConsecutiveFailures({
      idempotency_key: "obs-2",
      policy: boundedPolicy,
      state: first.state,
    });
    const third = recordConsecutiveFailure({
      failure_fingerprint: "unavailable",
      idempotency_key: "obs-3",
      policy: boundedPolicy,
      state: reset.state,
    });

    assert.throws(
      () =>
        recordConsecutiveFailure({
          failure_fingerprint: "changed",
          idempotency_key: "obs-4",
          policy: boundedPolicy,
          state: third.state,
        }),
      FailureObservationLimitError,
    );
    assert.equal(third.state.observation_receipts.length, 3);
  });
});

describe("per-turn dependency circuit", () => {
  test("stops repeated calls and replays an invocation idempotently", async () => {
    const circuit = new TurnDependencyCircuit({
      block_after_consecutive_failures: 2,
      failure_fingerprint: (error) =>
        error instanceof Error ? error.message : String(error),
      observation_receipt_limit: 8,
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
      observation_receipt_limit: 8,
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

  test("coalesces concurrent exact calls and rejects changed in-flight input", async () => {
    const circuit = new TurnDependencyCircuit({
      block_after_consecutive_failures: 2,
      failure_fingerprint: () => "timeout",
      observation_receipt_limit: 8,
    });
    const invocation = {
      dependency_ref: "dependency://lookup",
      idempotency_key: "call-1",
      input_fingerprint: "input-1",
    };
    let calls = 0;
    let resolveOperation: ((value: string) => void) | undefined;
    const first = circuit.execute(invocation, () => {
      calls += 1;
      return new Promise<string>((resolve) => {
        resolveOperation = resolve;
      });
    });
    const duplicate = circuit.execute(invocation, () => {
      calls += 1;
      return "duplicate";
    });
    const conflict = circuit.execute(
      { ...invocation, input_fingerprint: "changed-input" },
      () => {
        calls += 1;
        return "conflict";
      },
    );

    await assert.rejects(conflict, FailurePolicyIdempotencyConflictError);
    assert.equal(calls, 1);
    assert.ok(resolveOperation);
    resolveOperation("completed");
    assert.deepEqual(await Promise.all([first, duplicate]), [
      "completed",
      "completed",
    ]);
    assert.equal(calls, 1);
  });

  test("coalesces the error from concurrent exact calls", async () => {
    const circuit = new TurnDependencyCircuit({
      block_after_consecutive_failures: 2,
      failure_fingerprint: () => "timeout",
      observation_receipt_limit: 8,
    });
    const invocation = {
      dependency_ref: "dependency://lookup",
      idempotency_key: "call-1",
      input_fingerprint: "input-1",
    };
    const failure = new Error("timeout");
    let calls = 0;
    let rejectOperation: ((error: Error) => void) | undefined;
    const first = circuit.execute(invocation, () => {
      calls += 1;
      return new Promise<string>((_resolve, reject) => {
        rejectOperation = reject;
      });
    });
    const duplicate = circuit.execute(invocation, () => {
      calls += 1;
      return "duplicate";
    });

    assert.equal(calls, 1);
    assert.ok(rejectOperation);
    rejectOperation(failure);
    const outcomes = await Promise.allSettled([first, duplicate]);
    assert.equal(outcomes[0]?.status, "rejected");
    assert.equal(outcomes[1]?.status, "rejected");
    if (
      outcomes[0]?.status !== "rejected" ||
      outcomes[1]?.status !== "rejected"
    ) {
      assert.fail("expected both calls to reject");
    }
    assert.equal(outcomes[0].reason, failure);
    assert.equal(outcomes[1].reason, failure);
    assert.equal(calls, 1);
  });

  test("reserves bounded receipt capacity before concurrent calls", async () => {
    const circuit = new TurnDependencyCircuit({
      block_after_consecutive_failures: 2,
      failure_fingerprint: () => "timeout",
      observation_receipt_limit: 2,
    });
    let calls = 0;
    await circuit.execute(
      {
        dependency_ref: "dependency://lookup",
        idempotency_key: "call-1",
        input_fingerprint: "input-1",
      },
      () => {
        calls += 1;
        return "completed";
      },
    );

    let resolveOperation: ((value: string) => void) | undefined;
    const pending = circuit.execute(
      {
        dependency_ref: "dependency://lookup",
        idempotency_key: "call-2",
        input_fingerprint: "input-2",
      },
      () => {
        calls += 1;
        return new Promise<string>((resolve) => {
          resolveOperation = resolve;
        });
      },
    );
    const overCapacity = circuit.execute(
      {
        dependency_ref: "dependency://lookup",
        idempotency_key: "call-3",
        input_fingerprint: "input-3",
      },
      () => {
        calls += 1;
        return "must-not-run";
      },
    );

    await assert.rejects(overCapacity, FailureObservationLimitError);
    assert.equal(calls, 2);
    assert.ok(resolveOperation);
    resolveOperation("completed");
    assert.equal(await pending, "completed");
    assert.equal(calls, 2);
  });
});
