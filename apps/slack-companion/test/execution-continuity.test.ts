import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { RunReceiptV1 } from "@writer/cerebro-sdk";
import {
  ExecutionCoordinator,
  ExecutionInvariantError,
} from "../src/execution/coordinator.js";
import type {
  CheckpointDraft,
  ExecutionSession,
  ServiceAvailabilityState,
} from "../src/execution/model.js";
import {
  ReferenceMemoryExecutionStore,
  StaleLeaseError,
} from "../src/execution/reference-store.js";

describe("ExecutionCoordinator", () => {
  test("claims a turn idempotently and admits leases only while executable", async () => {
    const fixture = makeFixture();
    const first = await fixture.start("ready", 1, "worker-a", "lease-a");
    const duplicate = await fixture.start("ready", 1, "worker-a", "lease-a");
    const competing = await fixture.start("ready", 1, "worker-b", "lease-b");

    if (first.status === "not_runnable" || duplicate.status === "not_runnable") {
      assert.fail("expected the stable lease claim to be idempotent");
    }
    assert.equal(first.status, "started");
    assert.equal(duplicate.status, "started");
    assert.equal(competing.status, "not_runnable");
    assert.equal(
      duplicate.session.lease.fencing_token,
      first.session.lease.fencing_token,
    );
    assert.equal(duplicate.session.run.revision, first.session.run.revision);

    assert.equal((await fixture.coordinator.release(first.session)).state, "queued");
    const replacement = await fixture.start("ready", 2, "worker-b", "lease-b");
    if (replacement.status === "not_runnable") {
      assert.fail("expected released work to be claimable");
    }
    assert.equal(
      replacement.session.lease.fencing_token,
      first.session.lease.fencing_token + 1,
    );

    for (const state of ["draining", "recovering", "offline"] as const) {
      const other = makeFixture(`run-${state}`);
      assert.equal(
        (await other.start(state, 2, "worker-c", `lease-${state}`)).status,
        "not_runnable",
      );
    }
  });

  test("renews ownership and rejects the pre-renewal proof", async () => {
    const fixture = makeFixture();
    const session = await fixture.session();
    fixture.clock.advance(1_000);

    const renewed = await fixture.coordinator.renew(session.lease);

    assert.equal(renewed.fencing_token, session.lease.fencing_token);
    assert.notEqual(renewed.lease_expires_at, session.lease.lease_expires_at);
    await assert.rejects(
      async () => fixture.coordinator.checkpoint(session, checkpoint(1)),
      StaleLeaseError,
    );
  });

  test("checkpoints before drain pause and resumes on a newer generation", async () => {
    const fixture = makeFixture();
    const oldSession = await fixture.session();

    const paused = await fixture.coordinator.pauseForDrain(
      oldSession,
      checkpoint(1),
    );
    assert.equal(paused.run.state, "paused");
    assert.equal(paused.checkpoint.resume_cursor, "cursor-1");

    const resumed = await fixture.start("ready", 2, "worker-b", "lease-b");
    if (resumed.status === "not_runnable") {
      assert.fail("expected a resumable run");
    }
    assert.equal(resumed.status, "resumed");
    assert.equal(resumed.session.checkpoint?.sequence, 1);
    assert.equal(resumed.session.lease.generation, 2);
    assert.equal(
      resumed.session.lease.fencing_token,
      oldSession.lease.fencing_token + 1,
    );

    await assert.rejects(
      async () => fixture.coordinator.checkpoint(oldSession, checkpoint(2)),
      StaleLeaseError,
    );
    await assert.rejects(
      async () => fixture.coordinator.beginEffect(oldSession, effect()),
      StaleLeaseError,
    );
    await assert.rejects(
      async () => fixture.coordinator.finishExecution(oldSession),
      StaleLeaseError,
    );
  });

  test("rejects generation regression after release and expiry recovery", async () => {
    const fixture = makeFixture();

    for (const invalid of [
      { generation: 0, ownerId: "worker-a", leaseToken: "lease-a" },
      { generation: 1, ownerId: " ", leaseToken: "lease-a" },
      { generation: 1, ownerId: "worker-a", leaseToken: " " },
    ]) {
      await assert.rejects(
        async () =>
          fixture.start(
            "ready",
            invalid.generation,
            invalid.ownerId,
            invalid.leaseToken,
          ),
        ExecutionInvariantError,
      );
    }

    const generationFour = await fixture.start(
      "ready",
      4,
      "worker-a",
      "lease-a",
    );
    if (generationFour.status === "not_runnable") {
      assert.fail("expected generation four to claim the run");
    }
    await fixture.coordinator.release(generationFour.session);
    await assert.rejects(
      async () => fixture.start("ready", 3, "worker-b", "lease-b"),
      ExecutionInvariantError,
    );

    const generationFive = await fixture.start(
      "ready",
      5,
      "worker-b",
      "lease-b",
    );
    assert.notEqual(generationFive.status, "not_runnable");
    fixture.clock.advance(31_000);
    assert.equal((await fixture.coordinator.reconcileExpired()).length, 1);
    await assert.rejects(
      async () => fixture.start("ready", 4, "worker-c", "lease-c"),
      ExecutionInvariantError,
    );
  });

  test("accepts only exact checkpoint retries for the same sequence", async () => {
    const fixture = makeFixture();
    const session = await fixture.session();
    const original = checkpoint(1);
    const first = await fixture.coordinator.checkpoint(session, original);
    fixture.clock.advance(1_000);
    const duplicate = await fixture.coordinator.checkpoint(session, original);

    assert.deepEqual(duplicate, first);
    for (const conflict of [
      { ...original, checkpoint_id: "checkpoint-other" },
      { ...original, completed_step_ids: ["step-other"] },
      { ...original, effect_receipt_ids: ["effect-other"] },
      { ...original, resume_cursor: "cursor-other" },
    ]) {
      await assert.rejects(
        async () => fixture.coordinator.checkpoint(session, conflict),
        ExecutionInvariantError,
      );
    }
  });

  test("records effect intent before execution and requires approval and verification", async () => {
    const fixture = makeFixture();
    const session = await fixture.session();

    await assert.rejects(
      fixture.coordinator.beginEffect(session, {
        ...effect(),
        approval_ref: undefined,
      }),
      ExecutionInvariantError,
    );

    const planned = await fixture.coordinator.beginEffect(session, effect());
    const duplicate = await fixture.coordinator.beginEffect(session, effect());
    assert.equal(planned.state, "planned");
    assert.equal(duplicate.effect_id, planned.effect_id);

    const executing = await fixture.coordinator.markEffectExecuting(
      session,
      effect().idempotency_key,
    );
    assert.equal(executing.state, "executing");

    await assert.rejects(
      fixture.coordinator.resolveEffect(session, effect().idempotency_key, {
        result_digest: "sha256:result",
        result_ref: "result://effect-1",
        state: "succeeded",
        verification_receipt_ref: "verification://effect-1",
        verification_state: "failed",
      }),
      ExecutionInvariantError,
    );

    const resolved = await fixture.coordinator.resolveEffect(
      session,
      effect().idempotency_key,
      {
        result_digest: "sha256:result",
        result_ref: "result://effect-1",
        state: "succeeded",
        verification_receipt_ref: "verification://effect-1",
        verification_state: "verified",
      },
    );
    assert.equal(resolved.state, "succeeded");
    assert.equal(resolved.verification_state, "verified");
    assert.equal(
      (await fixture.coordinator.finishExecution(session)).state,
      "delivering",
    );
    assert.equal(
      (await fixture.start("ready", 2, "worker-b", "lease-b")).status,
      "not_runnable",
    );
  });

  test("keeps a verified failed effect terminal and blocks delivery handoff", async () => {
    const fixture = makeFixture();
    const session = await fixture.session();
    await fixture.coordinator.beginEffect(session, effect());
    await fixture.coordinator.markEffectExecuting(
      session,
      effect().idempotency_key,
    );

    const failed = await fixture.coordinator.resolveEffect(
      session,
      effect().idempotency_key,
      {
        result_digest: "sha256:failure",
        result_ref: "result://failure",
        state: "failed",
        verification_receipt_ref: "verification://failure",
        verification_state: "verified",
      },
    );

    assert.equal(failed.state, "failed");
    await assert.rejects(
      async () => fixture.coordinator.finishExecution(session),
      ExecutionInvariantError,
    );
  });

  test("recovers an expired run and preserves uncertain effect truth", async () => {
    const fixture = makeFixture();
    const staleSession = await fixture.session();
    await fixture.coordinator.beginEffect(staleSession, effect());
    await fixture.coordinator.markEffectExecuting(
      staleSession,
      effect().idempotency_key,
    );

    fixture.clock.advance(31_000);
    const recovered = await fixture.coordinator.reconcileExpired();

    assert.equal(recovered.length, 1);
    assert.equal(recovered[0]?.run?.state, "queued");
    assert.deepEqual(recovered[0]?.uncertain_effect_ids, ["effect-1"]);
    assert.equal(
      (await fixture.store.getEffect("run-1", effect().idempotency_key))?.state,
      "unknown",
    );
    await assert.rejects(
      async () => fixture.coordinator.checkpoint(staleSession, checkpoint(1)),
      StaleLeaseError,
    );

    const resumed = await fixture.start("ready", 2, "worker-b", "lease-b");
    if (resumed.status === "not_runnable") {
      assert.fail("expected recovered work to be runnable");
    }
    const adopted = await fixture.coordinator.beginEffect(
      resumed.session,
      effect(),
    );
    assert.equal(adopted.state, "unknown");
    const verified = await fixture.coordinator.resolveEffect(
      resumed.session,
      effect().idempotency_key,
      {
        result_digest: "sha256:observed-result",
        result_ref: "result://observed-effect-1",
        state: "succeeded",
        verification_receipt_ref: "verification://observed-effect-1",
        verification_state: "verified",
      },
    );
    assert.equal(verified.generation, 2);
    assert.equal(verified.fencing_token, resumed.session.lease.fencing_token);
    assert.equal(
      (await fixture.coordinator.finishExecution(resumed.session)).state,
      "delivering",
    );
  });
});

function makeFixture(runId = "run-1") {
  const clock = new MutableClock();
  const store = new ReferenceMemoryExecutionStore();
  store.seedRun(runReceipt(runId));
  const coordinator = new ExecutionCoordinator({
    clock,
    lease_duration_ms: 30_000,
    store,
  });

  const start = (
    serviceState: ServiceAvailabilityState,
    generation: number,
    ownerId: string,
    leaseToken: string,
  ) =>
    coordinator.start({
      generation,
      lease_token: leaseToken,
      owner_id: ownerId,
      run_id: runId,
      service_state: serviceState,
    });

  return {
    clock,
    coordinator,
    session: async (): Promise<ExecutionSession> => {
      const result = await start("ready", 1, "worker-a", "lease-a");
      if (result.status === "not_runnable") {
        throw new Error("fixture run was not runnable");
      }
      return result.session;
    },
    start,
    store,
  };
}

class MutableClock {
  private milliseconds = Date.parse("2026-07-16T12:00:00.000Z");

  advance(durationMs: number): void {
    this.milliseconds += durationMs;
  }

  now(): Date {
    return new Date(this.milliseconds);
  }
}

function runReceipt(runId: string): RunReceiptV1 {
  const now = "2026-07-16T11:59:00.000Z";
  return {
    admitted_at: now,
    binding_id: "binding-1",
    idempotency_key: `event:${runId}`,
    input_digest: "sha256:input",
    receipt_id: `receipt-${runId}`,
    received_at: now,
    required_capabilities: [],
    retention_policy_ref: "retention://default",
    revision: 1,
    run_id: runId,
    run_kind: "interactive",
    schema_version: "run-receipt/v1",
    state: "queued",
    subject_ref: "slack-thread://conversation/thread",
    tenant_id: "tenant-1",
    updated_at: now,
  };
}

function checkpoint(sequence: number): CheckpointDraft {
  return {
    checkpoint_id: `checkpoint-${sequence}`,
    completed_step_ids: [`step-${sequence}`],
    effect_receipt_ids: [],
    payload_digest: `sha256:checkpoint-${sequence}`,
    payload_ref: `checkpoint://payload-${sequence}`,
    resume_cursor: `cursor-${sequence}`,
    sequence,
  };
}

function effect() {
  return {
    approval_ref: "approval://effect-1",
    approval_required: true,
    effect_id: "effect-1",
    idempotency_key: "turn-1:step-1",
    request_digest: "sha256:request",
    rollback_plan_ref: "rollback://effect-1",
    step_id: "step-1",
    target_ref: "resource://target-1",
  } as const;
}
