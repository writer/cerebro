import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { RunReceiptV1, WorkLeaseV1 } from "@writer/cerebro-sdk";
import { ExecutionCoordinator } from "../src/execution/coordinator.js";
import {
  effectIntentDigest,
  normalizeEffectIntentValue,
} from "../src/execution/effect-intent.js";
import {
  EffectReconciliationBlockedError,
  ExternalEffectReconciler,
} from "../src/execution/effect-reconciliation.js";
import type {
  ExternalEffectDraft,
  ExternalEffectInspection,
  ExternalEffectJob,
  ExternalEffectPort,
  ExternalEffectResult,
  ExternalEffectVerification,
  RecoverableExternalEffectInspection,
} from "../src/execution/effect-reconciliation.js";
import type {
  ExecutionSession,
  ExternalEffectIntentDraft,
  ExternalEffectIntentV1,
} from "../src/execution/model.js";
import { ReferenceMemoryExecutionStore } from "../src/execution/reference-store.js";

describe("ExternalEffectReconciler", () => {
  test("continues from an immutable intent persisted before the external call", async () => {
    const fixture = makeFixture();
    const session = await fixture.session(1);
    const input = effectDraft();
    const persisted = await fixture.store.persistEffectIntent(
      session.lease,
      intentDraft(input),
      fixture.clock.now().toISOString(),
    );

    assert.equal(persisted.created, true);
    assert.deepEqual(persisted.intent.request, {
      change: { mode: "bounded", target: "opaque-target-1" },
      scope: "opaque-scope-1",
    });
    await assert.rejects(
      async () => fixture.execution.finishExecution(session),
      /external intent without a verified effect/,
    );

    const result = await fixture.reconciler.execute(
      session,
      effectJob(session, input),
      input,
    );

    assert.equal(result.status, "applied");
    assert.equal(fixture.external.applyCalls, 1);
    assert.equal(fixture.external.inspectCalls, 0);
    assert.equal(
      (await fixture.store.getEffectIntent(session.run.run_id, input.idempotency_key))
        ?.request_digest,
      persisted.intent.request_digest,
    );
  });

  test("rejects a changed request under the same durable effect identity", async () => {
    const fixture = makeFixture();
    const session = await fixture.session(1);
    const input = effectDraft();
    await fixture.store.persistEffectIntent(
      session.lease,
      intentDraft(input),
      fixture.clock.now().toISOString(),
    );

    await assert.rejects(
      fixture.reconciler.execute(
        session,
        effectJob(session, input),
        {
          ...input,
          request: {
            change: { mode: "expanded", target: "opaque-target-2" },
            scope: "opaque-scope-1",
          },
        },
      ),
      /different external intent/,
    );
    assert.equal(fixture.external.callCount, 0);
  });

  test("inspects an outcome-unknown effect after a post-call crash without duplicating it", async () => {
    const fixture = makeFixture();
    const firstSession = await fixture.session(1);
    const input = effectDraft();
    fixture.external.crashAfterApply = true;

    await assert.rejects(
      fixture.reconciler.execute(
        firstSession,
        effectJob(firstSession, input),
        input,
      ),
      /simulated crash/,
    );
    assert.equal(fixture.external.applyCalls, 1);

    const resumed = await fixture.recover(firstSession, 2);
    fixture.external.crashAfterApply = false;
    const result = await fixture.reconciler.execute(
      resumed,
      effectJob(resumed, input),
      input,
    );

    assert.equal(result.status, "recovered");
    assert.equal(fixture.external.inspectCalls, 1);
    assert.equal(fixture.external.applyCalls, 1);
    assert.equal(result.effect.generation, 2);
  });

  for (const partialState of ["prepared", "materialized"] as const) {
    test(`resumes the ${partialState} partial window exactly once`, async () => {
      const fixture = makeFixture();
      const firstSession = await fixture.session(1);
      const input = effectDraft();
      await seedExecuting(fixture, firstSession, input);
      fixture.external.inspection = {
        candidate_version: input.candidate_version,
        resume_token: `resume-${partialState}`,
        state: partialState,
      };

      const resumed = await fixture.recover(firstSession, 2);
      const result = await fixture.reconciler.execute(
        resumed,
        effectJob(resumed, input),
        input,
      );

      assert.equal(result.status, "recovered");
      assert.equal(fixture.external.inspectCalls, 1);
      assert.equal(fixture.external.resumeCalls, 1);
      assert.equal(fixture.external.applyCalls, 0);
      assert.equal(fixture.external.inspection.state, "applied");
    });
  }

  test("consumes stale generation and fencing jobs without creating an intent", async () => {
    const fixture = makeFixture();
    const session = await fixture.session(4);
    const input = effectDraft();

    const staleGeneration = await fixture.reconciler.execute(
      session,
      { ...effectJob(session, input), generation: 3 },
      input,
    );
    const staleFence = await fixture.reconciler.execute(
      session,
      { ...effectJob(session, input), fencing_token: session.lease.fencing_token + 1 },
      input,
    );

    assert.deepEqual(staleGeneration, {
      reason: "generation_mismatch",
      status: "stale",
    });
    assert.deepEqual(staleFence, {
      reason: "fencing_token_mismatch",
      status: "stale",
    });
    assert.equal(
      await fixture.store.getEffectIntent(session.run.run_id, input.idempotency_key),
      undefined,
    );
    assert.equal(fixture.external.callCount, 0);
  });

  test("consumes a superseded candidate job without retargeting its durable intent", async () => {
    const fixture = makeFixture();
    const firstSession = await fixture.session(1);
    const original = effectDraft("candidate-version-1");
    const committed = await fixture.store.persistEffectIntent(
      firstSession.lease,
      intentDraft(original),
      fixture.clock.now().toISOString(),
    );
    await fixture.execution.release(firstSession);
    const resumed = await fixture.session(2);
    const superseding = effectDraft("candidate-version-2");

    const result = await fixture.reconciler.execute(
      resumed,
      effectJob(resumed, superseding),
      superseding,
    );

    assert.deepEqual(result, {
      reason: "candidate_version_mismatch",
      status: "stale",
    });
    assert.equal(
      (await fixture.store.getEffectIntent(resumed.run.run_id, original.idempotency_key))
        ?.candidate_version,
      committed.intent.candidate_version,
    );
    assert.equal(fixture.external.callCount, 0);
  });

  for (const blockedState of [
    "ambiguous",
    "boundary_mismatch",
    "target_moved",
  ] as const) {
    test(`fails closed when inspection reports ${blockedState}`, async () => {
      const fixture = makeFixture();
      const firstSession = await fixture.session(1);
      const input = effectDraft();
      await seedExecuting(fixture, firstSession, input);
      fixture.external.inspection = {
        reason_code: `fake-${blockedState}`,
        state: blockedState,
      };
      const resumed = await fixture.recover(firstSession, 2);

      await assert.rejects(
        fixture.reconciler.execute(
          resumed,
          effectJob(resumed, input),
          input,
        ),
        (error: unknown) =>
          error instanceof EffectReconciliationBlockedError &&
          error.code === blockedState,
      );
      assert.equal(fixture.external.inspectCalls, 1);
      assert.equal(fixture.external.applyCalls, 0);
      assert.equal(fixture.external.resumeCalls, 0);
      assert.equal(
        (await fixture.store.getEffect(resumed.run.run_id, input.idempotency_key))
          ?.state,
        "unknown",
      );
    });
  }

  test("returns the terminal effect on an exact retry without another external call", async () => {
    const fixture = makeFixture();
    const session = await fixture.session(1);
    const input = effectDraft();

    const first = await fixture.reconciler.execute(
      session,
      effectJob(session, input),
      input,
    );
    const duplicate = await fixture.reconciler.execute(
      session,
      effectJob(session, input),
      input,
    );

    assert.equal(first.status, "applied");
    assert.equal(duplicate.status, "duplicate");
    assert.equal(fixture.external.applyCalls, 1);
    assert.equal(fixture.external.inspectCalls, 0);
    assert.equal(fixture.external.verifyCalls, 1);
  });
});

function makeFixture(runId = "run-effect-1") {
  const clock = new MutableClock();
  const store = new ReferenceMemoryExecutionStore();
  store.seedRun(runReceipt(runId));
  const execution = new ExecutionCoordinator({
    clock,
    lease_duration_ms: 30_000,
    store,
  });
  const external = new FakeExternalEffectPort();
  const reconciler = new ExternalEffectReconciler({
    clock,
    execution,
    external,
    store,
  });

  const session = async (generation: number): Promise<ExecutionSession> => {
    const result = await execution.start({
      generation,
      lease_token: `lease-${generation}`,
      owner_id: `worker-${generation}`,
      run_id: runId,
      service_state: "ready",
    });
    if (result.status === "not_runnable") {
      throw new Error("fixture run was not runnable");
    }
    return result.session;
  };

  return {
    clock,
    execution,
    external,
    reconciler,
    recover: async (
      staleSession: ExecutionSession,
      generation: number,
    ): Promise<ExecutionSession> => {
      clock.advance(31_000);
      assert.equal((await execution.reconcileExpired()).length, 1);
      assert.equal(
        (await store.getEffect(staleSession.run.run_id, effectDraft().idempotency_key))
          ?.state,
        "unknown",
      );
      return session(generation);
    },
    session,
    store,
  };
}

class FakeExternalEffectPort implements ExternalEffectPort {
  applyCalls = 0;
  crashAfterApply = false;
  inspectCalls = 0;
  inspection: ExternalEffectInspection = { state: "absent" };
  resumeCalls = 0;
  verifyCalls = 0;

  get callCount(): number {
    return this.applyCalls + this.inspectCalls + this.resumeCalls + this.verifyCalls;
  }

  apply(
    intent: ExternalEffectIntentV1,
    _lease: WorkLeaseV1,
  ): Promise<ExternalEffectResult> {
    this.applyCalls += 1;
    const result = externalResult(intent.candidate_version);
    this.inspection = { result, state: "applied" };
    if (this.crashAfterApply) {
      return Promise.reject(new Error("simulated crash after external apply"));
    }
    return Promise.resolve(result);
  }

  inspect(
    _intent: ExternalEffectIntentV1,
    _lease: WorkLeaseV1,
  ): Promise<ExternalEffectInspection> {
    this.inspectCalls += 1;
    return Promise.resolve(structuredClone(this.inspection));
  }

  resume(
    intent: ExternalEffectIntentV1,
    _inspection: RecoverableExternalEffectInspection,
    _lease: WorkLeaseV1,
  ): Promise<ExternalEffectResult> {
    this.resumeCalls += 1;
    const result = externalResult(intent.candidate_version);
    this.inspection = { result, state: "applied" };
    return Promise.resolve(result);
  }

  verify(
    intent: ExternalEffectIntentV1,
    _result: ExternalEffectResult,
    _lease: WorkLeaseV1,
  ): Promise<ExternalEffectVerification> {
    this.verifyCalls += 1;
    return Promise.resolve({
      candidate_version: intent.candidate_version,
      receipt_ref: `verification://${intent.effect_id}`,
      state: "verified",
    });
  }
}

async function seedExecuting(
  fixture: ReturnType<typeof makeFixture>,
  session: ExecutionSession,
  draft: ExternalEffectDraft,
): Promise<void> {
  const committed = await fixture.store.persistEffectIntent(
    session.lease,
    intentDraft(draft),
    fixture.clock.now().toISOString(),
  );
  await fixture.execution.beginEffect(session, {
    approval_ref: committed.intent.approval_ref,
    approval_required: committed.intent.approval_required,
    effect_id: committed.intent.effect_id,
    idempotency_key: committed.intent.idempotency_key,
    request_digest: committed.intent.request_digest,
    rollback_plan_ref: committed.intent.rollback_plan_ref,
    step_id: committed.intent.step_id,
    target_ref: committed.intent.target_ref,
  });
  await fixture.execution.markEffectExecuting(
    session,
    committed.intent.idempotency_key,
  );
}

function effectDraft(candidateVersion = "candidate-version-1"): ExternalEffectDraft {
  return {
    approval_ref: "approval://effect-1",
    approval_required: true,
    candidate_version: candidateVersion,
    effect_id: "effect-1",
    idempotency_key: "turn-1:step-1",
    request: {
      scope: "opaque-scope-1",
      change: { mode: "bounded", target: "opaque-target-1" },
    },
    rollback_plan_ref: "rollback://effect-1",
    step_id: "step-1",
    target_ref: "target://opaque-1",
  };
}

function intentDraft(draft: ExternalEffectDraft): ExternalEffectIntentDraft {
  const request = normalizeEffectIntentValue(draft.request);
  const intentFields = {
    approval_ref: draft.approval_ref,
    approval_required: draft.approval_required,
    candidate_version: draft.candidate_version,
    effect_id: draft.effect_id,
    idempotency_key: draft.idempotency_key,
    request,
    rollback_plan_ref: draft.rollback_plan_ref,
    step_id: draft.step_id,
    target_ref: draft.target_ref,
  };
  return {
    ...intentFields,
    request_digest: effectIntentDigest(intentFields),
  };
}

function effectJob(
  session: ExecutionSession,
  draft: ExternalEffectDraft,
): ExternalEffectJob {
  return {
    candidate_version: draft.candidate_version,
    fencing_token: session.lease.fencing_token,
    generation: session.lease.generation,
    idempotency_key: draft.idempotency_key,
    lease_token: session.lease.lease_token,
    run_id: session.run.run_id,
  };
}

function externalResult(candidateVersion: string): ExternalEffectResult {
  return {
    candidate_version: candidateVersion,
    result_digest: `sha256:result-${candidateVersion}`,
    result_ref: `result://${candidateVersion}`,
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
    subject_ref: "conversation://opaque/thread",
    tenant_id: "tenant-1",
    updated_at: now,
  };
}
