import assert from "node:assert/strict";
import test from "node:test";
import {
  installEvidenceRecheckHost,
  PUBLIC_CEREBRO_COMMIT,
  PUBLIC_SLACK_COMPANION_TREE,
  type EvidenceRecheckHostBehaviorReceiptPort,
  type EvidenceRecheckHostBehaviorReceiptV1,
  type EvidenceRecheckHostRuntimeEvidenceV1,
} from "../src/evidence-recheck/activation.js";
import type {
  EvidenceRecheckExecutionClaimV1,
  EvidenceRecheckExecutorPort,
  EvidenceRecheckRouteRegistrationPort,
  VerifiedEvidenceRecheckInvocationV1,
} from "../src/evidence-recheck/contracts.js";
import { EvidenceRecheckHost } from "../src/evidence-recheck/host.js";
import {
  AtomicEvidenceRecheckStore,
  EvidenceRecheckStoreConflictError,
} from "../src/evidence-recheck/persistence.js";
import {
  FixturePortableContract,
  InvocationStore,
  MemoryAtomicDocumentStore,
  MutableClock,
  RecordingStatusDelivery,
  completingExecutor,
  completion,
  deliveredAnswerInput,
  invocation,
  T0,
} from "./fixtures.js";

function fixture(
  executor?: EvidenceRecheckExecutorPort,
  clock: MutableClock = new MutableClock(),
) {
  const contract = new FixturePortableContract();
  const documents = new MemoryAtomicDocumentStore();
  const invocations = new InvocationStore();
  const delivery = new RecordingStatusDelivery();
  const store = new AtomicEvidenceRecheckStore({ contract, documents });
  const host = new EvidenceRecheckHost({
    clock,
    contract,
    executor: executor ?? completingExecutor(clock),
    invocations,
    status_delivery: delivery,
    store,
  });
  return { clock, contract, delivery, documents, host, invocations, store };
}

async function prepare(
  current: ReturnType<typeof fixture>,
  value = invocation(),
): Promise<void> {
  await current.host.registerDeliveredAnswer(deliveredAnswerInput());
  current.invocations.records.set(value.payload_ref, value);
}

function claim(
  clock: MutableClock,
  generation = 1,
  ownerId = `worker:${generation}`,
  leaseDurationMs = 1_000,
): EvidenceRecheckExecutionClaimV1 {
  return {
    generation,
    lease_duration_ms: leaseDurationMs,
    observed_at: clock.now().toISOString(),
    owner_id: ownerId,
  };
}

test("1. delivered answer binding survives a host restart", async () => {
  const current = fixture();
  const registered = await current.host.registerDeliveredAnswer(deliveredAnswerInput());
  assert.equal(registered.created, true);

  const restartedStore = new AtomicEvidenceRecheckStore({
    contract: current.contract,
    documents: current.documents,
  });
  const lookup = await restartedStore.bindingLookup(registered.binding.binding_ref);
  assert.equal(lookup.found, true);
  assert.equal(lookup.found && lookup.binding.thread_ref, "thread:fixture");
});

test("2. incomplete delivery and missing binding fail closed", async () => {
  const current = fixture();
  const incomplete = deliveredAnswerInput();
  incomplete.delivery.state = "delivering";
  await assert.rejects(current.host.registerDeliveredAnswer(incomplete));

  const request = invocation();
  current.invocations.records.set(request.payload_ref, request);
  const outcome = await current.host.admitPersistedInvocation(request.payload_ref);
  assert.equal(outcome.acknowledgement_permitted, false);
  assert.equal(outcome.status.status, "rejected");
  assert.deepEqual(await current.store.pendingCounts(), { execution: 0, outbox: 0 });
});

test("3. cross-context and caller-shaped payloads fail before admission", async () => {
  const current = fixture();
  await current.host.registerDeliveredAnswer(deliveredAnswerInput());
  const crossed = invocation({ conversation_ref: "conversation:other" });
  current.invocations.records.set(crossed.payload_ref, crossed);
  const rejected = await current.host.admitPersistedInvocation(crossed.payload_ref);
  assert.equal(rejected.acknowledgement_permitted, false);

  const shaped = {
    ...invocation({ payload_ref: "payload:shaped" }),
    evidence_artifact_ids: ["caller-controlled"],
  } as VerifiedEvidenceRecheckInvocationV1;
  current.invocations.records.set(shaped.payload_ref, shaped);
  await assert.rejects(
    current.host.admitPersistedInvocation(shaped.payload_ref),
    /invocation is invalid/,
  );
  assert.deepEqual(await current.store.pendingCounts(), { execution: 0, outbox: 0 });
});

test("4. acknowledgement follows the atomic durable admission commit", async () => {
  const current = fixture();
  await prepare(current);
  const outcome = await current.host.admitPersistedInvocation("payload:fixture");
  assert.equal(outcome.acknowledgement_permitted, true);
  assert.equal(outcome.duplicate, false);
  assert.deepEqual(await current.store.pendingCounts(), { execution: 1, outbox: 1 });
  const receipt = await current.store.receiptLookup(
    current.contract.evidenceRecheckAdmissionReceiptIdentity(
      current.contract.evidenceRecheckIdentity("binding:fixture", "request:fixture"),
    ),
  );
  assert.equal(receipt.found, true);
  assert.equal(receipt.found && receipt.receipt.queue_item.run_id, outcome.run_id);
});

test("5. durable-store failure permits no acknowledgement or partial work", async () => {
  const current = fixture();
  await prepare(current);
  current.documents.failNextPut = true;
  const outcome = await current.host.admitPersistedInvocation("payload:fixture");
  assert.equal(outcome.acknowledgement_permitted, false);
  assert.equal(outcome.retryable, true);
  assert.equal(outcome.status.status, "degraded");
  assert.deepEqual(await current.store.pendingCounts(), { execution: 0, outbox: 0 });
});

test("6. an exact retry reuses the receipt without duplicate work", async () => {
  const current = fixture();
  await prepare(current);
  const first = await current.host.admitPersistedInvocation("payload:fixture");
  const second = await current.host.admitPersistedInvocation("payload:fixture");
  assert.equal(first.run_id, second.run_id);
  assert.equal(second.acknowledgement_permitted, true);
  assert.equal(second.duplicate, true);
  assert.deepEqual(await current.store.pendingCounts(), { execution: 1, outbox: 1 });
});

test("7. concurrent admission elects one durable winner", async () => {
  class SteppingClock extends MutableClock {
    override now(): Date {
      const value = super.now();
      this.advance(1);
      return value;
    }
  }
  const current = fixture(undefined, new SteppingClock());
  await prepare(current);
  const outcomes = await Promise.all([
    current.host.admitPersistedInvocation("payload:fixture"),
    current.host.admitPersistedInvocation("payload:fixture"),
  ]);
  assert.equal(new Set(outcomes.map((outcome) => outcome.run_id)).size, 1);
  assert.equal(outcomes.filter((outcome) => !outcome.duplicate).length, 1);
  assert.equal(outcomes.filter((outcome) => outcome.duplicate).length, 1);
  assert.deepEqual(await current.store.pendingCounts(), { execution: 1, outbox: 1 });
});

test("8. changed intent cannot replace an immutable request identity", async () => {
  const current = fixture();
  await prepare(current);
  await current.host.admitPersistedInvocation("payload:fixture");
  const changed = invocation({ actor_ref: "actor:operator", payload_ref: "payload:changed" });
  current.invocations.records.set(changed.payload_ref, changed);
  await assert.rejects(
    current.host.admitPersistedInvocation(changed.payload_ref),
    /conflicts with retried content/,
  );
  assert.deepEqual(await current.store.pendingCounts(), { execution: 1, outbox: 1 });
});

test("9. queued status delivery is idempotent", async () => {
  const current = fixture();
  await prepare(current);
  await current.host.admitPersistedInvocation("payload:fixture");
  const delivered = await current.host.deliverNextStatus(claim(current.clock));
  const idle = await current.host.deliverNextStatus(claim(current.clock, 2));
  assert.equal(delivered.status, "delivered");
  assert.equal(idle.status, "idle");
  assert.equal(current.delivery.delivered.size, 1);
  assert.deepEqual(current.delivery.threads, ["thread:fixture"]);
});

test("10. overlapping unknown delivery outcomes remain destination-idempotent", async () => {
  const current = fixture();
  await prepare(current);
  await current.host.admitPersistedInvocation("payload:fixture");
  current.delivery.holdNextSend = true;
  const first = current.host.deliverNextStatus(claim(current.clock));
  const firstHandled = first.catch(() => undefined);
  await current.delivery.heldStarted;

  current.clock.advance(1_001);
  const inspected = await current.host.deliverNextStatus(claim(current.clock, 2));
  assert.equal(inspected.status, "requeued_after_inspection");
  const retry = current.host.deliverNextStatus(claim(current.clock, 3));
  current.delivery.releaseHeld();
  const reconciled = await retry;
  assert.equal(reconciled.status, "delivered");
  await firstHandled;
  assert.equal(current.delivery.threads.length, 1);
  assert.deepEqual(await current.store.pendingCounts(), { execution: 1, outbox: 0 });
});

test("11. checkpointed execution resumes after process restart", async () => {
  let firstAttempt = true;
  const current = fixture({
    execute: async (_session, controls) => {
      if (firstAttempt) {
        firstAttempt = false;
        await controls.checkpoint(
          "checkpoint-payload:one",
          "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        throw new Error("synthetic worker loss");
      }
      throw new Error("unexpected executor reuse");
    },
  });
  await prepare(current);
  const admitted = await current.host.admitPersistedInvocation("payload:fixture");
  const degraded = await current.host.executeNext(claim(current.clock));
  assert.equal(degraded.status, "degraded");

  let resumedCheckpoint = 0;
  const restarted = new EvidenceRecheckHost({
    clock: current.clock,
    contract: current.contract,
    executor: {
      execute: async (session) => {
        resumedCheckpoint = session.checkpoint?.sequence ?? 0;
        return completion(current.clock.now().toISOString());
      },
    },
    invocations: current.invocations,
    status_delivery: current.delivery,
    store: new AtomicEvidenceRecheckStore({
      contract: current.contract,
      documents: current.documents,
    }),
  });
  const completed = await restarted.executeNext(claim(current.clock, 2));
  assert.equal(completed.status, "completed");
  assert.equal(completed.run_id, admitted.run_id);
  assert.equal(resumedCheckpoint, 1);
});

test("12. stale generations and fencing tokens cannot complete work", async () => {
  const current = fixture();
  await prepare(current);
  await current.host.admitPersistedInvocation("payload:fixture");
  const stale = await current.store.claimNextExecution(claim(current.clock, 2));
  assert.ok(stale);
  assert.equal(await current.store.claimNextExecution(claim(current.clock, 1)), undefined);

  current.clock.advance(1_001);
  await assert.rejects(
    current.store.completeExecution(
      stale.lease,
      completion(T0),
      current.clock.now().toISOString(),
    ),
    EvidenceRecheckStoreConflictError,
  );
  await current.store.recoverExpiredExecutions(current.clock.now().toISOString());
  const currentSession = await current.store.claimNextExecution(claim(current.clock, 3));
  assert.ok(currentSession);
  await assert.rejects(
    current.store.completeExecution(
      stale.lease,
      completion(current.clock.now().toISOString()),
      current.clock.now().toISOString(),
    ),
    EvidenceRecheckStoreConflictError,
  );
  await current.store.completeExecution(
    currentSession.lease,
    completion(current.clock.now().toISOString()),
    current.clock.now().toISOString(),
  );
});

test("13. expired work records degradation then recovers the original thread", async () => {
  const current = fixture();
  await prepare(current);
  const admitted = await current.host.admitPersistedInvocation("payload:fixture");
  const session = await current.store.claimNextExecution(claim(current.clock));
  assert.ok(session);

  current.clock.advance(1_001);
  assert.equal(await current.store.claimNextExecution(claim(current.clock, 2)), undefined);
  assert.deepEqual(await current.host.recoverExpiredExecutions(), [admitted.run_id]);
  const degraded = await current.store.readCurrentRecheck(admitted.run_id!);
  assert.equal(degraded?.state, "degraded");
  const completed = await current.host.executeNext(claim(current.clock, 2));
  assert.equal(completed.status, "completed");

  for (;;) {
    const outcome = await current.host.deliverNextStatus(claim(current.clock, 3));
    if (outcome.status === "idle") break;
  }
  assert.ok(current.delivery.threads.length >= 4);
  assert.ok(current.delivery.threads.every((thread) => thread === "thread:fixture"));
  assert.equal((await current.store.readCurrentRecheck(admitted.run_id!))?.state, "completed");
});

test("14. activation requires the exact source lock and complete behavior receipts", async () => {
  const registrations: Array<{ action_id: string; generation: number; route_id: string }> = [];
  const routes: EvidenceRecheckRouteRegistrationPort = {
    register: async (input) => {
      registrations.push(input);
      return { registration_receipt_ref: "registration-receipt:fixture" };
    },
  };
  const evidence: EvidenceRecheckHostRuntimeEvidenceV1 = {
    generation: 7,
    observed_at: T0,
    public_commit: PUBLIC_CEREBRO_COMMIT,
    public_slack_companion_tree: PUBLIC_SLACK_COMPANION_TREE,
    receipt_refs: {
      atomic_admission: "receipt:atomic-admission",
      binding_lookup: "receipt:binding-lookup",
      checkpoint_recovery: "receipt:checkpoint-recovery",
      public_source_lock: "receipt:public-source-lock",
      queue_recovery: "receipt:queue-recovery",
      route_probe: "receipt:route-probe",
      status_outbox: "receipt:status-outbox",
    },
    schema_version: "private-evidence-recheck-runtime-evidence/v1",
  };
  const behaviorReceipts = new Map<string, EvidenceRecheckHostBehaviorReceiptV1>();
  for (const [behavior, receiptRef] of Object.entries(evidence.receipt_refs)) {
    behaviorReceipts.set(receiptRef, {
      behavior: behavior as EvidenceRecheckHostBehaviorReceiptV1["behavior"],
      evidence_digest:
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      generation: evidence.generation,
      observed_at: evidence.observed_at,
      producer_ref: "producer:evidence-recheck-host",
      public_commit: evidence.public_commit,
      public_slack_companion_tree: evidence.public_slack_companion_tree,
      receipt_ref: receiptRef,
      schema_version: "private-evidence-recheck-behavior-receipt/v1",
      status: "verified",
    });
  }
  const receiptPort: EvidenceRecheckHostBehaviorReceiptPort = {
    resolve: async (receiptRef) => behaviorReceipts.get(receiptRef),
  };
  await assert.rejects(
    installEvidenceRecheckHost(
      { ...evidence, public_commit: "0000000000000000000000000000000000000000" as typeof PUBLIC_CEREBRO_COMMIT },
      receiptPort,
      routes,
    ),
  );
  assert.equal(registrations.length, 0);

  behaviorReceipts.delete("receipt:checkpoint-recovery");
  await assert.rejects(installEvidenceRecheckHost(evidence, receiptPort, routes));
  assert.equal(registrations.length, 0);
  behaviorReceipts.set("receipt:checkpoint-recovery", {
    ...behaviorReceipts.get("receipt:queue-recovery")!,
    behavior: "checkpoint_recovery",
    receipt_ref: "receipt:checkpoint-recovery",
  });

  const receipt = await installEvidenceRecheckHost(evidence, receiptPort, routes);
  assert.equal(receipt.generation, 7);
  assert.equal(receipt.registration_receipt_ref, "registration-receipt:fixture");
  assert.deepEqual(registrations, [
    { action_id: "evidence_recheck", generation: 7, route_id: "evidence-recheck" },
  ]);
});
