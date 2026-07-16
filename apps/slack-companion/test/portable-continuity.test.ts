import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { test } from "node:test";
import type {
  AdmissionContext,
  DurableInboundPayloadPort,
  InboundPayloadCommit,
  InboundPayloadReceipt,
  PlatformAcceptanceReceipt,
  PlatformDeliveryRequest,
  PlatformDeliveryPort,
  ScheduledOccurrenceCommitResult,
  ScheduledOccurrenceStorePort,
  SlackEventsApiRequest,
  SlackThreadBindingV1,
  ThreadBindingCommit,
  ThreadBindingCommitResult,
  ThreadBindingStorePort,
  WorkLeaseV1,
} from "../src/index.js";
import {
  acquireScheduledOccurrence,
  createScheduledOccurrence,
  DeliveryCoordinator,
  ExecutionCoordinator,
  handleEventsApiRequest,
  SlackAdmissionController,
  SlackThreadBindingCoordinator,
  StructuralSlackEventNormalizer,
  ThreadBindingConflictError,
  updateScheduledOccurrence,
} from "../src/index.js";
import { ReferenceMemoryDeliveryStore } from "../src/delivery/reference-store.js";
import { ReferenceMemoryExecutionStore } from "../src/execution/reference-store.js";

const now = "2026-07-16T12:00:00.000Z";
const requestTimestamp = String(Date.parse(now) / 1_000);
const signingKey = Uint8Array.from({ length: 32 }, (_, index) => index + 1);

test("one scheduled Slack run remains durable across transport, execution, and delivery", async () => {
  const clock = { now: () => new Date(now) };
  const occurrenceStore = new MemoryOccurrenceStore();
  const occurrence = createScheduledOccurrence(
    {
      due_at: now,
      generation: 1,
      misfire_policy: "coalesce_once",
      schedule_id: "portable-continuity",
      schedule_revision: 1,
    },
    "2026-07-16T11:59:00.000Z",
  );
  assert.equal((await occurrenceStore.putIfAbsent(occurrence)).created, true);
  assert.equal((await occurrenceStore.putIfAbsent(occurrence)).created, false);

  const scheduledClaim = {
    fencing_token: 1,
    generation: 1,
    lease_token: "schedule-lease-1",
    owner_id: "scheduler-1",
  };
  const scheduledLease = acquireScheduledOccurrence(occurrence, {
    ...scheduledClaim,
    lease_expires_at: "2026-07-16T12:05:00.000Z",
    now,
  });
  assert.equal(scheduledLease.acquired, true);
  if (!scheduledLease.acquired) {
    assert.fail("expected the scheduled occurrence lease");
  }
  await occurrenceStore.compareAndSet(occurrence, scheduledLease.occurrence);
  const runningOccurrence = updateScheduledOccurrence(
    scheduledLease.occurrence,
    scheduledClaim,
    "running",
    now,
  );
  assert.notEqual(runningOccurrence, undefined);
  if (runningOccurrence === undefined) {
    assert.fail("expected the scheduled occurrence to start");
  }
  await occurrenceStore.compareAndSet(
    scheduledLease.occurrence,
    runningOccurrence,
  );

  const continuityStore = new ReferenceMemoryExecutionStore();
  const admission = new SlackAdmissionController({
    clock,
    context: { read: async () => readyContext() },
    identities: {
      nextReceiptId: () => "receipt-portable-continuity",
      nextRunId: () => occurrence.run_id,
    },
    policy: { admit_while_degraded: true, offline_behavior: "queue" },
    store: continuityStore,
  });
  const payloads = new MemoryInboundPayloadStore();
  const request = eventsApiRequest();
  const dependencies = {
    admission,
    clock,
    normalizer: new StructuralSlackEventNormalizer(),
    payloads,
  };

  const first = await handleEventsApiRequest(request, signingKey, dependencies);
  const duplicate = await handleEventsApiRequest(
    request,
    signingKey,
    dependencies,
  );
  assert.equal(first.kind, "acknowledge");
  assert.equal(duplicate.kind, "acknowledge");
  if (first.kind !== "acknowledge" || duplicate.kind !== "acknowledge") {
    assert.fail("expected durable transport acknowledgement");
  }
  assert.equal(first.run_id, occurrence.run_id);
  assert.equal(duplicate.run_id, first.run_id);
  assert.equal(payloads.recordCount, 1);
  assert.equal(continuityStore.runCount(), 1);
  assert.equal(continuityStore.readRun(first.run_id)?.state, "queued");

  const execution = new ExecutionCoordinator({
    clock,
    lease_duration_ms: 60_000,
    store: continuityStore,
  });
  const started = await execution.start({
    generation: 1,
    lease_token: "execution-lease-1",
    owner_id: "executor-1",
    run_id: first.run_id,
    service_state: "ready",
  });
  if (started.status === "not_runnable") {
    assert.fail("expected the admitted run to execute");
  }
  const checkpoint = await execution.checkpoint(started.session, {
    checkpoint_id: "checkpoint-portable-continuity",
    completed_step_ids: ["prepare-response"],
    effect_receipt_ids: [],
    payload_digest: "sha256:checkpoint-portable-continuity",
    payload_ref: "checkpoint://portable-continuity",
    resume_cursor: "delivery-ready",
    sequence: 1,
  });
  assert.equal(checkpoint.run_id, first.run_id);
  const deliveringRun = await execution.finishExecution(started.session);
  assert.equal(deliveringRun.state, "delivering");
  assert.equal(continuityStore.runCount(), 1);

  const deliveryStore = new ReferenceMemoryDeliveryStore(1);
  const sender = new IdempotentDestination(clock);
  const delivery = new DeliveryCoordinator({
    clock,
    sender,
    store: deliveryStore,
  });
  const plan = {
    delivery_key: "scheduled-response",
    destination_ref: "conversation://conversation-1/thread-1",
    max_attempts: 3,
    parts: [
      {
        payload_digest: "sha256:response-part-1",
        payload_ref: "response://portable-continuity/part-1",
      },
    ],
    run_id: first.run_id,
  } as const;
  const planned = await delivery.plan(plan);
  const duplicatePlan = await delivery.plan(plan);
  assert.equal(planned.created, true);
  assert.equal(duplicatePlan.created, false);
  assert.equal(duplicatePlan.receipt.delivery_id, planned.receipt.delivery_id);

  const delivered = await delivery.deliverNext(
    planned.receipt.delivery_id,
    deliveryLease(first.run_id),
  );
  assert.equal(delivered.status, "delivered");
  if (delivered.status !== "delivered") {
    assert.fail("expected the durable outbox part to be delivered");
  }
  assert.equal(delivered.receipt.state, "completed");
  assert.deepEqual(
    await deliveryStore.read(planned.receipt.delivery_id),
    delivered.receipt,
  );
  assert.equal(sender.uniqueAcceptanceCount, 1);

  const threadStore = new MemoryThreadBindingStore();
  const threads = new SlackThreadBindingCoordinator(clock, threadStore);
  const bound = await threads.bind(
    {
      app_id: "app-1",
      binding_id: "binding-1",
      conversation_id: "conversation-1",
      delivery_id: delivered.receipt.delivery_id,
      destination_receipt: delivered.destination_receipt,
      expires_at: "2026-07-16T13:00:00.000Z",
      goal_ref: "goal://portable-continuity",
      installation_id: "installation-1",
      subject_ref: deliveringRun.subject_ref,
      thread_id: "thread-1",
    },
    delivered.receipt,
  );
  assert.equal(bound.created, true);
  assert.equal(threadStore.recordCount, 1);
  assert.equal(bound.binding.delivery_id, planned.receipt.delivery_id);

  const completedOccurrence = updateScheduledOccurrence(
    runningOccurrence,
    scheduledClaim,
    "completed",
    now,
  );
  assert.notEqual(completedOccurrence, undefined);
  if (completedOccurrence === undefined) {
    assert.fail("expected the scheduled occurrence to complete");
  }
  await occurrenceStore.compareAndSet(
    runningOccurrence,
    completedOccurrence,
  );
  assert.equal(
    (await occurrenceStore.read(occurrence.occurrence_id))?.run_id,
    first.run_id,
  );
  assert.equal(
    (await occurrenceStore.read(occurrence.occurrence_id))?.state,
    "completed",
  );
  assert.equal(occurrenceStore.recordCount, 1);
});

class MemoryInboundPayloadStore implements DurableInboundPayloadPort {
  private readonly records = new Map<
    string,
    { body_digest: string; receipt: InboundPayloadReceipt }
  >();

  get recordCount(): number {
    return this.records.size;
  }

  persist(commit: InboundPayloadCommit): Promise<InboundPayloadReceipt> {
    const bodyDigest = digest(commit.raw_body);
    const prior = this.records.get(commit.idempotency_key);
    if (prior !== undefined) {
      if (prior.body_digest !== bodyDigest) {
        return Promise.reject(
          new Error("inbound payload identity has different bytes"),
        );
      }
      return Promise.resolve(structuredClone(prior.receipt));
    }
    const receipt = {
      digest: bodyDigest,
      payload_ref: `payload://${commit.idempotency_key}`,
    };
    this.records.set(commit.idempotency_key, {
      body_digest: bodyDigest,
      receipt,
    });
    return Promise.resolve(structuredClone(receipt));
  }
}

class MemoryOccurrenceStore implements ScheduledOccurrenceStorePort {
  private readonly records = new Map<
    string,
    Parameters<ScheduledOccurrenceStorePort["putIfAbsent"]>[0]
  >();

  get recordCount(): number {
    return this.records.size;
  }

  putIfAbsent(
    occurrence: Parameters<ScheduledOccurrenceStorePort["putIfAbsent"]>[0],
  ): Promise<ScheduledOccurrenceCommitResult> {
    const prior = this.records.get(occurrence.occurrence_id);
    if (prior !== undefined) {
      if (!sameValue(prior, occurrence)) {
        return Promise.reject(
          new Error("scheduled occurrence identity has different intent"),
        );
      }
      return Promise.resolve({
        created: false,
        occurrence: structuredClone(prior),
      });
    }
    this.records.set(occurrence.occurrence_id, structuredClone(occurrence));
    return Promise.resolve({
      created: true,
      occurrence: structuredClone(occurrence),
    });
  }

  compareAndSet(
    expected: Parameters<ScheduledOccurrenceStorePort["compareAndSet"]>[0],
    next: Parameters<ScheduledOccurrenceStorePort["compareAndSet"]>[1],
  ) {
    const current = this.records.get(expected.occurrence_id);
    if (
      current === undefined ||
      !sameValue(current, expected) ||
      next.occurrence_id !== expected.occurrence_id
    ) {
      return Promise.reject(new Error("scheduled occurrence changed"));
    }
    this.records.set(next.occurrence_id, structuredClone(next));
    return Promise.resolve(structuredClone(next));
  }

  read(occurrenceId: string) {
    const occurrence = this.records.get(occurrenceId);
    return Promise.resolve(
      occurrence === undefined ? undefined : structuredClone(occurrence),
    );
  }
}

class IdempotentDestination implements PlatformDeliveryPort {
  private readonly acceptances = new Map<string, PlatformAcceptanceReceipt>();

  constructor(private readonly clock: { now(): Date }) {}

  get uniqueAcceptanceCount(): number {
    return this.acceptances.size;
  }

  send(request: PlatformDeliveryRequest): Promise<PlatformAcceptanceReceipt> {
    const prior = this.acceptances.get(request.client_message_id);
    if (prior !== undefined) {
      return Promise.resolve(structuredClone(prior));
    }
    const receipt = {
      accepted_at: this.clock.now().toISOString(),
      destination_receipt: `destination://${request.client_message_id}`,
    };
    this.acceptances.set(request.client_message_id, receipt);
    return Promise.resolve(structuredClone(receipt));
  }
}

class MemoryThreadBindingStore implements ThreadBindingStorePort {
  private readonly fingerprints = new Map<string, string>();
  private readonly records = new Map<string, SlackThreadBindingV1>();

  get recordCount(): number {
    return this.records.size;
  }

  putIfAbsent(commit: ThreadBindingCommit): Promise<ThreadBindingCommitResult> {
    const id = commit.binding.thread_binding_id;
    const prior = this.records.get(id);
    if (prior !== undefined) {
      if (this.fingerprints.get(id) !== commit.payload_fingerprint) {
        return Promise.reject(
          new ThreadBindingConflictError(
            "thread identity has different continuity intent",
          ),
        );
      }
      return Promise.resolve({ binding: structuredClone(prior), created: false });
    }
    this.records.set(id, structuredClone(commit.binding));
    this.fingerprints.set(id, commit.payload_fingerprint);
    return Promise.resolve({
      binding: structuredClone(commit.binding),
      created: true,
    });
  }

  read(threadBindingId: string) {
    const binding = this.records.get(threadBindingId);
    return Promise.resolve(
      binding === undefined ? undefined : structuredClone(binding),
    );
  }

  close(threadBindingId: string, closedAt: string) {
    const binding = this.require(threadBindingId);
    binding.closed_at = binding.closed_at ?? closedAt;
    binding.state = "closed";
    binding.updated_at = binding.closed_at;
    return Promise.resolve(structuredClone(binding));
  }

  expire(threadBindingId: string, expiredAt: string) {
    const binding = this.require(threadBindingId);
    if (binding.state === "active") {
      binding.state = "expired";
      binding.updated_at = expiredAt;
    }
    return Promise.resolve(structuredClone(binding));
  }

  private require(threadBindingId: string): SlackThreadBindingV1 {
    const binding = this.records.get(threadBindingId);
    if (binding === undefined) {
      throw new Error("thread binding does not exist");
    }
    return binding;
  }
}

function eventsApiRequest(): SlackEventsApiRequest {
  const rawBody = Buffer.from(
    JSON.stringify({
      api_app_id: "app-1",
      event: {
        channel: "conversation-1",
        thread_ts: "thread-1",
        ts: "event-time-1",
        type: "app_mention",
      },
      event_id: "event-portable-continuity",
      event_time: Date.parse(now) / 1_000,
      team_id: "team-1",
      type: "event_callback",
    }),
  );
  return {
    raw_body: rawBody,
    received_at: now,
    request_signature: `v0=${createHmac("sha256", signingKey)
      .update(`v0:${requestTimestamp}:`)
      .update(rawBody)
      .digest("hex")}`,
    request_timestamp: requestTimestamp,
    route: {
      binding_id: "binding-1",
      required_capabilities: [],
      retention_policy_ref: "retention://default",
      run_kind: "scheduled",
      tenant_id: "tenant-1",
    },
  };
}

function readyContext(): AdmissionContext {
  return {
    binding: {
      binding_id: "binding-1",
      created_at: now,
      installation_generation: 1,
      retention_policy_ref: "retention://default",
      route_generation: 1,
      schema_version: "agent-service-binding/v1",
      service_id: "service-1",
      state: "active",
      tenant_id: "tenant-1",
      updated_at: now,
    },
    presence: {
      active_generation: 1,
      binding_id: "binding-1",
      compatibility: "supported",
      expires_at: "2026-07-16T12:10:00.000Z",
      observed_at: now,
      reason_code: "ready",
      route_generation: 1,
      schema_version: "presence-snapshot/v1",
      service_state: "ready",
    },
  };
}

function deliveryLease(runId: string): WorkLeaseV1 {
  return {
    fencing_token: 2,
    generation: 1,
    heartbeat_at: now,
    lease_expires_at: "2026-07-16T12:05:00.000Z",
    lease_token: "delivery-lease-1",
    owner_id: "delivery-reconciler-1",
    run_id: runId,
    schema_version: "work-lease/v1",
  };
}

function digest(value: Uint8Array): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function sameValue(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}
