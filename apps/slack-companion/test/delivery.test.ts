import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type {
  PlatformAcceptanceReceipt,
  PlatformDeliveryRequest,
  WorkLeaseV1,
} from "../src/delivery/contracts.js";
import {
  DeliveryCoordinator,
  type DeliveryCoordinatorOptions,
} from "../src/delivery/coordinator.js";
import type { PlatformDeliveryPort } from "../src/delivery/ports.js";
import {
  DeliveryConflictError,
  DeliveryFenceError,
  ReferenceMemoryDeliveryStore,
} from "../src/delivery/reference-store.js";
import { projectSlackMultipartDelivery } from "../src/projections/multipart.js";

const start = "2026-07-16T12:00:00.000Z";

describe("DeliveryCoordinator", () => {
  test("persists every deterministic part before any platform send", async () => {
    const clock = new MutableClock(start);
    const store = new ReferenceMemoryDeliveryStore(1);
    const sender = new IdempotentSender(clock);
    const coordinator = makeCoordinator(clock, store, sender);
    store.failNextPlan();

    await assert.rejects(() => coordinator.plan(planRequest()));
    assert.equal(sender.callCount, 0);

    const first = await coordinator.plan(planRequest());
    const duplicate = await coordinator.plan(planRequest());
    assert.equal(first.created, true);
    assert.equal(duplicate.created, false);
    assert.deepEqual(duplicate.receipt, first.receipt);
    assert.equal(first.receipt.parts.length, 2);
    assert.deepEqual(first.receipt.parts.map((part) => part.sequence), [1, 2]);
    assert.equal(new Set(first.receipt.parts.map((part) => part.part_id)).size, 2);
    assert.equal(first.receipt.parts.every((part) => part.state === "pending"), true);
    assert.equal(sender.callCount, 0);
  });

  test("rejects a changed payload under the same logical delivery identity", async () => {
    const clock = new MutableClock(start);
    const store = new ReferenceMemoryDeliveryStore(1);
    const coordinator = makeCoordinator(clock, store, new IdempotentSender(clock));
    await coordinator.plan(planRequest());

    await assert.rejects(
      () =>
        coordinator.plan(
          planRequest({
            parts: [
              { payload_digest: "sha256:changed", payload_ref: "payload://1" },
            ],
          }),
        ),
      DeliveryConflictError,
    );
    await assert.rejects(
      () => coordinator.plan(planRequest({ max_attempts: 4 })),
      DeliveryConflictError,
    );
  });

  test("delivers multipart output and persists each acceptance receipt", async () => {
    const clock = new MutableClock(start);
    const store = new ReferenceMemoryDeliveryStore(1);
    const sender = new IdempotentSender(clock);
    const coordinator = makeCoordinator(clock, store, sender);
    const planned = await coordinator.plan(planRequest());
    const activeLease = lease();

    const first = await coordinator.deliverNext(
      planned.receipt.delivery_id,
      activeLease,
    );
    const second = await coordinator.deliverNext(
      planned.receipt.delivery_id,
      activeLease,
    );
    const complete = await coordinator.deliverNext(
      planned.receipt.delivery_id,
      activeLease,
    );

    assert.equal(first.status, "delivered");
    assert.equal(second.status, "delivered");
    assert.equal(complete.status, "complete");
    assert.equal(complete.receipt.state, "completed");
    assert.equal(
      complete.receipt.parts.every(
        (part) => part.state === "delivered" && part.destination_receipt,
      ),
      true,
    );
    assert.equal(sender.callCount, 2);
    assert.equal(sender.acceptCount, 2);
  });

  test("resumes an accepted send after completion persistence fails without reposting", async () => {
    const clock = new MutableClock(start);
    const store = new ReferenceMemoryDeliveryStore(1);
    const sender = new IdempotentSender(clock);
    const coordinator = makeCoordinator(clock, store, sender);
    const planned = await coordinator.plan(planRequest({ parts: [part(1)] }));
    store.failNextCompletion();

    await assert.rejects(
      () => coordinator.deliverNext(planned.receipt.delivery_id, lease()),
      /injected completion failure/,
    );
    assert.equal(sender.acceptCount, 1);

    clock.set("2026-07-16T12:00:31.000Z");
    const resumed = await coordinator.deliverNext(
      planned.receipt.delivery_id,
      lease({
        fencing_token: 2,
        heartbeat_at: "2026-07-16T12:00:31.000Z",
        lease_expires_at: "2026-07-16T12:01:01.000Z",
        lease_token: "lease-2",
      }),
    );

    assert.equal(resumed.status, "delivered");
    assert.equal(resumed.receipt.state, "completed");
    assert.equal(sender.callCount, 2);
    assert.equal(sender.acceptCount, 1);
    assert.equal(
      resumed.receipt.parts[0]?.destination_receipt,
      sender.acceptedReceipts[0],
    );
  });

  test("enforces active generation and fencing ownership", async () => {
    const clock = new MutableClock(start);
    const store = new ReferenceMemoryDeliveryStore(1);
    const coordinator = makeCoordinator(clock, store, new IdempotentSender(clock));
    const planned = await coordinator.plan(planRequest({ parts: [part(1)] }));
    await store.claimNext({
      delivery_id: planned.receipt.delivery_id,
      lease: lease(),
      now: start,
    });

    await assert.rejects(
      () =>
        store.claimNext({
          delivery_id: planned.receipt.delivery_id,
          lease: lease({ lease_token: "lease-other", owner_id: "worker-2" }),
          now: start,
        }),
      DeliveryFenceError,
    );
    await assert.rejects(
      () =>
        store.claimNext({
          delivery_id: planned.receipt.delivery_id,
          lease: lease({
            heartbeat_at: "2026-07-16T12:00:01.000Z",
            lease_expires_at: "2026-07-16T12:00:40.000Z",
          }),
          now: start,
        }),
      DeliveryFenceError,
    );

    store.setActiveGeneration(2);
    await assert.rejects(
      () =>
        store.completePart({
          accepted_at: start,
          delivery_id: planned.receipt.delivery_id,
          destination_receipt: "receipt-1",
          lease: lease(),
          part_id: planned.receipt.parts[0]!.part_id,
        }),
      DeliveryFenceError,
    );
  });

  test("repeats claim and completion safely for the same lease and receipt", async () => {
    const clock = new MutableClock(start);
    const store = new ReferenceMemoryDeliveryStore(1);
    const coordinator = makeCoordinator(clock, store, new IdempotentSender(clock));
    const planned = await coordinator.plan(planRequest({ parts: [part(1)] }));
    const activeLease = lease();
    const claimRequest = {
      delivery_id: planned.receipt.delivery_id,
      lease: activeLease,
      now: start,
    };

    const firstClaim = await store.claimNext(claimRequest);
    const duplicateClaim = await store.claimNext(claimRequest);
    assert.deepEqual(duplicateClaim, firstClaim);
    assert.equal(firstClaim.status, "claimed");
    if (firstClaim.status !== "claimed") {
      assert.fail("expected claimed part");
    }

    const completion = {
      accepted_at: start,
      delivery_id: planned.receipt.delivery_id,
      destination_receipt: "destination-1",
      lease: activeLease,
      part_id: firstClaim.claim.part.part_id,
    };
    const firstCompletion = await store.completePart(completion);
    const duplicateCompletion = await store.completePart(completion);
    assert.deepEqual(duplicateCompletion, firstCompletion);
    assert.equal(firstCompletion.state, "completed");
  });

  test("reclaims an expired part only with a newer fencing value", async () => {
    const clock = new MutableClock(start);
    const store = new ReferenceMemoryDeliveryStore(1);
    const coordinator = makeCoordinator(clock, store, new IdempotentSender(clock));
    const planned = await coordinator.plan(planRequest({ parts: [part(1)] }));
    await store.claimNext({
      delivery_id: planned.receipt.delivery_id,
      lease: lease(),
      now: start,
    });
    const recoveryTime = "2026-07-16T12:00:31.000Z";

    await assert.rejects(
      () =>
        store.claimNext({
          delivery_id: planned.receipt.delivery_id,
          lease: lease({
            heartbeat_at: recoveryTime,
            lease_expires_at: "2026-07-16T12:01:01.000Z",
            lease_token: "lease-reused-fence",
          }),
          now: recoveryTime,
        }),
      DeliveryFenceError,
    );

    const recovered = await store.claimNext({
      delivery_id: planned.receipt.delivery_id,
      lease: lease({
        fencing_token: 2,
        heartbeat_at: recoveryTime,
        lease_expires_at: "2026-07-16T12:01:01.000Z",
        lease_token: "lease-recovery",
      }),
      now: recoveryTime,
    });
    assert.equal(recovered.status, "claimed");
    if (recovered.status === "claimed") {
      assert.equal(recovered.claim.attempt, 2);
    }
  });

  test("does not skip a busy earlier part to deliver a later part", async () => {
    const clock = new MutableClock(start);
    const store = new ReferenceMemoryDeliveryStore(1);
    const coordinator = makeCoordinator(clock, store, new IdempotentSender(clock));
    const planned = await coordinator.plan(planRequest());
    await store.claimNext({
      delivery_id: planned.receipt.delivery_id,
      lease: lease(),
      now: start,
    });

    const blocked = await store.claimNext({
      delivery_id: planned.receipt.delivery_id,
      lease: lease({ fencing_token: 2, lease_token: "lease-2" }),
      now: start,
    });

    assert.equal(blocked.status, "idle");
    if (blocked.status === "idle") {
      assert.equal(blocked.reason, "busy");
      assert.equal(blocked.receipt.parts[0]?.state, "delivering");
      assert.equal(blocked.receipt.parts[1]?.state, "pending");
    }
  });

  test("stops retrying when the persisted attempt bound is reached", async () => {
    const clock = new MutableClock(start);
    const store = new ReferenceMemoryDeliveryStore(1);
    const sender = new IdempotentSender(clock);
    sender.rejectAll = true;
    const coordinator = makeCoordinator(clock, store, sender);
    const planned = await coordinator.plan(
      planRequest({ max_attempts: 2 }),
    );

    const first = await coordinator.deliverNext(planned.receipt.delivery_id, lease());
    const second = await coordinator.deliverNext(planned.receipt.delivery_id, lease());
    const third = await coordinator.deliverNext(planned.receipt.delivery_id, lease());

    assert.equal(first.status, "retry_scheduled");
    assert.equal(second.status, "retry_exhausted");
    assert.equal(third.status, "retry_exhausted");
    assert.equal(third.receipt.state, "failed");
    assert.equal(third.receipt.parts[1]?.state, "pending");
    assert.equal(sender.callCount, 2);
  });

  test("honors portable retry backoff before reclaiming a failed part", async () => {
    const clock = new MutableClock(start);
    const store = new ReferenceMemoryDeliveryStore(1);
    const sender = new IdempotentSender(clock);
    sender.rejectAll = true;
    const coordinator = makeCoordinator(clock, store, sender);
    const planned = await coordinator.plan(
      planRequest({
        max_attempts: 3,
        parts: [part(1)],
        retry_policy: {
          initial_delay_seconds: 5,
          max_delay_seconds: 30,
          multiplier: 2,
          schema_version: "delivery-retry-policy/v1",
        },
      }),
    );

    const first = await coordinator.deliverNext(planned.receipt.delivery_id, lease());
    const waiting = await coordinator.deliverNext(planned.receipt.delivery_id, lease());
    clock.set("2026-07-16T12:00:05.000Z");
    const second = await coordinator.deliverNext(planned.receipt.delivery_id, lease());

    assert.equal(first.status, "retry_scheduled");
    assert.equal(
      (first.receipt.parts[0] as { next_attempt_at?: string } | undefined)?.next_attempt_at,
      "2026-07-16T12:00:05.000Z",
    );
    assert.equal(waiting.status, "waiting_for_retry");
    assert.equal(waiting.next_attempt_at, "2026-07-16T12:00:05.000Z");
    assert.equal(second.status, "retry_scheduled");
    assert.equal(second.receipt.state, "delivering");
    assert.equal(sender.callCount, 2);
  });

  test("clears retry timing when paused or abandoned and restores it on resume", async () => {
    const clock = new MutableClock(start);
    const store = new ReferenceMemoryDeliveryStore(1);
    const sender = new IdempotentSender(clock);
    sender.rejectAll = true;
    const coordinator = makeCoordinator(clock, store, sender);
    const planned = await coordinator.plan(
      planRequest({
        parts: [part(1)],
        retry_policy: {
          initial_delay_seconds: 5,
          max_delay_seconds: 30,
          multiplier: 2,
          schema_version: "delivery-retry-policy/v1",
        },
      }),
    );
    const failed = await coordinator.deliverNext(planned.receipt.delivery_id, lease());
    assert.equal(
      (failed.receipt.parts[0] as { next_attempt_at?: string } | undefined)?.next_attempt_at,
      "2026-07-16T12:00:05.000Z",
    );

    const paused = await coordinator.pause(planned.receipt.delivery_id, lease());
    assert.equal(paused.parts[0]?.state, "paused");
    assert.equal(
      (paused.parts[0] as { next_attempt_at?: string } | undefined)?.next_attempt_at,
      undefined,
    );
    assert.doesNotThrow(() => projectSlackMultipartDelivery(paused));

    const resumed = await coordinator.resume(planned.receipt.delivery_id, lease());
    assert.equal(resumed.parts[0]?.state, "failed");
    assert.equal(
      (resumed.parts[0] as { next_attempt_at?: string } | undefined)?.next_attempt_at,
      "2026-07-16T12:00:05.000Z",
    );
    assert.equal(
      projectSlackMultipartDelivery(resumed).parts[0]?.next_attempt_at,
      "2026-07-16T12:00:05.000Z",
    );

    const abandoned = await coordinator.abandon(planned.receipt.delivery_id, lease());
    assert.equal(abandoned.parts[0]?.state, "abandoned");
    assert.equal(
      (abandoned.parts[0] as { next_attempt_at?: string } | undefined)?.next_attempt_at,
      undefined,
    );
    assert.doesNotThrow(() => projectSlackMultipartDelivery(abandoned));
  });

  test("pauses active work, fences stale resume, and resumes without duplicate send", async () => {
    const clock = new MutableClock(start);
    const store = new ReferenceMemoryDeliveryStore(1);
    const sender = new IdempotentSender(clock);
    const coordinator = makeCoordinator(clock, store, sender);
    const planned = await coordinator.plan(planRequest({ parts: [part(1)] }));
    const staleLease = lease();
    store.failNextCompletion();
    await assert.rejects(
      () => coordinator.deliverNext(planned.receipt.delivery_id, staleLease),
      /injected completion failure/,
    );
    assert.equal(store.claimCount(planned.receipt.delivery_id), 1);
    assert.equal(sender.acceptCount, 1);

    store.setActiveGeneration(2);
    clock.set("2026-07-16T12:00:10.000Z");
    const currentLease = lease({
      fencing_token: 2,
      generation: 2,
      heartbeat_at: "2026-07-16T12:00:10.000Z",
      lease_expires_at: "2026-07-16T12:00:40.000Z",
      lease_token: "lease-current",
    });
    const paused = await coordinator.pause(
      planned.receipt.delivery_id,
      currentLease,
    );
    assert.equal(paused.state, "paused");
    assert.equal(paused.parts[0]?.state, "paused");
    assert.equal(store.claimCount(planned.receipt.delivery_id), 0);

    const recoveryLease = lease({
      fencing_token: 3,
      generation: 2,
      heartbeat_at: "2026-07-16T12:00:10.000Z",
      lease_expires_at: "2026-07-16T12:00:40.000Z",
      lease_token: "lease-recovery",
      owner_id: "worker-recovery",
    });
    const pausedAgain = await coordinator.pause(
      planned.receipt.delivery_id,
      recoveryLease,
    );
    assert.equal(pausedAgain.state, "paused");
    assert.equal(pausedAgain.parts[0]?.state, "paused");

    await assert.rejects(
      () => coordinator.resume(planned.receipt.delivery_id, staleLease),
      DeliveryFenceError,
    );
    await assert.rejects(
      () => coordinator.resume(planned.receipt.delivery_id, currentLease),
      DeliveryFenceError,
    );
    const resumed = await coordinator.resume(
      planned.receipt.delivery_id,
      recoveryLease,
    );
    assert.equal(resumed.state, "pending");
    assert.equal(resumed.parts[0]?.state, "pending");

    const delivered = await coordinator.deliverNext(
      planned.receipt.delivery_id,
      recoveryLease,
    );
    assert.equal(delivered.status, "delivered");
    assert.equal(delivered.receipt.state, "completed");
    assert.equal(sender.callCount, 2);
    assert.equal(sender.acceptCount, 1);
  });

  test("abandons unfinished parts as a terminal delivery", async () => {
    const clock = new MutableClock(start);
    const store = new ReferenceMemoryDeliveryStore(1);
    const sender = new IdempotentSender(clock);
    const coordinator = makeCoordinator(clock, store, sender);
    const planned = await coordinator.plan(planRequest());

    const abandoned = await coordinator.abandon(
      planned.receipt.delivery_id,
      lease(),
    );
    const duplicate = await coordinator.abandon(
      planned.receipt.delivery_id,
      lease(),
    );
    assert.equal(abandoned.state, "abandoned");
    assert.equal(
      abandoned.parts.every((deliveryPart) => deliveryPart.state === "abandoned"),
      true,
    );
    assert.deepEqual(duplicate, abandoned);

    const terminal = await coordinator.deliverNext(
      planned.receipt.delivery_id,
      lease(),
    );
    assert.equal(terminal.status, "abandoned");
    assert.equal(sender.callCount, 0);
    await assert.rejects(
      () => coordinator.resume(planned.receipt.delivery_id, lease()),
      DeliveryConflictError,
    );
  });
});

class MutableClock {
  private instant: string;

  constructor(instant: string) {
    this.instant = instant;
  }

  now(): Date {
    return new Date(this.instant);
  }

  set(instant: string): void {
    this.instant = instant;
  }
}

class IdempotentSender implements PlatformDeliveryPort {
  readonly acceptedReceipts: string[] = [];
  private readonly acceptedByMessage = new Map<string, PlatformAcceptanceReceipt>();
  callCount = 0;
  rejectAll = false;

  constructor(private readonly clock: MutableClock) {}

  get acceptCount(): number {
    return this.acceptedByMessage.size;
  }

  send(request: PlatformDeliveryRequest): Promise<PlatformAcceptanceReceipt> {
    this.callCount += 1;
    if (this.rejectAll) {
      return Promise.reject(new Error("injected destination rejection"));
    }
    const prior = this.acceptedByMessage.get(request.client_message_id);
    if (prior !== undefined) {
      return Promise.resolve(prior);
    }
    const destinationReceipt = `destination-${this.acceptedByMessage.size + 1}`;
    const accepted = {
      accepted_at: this.clock.now().toISOString(),
      destination_receipt: destinationReceipt,
    };
    this.acceptedByMessage.set(request.client_message_id, accepted);
    this.acceptedReceipts.push(destinationReceipt);
    return Promise.resolve(accepted);
  }
}

function makeCoordinator(
  clock: MutableClock,
  store: ReferenceMemoryDeliveryStore,
  sender: IdempotentSender,
): DeliveryCoordinator {
  const options: DeliveryCoordinatorOptions = { clock, sender, store };
  return new DeliveryCoordinator(options);
}

function part(sequence: number) {
  return {
    payload_digest: `sha256:payload-${sequence}`,
    payload_ref: `payload://${sequence}`,
  };
}

function planRequest(
  changes: Partial<Parameters<DeliveryCoordinator["plan"]>[0]> = {},
): Parameters<DeliveryCoordinator["plan"]>[0] {
  return {
    delivery_key: "final-response",
    destination_ref: "conversation://conversation-1/thread-1",
    max_attempts: 3,
    parts: [part(1), part(2)],
    run_id: "run-1",
    ...changes,
  };
}

function lease(changes: Partial<WorkLeaseV1> = {}): WorkLeaseV1 {
  return {
    fencing_token: 1,
    generation: 1,
    heartbeat_at: start,
    lease_expires_at: "2026-07-16T12:00:30.000Z",
    lease_token: "lease-1",
    owner_id: "worker-1",
    run_id: "run-1",
    schema_version: "work-lease/v1",
    ...changes,
  };
}
