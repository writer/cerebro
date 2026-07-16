import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { DeliveryReceiptV1 } from "@writer/cerebro-sdk";
import {
  SlackThreadBindingCoordinator,
  ThreadBindingConflictError,
  type BindSlackThreadRequest,
  type SlackThreadBindingV1,
  type ThreadBindingCommit,
  type ThreadBindingCommitResult,
  type ThreadBindingStorePort,
} from "../src/thread-binding.js";

const now = "2026-07-16T12:00:00.000Z";

describe("SlackThreadBindingCoordinator", () => {
  test("binds stable thread identity to the persisted platform receipt", async () => {
    const store = new MemoryThreadBindingStore();
    const coordinator = makeCoordinator(store);

    const first = await coordinator.bind(bindingRequest(), deliveredReceipt());
    const duplicate = await coordinator.bind(bindingRequest(), deliveredReceipt());
    const resumed = await coordinator.resume(bindingRequest());

    assert.equal(first.created, true);
    assert.equal(duplicate.created, false);
    assert.deepEqual(duplicate.binding, first.binding);
    assert.deepEqual(resumed, first.binding);
    assert.equal(first.binding.destination_receipt, "destination-1");
    assert.equal(first.binding.subject_ref, "subject://control-1");
    assert.equal(first.binding.goal_ref, "goal://explain-control");
    assert.equal(store.writeCount, 1);
  });

  test("does not bind before the destination acceptance is durable", async () => {
    const store = new MemoryThreadBindingStore();
    const coordinator = makeCoordinator(store);
    const receipt = deliveredReceipt();
    receipt.parts[0] = {
      ...receipt.parts[0]!,
      destination_receipt: undefined,
      state: "delivering",
    };
    receipt.state = "delivering";

    await assert.rejects(() => coordinator.bind(bindingRequest(), receipt));
    assert.equal(store.writeCount, 0);
  });

  test("binds after the referenced part is durable while later parts remain", async () => {
    const store = new MemoryThreadBindingStore();
    const coordinator = makeCoordinator(store);
    const receipt = deliveredReceipt();
    receipt.parts.push({
      idempotency_key: "message-2",
      part_id: "part-2",
      payload_digest: "sha256:payload-2",
      payload_ref: "payload://2",
      sequence: 2,
      state: "pending",
    });
    receipt.state = "delivering";

    const result = await coordinator.bind(bindingRequest(), receipt);

    assert.equal(result.created, true);
    assert.equal(result.binding.destination_receipt, "destination-1");
  });

  test("leaves no binding when its durable write fails", async () => {
    const store = new MemoryThreadBindingStore();
    store.failNext();
    const coordinator = makeCoordinator(store);

    await assert.rejects(
      () => coordinator.bind(bindingRequest(), deliveredReceipt()),
      /injected thread binding failure/,
    );
    assert.equal(store.writeCount, 0);
    assert.equal(await coordinator.resume(bindingRequest()), undefined);
  });

  test("rejects identity reuse for a different subject or goal", async () => {
    const store = new MemoryThreadBindingStore();
    const coordinator = makeCoordinator(store);
    await coordinator.bind(bindingRequest(), deliveredReceipt());

    await assert.rejects(
      () =>
        coordinator.bind(
          bindingRequest({ goal_ref: "goal://different" }),
          deliveredReceipt(),
        ),
      ThreadBindingConflictError,
    );
  });

  test("closes idempotently and never resumes a closed binding", async () => {
    const store = new MemoryThreadBindingStore();
    const coordinator = makeCoordinator(store);
    const bound = await coordinator.bind(bindingRequest(), deliveredReceipt());

    const first = await coordinator.close(bound.binding.thread_binding_id);
    const second = await coordinator.close(bound.binding.thread_binding_id);

    assert.equal(first.state, "closed");
    assert.deepEqual(second, first);
    assert.equal(await coordinator.resume(bindingRequest()), undefined);
  });

  test("expires a binding before returning resume context", async () => {
    const store = new MemoryThreadBindingStore();
    const clock = new MutableClock(now);
    const coordinator = new SlackThreadBindingCoordinator(clock, store);
    const bound = await coordinator.bind(bindingRequest(), deliveredReceipt());
    clock.set("2026-07-16T13:00:01.000Z");

    assert.equal(await coordinator.resume(bindingRequest()), undefined);
    assert.equal(
      (await store.read(bound.binding.thread_binding_id))?.state,
      "expired",
    );
  });
});

class MutableClock {
  constructor(private instant: string) {}

  now(): Date {
    return new Date(this.instant);
  }

  set(instant: string): void {
    this.instant = instant;
  }
}

class MemoryThreadBindingStore implements ThreadBindingStorePort {
  private readonly fingerprints = new Map<string, string>();
  private readonly records = new Map<string, SlackThreadBindingV1>();
  private failPut = false;
  writeCount = 0;

  putIfAbsent(commit: ThreadBindingCommit): Promise<ThreadBindingCommitResult> {
    if (this.failPut) {
      this.failPut = false;
      return Promise.reject(new Error("injected thread binding failure"));
    }
    const id = commit.binding.thread_binding_id;
    const prior = this.records.get(id);
    if (prior !== undefined) {
      if (this.fingerprints.get(id) !== commit.payload_fingerprint) {
        return Promise.reject(
          new ThreadBindingConflictError(
            "The thread identity already has different intent.",
          ),
        );
      }
      return Promise.resolve({ binding: structuredClone(prior), created: false });
    }
    this.records.set(id, structuredClone(commit.binding));
    this.fingerprints.set(id, commit.payload_fingerprint);
    this.writeCount += 1;
    return Promise.resolve({ binding: structuredClone(commit.binding), created: true });
  }

  read(threadBindingId: string): Promise<SlackThreadBindingV1 | undefined> {
    const binding = this.records.get(threadBindingId);
    return Promise.resolve(binding === undefined ? undefined : structuredClone(binding));
  }

  close(threadBindingId: string, closedAt: string): Promise<SlackThreadBindingV1> {
    const binding = this.require(threadBindingId);
    if (binding.state === "closed") {
      return Promise.resolve(structuredClone(binding));
    }
    binding.closed_at = closedAt;
    binding.state = "closed";
    binding.updated_at = closedAt;
    return Promise.resolve(structuredClone(binding));
  }

  expire(threadBindingId: string, expiredAt: string): Promise<SlackThreadBindingV1> {
    const binding = this.require(threadBindingId);
    if (binding.state === "active") {
      binding.state = "expired";
      binding.updated_at = expiredAt;
    }
    return Promise.resolve(structuredClone(binding));
  }

  failNext(): void {
    this.failPut = true;
  }

  private require(threadBindingId: string): SlackThreadBindingV1 {
    const binding = this.records.get(threadBindingId);
    if (binding === undefined) {
      throw new Error("thread binding does not exist");
    }
    return binding;
  }
}

function makeCoordinator(
  store: MemoryThreadBindingStore,
): SlackThreadBindingCoordinator {
  return new SlackThreadBindingCoordinator(new MutableClock(now), store);
}

function bindingRequest(
  changes: Partial<BindSlackThreadRequest> = {},
): BindSlackThreadRequest {
  return {
    app_id: "app-1",
    binding_id: "binding-1",
    conversation_id: "conversation-1",
    delivery_id: "delivery-1",
    destination_receipt: "destination-1",
    expires_at: "2026-07-16T13:00:00.000Z",
    goal_ref: "goal://explain-control",
    installation_id: "installation-1",
    subject_ref: "subject://control-1",
    thread_id: "thread-1",
    ...changes,
  };
}

function deliveredReceipt(): DeliveryReceiptV1 {
  return {
    created_at: now,
    delivery_id: "delivery-1",
    destination_ref: "conversation://conversation-1/thread-1",
    parts: [
      {
        delivered_at: now,
        destination_receipt: "destination-1",
        idempotency_key: "message-1",
        part_id: "part-1",
        payload_digest: "sha256:payload-1",
        payload_ref: "payload://1",
        sequence: 1,
        state: "delivered",
      },
    ],
    run_id: "run-1",
    schema_version: "delivery-receipt/v1",
    state: "completed",
    updated_at: now,
  };
}
