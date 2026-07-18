import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type {
  AdmissionContext,
  SlackIngressEnvelope,
} from "../src/contracts.js";
import { SlackAdmissionController } from "../src/admission.js";
import { ReferenceMemoryAdmissionStore } from "../src/testing/reference-store.js";

const now = "2026-07-16T12:00:00.000Z";

describe("SlackAdmissionController", () => {
  test("permits acknowledgement only after the run is durable and queued", async () => {
    const store = new ReferenceMemoryAdmissionStore();
    const controller = makeController(store, readyContext());

    const result = await controller.admit(envelope());

    assert.equal(result.acknowledgement_permitted, true);
    if (!result.acknowledgement_permitted) {
      assert.fail("expected accepted admission");
    }
    assert.equal(result.status, "queued");
    assert.equal(result.duplicate, false);
    assert.equal(store.receiptCount(), 1);
    assert.equal(store.hasQueuedRun(result.run_id), true);
    assert.equal(store.transitionCount(result.run_id), 2);
  });

  test("does not permit acknowledgement when the durable transaction fails", async () => {
    const store = new ReferenceMemoryAdmissionStore();
    store.failNext();
    const controller = makeController(store, readyContext());

    const result = await controller.admit(envelope());

    assert.deepEqual(result, {
      acknowledgement_permitted: false,
      duplicate: false,
      message: "The request was not saved. Slack should retry this event.",
      retryable: true,
      status: "rejected",
    });
    assert.equal(store.receiptCount(), 0);
  });

  test("returns the same durable run when Slack retries an event", async () => {
    const store = new ReferenceMemoryAdmissionStore();
    const controller = makeController(store, readyContext());

    const first = await controller.admit(envelope());
    const second = await controller.admit(envelope());

    assert.equal(first.acknowledgement_permitted, true);
    assert.equal(second.acknowledgement_permitted, true);
    if (!first.acknowledgement_permitted || !second.acknowledgement_permitted) {
      assert.fail("expected accepted admissions");
    }
    assert.equal(second.duplicate, true);
    assert.equal(second.run_id, first.run_id);
    assert.equal(store.receiptCount(), 1);
  });

  test("rejects an idempotency key reused for a different payload", async () => {
    const store = new ReferenceMemoryAdmissionStore();
    const controller = makeController(store, readyContext());
    await controller.admit(envelope());

    const result = await controller.admit({
      ...envelope(),
      payload_digest: "sha256:different",
    });

    assert.equal(result.acknowledgement_permitted, false);
    assert.equal(result.retryable, false);
    assert.equal(store.receiptCount(), 1);
  });

  test("shows degraded and recovery queue states after durable admission", async () => {
    const degraded = await makeController(
      new ReferenceMemoryAdmissionStore(),
      readyContext({ service_state: "degraded", compatibility: "degraded" }),
    ).admit(envelope({ event_id: "event-degraded" }));
    const recovering = await makeController(
      new ReferenceMemoryAdmissionStore(),
      readyContext({ service_state: "recovering" }),
    ).admit(envelope({ event_id: "event-recovering" }));

    assert.equal(degraded.acknowledgement_permitted, true);
    assert.equal(recovering.acknowledgement_permitted, true);
    if (!degraded.acknowledgement_permitted || !recovering.acknowledgement_permitted) {
      assert.fail("expected accepted admissions");
    }
    assert.equal(degraded.status, "degraded");
    assert.equal(recovering.status, "recovering");
  });

  test("does not admit work for an inactive installation", async () => {
    const store = new ReferenceMemoryAdmissionStore();
    const context = readyContext();
    context.binding.state = "suspended";
    const result = await makeController(store, context).admit(envelope());

    assert.equal(result.acknowledgement_permitted, false);
    assert.equal(store.receiptCount(), 0);
  });
});

function makeController(
  store: ReferenceMemoryAdmissionStore,
  context: AdmissionContext,
): SlackAdmissionController {
  let sequence = 0;
  return new SlackAdmissionController({
    clock: { now: () => new Date(now) },
    context: { read: async () => context },
    identities: {
      nextReceiptId: () => `receipt-${++sequence}`,
      nextRunId: () => `run-${++sequence}`,
    },
    policy: { admit_while_degraded: true, offline_behavior: "queue" },
    store,
  });
}

function envelope(
  changes: Partial<SlackIngressEnvelope> = {},
): SlackIngressEnvelope {
  return {
    app_id: "app-1",
    binding_id: "binding-1",
    conversation_id: "conversation-1",
    event_id: "event-1",
    event_type: "app_mention",
    payload_digest: "sha256:payload",
    payload_ref: "payload://event-1",
    received_at: now,
    required_capabilities: [],
    retention_policy_ref: "retention://default",
    run_kind: "interactive",
    subject_ref: "slack-thread://conversation-1/thread-1",
    tenant_id: "tenant-1",
    thread_id: "thread-1",
    ...changes,
  };
}

function readyContext(
  changes: Partial<AdmissionContext["presence"]> = {},
): AdmissionContext {
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
      expires_at: "2026-07-16T12:01:00.000Z",
      observed_at: now,
      reason_code: "ready",
      route_generation: 1,
      schema_version: "presence-snapshot/v1",
      service_state: "ready",
      ...changes,
    },
  };
}
