import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type {
  DeliveryPlanRequest,
  DeliveryPlanResult,
  DeliveryReceiptV1,
  RunReceiptV1,
} from "../src/index.js";
import {
  AssistanceConflictError,
  AssistanceCoordinator,
  AssistanceReplyRejectedError,
} from "../src/assistance/coordinator.js";
import type {
  AssistanceDeliveryAttachment,
  AssistanceOutcomeCommit,
  AssistanceRefinementAdmission,
  AssistanceRefinementAttachment,
  AssistanceRefinementReceipt,
  AssistanceRequestCommit,
  AssistanceRequestCommitResult,
  AssistanceRequestInput,
  AssistanceRequestV1,
  AssistanceThreadAttachment,
  NormalizedAssistanceReply,
} from "../src/assistance/contracts.js";
import type {
  AssistanceRefinementPort,
  AssistanceRunReceiptPort,
  DurableAssistancePort,
} from "../src/assistance/ports.js";
import {
  SlackThreadBindingCoordinator,
  ThreadBindingConflictError,
} from "../src/thread-binding.js";
import type {
  SlackThreadBindingV1,
  ThreadBindingCommit,
  ThreadBindingCommitResult,
  ThreadBindingStorePort,
} from "../src/thread-binding.js";

const start = "2026-07-16T12:00:00.000Z";

describe("AssistanceCoordinator", () => {
  test("persists assistance before deterministic delivery planning and resumes a failed plan", async () => {
    const fixture = makeFixture();
    fixture.delivery.failOnce = true;

    await assert.rejects(
      fixture.coordinator.request(requestInput()),
      /injected delivery plan failure/,
    );
    assert.equal(fixture.store.recordCount, 1);
    assert.equal(fixture.delivery.observedDurableRequest, true);

    fixture.store.failNextDeliveryAttachment = true;
    await assert.rejects(
      fixture.coordinator.request(requestInput()),
      /injected delivery attachment failure/,
    );
    assert.equal(fixture.delivery.uniquePlanCount, 1);

    const resumed = await fixture.coordinator.request(requestInput());
    const duplicate = await fixture.coordinator.request(requestInput());
    assert.equal(resumed.request.status, "delivery_planned");
    assert.equal(duplicate.request.delivery_id, resumed.request.delivery_id);
    assert.equal(fixture.store.recordCount, 1);
    assert.equal(fixture.delivery.uniquePlanCount, 1);
  });

  test("rejects changed assistance payload under one idempotency identity", async () => {
    const fixture = makeFixture();
    await fixture.coordinator.request(requestInput());

    await assert.rejects(
      fixture.coordinator.request(
        requestInput({ payload_digest: "sha256:changed-assistance" }),
      ),
      AssistanceConflictError,
    );
    assert.equal(fixture.delivery.uniquePlanCount, 1);
  });

  test("records a bounded redacted outcome before idempotent refinement admission", async () => {
    const fixture = makeFixture();
    const bound = await fixture.bind();
    fixture.store.failNextRefinementAttachment = true;

    await assert.rejects(
      fixture.coordinator.acceptReply(replyInput(bound.request.assistance_id)),
      /injected refinement attachment failure/,
    );
    assert.equal((await fixture.store.read(bound.request.assistance_id))?.status, "outcome_recorded");
    assert.equal(fixture.refinements.observedOutcomeFirst, true);
    assert.equal(fixture.refinements.uniqueAdmissionCount, 1);

    const retry = await fixture.coordinator.acceptReply(
      replyInput(bound.request.assistance_id),
    );
    assert.equal(retry.request.status, "refinement_admitted");
    assert.equal(retry.reply_run.run_id, "run-reply-1");
    assert.equal(fixture.refinements.uniqueAdmissionCount, 1);

    await assert.rejects(
      fixture.coordinator.acceptReply(
        replyInput(bound.request.assistance_id, {
          outcome_digest: "sha256:conflicting-outcome",
          outcome_ref: "outcome://conflicting",
        }),
      ),
      AssistanceConflictError,
    );
  });

  test("accepts replies only from the admitted human on the exact active thread", async () => {
    const cases: Array<{
      name: string;
      mutate?: Partial<NormalizedAssistanceReply>;
      prepare?: (fixture: ReturnType<typeof makeFixture>) => void;
    }> = [
      { name: "bot", mutate: { actor_kind: "bot" } },
      { name: "app", mutate: { actor_kind: "app" } },
      { name: "subtype", mutate: { subtype: "message_changed" } },
      { name: "wrong actor", mutate: { actor_ref: "actor://other" } },
      { name: "wrong channel", mutate: { conversation_id: "conversation-other" } },
      { name: "wrong thread", mutate: { thread_id: "thread-other" } },
      { name: "action-like", mutate: { action_classification: "action_like" } },
      { name: "unsafe", mutate: { action_classification: "unsafe" } },
      {
        name: "missing admitted run",
        prepare: (fixture) => fixture.runs.delete("run-reply-1"),
      },
      { name: "wrong admitted payload", mutate: { payload_digest: "sha256:other" } },
      {
        name: "expired",
        prepare: (fixture) => fixture.clock.set("2026-07-16T13:01:00.000Z"),
      },
    ];

    for (const testCase of cases) {
      const fixture = makeFixture();
      const bound = await fixture.bind();
      testCase.prepare?.(fixture);
      await assert.rejects(
        fixture.coordinator.acceptReply(
          replyInput(bound.request.assistance_id, testCase.mutate),
        ),
        AssistanceReplyRejectedError,
        testCase.name,
      );
      assert.equal(fixture.refinements.uniqueAdmissionCount, 0, testCase.name);
    }
  });
});

function makeFixture() {
  const clock = new MutableClock();
  const store = new MemoryAssistanceStore();
  const runs = new MemoryRunStore([runReceipt("run-request-1", "running")]);
  runs.seed(runReceipt("run-reply-1", "queued", "sha256:reply-payload"));
  const delivery = new MemoryDeliveryPlanner(store, clock);
  const threadStore = new MemoryThreadStore();
  const threads = new SlackThreadBindingCoordinator(clock, threadStore);
  const refinements = new MemoryRefinementPort(store);
  const coordinator = new AssistanceCoordinator({
    clock,
    delivery,
    max_outcome_bytes: 1024,
    refinements,
    runs,
    store,
    threads,
  });

  return {
    async bind() {
      const requested = await coordinator.request(requestInput());
      const delivered = deliveredReceipt(requested.delivery);
      return coordinator.bindThread(requested.request.assistance_id, {
        bind: {
          app_id: "app-1",
          binding_id: "binding-1",
          conversation_id: "conversation-1",
          delivery_id: delivered.delivery_id,
          destination_receipt: "destination-receipt-1",
          expires_at: requestInput().expires_at,
          goal_ref: "goal://assistance-1",
          installation_id: "installation-1",
          subject_ref: "subject://assistance-1",
          thread_id: "thread-1",
        },
        delivered,
      });
    },
    clock,
    coordinator,
    delivery,
    refinements,
    runs,
    store,
  };
}

class MemoryAssistanceStore implements DurableAssistancePort {
  failNextDeliveryAttachment = false;
  failNextRefinementAttachment = false;
  private readonly fingerprints = new Map<string, string>();
  private readonly records = new Map<string, AssistanceRequestV1>();

  get recordCount(): number {
    return this.records.size;
  }

  putIfAbsent(commit: AssistanceRequestCommit): Promise<AssistanceRequestCommitResult> {
    const id = commit.request.assistance_id;
    const prior = this.records.get(id);
    if (prior !== undefined) {
      if (this.fingerprints.get(id) !== commit.payload_fingerprint) {
        return Promise.reject(new AssistanceConflictError("Assistance intent changed."));
      }
      return Promise.resolve({ created: false, request: clone(prior) });
    }
    this.records.set(id, clone(commit.request));
    this.fingerprints.set(id, commit.payload_fingerprint);
    return Promise.resolve({ created: true, request: clone(commit.request) });
  }

  read(assistanceId: string) {
    const request = this.records.get(assistanceId);
    return Promise.resolve(request === undefined ? undefined : clone(request));
  }

  attachDelivery(attachment: AssistanceDeliveryAttachment) {
    if (this.failNextDeliveryAttachment) {
      this.failNextDeliveryAttachment = false;
      return Promise.reject(new Error("injected delivery attachment failure"));
    }
    return Promise.resolve(this.mutate(attachment.assistance_id, (request) => {
      if (request.delivery_id !== undefined) {
        if (request.delivery_id !== attachment.delivery_id) throw new AssistanceConflictError("Delivery changed.");
        return request;
      }
      this.requireRevision(request, attachment.expected_revision);
      return {
        ...request,
        delivery_id: attachment.delivery_id,
        revision: request.revision + 1,
        status: "delivery_planned",
        updated_at: attachment.updated_at,
      };
    }));
  }

  attachThreadBinding(attachment: AssistanceThreadAttachment) {
    return Promise.resolve(this.mutate(attachment.assistance_id, (request) => {
      if (request.thread_binding_id !== undefined) {
        if (
          request.thread_binding_id !== attachment.thread_binding_id ||
          request.thread_binding_updated_at !== attachment.thread_binding_updated_at
        ) throw new AssistanceConflictError("Thread binding changed.");
        return request;
      }
      this.requireRevision(request, attachment.expected_revision);
      return {
        ...request,
        revision: request.revision + 1,
        status: "awaiting_reply",
        thread_binding_id: attachment.thread_binding_id,
        thread_binding_updated_at: attachment.thread_binding_updated_at,
        updated_at: attachment.updated_at,
      };
    }));
  }

  recordOutcome(commit: AssistanceOutcomeCommit) {
    return Promise.resolve(this.mutate(commit.assistance_id, (request) => {
      if (request.outcome !== undefined) {
        if (!same(request.outcome, commit.outcome)) throw new AssistanceConflictError("Outcome changed.");
        return request;
      }
      this.requireRevision(request, commit.expected_revision);
      if (request.status !== "awaiting_reply") throw new AssistanceConflictError("Assistance is not awaiting a reply.");
      return {
        ...request,
        outcome: clone(commit.outcome),
        revision: request.revision + 1,
        status: "outcome_recorded",
        updated_at: commit.updated_at,
      };
    }));
  }

  attachRefinement(attachment: AssistanceRefinementAttachment) {
    if (this.failNextRefinementAttachment) {
      this.failNextRefinementAttachment = false;
      return Promise.reject(new Error("injected refinement attachment failure"));
    }
    return Promise.resolve(this.mutate(attachment.assistance_id, (request) => {
      if (request.refinement_ref !== undefined) {
        if (request.refinement_ref !== attachment.refinement_ref) throw new AssistanceConflictError("Refinement changed.");
        return request;
      }
      this.requireRevision(request, attachment.expected_revision);
      return {
        ...request,
        refinement_ref: attachment.refinement_ref,
        revision: request.revision + 1,
        status: "refinement_admitted",
        updated_at: attachment.updated_at,
      };
    }));
  }

  expire(assistanceId: string, expectedRevision: number, expiredAt: string) {
    return Promise.resolve(this.mutate(assistanceId, (request) => {
      if (request.status === "expired") return request;
      this.requireRevision(request, expectedRevision);
      return {
        ...request,
        revision: request.revision + 1,
        status: "expired",
        updated_at: expiredAt,
      };
    }));
  }

  private mutate(
    id: string,
    mutation: (request: AssistanceRequestV1) => AssistanceRequestV1,
  ): AssistanceRequestV1 {
    const current = this.records.get(id);
    if (current === undefined) throw new AssistanceConflictError("Assistance does not exist.");
    const next = mutation(clone(current));
    this.records.set(id, clone(next));
    return clone(next);
  }

  private requireRevision(request: AssistanceRequestV1, expected: number): void {
    if (request.revision !== expected) throw new AssistanceConflictError("Assistance revision changed.");
  }
}

class MemoryDeliveryPlanner {
  failOnce = false;
  observedDurableRequest = false;
  private readonly plans = new Map<string, DeliveryReceiptV1>();

  constructor(
    private readonly assistance: MemoryAssistanceStore,
    private readonly clock: MutableClock,
  ) {}

  get uniquePlanCount(): number {
    return this.plans.size;
  }

  async plan(request: DeliveryPlanRequest): Promise<DeliveryPlanResult> {
    this.observedDurableRequest = this.assistance.recordCount === 1;
    if (!this.observedDurableRequest) throw new Error("assistance was not durable before delivery");
    if (this.failOnce) {
      this.failOnce = false;
      throw new Error("injected delivery plan failure");
    }
    const deliveryId = `delivery-${request.delivery_key}`;
    const prior = this.plans.get(deliveryId);
    if (prior !== undefined) return { created: false, receipt: clone(prior) };
    const receipt: DeliveryReceiptV1 = {
      created_at: this.clock.now().toISOString(),
      delivery_id: deliveryId,
      destination_ref: request.destination_ref,
      parts: request.parts.map((part, index) => ({
        idempotency_key: `message-${deliveryId}-${index + 1}`,
        part_id: `part-${deliveryId}-${index + 1}`,
        payload_digest: part.payload_digest,
        payload_ref: part.payload_ref,
        sequence: index + 1,
        state: "pending",
      })),
      run_id: request.run_id,
      schema_version: "delivery-receipt/v1",
      state: "pending",
      updated_at: this.clock.now().toISOString(),
    };
    this.plans.set(deliveryId, clone(receipt));
    return { created: true, receipt };
  }
}

class MemoryRefinementPort implements AssistanceRefinementPort {
  observedOutcomeFirst = false;
  private readonly admissions = new Map<string, AssistanceRefinementReceipt>();

  constructor(private readonly store: MemoryAssistanceStore) {}

  get uniqueAdmissionCount(): number {
    return this.admissions.size;
  }

  async admit(admission: AssistanceRefinementAdmission) {
    this.observedOutcomeFirst =
      (await this.store.read(admission.assistance_id))?.status === "outcome_recorded";
    if (!this.observedOutcomeFirst) throw new Error("outcome was not durable first");
    const prior = this.admissions.get(admission.idempotency_key);
    if (prior !== undefined) return { ...clone(prior), created: false };
    const receipt = {
      created: true,
      refinement_ref: `refinement://${admission.idempotency_key}`,
    };
    this.admissions.set(admission.idempotency_key, receipt);
    return clone(receipt);
  }
}

class MemoryRunStore implements AssistanceRunReceiptPort {
  private readonly records = new Map<string, RunReceiptV1>();

  constructor(runs: RunReceiptV1[]) {
    for (const run of runs) this.seed(run);
  }

  seed(run: RunReceiptV1): void {
    this.records.set(run.run_id, clone(run));
  }

  delete(runId: string): void {
    this.records.delete(runId);
  }

  readRun(runId: string) {
    const run = this.records.get(runId);
    return run === undefined ? undefined : clone(run);
  }
}

class MemoryThreadStore implements ThreadBindingStorePort {
  private readonly fingerprints = new Map<string, string>();
  private readonly records = new Map<string, SlackThreadBindingV1>();

  putIfAbsent(commit: ThreadBindingCommit): Promise<ThreadBindingCommitResult> {
    const id = commit.binding.thread_binding_id;
    const prior = this.records.get(id);
    if (prior !== undefined) {
      if (this.fingerprints.get(id) !== commit.payload_fingerprint) {
        return Promise.reject(new ThreadBindingConflictError("Thread intent changed."));
      }
      return Promise.resolve({ binding: clone(prior), created: false });
    }
    this.records.set(id, clone(commit.binding));
    this.fingerprints.set(id, commit.payload_fingerprint);
    return Promise.resolve({ binding: clone(commit.binding), created: true });
  }

  read(id: string) {
    const binding = this.records.get(id);
    return Promise.resolve(binding === undefined ? undefined : clone(binding));
  }

  close(id: string, at: string) {
    return Promise.resolve(this.mutate(id, "closed", at));
  }

  expire(id: string, at: string) {
    return Promise.resolve(this.mutate(id, "expired", at));
  }

  private mutate(id: string, state: "closed" | "expired", at: string) {
    const binding = this.records.get(id);
    if (binding === undefined) throw new Error("binding missing");
    const next = { ...binding, state, updated_at: at };
    this.records.set(id, next);
    return clone(next);
  }
}

class MutableClock {
  private value = Date.parse(start);

  now(): Date {
    return new Date(this.value);
  }

  set(value: string): void {
    this.value = Date.parse(value);
  }
}

function requestInput(
  overrides: Partial<AssistanceRequestInput> = {},
): AssistanceRequestInput {
  return {
    binding_id: "binding-1",
    destination_ref: "conversation://opaque-assistance",
    expires_at: "2026-07-16T13:00:00.000Z",
    idempotency_key: "assistance-step-1",
    intended_actor_ref: "actor://intended",
    max_delivery_attempts: 3,
    payload_digest: "sha256:assistance-payload",
    payload_ref: "payload://assistance-question",
    request_run_id: "run-request-1",
    ...overrides,
  };
}

function replyInput(
  assistanceId: string,
  overrides: Partial<NormalizedAssistanceReply> = {},
): NormalizedAssistanceReply {
  return {
    action_classification: "informational",
    actor_kind: "human",
    actor_ref: "actor://intended",
    app_id: "app-1",
    assistance_id: assistanceId,
    binding_id: "binding-1",
    conversation_id: "conversation-1",
    installation_id: "installation-1",
    outcome_digest: "sha256:redacted-outcome",
    outcome_ref: "outcome://redacted-1",
    outcome_size_bytes: 128,
    payload_digest: "sha256:reply-payload",
    redaction_state: "redacted",
    reply_run_id: "run-reply-1",
    thread_id: "thread-1",
    ...overrides,
  };
}

function runReceipt(
  runId: string,
  state: RunReceiptV1["state"],
  inputDigest = "sha256:request-payload",
): RunReceiptV1 {
  return {
    admitted_at: start,
    binding_id: "binding-1",
    idempotency_key: `event:${runId}`,
    input_digest: inputDigest,
    receipt_id: `receipt-${runId}`,
    received_at: start,
    required_capabilities: [],
    retention_policy_ref: "retention://default",
    revision: 1,
    run_id: runId,
    run_kind: "interactive",
    schema_version: "run-receipt/v1",
    state,
    subject_ref: "subject://assistance-1",
    tenant_id: "opaque-tenant",
    updated_at: start,
  };
}

function deliveredReceipt(receipt: DeliveryReceiptV1): DeliveryReceiptV1 {
  return {
    ...clone(receipt),
    parts: receipt.parts.map((part) => ({
      ...part,
      delivered_at: start,
      destination_receipt: "destination-receipt-1",
      state: "delivered",
    })),
    state: "completed",
  };
}

function same(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function clone<T>(value: T): T {
  return structuredClone(value);
}
