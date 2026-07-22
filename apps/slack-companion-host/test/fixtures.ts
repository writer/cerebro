import { createHash } from "node:crypto";
import type {
  AdmitEvidenceRecheckInputV1,
  AdmitEvidenceRecheckResultV1,
  AtomicDocument,
  AtomicDocumentStore,
  BindDeliveredAnswerEvidenceInputV1,
  DeliveredAnswerEvidenceBindingLookupV1,
  DeliveredAnswerEvidenceBindingV1,
  DurableEvidenceRecheckAdmissionPort,
  EvidenceRecheckAdmissionCommitV1,
  EvidenceRecheckAdmissionReceiptLookupV1,
  EvidenceRecheckAdmissionReceiptV1,
  EvidenceRecheckCompletionV1,
  EvidenceRecheckExecutorPort,
  EvidenceRecheckRunContextV1,
  EvidenceRecheckStatusDeliveryPort,
  EvidenceRecheckStatusDeliveryReceiptV1,
  EvidenceRecheckStatusInputV1,
  EvidenceRecheckV1,
  PortableEvidenceRecheckContract,
  SlackEvidenceRecheckStatusV1,
  VerifiedEvidenceRecheckInvocationPort,
  VerifiedEvidenceRecheckInvocationV1,
} from "../src/evidence-recheck/contracts.js";

export const T0 = "2026-07-18T12:00:00.000Z";

export class MutableClock {
  value = new Date(T0);
  now(): Date {
    return new Date(this.value);
  }
  advance(milliseconds: number): void {
    this.value = new Date(this.value.getTime() + milliseconds);
  }
}

export class MemoryAtomicDocumentStore implements AtomicDocumentStore {
  private readonly records = new Map<string, AtomicDocument>();
  private sequence = 0;
  failNextPut = false;

  async compareAndSwap(key: string, token: string, value: unknown): Promise<boolean> {
    const current = this.records.get(key);
    if (current === undefined || current.token !== token) return false;
    this.records.set(key, this.document(key, value));
    return true;
  }

  async list(prefix: string, limit: number, afterKey?: string): Promise<AtomicDocument[]> {
    return [...this.records.values()]
      .filter(
        (record) => record.key.startsWith(prefix) && (afterKey === undefined || record.key > afterKey),
      )
      .sort((left, right) => left.key.localeCompare(right.key))
      .slice(0, limit)
      .map((record) => clone(record));
  }

  async putIfAbsent(key: string, value: unknown): Promise<boolean> {
    if (this.failNextPut) {
      this.failNextPut = false;
      throw new Error("synthetic durable store failure");
    }
    if (this.records.has(key)) return false;
    this.records.set(key, this.document(key, value));
    return true;
  }

  async read(key: string): Promise<AtomicDocument | undefined> {
    const record = this.records.get(key);
    return record === undefined ? undefined : clone(record);
  }

  private document(key: string, value: unknown): AtomicDocument {
    this.sequence += 1;
    return { key, token: `token:${this.sequence}`, value: clone(value) };
  }
}

export class InvocationStore implements VerifiedEvidenceRecheckInvocationPort {
  readonly records = new Map<string, VerifiedEvidenceRecheckInvocationV1>();
  async readVerified(payloadRef: string): Promise<VerifiedEvidenceRecheckInvocationV1> {
    const invocation = this.records.get(payloadRef);
    if (invocation === undefined) throw new Error("verified invocation not found");
    return clone(invocation);
  }
}

export class RecordingStatusDelivery implements EvidenceRecheckStatusDeliveryPort {
  readonly delivered = new Map<string, EvidenceRecheckStatusDeliveryReceiptV1>();
  readonly threads: string[] = [];
  failAfterAccept = false;
  holdNextSend = false;
  private held?: {
    outboxId: string;
    resolve: (receipt: EvidenceRecheckStatusDeliveryReceiptV1) => void;
  };
  private readonly heldStartedResolve: (outboxId: string) => void;
  readonly heldStarted: Promise<string>;

  constructor() {
    let resolve!: (outboxId: string) => void;
    this.heldStarted = new Promise<string>((accept) => {
      resolve = accept;
    });
    this.heldStartedResolve = resolve;
  }

  async inspect(outboxId: string): Promise<EvidenceRecheckStatusDeliveryReceiptV1 | undefined> {
    return clone(this.delivered.get(outboxId));
  }

  async send(input: {
    idempotency_key: string;
    outbox_id: string;
    status: SlackEvidenceRecheckStatusV1;
    thread_ref: string;
  }): Promise<EvidenceRecheckStatusDeliveryReceiptV1> {
    const existing = this.delivered.get(input.idempotency_key);
    if (existing !== undefined) return clone(existing);
    if (this.held?.outboxId === input.idempotency_key) {
      return new Promise((resolve) => {
        const priorResolve = this.held!.resolve;
        this.held!.resolve = (receipt) => {
          priorResolve(receipt);
          resolve(clone(receipt));
        };
      });
    }
    this.threads.push(input.thread_ref);
    const receipt: EvidenceRecheckStatusDeliveryReceiptV1 = {
      accepted_at: T0,
      destination_receipt: `destination-receipt:${hash(input.outbox_id).slice(0, 24)}`,
      idempotency_key: input.idempotency_key,
      outbox_id: input.outbox_id,
      schema_version: "private-evidence-recheck-status-delivery-receipt/v1",
    };
    if (this.holdNextSend) {
      this.holdNextSend = false;
      this.heldStartedResolve(input.outbox_id);
      return new Promise((resolve) => {
        this.held = { outboxId: input.outbox_id, resolve };
      });
    }
    this.delivered.set(input.idempotency_key, receipt);
    if (this.failAfterAccept) {
      this.failAfterAccept = false;
      throw new Error("synthetic process loss after destination acceptance");
    }
    return clone(receipt);
  }

  releaseHeld(): void {
    if (this.held === undefined) throw new Error("no held destination send");
    const receipt: EvidenceRecheckStatusDeliveryReceiptV1 = {
      accepted_at: T0,
      destination_receipt: `destination-receipt:${hash(this.held.outboxId).slice(0, 24)}`,
      idempotency_key: this.held.outboxId,
      outbox_id: this.held.outboxId,
      schema_version: "private-evidence-recheck-status-delivery-receipt/v1",
    };
    this.delivered.set(this.held.outboxId, receipt);
    const resolve = this.held.resolve;
    this.held = undefined;
    resolve(clone(receipt));
  }
}

export function invocation(
  overrides: Partial<VerifiedEvidenceRecheckInvocationV1> = {},
): VerifiedEvidenceRecheckInvocationV1 {
  return {
    actor_ref: "actor:requester",
    binding_ref: "binding:fixture",
    conversation_ref: "conversation:fixture",
    payload_ref: "payload:fixture",
    received_at: T0,
    request_key: "request:fixture",
    run_context: runContext(),
    schema_version: "verified-evidence-recheck-invocation/v1",
    thread_ref: "thread:fixture",
    ...overrides,
  };
}

export function runContext(): EvidenceRecheckRunContextV1 {
  return {
    required_capabilities: [
      { capability_id: "evidence_recheck", level: "required", version: "1" },
    ],
    retention_policy_ref: "retention:fixture",
    service_binding_id: "service-binding:fixture",
    subject_ref: "subject:fixture",
    tenant_id: "tenant:fixture",
  };
}

export function deliveredAnswerInput(): BindDeliveredAnswerEvidenceInputV1 {
  return {
    answer_ref: "answer:fixture",
    answer_run_id: "answer-run:fixture",
    bound_at: T0,
    conversation_ref: "conversation:fixture",
    delivery: {
      created_at: T0,
      delivery_id: "delivery:fixture",
      destination_ref: "destination:fixture",
      parts: [
        {
          delivered_at: T0,
          destination_receipt: "destination-receipt:fixture",
          idempotency_key: "delivery-part:fixture",
          part_id: "part:fixture",
          payload_digest: digest("answer payload"),
          payload_ref: "payload:answer",
          sequence: 1,
          state: "delivered",
        },
      ],
      run_id: "answer-run:fixture",
      schema_version: "delivery-receipt/v1",
      state: "completed",
      updated_at: T0,
    },
    evidence_artifact_ids: ["evidence:one", "evidence:two"],
    operator_refs: ["actor:operator"],
    requester_ref: "actor:requester",
    thread_ref: "thread:fixture",
  };
}

export function completion(at = T0): EvidenceRecheckCompletionV1 {
  return {
    completed_at: at,
    outcome_digest: digest("rechecked evidence"),
    outcome_ref: "outcome:fixture",
    reason_code: "evidence_rechecked",
  };
}

export function completingExecutor(clock: MutableClock): EvidenceRecheckExecutorPort {
  return { execute: async () => completion(clock.now().toISOString()) };
}

export class FixturePortableContract implements PortableEvidenceRecheckContract {
  evidenceRecheckIdentity(bindingRef: string, requestKey: string): string {
    return `evidence-recheck:${hash([bindingRef, requestKey]).slice(0, 32)}`;
  }

  evidenceRecheckAdmissionReceiptIdentity(recheckId: string): string {
    return `evidence-recheck-admission:${hash(recheckId).slice(0, 32)}`;
  }

  bindDeliveredAnswerEvidence(
    input: BindDeliveredAnswerEvidenceInputV1,
  ): DeliveredAnswerEvidenceBindingV1 {
    if (
      input.delivery.state !== "completed" ||
      input.delivery.parts.length === 0 ||
      input.delivery.parts.some(
        (part) => part.state !== "delivered" || part.destination_receipt === undefined,
      ) ||
      input.evidence_artifact_ids.length === 0 ||
      input.answer_run_id !== input.delivery.run_id
    ) {
      throw new Error("Only a fully delivered evidence-backed answer may be bound.");
    }
    const core = {
      answer_ref: input.answer_ref,
      answer_run_id: input.answer_run_id,
      bound_at: input.bound_at,
      conversation_ref: input.conversation_ref,
      delivery_digest: digest(input.delivery),
      delivery_id: input.delivery.delivery_id,
      evidence_artifact_ids: [...input.evidence_artifact_ids].sort(),
      operator_refs: [...input.operator_refs].sort(),
      requester_ref: input.requester_ref,
      thread_ref: input.thread_ref,
    };
    const binding: DeliveredAnswerEvidenceBindingV1 = {
      ...core,
      binding_digest: digest(core),
      binding_ref: "binding:fixture",
      schema_version: "delivered-answer-evidence-binding/v1",
    };
    this.validateDeliveredAnswerEvidenceBinding(binding);
    return binding;
  }

  async admitEvidenceRecheck(
    input: AdmitEvidenceRecheckInputV1,
    bindingLookup: DeliveredAnswerEvidenceBindingLookupV1,
    receiptLookup: EvidenceRecheckAdmissionReceiptLookupV1,
    store: DurableEvidenceRecheckAdmissionPort,
  ): Promise<AdmitEvidenceRecheckResultV1> {
    if (!bindingLookup.found) return rejected("binding_reference_mismatch");
    const binding = bindingLookup.binding;
    const role =
      input.actor_ref === binding.requester_ref
        ? "requester"
        : binding.operator_refs.includes(input.actor_ref)
          ? "operator"
          : undefined;
    if (role === undefined) return rejected("actor_not_authorized");

    const recheckId = this.evidenceRecheckIdentity(input.binding_ref, input.request_key);
    const receiptId = this.evidenceRecheckAdmissionReceiptIdentity(recheckId);
    const inputDigest = digest({ ...input, admitted_at: undefined });
    if (receiptLookup.found) {
      if (
        receiptLookup.receipt.receipt_id !== receiptId ||
        receiptLookup.receipt.input_digest !== inputDigest
      ) {
        throw new Error("Immutable admission receipt conflicts with retried content.");
      }
      return accepted(receiptLookup.receipt, role, true);
    }

    const runId = `run:${hash(recheckId).slice(0, 32)}`;
    const recheck: EvidenceRecheckV1 = {
      actor_ref: input.actor_ref,
      answer_ref: binding.answer_ref,
      binding_digest: binding.binding_digest,
      binding_ref: binding.binding_ref,
      created_at: input.admitted_at,
      evidence_artifact_ids: [...binding.evidence_artifact_ids],
      reason_code: "admitted",
      recheck_id: recheckId,
      request_key: input.request_key,
      revision: 1,
      run_id: runId,
      schema_version: "evidence-recheck/v1",
      state: "queued",
      thread_ref: binding.thread_ref,
      updated_at: input.admitted_at,
    };
    const receipt: EvidenceRecheckAdmissionReceiptV1 = {
      input_digest: inputDigest,
      queue_item: {
        available_at: input.admitted_at,
        binding_digest: binding.binding_digest,
        binding_ref: binding.binding_ref,
        evidence_artifact_ids: [...binding.evidence_artifact_ids],
        idempotency_key: input.request_key,
        queue_item_id: `queue:${hash(recheckId).slice(0, 32)}`,
        recheck_id: recheckId,
        run_id: runId,
        schema_version: "evidence-recheck-queue-item/v1",
        thread_ref: binding.thread_ref,
      },
      receipt_id: receiptId,
      recheck,
      run: {
        admitted_at: input.admitted_at,
        binding_id: input.run_context.service_binding_id,
        idempotency_key: input.request_key,
        input_digest: inputDigest,
        receipt_id: `run-receipt:${hash(runId).slice(0, 32)}`,
        received_at: input.received_at,
        required_capabilities: [...input.run_context.required_capabilities],
        retention_policy_ref: input.run_context.retention_policy_ref,
        revision: 1,
        run_id: runId,
        run_kind: "reconciliation",
        schema_version: "run-receipt/v1",
        state: "queued",
        subject_ref: input.run_context.subject_ref,
        tenant_id: input.run_context.tenant_id,
        updated_at: input.admitted_at,
      },
      schema_version: "evidence-recheck-admission-receipt/v1",
    };
    const commit: EvidenceRecheckAdmissionCommitV1 = {
      receipt,
      transitions: [
        { from: "received", to: "admitted" },
        { from: "admitted", to: "queued" },
      ],
    };
    try {
      const committed = await store.admitAndEnqueue(commit);
      return accepted(committed.receipt, role, !committed.created);
    } catch {
      return {
        acknowledgement_permitted: false,
        authorization: {
          allowed: true,
          role,
          schema_version: "evidence-recheck-authorization/v1",
        },
        duplicate: false,
        reason_code: "durable_admission_unavailable",
        retryable: true,
        schema_version: "admit-evidence-recheck-result/v1",
        status: "degraded",
      };
    }
  }

  projectEvidenceRecheckStatus(input: EvidenceRecheckStatusInputV1): SlackEvidenceRecheckStatusV1 {
    if (input.kind === "admission") {
      const status = input.result.status;
      return {
        message:
          status === "queued" || status === "duplicate"
            ? "Evidence recheck queued."
            : status === "rejected"
              ? "Evidence recheck rejected."
              : "Evidence recheck is temporarily unavailable.",
        ...(input.result.acknowledgement_permitted
          ? { recheck_id: input.result.receipt.recheck.recheck_id }
          : {}),
        retryable: input.result.retryable,
        schema_version: "slack-evidence-recheck-status/v1",
        status,
        terminal: status === "rejected",
      };
    }
    const status =
      input.recheck.state === "running"
        ? "in_progress"
        : input.recheck.state;
    return {
      message: `Evidence recheck ${status.replace("_", " ")}.`,
      recheck_id: input.recheck.recheck_id,
      retryable: status === "degraded",
      schema_version: "slack-evidence-recheck-status/v1",
      status,
      terminal: status === "completed",
    };
  }

  validateDeliveredAnswerEvidenceBinding(binding: DeliveredAnswerEvidenceBindingV1): void {
    if (
      binding.schema_version !== "delivered-answer-evidence-binding/v1" ||
      binding.binding_ref.length === 0 ||
      binding.evidence_artifact_ids.length === 0 ||
      !binding.binding_digest.startsWith("sha256:")
    ) {
      throw new Error("Evidence binding is invalid.");
    }
  }

  validateEvidenceRecheck(recheck: EvidenceRecheckV1): void {
    if (
      recheck.schema_version !== "evidence-recheck/v1" ||
      recheck.revision < 1 ||
      recheck.run_id.length === 0 ||
      recheck.thread_ref.length === 0
    ) {
      throw new Error("Evidence recheck is invalid.");
    }
  }
}

function accepted(
  receipt: EvidenceRecheckAdmissionReceiptV1,
  role: "operator" | "requester",
  duplicate: boolean,
): AdmitEvidenceRecheckResultV1 {
  return {
    acknowledgement_permitted: true,
    authorization: {
      allowed: true,
      role,
      schema_version: "evidence-recheck-authorization/v1",
    },
    duplicate,
    receipt: clone(receipt),
    retryable: false,
    schema_version: "admit-evidence-recheck-result/v1",
    status: duplicate ? "duplicate" : "queued",
  };
}

function rejected(
  reason: "actor_not_authorized" | "binding_reference_mismatch",
): AdmitEvidenceRecheckResultV1 {
  return {
    acknowledgement_permitted: false,
    authorization: {
      allowed: false,
      reason_code: reason,
      schema_version: "evidence-recheck-authorization/v1",
    },
    duplicate: false,
    reason_code: reason,
    retryable: false,
    schema_version: "admit-evidence-recheck-result/v1",
    status: "rejected",
  };
}

function digest(value: unknown): string {
  return `sha256:${hash(value)}`;
}

function hash(value: unknown): string {
  return createHash("sha256").update(stableJson(value)).digest("hex");
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${stableJson(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function clone<T>(value: T): T {
  return structuredClone(value);
}
