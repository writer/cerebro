import assert from "node:assert/strict";
import test from "node:test";
import {
  admitEvidenceRecheck,
  bindDeliveredAnswerEvidence,
  evidenceRecheckAdmissionReceiptIdentity,
  evidenceRecheckIdentity,
  projectEvidenceRecheckStatus,
  validateDeliveredAnswerEvidenceBinding,
  validateEvidenceRecheck,
} from "@writer/cerebro-slack-companion";
import { AtomicEvidenceRecheckStore } from "../dist/src/evidence-recheck/persistence.js";

class Documents {
  #records = new Map();
  #sequence = 0;

  async compareAndSwap(key, token, value) {
    const current = this.#records.get(key);
    if (current === undefined || current.token !== token) return false;
    this.#records.set(key, this.#document(key, value));
    return true;
  }

  async list(prefix, limit, afterKey) {
    return [...this.#records.values()]
      .filter((record) => record.key.startsWith(prefix) && (afterKey === undefined || record.key > afterKey))
      .sort((left, right) => left.key.localeCompare(right.key))
      .slice(0, limit)
      .map((record) => structuredClone(record));
  }

  async putIfAbsent(key, value) {
    if (this.#records.has(key)) return false;
    this.#records.set(key, this.#document(key, value));
    return true;
  }

  async read(key) {
    const record = this.#records.get(key);
    return record === undefined ? undefined : structuredClone(record);
  }

  #document(key, value) {
    this.#sequence += 1;
    return { key, token: `compat:${this.#sequence}`, value: structuredClone(value) };
  }
}

const contract = {
  admitEvidenceRecheck,
  bindDeliveredAnswerEvidence,
  evidenceRecheckAdmissionReceiptIdentity,
  evidenceRecheckIdentity,
  projectEvidenceRecheckStatus,
  validateDeliveredAnswerEvidenceBinding,
  validateEvidenceRecheck,
};

function bindingInput() {
  return {
    answer_ref: "answer:compat",
    answer_run_id: "run:answer-compat",
    bound_at: "2026-07-18T11:59:00.000Z",
    conversation_ref: "conversation:compat",
    delivery: {
      created_at: "2026-07-18T11:58:00.000Z",
      delivery_id: "delivery:compat",
      destination_ref: "destination:compat",
      parts: [{
        delivered_at: "2026-07-18T11:58:30.000Z",
        destination_receipt: "destination-receipt:compat",
        idempotency_key: "delivery-part:compat",
        part_id: "part:compat",
        payload_digest: "sha256:answer-part-compat",
        payload_ref: "answer-part:compat",
        sequence: 1,
        state: "delivered",
      }],
      run_id: "run:answer-compat",
      schema_version: "delivery-receipt/v1",
      state: "completed",
      updated_at: "2026-07-18T11:58:30.000Z",
    },
    evidence_artifact_ids: ["artifact:b", "artifact:a"],
    operator_refs: ["actor:operator"],
    requester_ref: "actor:requester",
    thread_ref: "thread:compat",
  };
}

function admissionInput(binding, admittedAt) {
  return {
    actor_ref: "actor:requester",
    admitted_at: admittedAt,
    binding_ref: binding.binding_ref,
    received_at: "2026-07-18T11:59:30.000Z",
    request_key: "request:compat",
    run_context: {
      required_capabilities: [
        { capability_id: "evidence.read", level: "required", version: "v1" },
      ],
      retention_policy_ref: "retention:compat",
      service_binding_id: "service-binding:compat",
      subject_ref: "subject:compat",
      tenant_id: "tenant:compat",
    },
  };
}

function missingReceipt(input) {
  const recheckId = evidenceRecheckIdentity(input.binding_ref, input.request_key);
  return {
    found: false,
    receipt_id: evidenceRecheckAdmissionReceiptIdentity(recheckId),
    schema_version: "evidence-recheck-admission-receipt-lookup/v1",
  };
}

test("exact public recheck policy executes through the private atomic store", async () => {
  const documents = new Documents();
  const store = new AtomicEvidenceRecheckStore({ contract, documents });
  const binding = bindDeliveredAnswerEvidence(bindingInput());
  await store.putBindingIfAbsent(binding);
  const lookup = await store.bindingLookup(binding.binding_ref);
  const firstInput = admissionInput(binding, "2026-07-18T12:00:00.000Z");

  const [first, raced] = await Promise.all([
    admitEvidenceRecheck(firstInput, lookup, missingReceipt(firstInput), store),
    admitEvidenceRecheck(
      admissionInput(binding, "2026-07-18T12:00:01.000Z"),
      lookup,
      missingReceipt(firstInput),
      store,
    ),
  ]);
  assert.equal(first.acknowledgement_permitted, true);
  assert.equal(raced.acknowledgement_permitted, true);
  assert.equal(first.receipt.run.run_id, raced.receipt.run.run_id);
  assert.equal([first, raced].filter((result) => result.duplicate).length, 1);
  assert.deepEqual(await store.pendingCounts(), { execution: 1, outbox: 1 });

  const admissionStatus = projectEvidenceRecheckStatus({
    kind: "admission",
    result: first,
    schema_version: "evidence-recheck-status-input/v1",
  });
  assert.ok(["duplicate", "queued"].includes(admissionStatus.status));
  assert.equal(admissionStatus.recheck_id, first.receipt.recheck.recheck_id);
  assert.equal(admissionStatus.terminal, false);

  const persistedRecheck = await store.readCurrentRecheck(first.receipt.run.run_id);
  assert.ok(persistedRecheck);
  const recheckStatus = projectEvidenceRecheckStatus({
    kind: "recheck",
    recheck: persistedRecheck,
    schema_version: "evidence-recheck-status-input/v1",
  });
  assert.equal(recheckStatus.status, "queued");
  assert.equal(recheckStatus.recheck_id, first.receipt.recheck.recheck_id);
  assert.equal(recheckStatus.retryable, false);
  assert.equal(recheckStatus.terminal, false);

  const receiptLookup = await store.receiptLookup(first.receipt.receipt_id);
  const duplicate = await admitEvidenceRecheck(
    admissionInput(binding, "2026-07-18T12:00:02.000Z"),
    lookup,
    receiptLookup,
    store,
  );
  assert.equal(duplicate.acknowledgement_permitted, true);
  assert.equal(duplicate.duplicate, true);
});
