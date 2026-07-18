import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { DeliveryReceiptV1 } from "@writer/cerebro-sdk";
import type {
  AdmitEvidenceRecheckInputV1,
  DurableEvidenceRecheckAdmissionPort,
  DeliveredAnswerEvidenceBindingLookupV1,
  EvidenceRecheckAdmissionCommitResultV1,
  EvidenceRecheckAdmissionCommitV1,
  EvidenceRecheckAdmissionReceiptLookupV1,
  EvidenceRecheckAdmissionReceiptV1,
} from "../src/recheck/contracts.js";
import {
  admitEvidenceRecheck,
  authorizeEvidenceRecheck,
  bindDeliveredAnswerEvidence,
  evidenceRecheckAdmissionReceiptIdentity,
  evidenceRecheckIdentity,
  projectEvidenceRecheckStatus,
} from "../src/recheck/policy.js";

const RECEIVED_AT = "2026-07-18T12:00:00.000Z";
const ADMITTED_AT = "2026-07-18T12:00:01.000Z";

describe("server-bound delivered answer evidence", () => {
  test("binds only evidence attached to every durably delivered answer part", () => {
    const binding = makeBinding();
    assert.equal(binding.answer_run_id, "run:answer-1");
    assert.equal(binding.delivery_id, "delivery:answer-1");
    assert.match(binding.delivery_digest, /^sha256:[a-f0-9]{64}$/);
    assert.deepEqual(binding.evidence_artifact_ids, ["artifact:a", "artifact:b"]);
    assert.deepEqual(binding.operator_refs, ["actor:operator-a", "actor:operator-b"]);
    assert.match(binding.binding_digest, /^sha256:[a-f0-9]{64}$/);
    assert.match(binding.binding_ref, /^delivered-answer-evidence-binding:[a-f0-9]{32}$/);

    assert.throws(
      () => makeBinding({ delivery: delivery({ state: "delivering" }) }),
      /completed delivery/,
    );
    assert.throws(
      () =>
        makeBinding({
          delivery: delivery({
            parts: [
              {
                ...delivery().parts[0]!,
                delivered_at: undefined,
                destination_receipt: undefined,
                state: "failed",
              },
            ],
          }),
        }),
      /Every original answer part/,
    );
    assert.throws(
      () => makeBinding({ evidence_artifact_ids: [] }),
      /must be present and bounded/,
    );
  });

  test("hashes operator and evidence arrays as separate canonical fields", () => {
    const first = makeBinding({
      evidence_artifact_ids: ["evidence", "z"],
      operator_refs: ["a"],
    });
    const second = makeBinding({
      evidence_artifact_ids: ["z"],
      operator_refs: ["a", "evidence"],
    });

    assert.notEqual(first.binding_digest, second.binding_digest);
    assert.notEqual(first.binding_ref, second.binding_ref);
  });

  test("binds the immutable completed delivery receipt and rejects duplicate part identities", () => {
    const original = makeBinding();
    const firstPart = delivery().parts[0]!;
    const changedDelivery = makeBinding({
      delivery: delivery({
        parts: [{ ...firstPart, destination_receipt: "destination-receipt:changed" }],
      }),
    });
    assert.notEqual(original.delivery_digest, changedDelivery.delivery_digest);
    assert.notEqual(original.binding_digest, changedDelivery.binding_digest);

    const secondPart = {
      ...firstPart,
      delivered_at: "2026-07-18T11:58:31.000Z",
      destination_receipt: "destination-receipt:2",
      idempotency_key: "delivery-part:2",
      sequence: 2,
    };
    assert.throws(
      () => makeBinding({ delivery: delivery({ parts: [firstPart, secondPart] }) }),
      /part identities must be distinct/,
    );
    assert.throws(
      () =>
        makeBinding({
          delivery: delivery({
            parts: [
              firstPart,
              { ...secondPart, idempotency_key: firstPart.idempotency_key, part_id: "part:2" },
            ],
          }),
        }),
      /part identities must be distinct/,
    );
  });

  test("accepts no caller-selected evidence location or unmodeled content", () => {
    assert.throws(
      () => makeBinding({ evidence_artifact_ids: ["https://example.invalid/evidence"] }),
      /opaque server-owned identifiers/,
    );
    assert.throws(
      () =>
        bindDeliveredAnswerEvidence({
          ...bindingInput(),
          prompt: "unmodeled caller content",
        } as unknown as Parameters<typeof bindDeliveredAnswerEvidence>[0]),
      /unsupported fields/,
    );
  });

  test("authorizes only the original requester or a recorded operator", () => {
    const binding = makeBinding();
    assert.deepEqual(authorizeEvidenceRecheck("actor:requester", binding.binding_ref, binding), {
      allowed: true,
      role: "requester",
      schema_version: "evidence-recheck-authorization/v1",
    });
    assert.equal(
      authorizeEvidenceRecheck("actor:operator-b", binding.binding_ref, binding).allowed,
      true,
    );
    assert.deepEqual(authorizeEvidenceRecheck("actor:other", binding.binding_ref, binding), {
      allowed: false,
      reason_code: "actor_not_authorized",
      schema_version: "evidence-recheck-authorization/v1",
    });
    assert.deepEqual(authorizeEvidenceRecheck("actor:requester", "binding:other", binding), {
      allowed: false,
      reason_code: "binding_reference_mismatch",
      schema_version: "evidence-recheck-authorization/v1",
    });
  });
});

describe("durable evidence recheck admission", () => {
  test("commits request, canonical run, transitions, and queue item before acknowledgement", async () => {
    const input = admissionInput();
    const store = new RecordingStore();
    const result = await admitEvidenceRecheck(
      input,
      foundBindingLookup(input),
      missingLookup(input),
      store,
    );

    assert.equal(store.commits.length, 1);
    assert.equal(result.acknowledgement_permitted, true);
    assert.equal(result.status, "queued");
    assert.equal(result.duplicate, false);
    assert.deepEqual(store.commits[0]?.transitions, [
      { from: "received", to: "admitted" },
      { from: "admitted", to: "queued" },
    ]);
    assert.equal(result.receipt.run.run_kind, "reconciliation");
    assert.equal(result.receipt.run.state, "queued");
    assert.equal(result.receipt.recheck.run_id, result.receipt.run.run_id);
    assert.equal(result.receipt.queue_item.run_id, result.receipt.run.run_id);
    assert.equal(result.receipt.queue_item.thread_ref, foundBindingLookup(input).binding.thread_ref);
    assert.equal(result.receipt.queue_item.available_at, result.receipt.run.admitted_at);
  });

  test("does not permit acknowledgement when the durable transaction is unavailable", async () => {
    const input = admissionInput();
    const store = new RecordingStore();
    store.failure = new Error("storage unavailable");
    const result = await admitEvidenceRecheck(
      input,
      foundBindingLookup(input),
      missingLookup(input),
      store,
    );
    assert.deepEqual(result, {
      acknowledgement_permitted: false,
      authorization: {
        allowed: true,
        role: "requester",
        schema_version: "evidence-recheck-authorization/v1",
      },
      duplicate: false,
      reason_code: "durable_admission_unavailable",
      retryable: true,
      schema_version: "admit-evidence-recheck-result/v1",
      status: "degraded",
    });
  });

  test("replays the durable receipt without another transaction", async () => {
    const input = admissionInput();
    const firstStore = new RecordingStore();
    const first = await admitEvidenceRecheck(
      input,
      foundBindingLookup(input),
      missingLookup(input),
      firstStore,
    );
    assert(first.acknowledgement_permitted);

    const replayStore = new RecordingStore();
    const replay = await admitEvidenceRecheck(
      { ...input, admitted_at: "2026-07-18T12:05:00.000Z" },
      foundBindingLookup(input),
      foundLookup(first.receipt),
      replayStore,
    );
    assert.equal(replayStore.commits.length, 0);
    assert.equal(replay.acknowledgement_permitted, true);
    assert.equal(replay.status, "duplicate");
    assert.equal(replay.duplicate, true);
    assert.deepEqual(replay.receipt, first.receipt);
  });

  test("returns the persisted winner for a concurrent commit race", async () => {
    const winnerInput = admissionInput({ admitted_at: "2026-07-18T12:00:02.000Z" });
    const winner = await admitEvidenceRecheck(
      winnerInput,
      foundBindingLookup(winnerInput),
      missingLookup(winnerInput),
      new RecordingStore(),
    );
    assert(winner.acknowledgement_permitted);

    const loserInput = admissionInput({ admitted_at: "2026-07-18T12:00:03.000Z" });
    const store = new RecordingStore();
    store.created = false;
    store.mutateReceipt = () => structuredClone(winner.receipt);
    const result = await admitEvidenceRecheck(
      loserInput,
      foundBindingLookup(loserInput),
      missingLookup(loserInput),
      store,
    );
    assert.equal(result.acknowledgement_permitted, true);
    assert.equal(result.status, "duplicate");
    assert.equal(result.duplicate, true);
    assert.deepEqual(result.receipt, winner.receipt);
  });

  test("requires the host-resolved binding and ignores caller-forged authorization data", async () => {
    const forgedBinding = makeBinding({ requester_ref: "actor:attacker" });
    const input = admissionInput({ actor_ref: "actor:attacker" });
    const store = new RecordingStore();

    const denied = await admitEvidenceRecheck(
      input,
      foundBindingLookup(input),
      missingLookup(input),
      store,
    );
    assert.equal(denied.status, "rejected");
    assert.equal(store.commits.length, 0);

    await assert.rejects(
      admitEvidenceRecheck(
        { ...input, binding: forgedBinding } as unknown as AdmitEvidenceRecheckInputV1,
        foundBindingLookup(input),
        missingLookup(input),
        store,
      ),
      /unsupported fields/,
    );

    const missingBinding: DeliveredAnswerEvidenceBindingLookupV1 = {
      binding_ref: input.binding_ref,
      found: false,
      schema_version: "delivered-answer-evidence-binding-lookup/v1",
    };
    const missing = await admitEvidenceRecheck(
      input,
      missingBinding,
      missingLookup(input),
      store,
    );
    assert.equal(missing.status, "rejected");
    assert.equal(missing.acknowledgement_permitted, false);
  });

  test("fails closed on conflicting receipt reuse or a malformed transaction receipt", async () => {
    const input = admissionInput();
    const firstStore = new RecordingStore();
    const first = await admitEvidenceRecheck(
      input,
      foundBindingLookup(input),
      missingLookup(input),
      firstStore,
    );
    assert(first.acknowledgement_permitted);

    await assert.rejects(
      admitEvidenceRecheck(
        {
          ...input,
          run_context: { ...input.run_context, tenant_id: "tenant:changed" },
        },
        foundBindingLookup(input),
        foundLookup(first.receipt),
        new RecordingStore(),
      ),
      /conflicts with this request/,
    );

    const malformedStore = new RecordingStore();
    malformedStore.mutateReceipt = (receipt) => ({
      ...receipt,
      run: { ...receipt.run, run_id: "evidence-recheck-run:changed" },
    });
    await assert.rejects(
      admitEvidenceRecheck(
        input,
        foundBindingLookup(input),
        missingLookup(input),
        malformedStore,
      ),
      /canonical run receipt is invalid/,
    );
  });

  test("binds every returned durable record to the admitted request", async () => {
    const input = admissionInput();
    const mutations: Array<
      (receipt: EvidenceRecheckAdmissionReceiptV1) => EvidenceRecheckAdmissionReceiptV1
    > = [
      (receipt) => ({
        ...receipt,
        recheck: { ...receipt.recheck, actor_ref: "actor:operator-a" },
      }),
      (receipt) => ({
        ...receipt,
        recheck: { ...receipt.recheck, request_key: "event:another-recheck" },
      }),
      (receipt) => ({
        ...receipt,
        recheck: { ...receipt.recheck, evidence_artifact_ids: ["artifact:other"] },
      }),
      (receipt) => ({
        ...receipt,
        recheck: { ...receipt.recheck, created_at: "2026-07-18T12:00:02.000Z" },
      }),
      (receipt) => ({
        ...receipt,
        recheck: { ...receipt.recheck, updated_at: "2026-07-18T12:00:02.000Z" },
      }),
      (receipt) => ({
        ...receipt,
        queue_item: { ...receipt.queue_item, queue_item_id: "queue-item:forged" },
      }),
      (receipt) => ({
        ...receipt,
        queue_item: { ...receipt.queue_item, idempotency_key: "queue:forged" },
      }),
      (receipt) => ({
        ...receipt,
        run: {
          ...receipt.run,
          raw_payload: "not portable",
        } as unknown as EvidenceRecheckAdmissionReceiptV1["run"],
      }),
    ];

    for (const mutateReceipt of mutations) {
      const store = new RecordingStore();
      store.mutateReceipt = mutateReceipt;
      await assert.rejects(
        admitEvidenceRecheck(
          input,
          foundBindingLookup(input),
          missingLookup(input),
          store,
        ),
        /identities are invalid|mismatched recheck|not correlated|unsupported fields|updated_at cannot precede/,
      );
    }
  });

  test("rejects unauthorized, unbounded, and unmodeled requests before persistence", async () => {
    const unauthorized = admissionInput({ actor_ref: "actor:other" });
    const deniedStore = new RecordingStore();
    const denied = await admitEvidenceRecheck(
      unauthorized,
      foundBindingLookup(unauthorized),
      missingLookup(unauthorized),
      deniedStore,
    );
    assert.equal(denied.status, "rejected");
    assert.equal(denied.acknowledgement_permitted, false);
    assert.equal(deniedStore.commits.length, 0);

    const unmodeledStore = new RecordingStore();
    await assert.rejects(
      admitEvidenceRecheck(
        { ...admissionInput(), raw_payload: "not portable" } as unknown as AdmitEvidenceRecheckInputV1,
        foundBindingLookup(admissionInput()),
        missingLookup(admissionInput()),
        unmodeledStore,
      ),
      /unsupported fields/,
    );
    assert.equal(unmodeledStore.commits.length, 0);

    const oversizedInput = admissionInput({ request_key: `event:${"x".repeat(300)}` });
    await assert.rejects(
      admitEvidenceRecheck(
        oversizedInput,
        foundBindingLookup(oversizedInput),
        missingLookup(admissionInput()),
        new RecordingStore(),
      ),
      /request_key is not a bounded canonical value/,
    );
  });

  test("derives stable recheck correlation and changes it with the request identity", () => {
    const binding = makeBinding();
    const first = evidenceRecheckIdentity(binding.binding_ref, "event:recheck-1");
    assert.equal(first, evidenceRecheckIdentity(binding.binding_ref, "event:recheck-1"));
    assert.notEqual(first, evidenceRecheckIdentity(binding.binding_ref, "event:recheck-2"));
    assert.match(first, /^evidence-recheck:[a-f0-9]{32}$/);
    assert.match(
      evidenceRecheckAdmissionReceiptIdentity(first),
      /^evidence-recheck-admission-receipt:[a-f0-9]{64}$/,
    );
  });

  test("canonicalizes capability identity without host locale ordering", async () => {
    const input = admissionInput({
      run_context: {
        ...admissionInput().run_context,
        required_capabilities: [
          { capability_id: "ä", level: "required", version: "v1" },
          { capability_id: "z", level: "required", version: "v1" },
        ],
      },
    });
    const first = await admitEvidenceRecheck(
      input,
      foundBindingLookup(input),
      missingLookup(input),
      new RecordingStore(),
    );
    assert(first.acknowledgement_permitted);
    assert.deepEqual(
      first.receipt.run.required_capabilities.map((capability) => capability.capability_id),
      ["z", "ä"],
    );

    const replayInput = {
      ...input,
      admitted_at: "2026-07-18T12:05:00.000Z",
      run_context: {
        ...input.run_context,
        required_capabilities: [...input.run_context.required_capabilities].reverse(),
      },
    };
    const replay = await admitEvidenceRecheck(
      replayInput,
      foundBindingLookup(replayInput),
      foundLookup(first.receipt),
      new RecordingStore(),
    );
    assert(replay.acknowledgement_permitted);
    assert.deepEqual(replay.receipt, first.receipt);
  });
});

describe("Slack-visible evidence recheck status", () => {
  test("projects queued, duplicate, degraded, rejected, running, and completed truth", async () => {
    const input = admissionInput();
    const first = await admitEvidenceRecheck(
      input,
      foundBindingLookup(input),
      missingLookup(input),
      new RecordingStore(),
    );
    assert(first.acknowledgement_permitted);
    assert.equal(projectAdmission(first).status, "queued");

    const duplicate = await admitEvidenceRecheck(
      input,
      foundBindingLookup(input),
      foundLookup(first.receipt),
      new RecordingStore(),
    );
    assert.equal(projectAdmission(duplicate).status, "duplicate");

    const failedStore = new RecordingStore();
    failedStore.failure = new Error("unavailable");
    const degradedAdmission = await admitEvidenceRecheck(
      input,
      foundBindingLookup(input),
      missingLookup(input),
      failedStore,
    );
    assert.equal(projectAdmission(degradedAdmission).status, "degraded");

    const rejectedInput = admissionInput({ actor_ref: "actor:other" });
    const rejected = await admitEvidenceRecheck(
      rejectedInput,
      foundBindingLookup(rejectedInput),
      missingLookup(rejectedInput),
      new RecordingStore(),
    );
    assert.equal(projectAdmission(rejected).status, "rejected");

    assert.equal(projectRecheck({ ...first.receipt.recheck, state: "running" }).status, "in_progress");
    assert.equal(
      projectRecheck({
        ...first.receipt.recheck,
        completed_at: "2026-07-18T12:05:00.000Z",
        outcome_digest: `sha256:${"a".repeat(64)}`,
        outcome_ref: "evidence-recheck-outcome:1",
        reason_code: "evidence_rechecked",
        revision: 3,
        state: "completed",
        updated_at: "2026-07-18T12:05:00.000Z",
      }).status,
      "completed",
    );
    assert.equal(
      projectRecheck({
        ...first.receipt.recheck,
        reason_code: "evidence_temporarily_unavailable",
        revision: 2,
        state: "degraded",
        updated_at: "2026-07-18T12:03:00.000Z",
      }).status,
      "degraded",
    );
  });

  test("rejects invalid runtime states and incomplete completion truth", async () => {
    const input = admissionInput();
    const result = await admitEvidenceRecheck(
      input,
      foundBindingLookup(input),
      missingLookup(input),
      new RecordingStore(),
    );
    assert(result.acknowledgement_permitted);
    assert.throws(
      () => projectRecheck({ ...result.receipt.recheck, state: "unknown" as "queued" }),
      /state is unsupported/,
    );
    assert.throws(
      () =>
        projectRecheck({
          ...result.receipt.recheck,
          raw_payload: "not portable",
        } as unknown as EvidenceRecheckAdmissionReceiptV1["recheck"]),
      /unsupported fields/,
    );
    assert.throws(
      () =>
        projectAdmission({
          ...result,
          status: "unknown",
        } as unknown as Awaited<ReturnType<typeof admitEvidenceRecheck>>),
      /status is unsupported/,
    );
    assert.throws(
      () =>
        projectAdmission({
          ...result,
          acknowledgement_permitted: false,
          authorization: {
            allowed: false,
            reason_code: "actor_not_authorized",
            schema_version: "evidence-recheck-authorization/v1",
          },
          duplicate: true,
          receipt: {
            recheck: { recheck_id: "forged:recheck" },
          },
          retryable: true,
          status: "queued",
        } as unknown as Awaited<ReturnType<typeof admitEvidenceRecheck>>),
      /contradictory/,
    );
    assert.throws(
      () =>
        projectAdmission({
          ...result,
          receipt: {
            ...result.receipt,
            queue_item: {
              ...result.receipt.queue_item,
              queue_item_id: "queue-item:forged",
            },
          },
        }),
      /not correlated/,
    );
    assert.throws(
      () => projectRecheck({ ...result.receipt.recheck, state: "completed" }),
      /require a durable outcome/,
    );
    assert.throws(
      () =>
        projectRecheck({
          ...result.receipt.recheck,
          completed_at: "2026-07-18T12:05:00.000Z",
          outcome_digest: "not-a-digest",
          outcome_ref: "evidence-recheck-outcome:1",
          state: "completed",
          updated_at: "2026-07-18T12:05:00.000Z",
        }),
      /outcome_digest must be a canonical SHA-256 digest/,
    );
    assert.throws(
      () =>
        projectRecheck({
          ...result.receipt.recheck,
          completed_at: "2000-01-01T00:00:00.000Z",
          outcome_digest: `sha256:${"b".repeat(64)}`,
          outcome_ref: "evidence-recheck-outcome:1",
          state: "completed",
          updated_at: "2000-01-01T00:00:00.000Z",
        }),
      /updated_at cannot precede created_at|timestamps must be monotonic/,
    );
    assert.throws(
      () =>
        projectRecheck({
          ...result.receipt.recheck,
          created_at: "2026-07-18T05:00:01-07:00",
        }),
      /canonical UTC form/,
    );
    assert.throws(
      () =>
        projectRecheck({
          ...result.receipt.recheck,
          binding_digest: "not-a-digest",
        }),
      /binding_digest must be a canonical SHA-256 digest/,
    );
    assert.throws(
      () =>
        projectRecheck({
          ...result.receipt.recheck,
          recheck_id: "recheck:unrelated",
          run_id: "run:unrelated",
        }),
      /identities are invalid/,
    );
    assert.throws(
      () =>
        projectEvidenceRecheckStatus({
          kind: "recheck",
          raw_payload: "not portable",
          recheck: result.receipt.recheck,
          schema_version: "evidence-recheck-status-input/v1",
        } as unknown as Parameters<typeof projectEvidenceRecheckStatus>[0]),
      /unsupported fields/,
    );
  });
});

class RecordingStore implements DurableEvidenceRecheckAdmissionPort {
  commits: EvidenceRecheckAdmissionCommitV1[] = [];
  created = true;
  failure?: Error;
  mutateReceipt?: (
    receipt: EvidenceRecheckAdmissionReceiptV1,
  ) => EvidenceRecheckAdmissionReceiptV1;

  async admitAndEnqueue(
    commit: EvidenceRecheckAdmissionCommitV1,
  ): Promise<EvidenceRecheckAdmissionCommitResultV1> {
    this.commits.push(structuredClone(commit));
    if (this.failure !== undefined) {
      throw this.failure;
    }
    return {
      created: this.created,
      receipt: this.mutateReceipt?.(commit.receipt) ?? structuredClone(commit.receipt),
    };
  }
}

function projectAdmission(result: Awaited<ReturnType<typeof admitEvidenceRecheck>>) {
  return projectEvidenceRecheckStatus({
    kind: "admission",
    result,
    schema_version: "evidence-recheck-status-input/v1",
  });
}

function projectRecheck(
  recheck: EvidenceRecheckAdmissionReceiptV1["recheck"],
) {
  return projectEvidenceRecheckStatus({
    kind: "recheck",
    recheck,
    schema_version: "evidence-recheck-status-input/v1",
  });
}

function missingLookup(
  input: AdmitEvidenceRecheckInputV1,
): EvidenceRecheckAdmissionReceiptLookupV1 {
  const recheckId = evidenceRecheckIdentity(input.binding_ref, input.request_key);
  return {
    found: false,
    receipt_id: evidenceRecheckAdmissionReceiptIdentity(recheckId),
    schema_version: "evidence-recheck-admission-receipt-lookup/v1",
  };
}

function foundLookup(
  receipt: EvidenceRecheckAdmissionReceiptV1,
): EvidenceRecheckAdmissionReceiptLookupV1 {
  return {
    found: true,
    receipt,
    schema_version: "evidence-recheck-admission-receipt-lookup/v1",
  };
}

function admissionInput(
  overrides: Partial<AdmitEvidenceRecheckInputV1> = {},
): AdmitEvidenceRecheckInputV1 {
  return {
    actor_ref: "actor:requester",
    admitted_at: ADMITTED_AT,
    binding_ref: makeBinding().binding_ref,
    received_at: RECEIVED_AT,
    request_key: "event:recheck-1",
    run_context: {
      required_capabilities: [
        { capability_id: "evidence.read", level: "required", version: "v1" },
      ],
      retention_policy_ref: "retention:standard",
      service_binding_id: "service-binding:1",
      subject_ref: "subject:1",
      tenant_id: "tenant:1",
    },
    ...overrides,
  };
}

function foundBindingLookup(
  input: AdmitEvidenceRecheckInputV1,
  binding = makeBinding(),
): Extract<DeliveredAnswerEvidenceBindingLookupV1, { found: true }> {
  assert.equal(binding.binding_ref, input.binding_ref);
  return {
    binding,
    found: true,
    schema_version: "delivered-answer-evidence-binding-lookup/v1",
  };
}

function makeBinding(
  overrides: Partial<ReturnType<typeof bindingInput>> = {},
) {
  return bindDeliveredAnswerEvidence({ ...bindingInput(), ...overrides });
}

function bindingInput() {
  return {
    answer_ref: "answer:1",
    answer_run_id: "run:answer-1",
    bound_at: "2026-07-18T11:59:00.000Z",
    conversation_ref: "conversation:1",
    delivery: delivery(),
    evidence_artifact_ids: ["artifact:b", "artifact:a"] as readonly string[],
    operator_refs: ["actor:operator-b", "actor:operator-a"] as readonly string[],
    requester_ref: "actor:requester",
    thread_ref: "thread:1",
  };
}

function delivery(overrides: Partial<DeliveryReceiptV1> = {}): DeliveryReceiptV1 {
  return {
    created_at: "2026-07-18T11:58:00.000Z",
    delivery_id: "delivery:answer-1",
    destination_ref: "destination:conversation-1",
    parts: [
      {
        delivered_at: "2026-07-18T11:58:30.000Z",
        destination_receipt: "destination-receipt:1",
        idempotency_key: "delivery-part:1",
        part_id: "part:1",
        payload_digest: "sha256:answer-part-1",
        payload_ref: "answer-part:1",
        sequence: 1,
        state: "delivered",
      },
    ],
    run_id: "run:answer-1",
    schema_version: "delivery-receipt/v1",
    state: "completed",
    updated_at: "2026-07-18T11:58:30.000Z",
    ...overrides,
  };
}
