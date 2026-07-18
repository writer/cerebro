import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import type { CapabilityRequirement, RunReceiptV1 } from "@writer/cerebro-sdk";
import {
  EVIDENCE_RECHECK_LIMITS,
  type AdmitEvidenceRecheckInputV1,
  type AdmitEvidenceRecheckResultV1,
  type BindDeliveredAnswerEvidenceInputV1,
  type DeliveredAnswerEvidenceBindingV1,
  type DurableEvidenceRecheckAdmissionPort,
  type EvidenceRecheckAdmissionCommitResultV1,
  type EvidenceRecheckAdmissionReceiptLookupV1,
  type EvidenceRecheckAdmissionReceiptV1,
  type EvidenceRecheckAuthorizationV1,
  type EvidenceRecheckQueueItemV1,
  type EvidenceRecheckStatusInputV1,
  type EvidenceRecheckV1,
  type SlackEvidenceRecheckStatusV1,
} from "./contracts.js";

const UNSAFE_TEXT_CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;
const OPAQUE_ARTIFACT_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const SHA256_DIGEST = /^sha256:[a-f0-9]{64}$/;
const RECHECK_STATES: readonly EvidenceRecheckV1["state"][] = [
  "queued",
  "running",
  "completed",
  "degraded",
];

export class EvidenceRecheckInvariantError extends Error {}

export function bindDeliveredAnswerEvidence(
  input: BindDeliveredAnswerEvidenceInputV1,
): DeliveredAnswerEvidenceBindingV1 {
  assertExactKeys(input, [
    "answer_ref",
    "answer_run_id",
    "bound_at",
    "conversation_ref",
    "delivery",
    "evidence_artifact_ids",
    "operator_refs",
    "requester_ref",
    "thread_ref",
  ], "delivered answer evidence input");
  requireRef(input.answer_ref, "answer_ref");
  requireRef(input.answer_run_id, "answer_run_id");
  requireRef(input.conversation_ref, "conversation_ref");
  requireRef(input.requester_ref, "requester_ref");
  requireRef(input.thread_ref, "thread_ref");
  const boundAt = normalizeTimestamp(input.bound_at, "bound_at");
  validateCompletedDelivery(input.delivery, input.answer_run_id);
  const deliveryDigest = completedDeliveryDigest(input.delivery);
  const evidenceArtifactIds = canonicalArtifactIds(input.evidence_artifact_ids);
  const operatorRefs = canonicalRefs(
    input.operator_refs,
    EVIDENCE_RECHECK_LIMITS.operator_refs,
    "operator_refs",
  );
  const bindingDigest = deliveredAnswerEvidenceBindingDigest({
    answer_ref: input.answer_ref,
    answer_run_id: input.answer_run_id,
    bound_at: boundAt,
    conversation_ref: input.conversation_ref,
    delivery_digest: deliveryDigest,
    delivery_id: input.delivery.delivery_id,
    evidence_artifact_ids: evidenceArtifactIds,
    operator_refs: operatorRefs,
    requester_ref: input.requester_ref,
    thread_ref: input.thread_ref,
  });
  return {
    answer_ref: input.answer_ref,
    answer_run_id: input.answer_run_id,
    binding_digest: bindingDigest,
    binding_ref: evidenceBindingIdentity(bindingDigest),
    bound_at: boundAt,
    conversation_ref: input.conversation_ref,
    delivery_digest: deliveryDigest,
    delivery_id: input.delivery.delivery_id,
    evidence_artifact_ids: evidenceArtifactIds,
    operator_refs: operatorRefs,
    requester_ref: input.requester_ref,
    schema_version: "delivered-answer-evidence-binding/v1",
    thread_ref: input.thread_ref,
  };
}

export function authorizeEvidenceRecheck(
  actorRef: string,
  bindingRef: string,
  binding: DeliveredAnswerEvidenceBindingV1,
): EvidenceRecheckAuthorizationV1 {
  requireRef(actorRef, "actor_ref");
  requireRef(bindingRef, "binding_ref");
  validateDeliveredAnswerEvidenceBinding(binding);
  if (bindingRef !== binding.binding_ref) {
    return deniedAuthorization("binding_reference_mismatch");
  }
  if (actorRef === binding.requester_ref) {
    return allowedAuthorization("requester");
  }
  if (binding.operator_refs.includes(actorRef)) {
    return allowedAuthorization("operator");
  }
  return deniedAuthorization("actor_not_authorized");
}

export function evidenceRecheckIdentity(bindingRef: string, requestKey: string): string {
  requireRef(bindingRef, "binding_ref");
  requireRequestKey(requestKey);
  return `evidence-recheck:${stableDigest([bindingRef, requestKey]).slice(0, 32)}`;
}

export function evidenceRecheckAdmissionReceiptIdentity(recheckId: string): string {
  requireRef(recheckId, "recheck_id");
  return `evidence-recheck-admission-receipt:${stableDigest([recheckId])}`;
}

export async function admitEvidenceRecheck(
  input: AdmitEvidenceRecheckInputV1,
  receiptLookup: EvidenceRecheckAdmissionReceiptLookupV1,
  store: DurableEvidenceRecheckAdmissionPort,
): Promise<AdmitEvidenceRecheckResultV1> {
  validateAdmissionInput(input);
  const authorization = authorizeEvidenceRecheck(
    input.actor_ref,
    input.binding_ref,
    input.binding,
  );
  if (!authorization.allowed) {
    return {
      acknowledgement_permitted: false,
      authorization,
      duplicate: false,
      reason_code: authorization.reason_code,
      retryable: false,
      schema_version: "admit-evidence-recheck-result/v1",
      status: "rejected",
    };
  }

  const receivedAt = normalizeTimestamp(input.received_at, "received_at");
  const admittedAt = normalizeTimestamp(input.admitted_at, "admitted_at");
  if (Date.parse(admittedAt) < Date.parse(receivedAt)) {
    throw new EvidenceRecheckInvariantError("admitted_at cannot precede received_at.");
  }
  const capabilities = canonicalCapabilities(input.run_context.required_capabilities);
  const recheckId = evidenceRecheckIdentity(input.binding.binding_ref, input.request_key);
  const runId = evidenceRecheckRunIdentity(recheckId);
  const receiptId = evidenceRecheckAdmissionReceiptIdentity(recheckId);
  const inputDigest = evidenceRecheckInputDigest(input, receivedAt, capabilities);
  validateReceiptLookup(receiptLookup, receiptId);

  if (receiptLookup.found) {
    validateAdmissionReceipt(receiptLookup.receipt, {
      binding: input.binding,
      actor_ref: input.actor_ref,
      admitted_at: receiptLookup.receipt.run.admitted_at,
      capabilities,
      input_digest: inputDigest,
      receipt_id: receiptId,
      received_at: receivedAt,
      recheck_id: recheckId,
      request_key: input.request_key,
      run_context: input.run_context,
      run_id: runId,
    });
    return acceptedResult(authorization, receiptLookup.receipt, true);
  }

  const receipt = createAdmissionReceipt({
    admitted_at: admittedAt,
    actor_ref: input.actor_ref,
    binding: input.binding,
    capabilities,
    input_digest: inputDigest,
    receipt_id: receiptId,
    received_at: receivedAt,
    recheck_id: recheckId,
    request_key: input.request_key,
    run_context: input.run_context,
    run_id: runId,
  });

  let committed: EvidenceRecheckAdmissionCommitResultV1;
  try {
    committed = await store.admitAndEnqueue({
      receipt,
      transitions: [
        { from: "received", to: "admitted" },
        { from: "admitted", to: "queued" },
      ],
    });
  } catch {
    return {
      acknowledgement_permitted: false,
      authorization,
      duplicate: false,
      reason_code: "durable_admission_unavailable",
      retryable: true,
      schema_version: "admit-evidence-recheck-result/v1",
      status: "degraded",
    };
  }

  if (typeof committed.created !== "boolean") {
    throw new EvidenceRecheckInvariantError("Evidence recheck admission commit result is invalid.");
  }
  validateAdmissionReceipt(committed.receipt, {
    actor_ref: input.actor_ref,
    admitted_at: admittedAt,
    binding: input.binding,
    capabilities,
    input_digest: inputDigest,
    receipt_id: receiptId,
    received_at: receivedAt,
    recheck_id: recheckId,
    request_key: input.request_key,
    run_context: input.run_context,
    run_id: runId,
  });
  return acceptedResult(authorization, committed.receipt, !committed.created);
}

export function projectEvidenceRecheckStatus(
  input: EvidenceRecheckStatusInputV1,
): SlackEvidenceRecheckStatusV1 {
  if (input.schema_version !== "evidence-recheck-status-input/v1") {
    throw new EvidenceRecheckInvariantError("Evidence recheck status input version is unsupported.");
  }
  if (input.kind === "admission") {
    const result = input.result;
    if (result.schema_version !== "admit-evidence-recheck-result/v1") {
      throw new EvidenceRecheckInvariantError("Evidence recheck admission result version is unsupported.");
    }
    if (result.status === "queued") {
      return slackStatus("queued", "Evidence recheck queued.", false, false, result.receipt.recheck.recheck_id);
    }
    if (result.status === "duplicate") {
      return slackStatus(
        "duplicate",
        "This evidence recheck is already queued.",
        false,
        false,
        result.receipt.recheck.recheck_id,
      );
    }
    if (result.status === "degraded") {
      return slackStatus(
        "degraded",
        "Evidence recheck was not queued. Retry after service recovers.",
        true,
        false,
      );
    }
    if (result.status !== "rejected") {
      throw new EvidenceRecheckInvariantError("Evidence recheck admission status is unsupported.");
    }
    return slackStatus(
      "rejected",
      "Evidence recheck was not accepted.",
      result.retryable,
      true,
    );
  }
  if (input.kind !== "recheck") {
    throw new EvidenceRecheckInvariantError("Evidence recheck status input kind is unsupported.");
  }
  validateEvidenceRecheck(input.recheck);
  switch (input.recheck.state) {
    case "queued":
      return slackStatus("queued", "Evidence recheck queued.", false, false, input.recheck.recheck_id);
    case "running":
      return slackStatus(
        "in_progress",
        "Evidence recheck in progress.",
        false,
        false,
        input.recheck.recheck_id,
      );
    case "completed":
      return slackStatus(
        "completed",
        "Evidence recheck completed.",
        false,
        true,
        input.recheck.recheck_id,
      );
    case "degraded":
      return slackStatus(
        "degraded",
        "Evidence recheck is delayed. It will continue after service recovers.",
        true,
        false,
        input.recheck.recheck_id,
      );
  }
}

export function validateDeliveredAnswerEvidenceBinding(
  binding: DeliveredAnswerEvidenceBindingV1,
): void {
  assertExactKeys(binding, [
    "answer_ref",
    "answer_run_id",
    "binding_digest",
    "binding_ref",
    "bound_at",
    "conversation_ref",
    "delivery_digest",
    "delivery_id",
    "evidence_artifact_ids",
    "operator_refs",
    "requester_ref",
    "schema_version",
    "thread_ref",
  ], "delivered answer evidence binding");
  if (binding.schema_version !== "delivered-answer-evidence-binding/v1") {
    throw new EvidenceRecheckInvariantError("Delivered answer evidence binding version is unsupported.");
  }
  for (const [value, label] of [
    [binding.answer_ref, "answer_ref"],
    [binding.answer_run_id, "answer_run_id"],
    [binding.binding_digest, "binding_digest"],
    [binding.binding_ref, "binding_ref"],
    [binding.conversation_ref, "conversation_ref"],
    [binding.delivery_digest, "delivery_digest"],
    [binding.delivery_id, "delivery_id"],
    [binding.requester_ref, "requester_ref"],
    [binding.thread_ref, "thread_ref"],
  ] as const) {
    requireRef(value, label);
  }
  requireCanonicalTimestamp(binding.bound_at, "bound_at");
  requireSha256Digest(binding.delivery_digest, "delivery_digest");
  const artifactIds = canonicalArtifactIds(binding.evidence_artifact_ids);
  const operatorRefs = canonicalRefs(
    binding.operator_refs,
    EVIDENCE_RECHECK_LIMITS.operator_refs,
    "operator_refs",
  );
  if (!sameStrings(artifactIds, binding.evidence_artifact_ids)) {
    throw new EvidenceRecheckInvariantError("Evidence artifact ids must be canonical and distinct.");
  }
  if (!sameStrings(operatorRefs, binding.operator_refs)) {
    throw new EvidenceRecheckInvariantError("Operator refs must be canonical and distinct.");
  }
  const expectedDigest = deliveredAnswerEvidenceBindingDigest(binding);
  if (
    binding.binding_digest !== expectedDigest ||
    binding.binding_ref !== evidenceBindingIdentity(expectedDigest)
  ) {
    throw new EvidenceRecheckInvariantError("Delivered answer evidence binding digest is invalid.");
  }
}

export function validateEvidenceRecheck(recheck: EvidenceRecheckV1): void {
  assertExactKeys(recheck, [
    "actor_ref",
    "answer_ref",
    "binding_digest",
    "binding_ref",
    "completed_at",
    "created_at",
    "evidence_artifact_ids",
    "outcome_digest",
    "outcome_ref",
    "reason_code",
    "recheck_id",
    "request_key",
    "revision",
    "run_id",
    "schema_version",
    "state",
    "thread_ref",
    "updated_at",
  ], "evidence recheck");
  if (recheck.schema_version !== "evidence-recheck/v1") {
    throw new EvidenceRecheckInvariantError("Evidence recheck version is unsupported.");
  }
  if (!RECHECK_STATES.includes(recheck.state)) {
    throw new EvidenceRecheckInvariantError("Evidence recheck state is unsupported.");
  }
  for (const [value, label] of [
    [recheck.actor_ref, "actor_ref"],
    [recheck.answer_ref, "answer_ref"],
    [recheck.binding_digest, "binding_digest"],
    [recheck.binding_ref, "binding_ref"],
    [recheck.reason_code, "reason_code"],
    [recheck.recheck_id, "recheck_id"],
    [recheck.run_id, "run_id"],
    [recheck.thread_ref, "thread_ref"],
  ] as const) {
    requireRef(value, label);
  }
  requireRequestKey(recheck.request_key);
  requireCanonicalTimestamp(recheck.created_at, "created_at");
  requireCanonicalTimestamp(recheck.updated_at, "updated_at");
  requirePositiveInteger(recheck.revision, "revision");
  const artifactIds = canonicalArtifactIds(recheck.evidence_artifact_ids);
  if (!sameStrings(artifactIds, recheck.evidence_artifact_ids)) {
    throw new EvidenceRecheckInvariantError("Recheck evidence artifact ids must be canonical.");
  }
  const outcomeFields = [recheck.completed_at, recheck.outcome_digest, recheck.outcome_ref];
  if (recheck.state === "completed") {
    if (outcomeFields.some((value) => value === undefined)) {
      throw new EvidenceRecheckInvariantError("Completed evidence rechecks require a durable outcome.");
    }
    requireCanonicalTimestamp(recheck.completed_at!, "completed_at");
    requireRef(recheck.outcome_digest!, "outcome_digest");
    requireRef(recheck.outcome_ref!, "outcome_ref");
  } else if (outcomeFields.some((value) => value !== undefined)) {
    throw new EvidenceRecheckInvariantError("Only completed evidence rechecks may carry an outcome.");
  }
}

function createAdmissionReceipt(input: {
  admitted_at: string;
  actor_ref: string;
  binding: DeliveredAnswerEvidenceBindingV1;
  capabilities: CapabilityRequirement[];
  input_digest: string;
  receipt_id: string;
  received_at: string;
  recheck_id: string;
  request_key: string;
  run_context: AdmitEvidenceRecheckInputV1["run_context"];
  run_id: string;
}): EvidenceRecheckAdmissionReceiptV1 {
  const run: RunReceiptV1 = {
    admitted_at: input.admitted_at,
    binding_id: input.run_context.service_binding_id,
    idempotency_key: `evidence-recheck:${stableDigest([input.recheck_id])}`,
    input_digest: input.input_digest,
    receipt_id: `run-receipt:${stableDigest([input.run_id])}`,
    received_at: input.received_at,
    required_capabilities: structuredClone(input.capabilities),
    retention_policy_ref: input.run_context.retention_policy_ref,
    revision: 1,
    run_id: input.run_id,
    run_kind: "reconciliation",
    schema_version: "run-receipt/v1",
    state: "queued",
    subject_ref: input.run_context.subject_ref,
    tenant_id: input.run_context.tenant_id,
    updated_at: input.admitted_at,
  };
  const recheck: EvidenceRecheckV1 = {
    actor_ref: input.actor_ref,
    answer_ref: input.binding.answer_ref,
    binding_digest: input.binding.binding_digest,
    binding_ref: input.binding.binding_ref,
    created_at: input.admitted_at,
    evidence_artifact_ids: structuredClone(input.binding.evidence_artifact_ids),
    reason_code: "admitted",
    recheck_id: input.recheck_id,
    request_key: input.request_key,
    revision: 1,
    run_id: input.run_id,
    schema_version: "evidence-recheck/v1",
    state: "queued",
    thread_ref: input.binding.thread_ref,
    updated_at: input.admitted_at,
  };
  const queueItem: EvidenceRecheckQueueItemV1 = {
    available_at: input.admitted_at,
    binding_digest: input.binding.binding_digest,
    binding_ref: input.binding.binding_ref,
    evidence_artifact_ids: structuredClone(input.binding.evidence_artifact_ids),
    idempotency_key: `evidence-recheck-queue:${stableDigest([input.recheck_id])}`,
    queue_item_id: `evidence-recheck-queue-item:${stableDigest([input.recheck_id])}`,
    recheck_id: input.recheck_id,
    run_id: input.run_id,
    schema_version: "evidence-recheck-queue-item/v1",
    thread_ref: input.binding.thread_ref,
  };
  return {
    input_digest: input.input_digest,
    queue_item: queueItem,
    receipt_id: input.receipt_id,
    recheck,
    run,
    schema_version: "evidence-recheck-admission-receipt/v1",
  };
}

function validateAdmissionInput(input: AdmitEvidenceRecheckInputV1): void {
  assertExactKeys(input, [
    "actor_ref",
    "admitted_at",
    "binding",
    "binding_ref",
    "received_at",
    "request_key",
    "run_context",
  ], "evidence recheck admission input");
  assertExactKeys(input.run_context, [
    "required_capabilities",
    "retention_policy_ref",
    "service_binding_id",
    "subject_ref",
    "tenant_id",
  ], "evidence recheck run context");
  requireRef(input.actor_ref, "actor_ref");
  requireRef(input.binding_ref, "binding_ref");
  requireRequestKey(input.request_key);
  for (const [value, label] of [
    [input.run_context.retention_policy_ref, "retention_policy_ref"],
    [input.run_context.service_binding_id, "service_binding_id"],
    [input.run_context.subject_ref, "subject_ref"],
    [input.run_context.tenant_id, "tenant_id"],
  ] as const) {
    requireRef(value, label);
  }
  canonicalCapabilities(input.run_context.required_capabilities);
}

function validateAdmissionReceipt(
  receipt: EvidenceRecheckAdmissionReceiptV1,
  expected: {
    actor_ref: string;
    admitted_at: string;
    binding: DeliveredAnswerEvidenceBindingV1;
    capabilities: CapabilityRequirement[];
    input_digest: string;
    receipt_id: string;
    received_at: string;
    recheck_id: string;
    request_key: string;
    run_context: AdmitEvidenceRecheckInputV1["run_context"];
    run_id: string;
  },
): void {
  assertExactKeys(receipt, [
    "input_digest",
    "queue_item",
    "receipt_id",
    "recheck",
    "run",
    "schema_version",
  ], "evidence recheck admission receipt");
  if (receipt.schema_version !== "evidence-recheck-admission-receipt/v1") {
    throw new EvidenceRecheckInvariantError("Evidence recheck admission receipt version is unsupported.");
  }
  if (receipt.receipt_id !== expected.receipt_id || receipt.input_digest !== expected.input_digest) {
    throw new EvidenceRecheckInvariantError("Evidence recheck admission receipt conflicts with this request.");
  }
  validateEvidenceRecheck(receipt.recheck);
  if (
    receipt.recheck.recheck_id !== expected.recheck_id ||
    receipt.recheck.run_id !== expected.run_id ||
    receipt.recheck.actor_ref !== expected.actor_ref ||
    receipt.recheck.binding_ref !== expected.binding.binding_ref ||
    receipt.recheck.binding_digest !== expected.binding.binding_digest ||
    receipt.recheck.answer_ref !== expected.binding.answer_ref ||
    receipt.recheck.request_key !== expected.request_key ||
    receipt.recheck.thread_ref !== expected.binding.thread_ref ||
    !sameStrings(
      receipt.recheck.evidence_artifact_ids,
      expected.binding.evidence_artifact_ids,
    ) ||
    receipt.recheck.created_at !== expected.admitted_at ||
    receipt.recheck.updated_at !== expected.admitted_at ||
    receipt.recheck.state !== "queued" ||
    receipt.recheck.reason_code !== "admitted"
  ) {
    throw new EvidenceRecheckInvariantError("Evidence recheck receipt contains a mismatched recheck.");
  }
  validateRunReceipt(receipt.run, expected);
  validateQueueItem(receipt.queue_item, receipt.recheck);
  if (
    receipt.recheck.created_at !== receipt.run.admitted_at ||
    receipt.recheck.updated_at !== receipt.run.admitted_at ||
    receipt.queue_item.available_at !== receipt.run.admitted_at
  ) {
    throw new EvidenceRecheckInvariantError("Evidence recheck admission timestamps are not atomic.");
  }
}

function validateRunReceipt(
  run: RunReceiptV1,
  expected: {
    admitted_at: string;
    capabilities: CapabilityRequirement[];
    input_digest: string;
    recheck_id: string;
    received_at: string;
    run_context: AdmitEvidenceRecheckInputV1["run_context"];
    run_id: string;
  },
): void {
  assertExactKeys(run, [
    "admitted_at",
    "binding_id",
    "idempotency_key",
    "input_digest",
    "receipt_id",
    "received_at",
    "required_capabilities",
    "retention_policy_ref",
    "revision",
    "run_id",
    "run_kind",
    "schema_version",
    "state",
    "subject_ref",
    "tenant_id",
    "updated_at",
  ], "evidence recheck canonical run receipt");
  if (
    run.schema_version !== "run-receipt/v1" ||
    run.run_id !== expected.run_id ||
    run.run_kind !== "reconciliation" ||
    run.state !== "queued" ||
    run.revision !== 1 ||
    run.binding_id !== expected.run_context.service_binding_id ||
    run.tenant_id !== expected.run_context.tenant_id ||
    run.subject_ref !== expected.run_context.subject_ref ||
    run.retention_policy_ref !== expected.run_context.retention_policy_ref ||
    run.input_digest !== expected.input_digest ||
    run.received_at !== expected.received_at ||
    run.admitted_at !== expected.admitted_at ||
    run.updated_at !== expected.admitted_at ||
    run.receipt_id !== `run-receipt:${stableDigest([expected.run_id])}` ||
    run.idempotency_key !== `evidence-recheck:${stableDigest([expected.recheck_id])}`
  ) {
    throw new EvidenceRecheckInvariantError("Evidence recheck canonical run receipt is invalid.");
  }
  requireCanonicalTimestamp(run.admitted_at, "run admitted_at");
  requireCanonicalTimestamp(run.updated_at, "run updated_at");
  requireRef(run.receipt_id, "run receipt_id");
  requireRef(run.idempotency_key, "run idempotency_key");
  if (run.updated_at !== run.admitted_at) {
    throw new EvidenceRecheckInvariantError("Queued evidence recheck run timestamps must match.");
  }
  if (!sameCapabilities(canonicalCapabilities(run.required_capabilities), expected.capabilities)) {
    throw new EvidenceRecheckInvariantError("Evidence recheck run capabilities do not match admission.");
  }
}

function validateQueueItem(queueItem: EvidenceRecheckQueueItemV1, recheck: EvidenceRecheckV1): void {
  assertExactKeys(queueItem, [
    "available_at",
    "binding_digest",
    "binding_ref",
    "evidence_artifact_ids",
    "idempotency_key",
    "queue_item_id",
    "recheck_id",
    "run_id",
    "schema_version",
    "thread_ref",
  ], "evidence recheck queue item");
  if (queueItem.schema_version !== "evidence-recheck-queue-item/v1") {
    throw new EvidenceRecheckInvariantError("Evidence recheck queue item version is unsupported.");
  }
  for (const [value, label] of [
    [queueItem.binding_digest, "queue binding_digest"],
    [queueItem.binding_ref, "queue binding_ref"],
    [queueItem.idempotency_key, "queue idempotency_key"],
    [queueItem.queue_item_id, "queue_item_id"],
    [queueItem.recheck_id, "queue recheck_id"],
    [queueItem.run_id, "queue run_id"],
    [queueItem.thread_ref, "queue thread_ref"],
  ] as const) {
    requireRef(value, label);
  }
  requireCanonicalTimestamp(queueItem.available_at, "queue available_at");
  const artifactIds = canonicalArtifactIds(queueItem.evidence_artifact_ids);
  if (
    queueItem.recheck_id !== recheck.recheck_id ||
    queueItem.run_id !== recheck.run_id ||
    queueItem.binding_ref !== recheck.binding_ref ||
    queueItem.binding_digest !== recheck.binding_digest ||
    queueItem.thread_ref !== recheck.thread_ref ||
    !sameStrings(artifactIds, recheck.evidence_artifact_ids)
  ) {
    throw new EvidenceRecheckInvariantError("Evidence recheck queue item is not correlated to the recheck.");
  }
}

function validateReceiptLookup(
  lookup: EvidenceRecheckAdmissionReceiptLookupV1,
  expectedReceiptId: string,
): void {
  if (lookup.found !== true && lookup.found !== false) {
    throw new EvidenceRecheckInvariantError("Evidence recheck receipt lookup result is invalid.");
  }
  assertExactKeys(
    lookup,
    lookup.found
      ? ["found", "receipt", "schema_version"]
      : ["found", "receipt_id", "schema_version"],
    "evidence recheck receipt lookup",
  );
  if (lookup.schema_version !== "evidence-recheck-admission-receipt-lookup/v1") {
    throw new EvidenceRecheckInvariantError("Evidence recheck receipt lookup version is unsupported.");
  }
  if (lookup.found) {
    if (lookup.receipt.receipt_id !== expectedReceiptId) {
      throw new EvidenceRecheckInvariantError("Evidence recheck receipt lookup returned another receipt.");
    }
  } else if (lookup.receipt_id !== expectedReceiptId) {
    throw new EvidenceRecheckInvariantError("Evidence recheck receipt lookup used another identity.");
  }
}

function validateCompletedDelivery(
  delivery: BindDeliveredAnswerEvidenceInputV1["delivery"],
  answerRunId: string,
): void {
  assertExactKeys(delivery, [
    "created_at",
    "delivery_id",
    "destination_ref",
    "parts",
    "run_id",
    "schema_version",
    "state",
    "updated_at",
  ], "completed delivery receipt");
  if (
    delivery.schema_version !== "delivery-receipt/v1" ||
    delivery.run_id !== answerRunId ||
    delivery.state !== "completed"
  ) {
    throw new EvidenceRecheckInvariantError(
      "Evidence rechecks require a completed delivery for the original answer run.",
    );
  }
  requireRef(delivery.delivery_id, "delivery_id");
  requireRef(delivery.destination_ref, "delivery destination_ref");
  requireCanonicalTimestamp(delivery.created_at, "delivery created_at");
  requireCanonicalTimestamp(delivery.updated_at, "delivery updated_at");
  if (
    delivery.parts.length === 0 ||
    delivery.parts.length > EVIDENCE_RECHECK_LIMITS.delivery_parts
  ) {
    throw new EvidenceRecheckInvariantError("Delivered answers require bounded delivery parts.");
  }
  let expectedSequence = 1;
  const partIds = new Set<string>();
  const idempotencyKeys = new Set<string>();
  for (const part of [...delivery.parts].sort((left, right) => left.sequence - right.sequence)) {
    assertExactKeys(part, [
      "delivered_at",
      "destination_receipt",
      "idempotency_key",
      "part_id",
      "payload_digest",
      "payload_ref",
      "sequence",
      "state",
    ], "completed delivery part");
    if (
      part.state !== "delivered" ||
      part.destination_receipt === undefined ||
      part.delivered_at === undefined ||
      part.sequence !== expectedSequence
    ) {
      throw new EvidenceRecheckInvariantError(
        "Every original answer part must have a durable delivered receipt.",
      );
    }
    requireRef(part.part_id, "delivery part_id");
    requireRef(part.idempotency_key, "delivery part idempotency_key");
    requireRef(part.payload_digest, "delivery part payload_digest");
    requireRef(part.payload_ref, "delivery part payload_ref");
    requireRef(part.destination_receipt, "delivery part destination_receipt");
    requireCanonicalTimestamp(part.delivered_at, "delivery part delivered_at");
    if (partIds.has(part.part_id) || idempotencyKeys.has(part.idempotency_key)) {
      throw new EvidenceRecheckInvariantError(
        "Completed delivery part identities must be distinct.",
      );
    }
    partIds.add(part.part_id);
    idempotencyKeys.add(part.idempotency_key);
    expectedSequence += 1;
  }
}

function completedDeliveryDigest(
  delivery: BindDeliveredAnswerEvidenceInputV1["delivery"],
): string {
  return `sha256:${stableDigest({
    created_at: delivery.created_at,
    delivery_id: delivery.delivery_id,
    destination_ref: delivery.destination_ref,
    parts: [...delivery.parts]
      .sort((left, right) => left.sequence - right.sequence)
      .map((part) => ({
        delivered_at: part.delivered_at,
        destination_receipt: part.destination_receipt,
        idempotency_key: part.idempotency_key,
        part_id: part.part_id,
        payload_digest: part.payload_digest,
        payload_ref: part.payload_ref,
        sequence: part.sequence,
        state: part.state,
      })),
    run_id: delivery.run_id,
    schema_version: delivery.schema_version,
    state: delivery.state,
    updated_at: delivery.updated_at,
  })}`;
}

function evidenceRecheckInputDigest(
  input: AdmitEvidenceRecheckInputV1,
  receivedAt: string,
  capabilities: CapabilityRequirement[],
): string {
  return `sha256:${stableDigest([
    input.actor_ref,
    input.binding.binding_ref,
    input.binding.binding_digest,
    input.request_key,
    receivedAt,
    input.run_context.service_binding_id,
    input.run_context.tenant_id,
    input.run_context.subject_ref,
    input.run_context.retention_policy_ref,
    ...capabilities.flatMap((capability) => [
      capability.capability_id,
      capability.level,
      capability.version,
    ]),
  ])}`;
}

function deliveredAnswerEvidenceBindingDigest(input: {
  answer_ref: string;
  answer_run_id: string;
  bound_at: string;
  conversation_ref: string;
  delivery_digest: string;
  delivery_id: string;
  evidence_artifact_ids: readonly string[];
  operator_refs: readonly string[];
  requester_ref: string;
  thread_ref: string;
}): string {
  return `sha256:${stableDigest({
    answer_ref: input.answer_ref,
    answer_run_id: input.answer_run_id,
    bound_at: input.bound_at,
    conversation_ref: input.conversation_ref,
    delivery_digest: input.delivery_digest,
    delivery_id: input.delivery_id,
    evidence_artifact_ids: input.evidence_artifact_ids,
    operator_refs: input.operator_refs,
    requester_ref: input.requester_ref,
    thread_ref: input.thread_ref,
  })}`;
}

function evidenceBindingIdentity(bindingDigest: string): string {
  return `delivered-answer-evidence-binding:${bindingDigest.slice(
    "sha256:".length,
    "sha256:".length + 32,
  )}`;
}

function evidenceRecheckRunIdentity(recheckId: string): string {
  return `evidence-recheck-run:${stableDigest([recheckId]).slice(0, 32)}`;
}

function acceptedResult(
  authorization: Extract<EvidenceRecheckAuthorizationV1, { allowed: true }>,
  receipt: EvidenceRecheckAdmissionReceiptV1,
  duplicate: boolean,
): AdmitEvidenceRecheckResultV1 {
  return {
    acknowledgement_permitted: true,
    authorization,
    duplicate,
    receipt: structuredClone(receipt),
    retryable: false,
    schema_version: "admit-evidence-recheck-result/v1",
    status: duplicate ? "duplicate" : "queued",
  };
}

function allowedAuthorization(
  role: "requester" | "operator",
): Extract<EvidenceRecheckAuthorizationV1, { allowed: true }> {
  return { allowed: true, role, schema_version: "evidence-recheck-authorization/v1" };
}

function deniedAuthorization(
  reasonCode: "actor_not_authorized" | "binding_reference_mismatch",
): Extract<EvidenceRecheckAuthorizationV1, { allowed: false }> {
  return {
    allowed: false,
    reason_code: reasonCode,
    schema_version: "evidence-recheck-authorization/v1",
  };
}

function slackStatus(
  status: SlackEvidenceRecheckStatusV1["status"],
  message: string,
  retryable: boolean,
  terminal: boolean,
  recheckId?: string,
): SlackEvidenceRecheckStatusV1 {
  return {
    message,
    ...(recheckId === undefined ? {} : { recheck_id: recheckId }),
    retryable,
    schema_version: "slack-evidence-recheck-status/v1",
    status,
    terminal,
  };
}

function canonicalArtifactIds(values: readonly string[]): string[] {
  if (
    values.length === 0 ||
    values.length > EVIDENCE_RECHECK_LIMITS.evidence_artifact_ids
  ) {
    throw new EvidenceRecheckInvariantError("Evidence artifact ids must be present and bounded.");
  }
  const result = values.map((value) => {
    requireRef(value, "evidence_artifact_id");
    if (!OPAQUE_ARTIFACT_ID.test(value)) {
      throw new EvidenceRecheckInvariantError(
        "Evidence artifact ids must be opaque server-owned identifiers.",
      );
    }
    return value;
  }).sort();
  if (new Set(result).size !== result.length) {
    throw new EvidenceRecheckInvariantError("Evidence artifact ids must be distinct.");
  }
  return result;
}

function canonicalRefs(values: readonly string[], maximum: number, label: string): string[] {
  if (values.length > maximum) {
    throw new EvidenceRecheckInvariantError(`${label} exceeds the portable limit.`);
  }
  const result = values.map((value) => {
    requireRef(value, label);
    return value;
  }).sort();
  if (new Set(result).size !== result.length) {
    throw new EvidenceRecheckInvariantError(`${label} must be distinct.`);
  }
  return result;
}

function canonicalCapabilities(
  capabilities: readonly CapabilityRequirement[],
): CapabilityRequirement[] {
  if (capabilities.length > EVIDENCE_RECHECK_LIMITS.required_capabilities) {
    throw new EvidenceRecheckInvariantError("Required capabilities exceed the portable limit.");
  }
  const result = capabilities.map((capability) => {
    assertExactKeys(
      capability,
      ["capability_id", "level", "version"],
      "capability requirement",
    );
    requireRef(capability.capability_id, "capability_id");
    requireRef(capability.version, "capability version");
    if (capability.level !== "required" && capability.level !== "optional") {
      throw new EvidenceRecheckInvariantError("Capability requirement level is unsupported.");
    }
    return structuredClone(capability);
  }).sort((left, right) =>
    `${left.capability_id}\u0000${left.version}\u0000${left.level}`.localeCompare(
      `${right.capability_id}\u0000${right.version}\u0000${right.level}`,
    ),
  );
  const identities = result.map((capability) => `${capability.capability_id}\u0000${capability.version}`);
  if (new Set(identities).size !== identities.length) {
    throw new EvidenceRecheckInvariantError("Required capability identities must be distinct.");
  }
  return result;
}

function sameCapabilities(
  left: readonly CapabilityRequirement[],
  right: readonly CapabilityRequirement[],
): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function assertExactKeys(
  value: object,
  allowedKeys: readonly string[],
  label: string,
): void {
  const allowed = new Set(allowedKeys);
  const unexpected = Object.keys(value).filter((key) => !allowed.has(key));
  if (unexpected.length !== 0) {
    throw new EvidenceRecheckInvariantError(`${label} contains unsupported fields.`);
  }
}

function requireRequestKey(value: string): void {
  requireBoundedText(
    value,
    EVIDENCE_RECHECK_LIMITS.request_key_utf8_bytes,
    "request_key",
  );
}

function requireRef(value: string, label: string): void {
  requireBoundedText(value, EVIDENCE_RECHECK_LIMITS.ref_utf8_bytes, label);
}

function requireSha256Digest(value: string, label: string): void {
  if (typeof value !== "string" || !SHA256_DIGEST.test(value)) {
    throw new EvidenceRecheckInvariantError(`${label} must be a canonical SHA-256 digest.`);
  }
}

function requireBoundedText(value: string, maximumBytes: number, label: string): void {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.trim() !== value ||
    UNSAFE_TEXT_CONTROL_CHARACTERS.test(value) ||
    Buffer.byteLength(value, "utf8") > maximumBytes
  ) {
    throw new EvidenceRecheckInvariantError(`${label} is not a bounded canonical value.`);
  }
}

function requirePositiveInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new EvidenceRecheckInvariantError(`${label} must be a positive safe integer.`);
  }
}

function normalizeTimestamp(value: string, label: string): string {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) {
    throw new EvidenceRecheckInvariantError(`${label} must be an ISO timestamp.`);
  }
  return new Date(milliseconds).toISOString();
}

function requireCanonicalTimestamp(value: string, label: string): void {
  if (normalizeTimestamp(value, label) !== value) {
    throw new EvidenceRecheckInvariantError(`${label} must use canonical UTC form.`);
  }
}

function stableDigest(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
