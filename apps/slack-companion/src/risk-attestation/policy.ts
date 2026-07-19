import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

import {
  RISK_ATTESTATION_DECISIONS,
  RISK_ATTESTATION_LIMITS,
  RISK_ATTESTATION_STATES,
  type CreateRiskAttestationInputV1,
  type RiskAttestationDecisionKindV1,
  type RiskAttestationDecisionReceiptLookupV1,
  type RiskAttestationDecisionReceiptV1,
  type RiskAttestationDecisionRequestV1,
  type RiskAttestationDecisionResultV1,
  type RiskAttestationStateV1,
  type RiskAttestationV1,
} from "./contracts.js";

const SHA256_DIGEST = /^sha256:[a-f0-9]{64}$/;
const UNSAFE_CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;
const TRANSITIONS: Readonly<
  Record<RiskAttestationStateV1, Partial<Record<RiskAttestationDecisionKindV1, RiskAttestationStateV1>>>
> = {
  accepted: { expire: "expired", withdraw: "withdrawn" },
  expired: {},
  pending: {
    accept: "accepted",
    expire: "expired",
    reject: "rejected",
    withdraw: "withdrawn",
  },
  rejected: {},
  withdrawn: {},
};

export class RiskAttestationPolicyError extends Error {}

export function riskAttestationIdentity(subjectRef: string, requestKey: string): string {
  requireRef(subjectRef, "subject_ref");
  requireKey(requestKey, RISK_ATTESTATION_LIMITS.request_key_utf8_bytes, "request_key");
  return `risk-attestation:${stableDigest([subjectRef, requestKey]).slice(0, 32)}`;
}

export function createRiskAttestation(
  input: CreateRiskAttestationInputV1,
): RiskAttestationV1 {
  exactKeys(input, ["created_at", "request_key", "schema_version", "subject_ref"], "risk attestation input");
  if (input.schema_version !== "create-risk-attestation-input/v1") {
    throw new RiskAttestationPolicyError("The risk attestation input version is unsupported.");
  }
  requireRef(input.subject_ref, "subject_ref");
  requireKey(input.request_key, RISK_ATTESTATION_LIMITS.request_key_utf8_bytes, "request_key");
  const createdAt = canonicalTimestamp(input.created_at, "created_at");
  return Object.freeze({
    attestation_id: riskAttestationIdentity(input.subject_ref, input.request_key),
    created_at: createdAt,
    request_key: input.request_key,
    revision: 1,
    schema_version: "risk-attestation/v1",
    state: "pending",
    state_sequence: 0,
    subject_ref: input.subject_ref,
    updated_at: createdAt,
  });
}

export function riskAttestationDecisionIdentity(
  attestationId: string,
  decisionKey: string,
): string {
  requireRef(attestationId, "attestation_id");
  requireKey(
    decisionKey,
    RISK_ATTESTATION_LIMITS.decision_key_utf8_bytes,
    "decision_key",
  );
  return `risk-attestation-decision:${stableDigest([attestationId, decisionKey])}`;
}

export function riskAttestationDecisionReceiptIdentity(
  decisionId: string,
): string {
  requireRef(decisionId, "decision_id");
  return `risk-attestation-receipt:${stableDigest([decisionId])}`;
}

/** Applies one explicit state decision after a host-provided durable lookup. */
export function decideRiskAttestation(
  current: RiskAttestationV1,
  request: RiskAttestationDecisionRequestV1,
  receiptLookup: RiskAttestationDecisionReceiptLookupV1,
): RiskAttestationDecisionResultV1 {
  const attestation = validateAttestation(current);
  const normalizedRequest = validateDecisionRequest(request);
  const decisionId = riskAttestationDecisionIdentity(
    attestation.attestation_id,
    normalizedRequest.decision_key,
  );
  const receiptId = riskAttestationDecisionReceiptIdentity(decisionId);
  const requestDigest = decisionRequestDigest(attestation.attestation_id, normalizedRequest);
  validateLookup(receiptLookup, receiptId);

  if (receiptLookup.found) {
    const receipt = snapshotReceipt(receiptLookup.receipt);
    if (
      receipt.decision_id !== decisionId
      || receipt.decision_key !== normalizedRequest.decision_key
      || receipt.attestation.attestation_id !== attestation.attestation_id
    ) {
      throw new RiskAttestationPolicyError(
        "The risk attestation receipt does not match its decision identity.",
      );
    }
    if (receipt.request_digest !== requestDigest) {
      return Object.freeze({
        applied: false,
        reason_code: "idempotency_conflict",
        receipt_ref: receipt.receipt_id,
        replayed: false,
        schema_version: "risk-attestation-decision-result/v1",
      });
    }
    if (
      normalizedRequest.expected_revision !== receipt.from_revision
      || normalizedRequest.decision !== receipt.decision
      || normalizedRequest.decided_at !== receipt.attestation.updated_at
    ) {
      throw new RiskAttestationPolicyError(
        "The risk attestation receipt does not match its decision request.",
      );
    }
    const currentDigest = riskAttestationSnapshotDigest(attestation);
    const matchesPreState =
      currentDigest === receipt.from_attestation_digest
      && attestation.state === receipt.from_state
      && attestation.revision === receipt.from_revision
      && attestation.state_sequence === receipt.from_state_sequence;
    const matchesPostState =
      currentDigest === riskAttestationSnapshotDigest(receipt.attestation);
    if (!matchesPreState && !matchesPostState) {
      throw new RiskAttestationPolicyError(
        "The risk attestation replay does not match the current state.",
      );
    }
    return Object.freeze({
      applied: true,
      receipt,
      replayed: true,
      schema_version: "risk-attestation-decision-result/v1",
    });
  }

  if (normalizedRequest.expected_revision !== attestation.revision) {
    throw new RiskAttestationPolicyError("The risk attestation revision changed.");
  }
  if (Date.parse(normalizedRequest.decided_at) < Date.parse(attestation.updated_at)) {
    throw new RiskAttestationPolicyError("The risk attestation decision precedes current state.");
  }
  const toState = TRANSITIONS[attestation.state][normalizedRequest.decision];
  if (toState === undefined) {
    throw new RiskAttestationPolicyError("The risk attestation decision is invalid for its state.");
  }

  const updated = Object.freeze({
    ...attestation,
    last_decision_id: decisionId,
    revision: attestation.revision + 1,
    state: toState,
    state_sequence: attestation.state_sequence + 1,
    updated_at: normalizedRequest.decided_at,
  });
  const receiptWithoutDigest = {
    attestation: updated,
    decision: normalizedRequest.decision,
    decision_id: decisionId,
    decision_key: normalizedRequest.decision_key,
    from_attestation: attestation,
    from_attestation_digest: riskAttestationSnapshotDigest(attestation),
    from_revision: attestation.revision,
    from_state: attestation.state,
    from_state_sequence: attestation.state_sequence,
    receipt_id: receiptId,
    request_digest: requestDigest,
    schema_version: "risk-attestation-decision-receipt/v1" as const,
    to_revision: updated.revision,
    to_state: toState,
    to_state_sequence: updated.state_sequence,
  };
  const receipt = Object.freeze({
    ...receiptWithoutDigest,
    receipt_digest: decisionReceiptDigest(receiptWithoutDigest),
  });
  return Object.freeze({
    applied: true,
    receipt,
    replayed: false,
    schema_version: "risk-attestation-decision-result/v1",
  });
}

function validateAttestation(attestation: RiskAttestationV1): RiskAttestationV1 {
  exactKeys(attestation, [
    "attestation_id",
    "created_at",
    "last_decision_id",
    "request_key",
    "revision",
    "schema_version",
    "state",
    "state_sequence",
    "subject_ref",
    "updated_at",
  ], "risk attestation");
  if (attestation.schema_version !== "risk-attestation/v1") {
    throw new RiskAttestationPolicyError("The risk attestation version is unsupported.");
  }
  requireRef(attestation.subject_ref, "subject_ref");
  requireKey(attestation.request_key, RISK_ATTESTATION_LIMITS.request_key_utf8_bytes, "request_key");
  const expectedId = riskAttestationIdentity(attestation.subject_ref, attestation.request_key);
  if (attestation.attestation_id !== expectedId) {
    throw new RiskAttestationPolicyError("The risk attestation identity is invalid.");
  }
  if (!RISK_ATTESTATION_STATES.includes(attestation.state)) {
    throw new RiskAttestationPolicyError("The risk attestation state is unsupported.");
  }
  if (
    !Number.isSafeInteger(attestation.revision)
    || attestation.revision < 1
    || !Number.isSafeInteger(attestation.state_sequence)
    || attestation.state_sequence < 0
    || attestation.revision !== attestation.state_sequence + 1
  ) {
    throw new RiskAttestationPolicyError("The risk attestation revision is invalid.");
  }
  const createdAt = canonicalTimestamp(attestation.created_at, "created_at");
  const updatedAt = canonicalTimestamp(attestation.updated_at, "updated_at");
  if (Date.parse(updatedAt) < Date.parse(createdAt)) {
    throw new RiskAttestationPolicyError("The risk attestation update precedes creation.");
  }
  if (attestation.state_sequence === 0) {
    if (attestation.state !== "pending" || attestation.last_decision_id !== undefined) {
      throw new RiskAttestationPolicyError("The initial risk attestation state is invalid.");
    }
  } else {
    requireRef(attestation.last_decision_id, "last_decision_id");
  }
  return Object.freeze({ ...attestation, created_at: createdAt, updated_at: updatedAt });
}

function validateDecisionRequest(
  request: RiskAttestationDecisionRequestV1,
): RiskAttestationDecisionRequestV1 {
  exactKeys(request, [
    "actor_ref",
    "decided_at",
    "decision",
    "decision_key",
    "expected_revision",
    "rationale_ref",
    "schema_version",
  ], "risk attestation decision request");
  if (request.schema_version !== "risk-attestation-decision-request/v1") {
    throw new RiskAttestationPolicyError("The risk attestation decision version is unsupported.");
  }
  requireRef(request.actor_ref, "actor_ref");
  requireRef(request.rationale_ref, "rationale_ref");
  requireKey(
    request.decision_key,
    RISK_ATTESTATION_LIMITS.decision_key_utf8_bytes,
    "decision_key",
  );
  if (!RISK_ATTESTATION_DECISIONS.includes(request.decision)) {
    throw new RiskAttestationPolicyError("The risk attestation decision is unsupported.");
  }
  if (!Number.isSafeInteger(request.expected_revision) || request.expected_revision < 1) {
    throw new RiskAttestationPolicyError("The risk attestation expected revision is invalid.");
  }
  return Object.freeze({
    ...request,
    decided_at: canonicalTimestamp(request.decided_at, "decided_at"),
  });
}

function validateLookup(
  lookup: RiskAttestationDecisionReceiptLookupV1,
  receiptId: string,
): void {
  requirePlainRecord(lookup, "risk attestation receipt lookup");
  if (lookup.found !== true && lookup.found !== false) {
    throw new RiskAttestationPolicyError("The risk attestation receipt lookup is invalid.");
  }
  if (lookup.schema_version !== "risk-attestation-decision-receipt-lookup/v1") {
    throw new RiskAttestationPolicyError("The risk attestation receipt lookup version is unsupported.");
  }
  if (lookup.found) {
    exactKeys(lookup, ["found", "receipt", "schema_version"], "risk attestation receipt lookup");
    requirePlainRecord(lookup.receipt, "risk attestation receipt");
    if (lookup.receipt.receipt_id !== receiptId) {
      throw new RiskAttestationPolicyError("The risk attestation lookup returned a different receipt.");
    }
    return;
  }
  exactKeys(lookup, ["found", "receipt_id", "schema_version"], "risk attestation receipt lookup");
  if (lookup.receipt_id !== receiptId) {
    throw new RiskAttestationPolicyError("The risk attestation receipt lookup key is invalid.");
  }
}

function snapshotReceipt(
  receipt: RiskAttestationDecisionReceiptV1,
): RiskAttestationDecisionReceiptV1 {
  exactKeys(receipt, [
    "attestation",
    "decision",
    "decision_id",
    "decision_key",
    "from_attestation",
    "from_attestation_digest",
    "from_revision",
    "from_state",
    "from_state_sequence",
    "receipt_digest",
    "receipt_id",
    "request_digest",
    "schema_version",
    "to_revision",
    "to_state",
    "to_state_sequence",
  ], "risk attestation receipt");
  if (receipt.schema_version !== "risk-attestation-decision-receipt/v1") {
    throw new RiskAttestationPolicyError("The risk attestation receipt version is unsupported.");
  }
  if (!RISK_ATTESTATION_DECISIONS.includes(receipt.decision)) {
    throw new RiskAttestationPolicyError("The risk attestation receipt decision is invalid.");
  }
  requireKey(
    receipt.decision_key,
    RISK_ATTESTATION_LIMITS.decision_key_utf8_bytes,
    "decision_key",
  );
  const fromAttestation = validateAttestation(receipt.from_attestation);
  const attestation = validateAttestation(receipt.attestation);
  const expectedDecisionId = riskAttestationDecisionIdentity(
    attestation.attestation_id,
    receipt.decision_key,
  );
  if (
    receipt.decision_id !== expectedDecisionId
    || receipt.receipt_id !== riskAttestationDecisionReceiptIdentity(expectedDecisionId)
  ) {
    throw new RiskAttestationPolicyError("The risk attestation receipt identity is invalid.");
  }
  if (
    !SHA256_DIGEST.test(receipt.from_attestation_digest)
    || receipt.from_attestation_digest !== riskAttestationSnapshotDigest(fromAttestation)
    || receipt.from_revision !== fromAttestation.revision
    || receipt.from_state !== fromAttestation.state
    || receipt.from_state_sequence !== fromAttestation.state_sequence
    || receipt.to_revision !== attestation.revision
    || receipt.to_state_sequence !== attestation.state_sequence
    || receipt.to_revision !== receipt.from_revision + 1
    || receipt.to_state_sequence !== receipt.from_state_sequence + 1
    || attestation.attestation_id !== fromAttestation.attestation_id
    || attestation.subject_ref !== fromAttestation.subject_ref
    || attestation.request_key !== fromAttestation.request_key
    || attestation.created_at !== fromAttestation.created_at
    || Date.parse(attestation.updated_at) < Date.parse(fromAttestation.updated_at)
  ) {
    throw new RiskAttestationPolicyError("The risk attestation receipt state boundary is invalid.");
  }
  if (
    !RISK_ATTESTATION_STATES.includes(receipt.from_state)
    || !RISK_ATTESTATION_STATES.includes(receipt.to_state)
    || TRANSITIONS[receipt.from_state][receipt.decision] !== receipt.to_state
    || attestation.state !== receipt.to_state
    || attestation.last_decision_id !== receipt.decision_id
  ) {
    throw new RiskAttestationPolicyError("The risk attestation receipt transition is invalid.");
  }
  if (!SHA256_DIGEST.test(receipt.request_digest)) {
    throw new RiskAttestationPolicyError("The risk attestation request digest is invalid.");
  }
  const snapshot = {
    attestation,
    decision: receipt.decision,
    decision_id: receipt.decision_id,
    decision_key: receipt.decision_key,
    from_attestation: fromAttestation,
    from_attestation_digest: receipt.from_attestation_digest,
    from_revision: receipt.from_revision,
    from_state: receipt.from_state,
    from_state_sequence: receipt.from_state_sequence,
    receipt_id: receipt.receipt_id,
    request_digest: receipt.request_digest,
    schema_version: "risk-attestation-decision-receipt/v1" as const,
    to_revision: receipt.to_revision,
    to_state: receipt.to_state,
    to_state_sequence: receipt.to_state_sequence,
  };
  const digest = decisionReceiptDigest(snapshot);
  if (receipt.receipt_digest !== digest) {
    throw new RiskAttestationPolicyError("The risk attestation receipt digest is invalid.");
  }
  return Object.freeze({ ...snapshot, receipt_digest: digest });
}

function decisionRequestDigest(
  attestationId: string,
  request: RiskAttestationDecisionRequestV1,
): string {
  return sha256([
    request.schema_version,
    attestationId,
    request.actor_ref,
    request.decided_at,
    request.decision,
    request.decision_key,
    String(request.expected_revision),
    request.rationale_ref,
  ]);
}

function decisionReceiptDigest(
  receipt: Omit<RiskAttestationDecisionReceiptV1, "receipt_digest">,
): string {
  const fromAttestation = receipt.from_attestation;
  const attestation = receipt.attestation;
  return sha256([
    receipt.schema_version,
    receipt.receipt_id,
    receipt.request_digest,
    receipt.decision_id,
    receipt.decision_key,
    receipt.decision,
    receipt.from_attestation_digest,
    String(receipt.from_revision),
    receipt.from_state,
    String(receipt.from_state_sequence),
    String(receipt.to_revision),
    receipt.to_state,
    String(receipt.to_state_sequence),
    fromAttestation.schema_version,
    fromAttestation.attestation_id,
    fromAttestation.subject_ref,
    fromAttestation.request_key,
    fromAttestation.created_at,
    fromAttestation.updated_at,
    String(fromAttestation.revision),
    String(fromAttestation.state_sequence),
    fromAttestation.state,
    fromAttestation.last_decision_id ?? "",
    attestation.schema_version,
    attestation.attestation_id,
    attestation.subject_ref,
    attestation.request_key,
    attestation.created_at,
    attestation.updated_at,
    String(attestation.revision),
    String(attestation.state_sequence),
    attestation.state,
    attestation.last_decision_id ?? "",
  ]);
}

function riskAttestationSnapshotDigest(attestation: RiskAttestationV1): string {
  return sha256([
    attestation.schema_version,
    attestation.attestation_id,
    attestation.subject_ref,
    attestation.request_key,
    attestation.created_at,
    attestation.updated_at,
    String(attestation.revision),
    String(attestation.state_sequence),
    attestation.state,
    attestation.last_decision_id ?? "",
  ]);
}

function canonicalTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string") {
    throw new RiskAttestationPolicyError(`The ${label} is invalid.`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new RiskAttestationPolicyError(`The ${label} must be a canonical timestamp.`);
  }
  return value;
}

function requireRef(value: unknown, label: string): asserts value is string {
  requireText(value, RISK_ATTESTATION_LIMITS.ref_utf8_bytes, label);
}

function requireKey(
  value: unknown,
  maximumBytes: number,
  label: string,
): asserts value is string {
  requireText(value, maximumBytes, label);
  if (/\s/.test(value)) {
    throw new RiskAttestationPolicyError(`The ${label} cannot contain whitespace.`);
  }
}

function requireText(
  value: unknown,
  maximumBytes: number,
  label: string,
): asserts value is string {
  if (
    typeof value !== "string"
    || value.length === 0
    || Buffer.byteLength(value, "utf8") > maximumBytes
    || UNSAFE_CONTROL_CHARACTERS.test(value)
  ) {
    throw new RiskAttestationPolicyError(`The ${label} is invalid.`);
  }
}

function exactKeys(value: unknown, allowed: readonly string[], label: string): void {
  requirePlainRecord(value, label);
  const allowedKeys = new Set(allowed);
  if (Object.keys(value).some((key) => !allowedKeys.has(key))) {
    throw new RiskAttestationPolicyError(`The ${label} contains unknown fields.`);
  }
}

function requirePlainRecord(
  value: unknown,
  label: string,
): asserts value is Record<string, unknown> {
  if (
    value === null
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new RiskAttestationPolicyError(`The ${label} is invalid.`);
  }
}

function stableDigest(values: readonly string[]): string {
  return createHash("sha256").update(JSON.stringify(values), "utf8").digest("hex");
}

function sha256(values: readonly string[]): string {
  return `sha256:${stableDigest(values)}`;
}
