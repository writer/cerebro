import { createHash } from "node:crypto";
import type {
  CapabilityRequirement,
  WorkLeaseV1,
} from "@writer/cerebro-sdk";
import {
  DISTRIBUTED_WORK_OBSERVATION_SCHEMA_VERSION,
  DISTRIBUTED_WORK_PACKET_SCHEMA_VERSION,
  DISTRIBUTED_WORK_RECEIPT_SCHEMA_VERSION,
  DISTRIBUTED_WORK_SUMMARY_SCHEMA_VERSION,
  MAX_DISTRIBUTED_WORK_CAPABILITIES,
  MAX_DISTRIBUTED_WORK_CHECKPOINT_REFS,
  MAX_DISTRIBUTED_WORK_DELIVERABLES,
  MAX_DISTRIBUTED_WORK_OBSERVATIONS,
} from "./contracts.js";
import type {
  DistributedWorkDeliverableV1,
  DistributedWorkGeneratedSummaryV1,
  DistributedWorkPacketIdentityInput,
  DistributedWorkPacketV1,
  DistributedWorkReceiptDraft,
  DistributedWorkReceiptV1,
  RuntimeToolObservationV1,
} from "./contracts.js";
import type { DistributedWorkReceiptCommit } from "./ports.js";

const SHA256_DIGEST = /^sha256:[a-f0-9]{64}$/;
const PACKET_ID = /^distributed-work-packet:\/\/sha256\/[a-f0-9]{64}$/;
const RECEIPT_ID = /^distributed-work-receipt:\/\/sha256\/[a-f0-9]{64}$/;
const OBSERVATION_ID =
  /^distributed-work-observation:\/\/sha256\/[a-f0-9]{64}$/;
const LEASE_REF = /^work-lease:\/\/sha256\/[a-f0-9]{64}$/;
const OPAQUE_REFERENCE = /^[a-z][a-z0-9+.-]*:\/\/\S+$/;
const MAX_ID_LENGTH = 256;
const MAX_REF_LENGTH = 1_024;

export class DistributedWorkContractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DistributedWorkContractError";
  }
}

export function distributedWorkIntentDigest(
  input: DistributedWorkPacketIdentityInput,
): string {
  validateIdentityInput(input);
  return sha256(stableStringify(canonicalIdentityInput(input)));
}

export function distributedWorkPacketIdentity(
  input: DistributedWorkPacketIdentityInput,
): string {
  const digest = distributedWorkIntentDigest(input).slice("sha256:".length);
  return `distributed-work-packet://sha256/${digest}`;
}

export function distributedWorkReceiptIdentity(packetId: string): string {
  requirePattern(packetId, PACKET_ID, "packet_id");
  return `distributed-work-receipt://sha256/${hashHex(packetId)}`;
}

export function runtimeToolObservationIdentity(
  packetId: string,
  toolRef: string,
  attempt: number,
): string {
  requirePattern(packetId, PACKET_ID, "packet_id");
  requireOpaqueRef(toolRef, "tool_ref");
  requirePositiveInteger(attempt, "attempt");
  return `distributed-work-observation://sha256/${hashHex(
    stableStringify([packetId, toolRef, attempt]),
  )}`;
}

export function distributedWorkLeaseReference(lease: WorkLeaseV1): string {
  requireId(lease.run_id, "lease.run_id");
  requireId(lease.owner_id, "lease.owner_id");
  requireId(lease.lease_token, "lease.lease_token");
  requirePositiveInteger(lease.generation, "lease.generation");
  requirePositiveInteger(lease.fencing_token, "lease.fencing_token");
  return `work-lease://sha256/${hashHex(
    stableStringify([
      lease.run_id,
      lease.owner_id,
      lease.generation,
      lease.fencing_token,
      lease.lease_token,
    ]),
  )}`;
}

export function validateDistributedWorkPacket(
  packet: DistributedWorkPacketV1,
): void {
  if (packet.schema_version !== DISTRIBUTED_WORK_PACKET_SCHEMA_VERSION) {
    throw new DistributedWorkContractError(
      "distributed work packet schema version is unsupported",
    );
  }
  validateIdentityInput(packet);
  requireTimestamp(packet.created_at, "created_at");
  requirePattern(packet.intent_digest, SHA256_DIGEST, "intent_digest");
  requirePattern(packet.packet_id, PACKET_ID, "packet_id");
  const expectedDigest = distributedWorkIntentDigest(packet);
  const expectedPacketId = distributedWorkPacketIdentity(packet);
  if (packet.intent_digest !== expectedDigest || packet.packet_id !== expectedPacketId) {
    throw new DistributedWorkContractError(
      "distributed work packet identity does not match its immutable intent",
    );
  }

  const run = packet.child_run;
  if (run.schema_version !== "run-receipt/v1") {
    throw new DistributedWorkContractError("child run schema version is unsupported");
  }
  if (run.state !== "queued") {
    throw new DistributedWorkContractError(
      "an admitted distributed work packet requires a queued child run",
    );
  }
  requireId(run.run_id, "child_run.run_id");
  requireId(run.receipt_id, "child_run.receipt_id");
  requireId(run.binding_id, "child_run.binding_id");
  requirePositiveInteger(run.revision, "child_run.revision");
  requireTimestamp(run.received_at, "child_run.received_at");
  requireTimestamp(run.admitted_at, "child_run.admitted_at");
  requireTimestamp(run.updated_at, "child_run.updated_at");
  if (
    run.run_id === packet.parent_run_id ||
    run.subject_ref !== packet.packet_id ||
    run.tenant_id !== packet.tenant_id ||
    run.run_kind !== packet.child_run_kind ||
    run.idempotency_key !== packet.idempotency_key ||
    run.input_digest !== packet.intent_digest ||
    run.retention_policy_ref !== packet.retention_policy_ref ||
    !sameCapabilities(run.required_capabilities, packet.required_capabilities)
  ) {
    throw new DistributedWorkContractError(
      "child run does not match the distributed work packet",
    );
  }
}

export function createDistributedWorkReceipt(
  draft: DistributedWorkReceiptDraft,
): DistributedWorkReceiptV1 {
  validateDistributedWorkPacket(draft.packet);
  requirePattern(draft.lease_ref, LEASE_REF, "lease_ref");
  requireBoundedRefs(
    draft.checkpoint_refs,
    MAX_DISTRIBUTED_WORK_CHECKPOINT_REFS,
    "checkpoint_refs",
  );
  requireOpaqueRef(draft.outcome_ref, "outcome_ref");
  requirePattern(draft.outcome_digest, SHA256_DIGEST, "outcome_digest");
  requireTimestamp(draft.recorded_at, "recorded_at");
  validateGeneratedSummary(draft.generated_summary);
  validateRuntimeObservations(draft.packet, draft.runtime_observations);

  const runtimeObservations = structuredClone(draft.runtime_observations);
  const receipt: DistributedWorkReceiptV1 = {
    checkpoint_refs: [...draft.checkpoint_refs],
    completed_observation_count: runtimeObservations.filter(
      (observation) => observation.status === "completed",
    ).length,
    failed_observation_count: runtimeObservations.filter(
      (observation) => observation.status === "failed",
    ).length,
    generated_summary:
      draft.generated_summary === undefined
        ? undefined
        : structuredClone(draft.generated_summary),
    lease_ref: draft.lease_ref,
    outcome_digest: draft.outcome_digest,
    outcome_ref: draft.outcome_ref,
    packet_id: draft.packet.packet_id,
    parent_run_id: draft.packet.parent_run_id,
    receipt_id: distributedWorkReceiptIdentity(draft.packet.packet_id),
    recorded_at: draft.recorded_at,
    run_id: draft.packet.child_run.run_id,
    runtime_observations: runtimeObservations,
    schema_version: DISTRIBUTED_WORK_RECEIPT_SCHEMA_VERSION,
    status: draft.runtime_status,
  };
  validateDistributedWorkReceipt(draft.packet, receipt);
  return receipt;
}

export function validateDistributedWorkReceipt(
  packet: DistributedWorkPacketV1,
  receipt: DistributedWorkReceiptV1,
): void {
  validateDistributedWorkPacket(packet);
  if (receipt.schema_version !== DISTRIBUTED_WORK_RECEIPT_SCHEMA_VERSION) {
    throw new DistributedWorkContractError(
      "distributed work receipt schema version is unsupported",
    );
  }
  if (receipt.status !== "blocked" && receipt.status !== "completed") {
    throw new DistributedWorkContractError(
      "distributed work receipt has an invalid terminal status",
    );
  }
  requirePattern(receipt.receipt_id, RECEIPT_ID, "receipt_id");
  requireTimestamp(receipt.recorded_at, "recorded_at");
  requirePattern(receipt.lease_ref, LEASE_REF, "lease_ref");
  requireBoundedRefs(
    receipt.checkpoint_refs,
    MAX_DISTRIBUTED_WORK_CHECKPOINT_REFS,
    "checkpoint_refs",
  );
  requireOpaqueRef(receipt.outcome_ref, "outcome_ref");
  requirePattern(receipt.outcome_digest, SHA256_DIGEST, "outcome_digest");
  validateGeneratedSummary(receipt.generated_summary);
  validateRuntimeObservations(packet, receipt.runtime_observations);
  if (
    receipt.packet_id !== packet.packet_id ||
    receipt.parent_run_id !== packet.parent_run_id ||
    receipt.run_id !== packet.child_run.run_id ||
    receipt.receipt_id !== distributedWorkReceiptIdentity(packet.packet_id)
  ) {
    throw new DistributedWorkContractError(
      "distributed work receipt does not match its admitted packet",
    );
  }

  const completedCount = receipt.runtime_observations.filter(
    (observation) => observation.status === "completed",
  ).length;
  const failedCount = receipt.runtime_observations.filter(
    (observation) => observation.status === "failed",
  ).length;
  if (
    receipt.completed_observation_count !== completedCount ||
    receipt.failed_observation_count !== failedCount
  ) {
    throw new DistributedWorkContractError(
      "runtime observation counts do not match the authoritative observations",
    );
  }
}

export function validateDistributedWorkReceiptCommit(
  packet: DistributedWorkPacketV1,
  commit: DistributedWorkReceiptCommit,
): void {
  validateDistributedWorkReceipt(packet, commit.receipt);
  validateLease(packet, commit.lease);
  if (commit.receipt.lease_ref !== distributedWorkLeaseReference(commit.lease)) {
    throw new DistributedWorkContractError(
      "receipt lease reference does not match the active lease proof",
    );
  }
  requirePositiveInteger(commit.expected_run_revision, "expected_run_revision");
  if (commit.expected_run_revision < packet.child_run.revision) {
    throw new DistributedWorkContractError(
      "terminal receipt cannot expect a run revision older than admission",
    );
  }
  const terminalRun = commit.terminal_run;
  if (
    terminalRun.schema_version !== "run-receipt/v1" ||
    terminalRun.run_id !== packet.child_run.run_id ||
    terminalRun.subject_ref !== packet.child_run.subject_ref ||
    terminalRun.tenant_id !== packet.child_run.tenant_id ||
    terminalRun.binding_id !== packet.child_run.binding_id ||
    terminalRun.run_kind !== packet.child_run.run_kind ||
    terminalRun.idempotency_key !== packet.child_run.idempotency_key ||
    terminalRun.input_digest !== packet.child_run.input_digest ||
    terminalRun.retention_policy_ref !== packet.child_run.retention_policy_ref ||
    !sameCapabilities(
      terminalRun.required_capabilities,
      packet.child_run.required_capabilities,
    ) ||
    terminalRun.state !== commit.receipt.status ||
    terminalRun.revision !== commit.expected_run_revision + 1 ||
    terminalRun.updated_at !== commit.receipt.recorded_at
  ) {
    throw new DistributedWorkContractError(
      "terminal run does not match the admitted packet and worker receipt",
    );
  }
}

function validateIdentityInput(input: DistributedWorkPacketIdentityInput): void {
  for (const [value, label] of [
    [input.correlation_id, "correlation_id"],
    [input.idempotency_key, "idempotency_key"],
    [input.parent_run_id, "parent_run_id"],
    [input.parent_subject_ref, "parent_subject_ref"],
    [input.tenant_id, "tenant_id"],
  ] as const) {
    requireId(value, label);
  }
  if (input.causation_id !== undefined) {
    requireId(input.causation_id, "causation_id");
  }
  if (
    input.child_run_kind !== "interactive" &&
    input.child_run_kind !== "scheduled" &&
    input.child_run_kind !== "autonomy" &&
    input.child_run_kind !== "triage" &&
    input.child_run_kind !== "risk_attestation" &&
    input.child_run_kind !== "reconciliation"
  ) {
    throw new DistributedWorkContractError("child_run_kind is unsupported");
  }
  requireOpaqueRef(input.turn_ref, "turn_ref");
  requireOpaqueRef(input.thread_ref, "thread_ref");
  requireOpaqueRef(input.objective_ref, "objective_ref");
  requireOpaqueRef(input.retention_policy_ref, "retention_policy_ref");
  requirePattern(input.objective_digest, SHA256_DIGEST, "objective_digest");
  validateDeliverables(input.deliverables);
  validateCapabilities(input.required_capabilities);
}

function validateDeliverables(deliverables: DistributedWorkDeliverableV1[]): void {
  requireArrayBound(
    deliverables,
    1,
    MAX_DISTRIBUTED_WORK_DELIVERABLES,
    "deliverables",
  );
  const ids = new Set<string>();
  const refs = new Set<string>();
  for (const [index, deliverable] of deliverables.entries()) {
    requireId(deliverable.deliverable_id, "deliverable_id");
    requireOpaqueRef(deliverable.requirement_ref, "requirement_ref");
    requirePattern(
      deliverable.requirement_digest,
      SHA256_DIGEST,
      "requirement_digest",
    );
    if (deliverable.sequence !== index + 1) {
      throw new DistributedWorkContractError(
        "deliverables must use contiguous sequence order",
      );
    }
    if (
      ids.has(deliverable.deliverable_id) ||
      refs.has(deliverable.requirement_ref)
    ) {
      throw new DistributedWorkContractError(
        "deliverables must have unique identities and references",
      );
    }
    ids.add(deliverable.deliverable_id);
    refs.add(deliverable.requirement_ref);
  }
}

function validateCapabilities(capabilities: CapabilityRequirement[]): void {
  requireArrayBound(
    capabilities,
    1,
    MAX_DISTRIBUTED_WORK_CAPABILITIES,
    "required_capabilities",
  );
  const identities = new Set<string>();
  for (const capability of capabilities) {
    requireId(capability.capability_id, "capability_id");
    requireId(capability.version, "capability_version");
    if (capability.level !== "required" && capability.level !== "optional") {
      throw new DistributedWorkContractError(
        "capability requirement level is unsupported",
      );
    }
    const identity = capabilityVersionIdentity(capability);
    if (identities.has(identity)) {
      throw new DistributedWorkContractError(
        "required capabilities must not repeat",
      );
    }
    identities.add(identity);
  }
}

function validateRuntimeObservations(
  packet: DistributedWorkPacketV1,
  observations: RuntimeToolObservationV1[],
): void {
  requireArrayBound(
    observations,
    0,
    MAX_DISTRIBUTED_WORK_OBSERVATIONS,
    "runtime_observations",
  );
  const observationIds = new Set<string>();
  const attemptKeys = new Set<string>();
  const capabilities = new Set(
    packet.required_capabilities.map(capabilityVersionIdentity),
  );
  for (const [index, observation] of observations.entries()) {
    if (
      observation.schema_version !== DISTRIBUTED_WORK_OBSERVATION_SCHEMA_VERSION
    ) {
      throw new DistributedWorkContractError(
        "runtime observation schema version is unsupported",
      );
    }
    if (observation.sequence !== index + 1) {
      throw new DistributedWorkContractError(
        "runtime observations must preserve contiguous runtime order",
      );
    }
    requirePositiveInteger(observation.attempt, "observation.attempt");
    requireId(observation.capability_id, "observation.capability_id");
    requireId(observation.capability_version, "observation.capability_version");
    requireOpaqueRef(observation.tool_ref, "observation.tool_ref");
    requireTimestamp(observation.started_at, "observation.started_at");
    requireTimestamp(observation.completed_at, "observation.completed_at");
    if (Date.parse(observation.completed_at) < Date.parse(observation.started_at)) {
      throw new DistributedWorkContractError(
        "runtime observation cannot complete before it starts",
      );
    }
    if (
      !capabilities.has(
        capabilityVersionIdentity({
          capability_id: observation.capability_id,
          version: observation.capability_version,
        }),
      )
    ) {
      throw new DistributedWorkContractError(
        "runtime observation capability was not authorized by the packet",
      );
    }
    const expectedId = runtimeToolObservationIdentity(
      packet.packet_id,
      observation.tool_ref,
      observation.attempt,
    );
    requirePattern(observation.observation_id, OBSERVATION_ID, "observation_id");
    if (observation.observation_id !== expectedId) {
      throw new DistributedWorkContractError(
        "runtime observation identity does not match its tool attempt",
      );
    }
    const attemptKey = stableStringify([
      observation.tool_ref,
      observation.attempt,
    ]);
    if (observationIds.has(observation.observation_id) || attemptKeys.has(attemptKey)) {
      throw new DistributedWorkContractError(
        "runtime observations must not repeat a tool attempt",
      );
    }
    observationIds.add(observation.observation_id);
    attemptKeys.add(attemptKey);
    validateObservationOutcome(observation);
  }
}

function validateObservationOutcome(observation: RuntimeToolObservationV1): void {
  if (observation.status !== "completed" && observation.status !== "failed") {
    throw new DistributedWorkContractError(
      "runtime observation status is unsupported",
    );
  }
  if (observation.status === "completed") {
    requireOpaqueRef(observation.result_ref, "observation.result_ref");
    requirePattern(
      observation.result_digest,
      SHA256_DIGEST,
      "observation.result_digest",
    );
    if (observation.failure_ref !== undefined || observation.failure_digest !== undefined) {
      throw new DistributedWorkContractError(
        "completed runtime observations cannot carry failure receipts",
      );
    }
    return;
  }
  requireOpaqueRef(observation.failure_ref, "observation.failure_ref");
  requirePattern(
    observation.failure_digest,
    SHA256_DIGEST,
    "observation.failure_digest",
  );
  if (observation.result_ref !== undefined || observation.result_digest !== undefined) {
    throw new DistributedWorkContractError(
      "failed runtime observations cannot carry successful result receipts",
    );
  }
}

function validateGeneratedSummary(
  summary: DistributedWorkGeneratedSummaryV1 | undefined,
): void {
  if (summary === undefined) return;
  if (summary.schema_version !== DISTRIBUTED_WORK_SUMMARY_SCHEMA_VERSION) {
    throw new DistributedWorkContractError(
      "generated summary schema version is unsupported",
    );
  }
  if (summary.reported_status !== "blocked" && summary.reported_status !== "completed") {
    throw new DistributedWorkContractError(
      "generated summary reported status is unsupported",
    );
  }
  requireTimestamp(summary.generated_at, "generated_summary.generated_at");
  requireOpaqueRef(summary.summary_ref, "generated_summary.summary_ref");
  requirePattern(
    summary.summary_digest,
    SHA256_DIGEST,
    "generated_summary.summary_digest",
  );
}

function validateLease(
  packet: DistributedWorkPacketV1,
  lease: WorkLeaseV1,
): void {
  if (lease.schema_version !== "work-lease/v1") {
    throw new DistributedWorkContractError("work lease schema version is unsupported");
  }
  if (lease.run_id !== packet.child_run.run_id) {
    throw new DistributedWorkContractError(
      "work lease does not own the packet child run",
    );
  }
  requirePositiveInteger(lease.generation, "lease.generation");
  requirePositiveInteger(lease.fencing_token, "lease.fencing_token");
  requireId(lease.lease_token, "lease.lease_token");
  requireId(lease.owner_id, "lease.owner_id");
  requireTimestamp(lease.heartbeat_at, "lease.heartbeat_at");
  requireTimestamp(lease.lease_expires_at, "lease.lease_expires_at");
}

function canonicalIdentityInput(input: DistributedWorkPacketIdentityInput) {
  return {
    causation_id: input.causation_id ?? null,
    child_run_kind: input.child_run_kind,
    correlation_id: input.correlation_id,
    deliverables: input.deliverables.map((deliverable) => ({ ...deliverable })),
    idempotency_key: input.idempotency_key,
    objective_digest: input.objective_digest,
    objective_ref: input.objective_ref,
    parent_run_id: input.parent_run_id,
    parent_subject_ref: input.parent_subject_ref,
    required_capabilities: [...input.required_capabilities]
      .map((capability) => ({ ...capability }))
      .sort((left, right) =>
        capabilityRequirementIdentity(left).localeCompare(
          capabilityRequirementIdentity(right),
        ),
      ),
    retention_policy_ref: input.retention_policy_ref,
    tenant_id: input.tenant_id,
    thread_ref: input.thread_ref,
    turn_ref: input.turn_ref,
  };
}

function sameCapabilities(
  left: CapabilityRequirement[],
  right: CapabilityRequirement[],
): boolean {
  if (left.length !== right.length) return false;
  const leftIdentities = left.map(capabilityRequirementIdentity).sort();
  const rightIdentities = right.map(capabilityRequirementIdentity).sort();
  return leftIdentities.every(
    (identity, index) => identity === rightIdentities[index],
  );
}

function capabilityRequirementIdentity(
  capability: CapabilityRequirement,
): string {
  return stableStringify([
    capability.capability_id,
    capability.version,
    capability.level,
  ]);
}

function capabilityVersionIdentity(
  capability: Pick<CapabilityRequirement, "capability_id" | "version">,
): string {
  return stableStringify([capability.capability_id, capability.version]);
}

function requireBoundedRefs(
  values: string[],
  maximum: number,
  label: string,
): void {
  requireArrayBound(values, 0, maximum, label);
  const refs = new Set<string>();
  for (const value of values) {
    requireOpaqueRef(value, label);
    if (refs.has(value)) {
      throw new DistributedWorkContractError(`${label} must not repeat`);
    }
    refs.add(value);
  }
}

function requireArrayBound(
  values: unknown[],
  minimum: number,
  maximum: number,
  label: string,
): void {
  if (values.length < minimum || values.length > maximum) {
    throw new DistributedWorkContractError(
      `${label} must contain between ${minimum} and ${maximum} items`,
    );
  }
}

function requireId(value: string | undefined, label: string): asserts value is string {
  if (
    value === undefined ||
    value.trim() === "" ||
    Buffer.byteLength(value, "utf8") > MAX_ID_LENGTH
  ) {
    throw new DistributedWorkContractError(`${label} must be a bounded identifier`);
  }
}

function requireOpaqueRef(
  value: string | undefined,
  label: string,
): asserts value is string {
  if (
    value === undefined ||
    Buffer.byteLength(value, "utf8") > MAX_REF_LENGTH ||
    !OPAQUE_REFERENCE.test(value)
  ) {
    throw new DistributedWorkContractError(
      `${label} must be a bounded opaque reference`,
    );
  }
}

function requirePattern(
  value: string | undefined,
  pattern: RegExp,
  label: string,
): asserts value is string {
  if (value === undefined || !pattern.test(value)) {
    throw new DistributedWorkContractError(`${label} has an invalid format`);
  }
}

function requireTimestamp(value: string, label: string): void {
  if (!Number.isFinite(Date.parse(value))) {
    throw new DistributedWorkContractError(`${label} must be a timestamp`);
  }
}

function requirePositiveInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new DistributedWorkContractError(`${label} must be a positive integer`);
  }
}

function sha256(value: string): string {
  return `sha256:${hashHex(value)}`;
}

function hashHex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, nested]) => nested !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${stableStringify(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}
