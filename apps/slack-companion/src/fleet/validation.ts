import { createHash } from "node:crypto";
import {
  distributedWorkLeaseReference,
  validateDistributedWorkPacket,
} from "../distributed/validation.js";
import { assertCapacityPermit } from "../execution/capacity.js";
import {
  AGENT_FLEET_ADMISSION_RECEIPT_SCHEMA_VERSION,
  AGENT_FLEET_EXECUTION_BINDING_SCHEMA_VERSION,
  AGENT_FLEET_MEMBER_SCHEMA_VERSION,
  AGENT_FLEET_MESSAGE_SCHEMA_VERSION,
  AGENT_FLEET_PROTOCOL_VERSION,
  MAX_AGENT_FLEET_PAYLOAD_BYTES,
} from "./contracts.js";
import type {
  AgentFleetAdmissionReceiptV1,
  AgentFleetExecutionBindingV1,
  AgentFleetMemberState,
  AgentFleetMemberV1,
  AgentFleetMessageIdentityInput,
  AgentFleetMessageV1,
  AgentFleetPayloadReferenceV1,
  AgentFleetResumeReferenceV1,
  CapacityPermitV1,
  CheckpointV1,
  DistributedWorkPacketV1,
  WorkLeaseV1,
} from "./contracts.js";

const SHA256_DIGEST = /^sha256:[a-f0-9]{64}$/;
const FLEET_MESSAGE = /^agent-fleet-message:\/\/sha256\/[a-f0-9]{64}$/;
const FLEET_RECEIPT =
  /^agent-fleet-admission-receipt:\/\/sha256\/[a-f0-9]{64}$/;
const FLEET_PAYLOAD = /^agent-fleet-payload:\/\/sha256\/[a-f0-9]{64}$/;
const REDACTION_RECEIPT =
  /^agent-fleet-redaction-receipt:\/\/sha256\/[a-f0-9]{64}$/;
const CHECKPOINT_REFERENCE =
  /^agent-fleet-checkpoint:\/\/sha256\/[a-f0-9]{64}$/;
const HANDOFF_REFERENCE =
  /^agent-fleet-handoff:\/\/sha256\/[a-f0-9]{64}$/;
const CAPACITY_REFERENCE = /^capacity:\/\/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$/;
const MAX_IDENTIFIER_LENGTH = 256;

const memberStates = new Set<AgentFleetMemberState>([
  "ready",
  "degraded",
  "draining",
  "offline",
  "recovering",
  "retired",
]);

const memberTransitions: Readonly<Record<AgentFleetMemberState, readonly AgentFleetMemberState[]>> = {
  ready: ["degraded", "draining", "offline"],
  degraded: ["ready", "draining", "offline"],
  draining: ["offline"],
  offline: ["recovering", "retired"],
  recovering: ["ready", "degraded", "draining", "offline"],
  retired: [],
};

export class AgentFleetContractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AgentFleetContractError";
  }
}

export function createAgentFleetPayloadReference(input: {
  byte_length: number;
  media_type: AgentFleetPayloadReferenceV1["media_type"];
  payload_digest: string;
  redaction_receipt_digest: string;
}): AgentFleetPayloadReferenceV1 {
  const reference: AgentFleetPayloadReferenceV1 = {
    byte_length: input.byte_length,
    media_type: input.media_type,
    payload_digest: input.payload_digest,
    payload_ref: digestReference("agent-fleet-payload", input.payload_digest),
    redaction_receipt_digest: input.redaction_receipt_digest,
    redaction_receipt_ref: digestReference(
      "agent-fleet-redaction-receipt",
      input.redaction_receipt_digest,
    ),
  };
  validateAgentFleetPayloadReference(reference);
  return reference;
}

export function createAgentFleetResumeReference(
  checkpoint: CheckpointV1,
  handoffDigest: string,
): AgentFleetResumeReferenceV1 {
  validateCheckpoint(checkpoint);
  requireDigest(handoffDigest, "handoff_digest");
  const checkpointDigest = sha256(stableStringify(checkpoint));
  return {
    checkpoint_digest: checkpointDigest,
    checkpoint_ref: digestReference(
      "agent-fleet-checkpoint",
      checkpointDigest,
    ),
    handoff_digest: handoffDigest,
    handoff_ref: digestReference("agent-fleet-handoff", handoffDigest),
  };
}

export function agentFleetMessageIdentity(
  input: AgentFleetMessageIdentityInput,
): string {
  validateMessageIdentityInput(input);
  return digestReference(
    "agent-fleet-message",
    sha256(stableStringify(canonicalMessageIdentity(input))),
  );
}

export function createAgentFleetMessage(
  input: AgentFleetMessageIdentityInput,
): AgentFleetMessageV1 {
  requireExactKeys(input, [
    "created_at",
    "idempotency_key",
    "message_sequence",
    "packet_id",
    "payload",
    "protocol_version",
    "resume",
    "run_id",
    "sender_generation",
    "sender_member_id",
  ], "fleet message input", ["resume"]);
  const message: AgentFleetMessageV1 = {
    created_at: input.created_at,
    idempotency_key: input.idempotency_key,
    message_id: agentFleetMessageIdentity(input),
    message_sequence: input.message_sequence,
    packet_id: input.packet_id,
    payload: structuredClone(input.payload),
    protocol_version: input.protocol_version,
    resume:
      input.resume === undefined ? undefined : structuredClone(input.resume),
    run_id: input.run_id,
    schema_version: AGENT_FLEET_MESSAGE_SCHEMA_VERSION,
    sender_generation: input.sender_generation,
    sender_member_id: input.sender_member_id,
  };
  validateAgentFleetMessage(message);
  return message;
}

export function agentFleetAdmissionReceiptIdentity(messageId: string): string {
  requirePattern(messageId, FLEET_MESSAGE, "message_id");
  return digestReference(
    "agent-fleet-admission-receipt",
    sha256(messageId),
  );
}

export function createAgentFleetAdmissionReceipt(
  message: AgentFleetMessageV1,
  packet: DistributedWorkPacketV1,
): AgentFleetAdmissionReceiptV1 {
  validateAgentFleetMessageForPacket(message, packet);
  return {
    admitted_at: packet.child_run.admitted_at,
    idempotency_key: message.idempotency_key,
    message_id: message.message_id,
    packet_id: packet.packet_id,
    payload_digest: message.payload.payload_digest,
    receipt_id: agentFleetAdmissionReceiptIdentity(message.message_id),
    run_id: packet.child_run.run_id,
    schema_version: AGENT_FLEET_ADMISSION_RECEIPT_SCHEMA_VERSION,
  };
}

export function validateAgentFleetAdmissionReceipt(
  receipt: AgentFleetAdmissionReceiptV1,
  message: AgentFleetMessageV1,
  packet: DistributedWorkPacketV1,
): void {
  requireExactKeys(receipt, [
    "admitted_at",
    "idempotency_key",
    "message_id",
    "packet_id",
    "payload_digest",
    "receipt_id",
    "run_id",
    "schema_version",
  ], "admission receipt");
  if (receipt.schema_version !== AGENT_FLEET_ADMISSION_RECEIPT_SCHEMA_VERSION) {
    throw new AgentFleetContractError("admission receipt schema is unsupported");
  }
  requireCanonicalTime(receipt.admitted_at, "receipt.admitted_at");
  requirePattern(receipt.receipt_id, FLEET_RECEIPT, "receipt_id");
  const expected = createAgentFleetAdmissionReceipt(message, packet);
  if (!sameValue(receipt, expected)) {
    throw new AgentFleetContractError(
      "admission receipt does not match the mailbox message and run",
    );
  }
}

export function validateAgentFleetMember(member: AgentFleetMemberV1): void {
  requireExactKeys(member, [
    "capability_manifest",
    "capacity_resource_ref",
    "generation",
    "member_id",
    "protocol_version",
    "registered_at",
    "revision",
    "schema_compatibility",
    "schema_version",
    "service_id",
    "state",
    "updated_at",
    "valid_until",
  ], "fleet member");
  if (member.schema_version !== AGENT_FLEET_MEMBER_SCHEMA_VERSION) {
    throw new AgentFleetContractError("fleet member schema is unsupported");
  }
  if (member.protocol_version !== AGENT_FLEET_PROTOCOL_VERSION) {
    throw new AgentFleetContractError("fleet protocol version is unsupported");
  }
  requireIdentifier(member.member_id, "member_id");
  requireIdentifier(member.service_id, "service_id");
  requirePositiveInteger(member.generation, "generation");
  requirePositiveInteger(member.revision, "revision");
  requirePattern(
    member.capacity_resource_ref,
    CAPACITY_REFERENCE,
    "capacity_resource_ref",
  );
  if (!memberStates.has(member.state)) {
    throw new AgentFleetContractError("fleet member state is unsupported");
  }
  requireCanonicalTime(member.registered_at, "registered_at");
  requireCanonicalTime(member.updated_at, "updated_at");
  requireCanonicalTime(member.valid_until, "valid_until");
  if (
    Date.parse(member.updated_at) < Date.parse(member.registered_at) ||
    Date.parse(member.valid_until) <= Date.parse(member.updated_at)
  ) {
    throw new AgentFleetContractError("fleet member timestamps are inconsistent");
  }

  const manifest = member.capability_manifest;
  if (
    manifest.schema_version !== "capability-manifest/v1" ||
    manifest.service_id !== member.service_id ||
    manifest.generation !== member.generation
  ) {
    throw new AgentFleetContractError(
      "capability manifest does not belong to the member generation",
    );
  }
  requireDigest(manifest.digest, "capability_manifest.digest");
  requireCanonicalTime(manifest.produced_at, "capability_manifest.produced_at");
  if (Date.parse(manifest.produced_at) > Date.parse(member.updated_at)) {
    throw new AgentFleetContractError(
      "capability manifest cannot be produced after the member update",
    );
  }
  if (!manifest.contract_versions.includes(AGENT_FLEET_PROTOCOL_VERSION)) {
    throw new AgentFleetContractError(
      "capability manifest does not advertise the fleet protocol",
    );
  }
  validateStringSet(manifest.contract_versions, "contract_versions");
  validateCapabilities(manifest.capabilities);
  validateSchemaCompatibility(member.schema_compatibility);
}

export function validateAgentFleetMemberUpdate(
  current: AgentFleetMemberV1,
  next: AgentFleetMemberV1,
): void {
  validateAgentFleetMember(current);
  validateAgentFleetMember(next);
  if (
    current.member_id !== next.member_id ||
    current.service_id !== next.service_id ||
    current.capacity_resource_ref !== next.capacity_resource_ref ||
    current.protocol_version !== next.protocol_version ||
    current.registered_at !== next.registered_at ||
    next.revision !== current.revision + 1 ||
    Date.parse(next.updated_at) <= Date.parse(current.updated_at)
  ) {
    throw new AgentFleetContractError(
      "fleet member update changed immutable identity or revision order",
    );
  }
  const presenceRefresh =
    current.state === next.state && current.state !== "retired";
  if (!presenceRefresh && !memberTransitions[current.state].includes(next.state)) {
    throw new AgentFleetContractError(
      `fleet member transition ${current.state}->${next.state} is not allowed`,
    );
  }

  if (next.generation === current.generation) {
    if (
      next.capability_manifest.digest !== current.capability_manifest.digest ||
      !sameValue(next.schema_compatibility, current.schema_compatibility)
    ) {
      throw new AgentFleetContractError(
        "one member generation cannot change its compatibility manifest",
      );
    }
    return;
  }
  if (
    current.state !== "offline" ||
    next.state !== "recovering" ||
    next.generation !== current.generation + 1
  ) {
    throw new AgentFleetContractError(
      "a new member generation must advance offline to recovering by one",
    );
  }
}

export function validateAgentFleetMessage(message: AgentFleetMessageV1): void {
  requireExactKeys(message, [
    "created_at",
    "idempotency_key",
    "message_id",
    "message_sequence",
    "packet_id",
    "payload",
    "protocol_version",
    "resume",
    "run_id",
    "schema_version",
    "sender_generation",
    "sender_member_id",
  ], "fleet message", ["resume"]);
  if (message.schema_version !== AGENT_FLEET_MESSAGE_SCHEMA_VERSION) {
    throw new AgentFleetContractError("fleet message schema is unsupported");
  }
  requirePattern(message.message_id, FLEET_MESSAGE, "message_id");
  validateMessageIdentityInput(message);
  if (message.message_id !== agentFleetMessageIdentity(message)) {
    throw new AgentFleetContractError(
      "fleet message identity does not match its immutable input",
    );
  }
}

export function validateAgentFleetMessageForPacket(
  message: AgentFleetMessageV1,
  packet: DistributedWorkPacketV1,
): void {
  validateAgentFleetMessage(message);
  validateDistributedWorkPacket(packet);
  if (
    message.packet_id !== packet.packet_id ||
    message.run_id !== packet.child_run.run_id ||
    message.payload.payload_ref !== packet.objective_ref ||
    message.payload.payload_digest !== packet.objective_digest
  ) {
    throw new AgentFleetContractError(
      "fleet message does not match its distributed work packet and run",
    );
  }
}

export function validateAgentFleetSender(
  message: AgentFleetMessageV1,
  sender: AgentFleetMemberV1,
  observedAt: string,
): void {
  validateAgentFleetMessage(message);
  validateAgentFleetMember(sender);
  requireCanonicalTime(observedAt, "observed_at");
  if (
    sender.member_id !== message.sender_member_id ||
    sender.generation !== message.sender_generation
  ) {
    throw new AgentFleetContractError(
      "fleet message sender does not match the member generation",
    );
  }
  if (
    sender.state === "retired" ||
    sender.state === "offline" ||
    Date.parse(sender.valid_until) <= Date.parse(observedAt)
  ) {
    throw new AgentFleetContractError("fleet message sender is not present");
  }
}

export function createAgentFleetExecutionBinding(input: {
  bound_at: string;
  checkpoint?: CheckpointV1;
  lease: WorkLeaseV1;
  member: AgentFleetMemberV1;
  message: AgentFleetMessageV1;
  packet: DistributedWorkPacketV1;
  permit: CapacityPermitV1;
}): AgentFleetExecutionBindingV1 {
  validateAgentFleetMessageForPacket(input.message, input.packet);
  validateAgentFleetMember(input.member);
  requireCanonicalTime(input.bound_at, "bound_at");
  validateExecutionProof(input);
  const resume = input.message.resume;
  return {
    bound_at: input.bound_at,
    capacity_permit_id: input.permit.permit_id,
    checkpoint_ref: resume?.checkpoint_ref,
    fencing_token: input.lease.fencing_token,
    generation: input.lease.generation,
    handoff_ref: resume?.handoff_ref,
    lease_ref: distributedWorkLeaseReference(input.lease),
    member_id: input.member.member_id,
    message_id: input.message.message_id,
    run_id: input.packet.child_run.run_id,
    schema_version: AGENT_FLEET_EXECUTION_BINDING_SCHEMA_VERSION,
  };
}

function validateExecutionProof(input: {
  bound_at: string;
  checkpoint?: CheckpointV1;
  lease: WorkLeaseV1;
  member: AgentFleetMemberV1;
  message: AgentFleetMessageV1;
  packet: DistributedWorkPacketV1;
  permit: CapacityPermitV1;
}): void {
  const { bound_at: boundAt, checkpoint, lease, member, message, packet, permit } = input;
  if (
    member.state !== "ready" &&
    member.state !== "degraded" &&
    member.state !== "recovering"
  ) {
    throw new AgentFleetContractError("member cannot own existing work");
  }
  if (Date.parse(member.valid_until) <= Date.parse(boundAt)) {
    throw new AgentFleetContractError("member presence expired before execution");
  }
  requireCanonicalTime(lease.heartbeat_at, "lease.heartbeat_at");
  requireCanonicalTime(lease.lease_expires_at, "lease.lease_expires_at");
  if (
    lease.schema_version !== "work-lease/v1" ||
    lease.run_id !== packet.child_run.run_id ||
    lease.owner_id !== member.member_id ||
    lease.generation !== member.generation ||
    Date.parse(lease.heartbeat_at) > Date.parse(boundAt) ||
    Date.parse(lease.lease_expires_at) <= Date.parse(boundAt)
  ) {
    throw new AgentFleetContractError("work lease does not fence this member and run");
  }
  requirePositiveInteger(lease.fencing_token, "lease.fencing_token");
  assertCapacityPermit(permit);
  if (
    permit.state !== "active" ||
    permit.owner_id !== member.member_id ||
    permit.generation !== member.generation ||
    permit.run_id !== packet.child_run.run_id ||
    permit.resource_ref !== member.capacity_resource_ref ||
    Date.parse(permit.acquired_at) > Date.parse(boundAt) ||
    Date.parse(permit.expires_at) <= Date.parse(boundAt)
  ) {
    throw new AgentFleetContractError(
      "capacity permit does not fence this member and run",
    );
  }

  if (message.resume === undefined) {
    if (checkpoint !== undefined) {
      throw new AgentFleetContractError(
        "an initial fleet message cannot bind a resume checkpoint",
      );
    }
    return;
  }
  if (checkpoint === undefined) {
    throw new AgentFleetContractError(
      "a resumed fleet message requires its durable checkpoint",
    );
  }
  validateCheckpoint(checkpoint);
  const expected = createAgentFleetResumeReference(
    checkpoint,
    message.resume.handoff_digest,
  );
  if (
    checkpoint.run_id !== packet.child_run.run_id ||
    checkpoint.generation > lease.generation ||
    !sameValue(expected, message.resume)
  ) {
    throw new AgentFleetContractError(
      "resume references do not match the run checkpoint and handoff",
    );
  }
}

function validateMessageIdentityInput(input: AgentFleetMessageIdentityInput): void {
  if (input.protocol_version !== AGENT_FLEET_PROTOCOL_VERSION) {
    throw new AgentFleetContractError("fleet protocol version is unsupported");
  }
  requireCanonicalTime(input.created_at, "created_at");
  requireIdentifier(input.idempotency_key, "idempotency_key");
  requirePositiveInteger(input.message_sequence, "message_sequence");
  requireIdentifier(input.packet_id, "packet_id");
  requireIdentifier(input.run_id, "run_id");
  requirePositiveInteger(input.sender_generation, "sender_generation");
  requireIdentifier(input.sender_member_id, "sender_member_id");
  validateAgentFleetPayloadReference(input.payload);
  if (input.message_sequence === 1 && input.resume !== undefined) {
    throw new AgentFleetContractError(
      "the initial fleet message cannot contain resume references",
    );
  }
  if (input.message_sequence > 1 && input.resume === undefined) {
    throw new AgentFleetContractError(
      "a later fleet message requires checkpoint and handoff references",
    );
  }
  if (input.resume !== undefined) {
    validateAgentFleetResumeReference(input.resume);
  }
}

function validateAgentFleetPayloadReference(
  payload: AgentFleetPayloadReferenceV1,
): void {
  requireExactKeys(payload, [
    "byte_length",
    "media_type",
    "payload_digest",
    "payload_ref",
    "redaction_receipt_digest",
    "redaction_receipt_ref",
  ], "fleet payload reference");
  if (
    !Number.isSafeInteger(payload.byte_length) ||
    payload.byte_length < 1 ||
    payload.byte_length > MAX_AGENT_FLEET_PAYLOAD_BYTES
  ) {
    throw new AgentFleetContractError("payload byte length exceeds its bound");
  }
  if (
    payload.media_type !== "application/json" &&
    payload.media_type !== "text/plain"
  ) {
    throw new AgentFleetContractError("payload media type is unsupported");
  }
  requireDigest(payload.payload_digest, "payload_digest");
  requireDigest(payload.redaction_receipt_digest, "redaction_receipt_digest");
  requirePattern(payload.payload_ref, FLEET_PAYLOAD, "payload_ref");
  requirePattern(
    payload.redaction_receipt_ref,
    REDACTION_RECEIPT,
    "redaction_receipt_ref",
  );
  if (
    payload.payload_ref !==
      digestReference("agent-fleet-payload", payload.payload_digest) ||
    payload.redaction_receipt_ref !==
      digestReference(
        "agent-fleet-redaction-receipt",
        payload.redaction_receipt_digest,
      )
  ) {
    throw new AgentFleetContractError(
      "fleet payload references are not content addressed",
    );
  }
}

function validateAgentFleetResumeReference(
  resume: AgentFleetResumeReferenceV1,
): void {
  requireExactKeys(resume, [
    "checkpoint_digest",
    "checkpoint_ref",
    "handoff_digest",
    "handoff_ref",
  ], "fleet resume reference");
  requireDigest(resume.checkpoint_digest, "checkpoint_digest");
  requireDigest(resume.handoff_digest, "handoff_digest");
  requirePattern(resume.checkpoint_ref, CHECKPOINT_REFERENCE, "checkpoint_ref");
  requirePattern(resume.handoff_ref, HANDOFF_REFERENCE, "handoff_ref");
  if (
    resume.checkpoint_ref !==
      digestReference("agent-fleet-checkpoint", resume.checkpoint_digest) ||
    resume.handoff_ref !==
      digestReference("agent-fleet-handoff", resume.handoff_digest)
  ) {
    throw new AgentFleetContractError(
      "fleet resume references are not content addressed",
    );
  }
}

function validateCheckpoint(checkpoint: CheckpointV1): void {
  if (checkpoint.schema_version !== "checkpoint/v1") {
    throw new AgentFleetContractError("checkpoint schema is unsupported");
  }
  requireIdentifier(checkpoint.checkpoint_id, "checkpoint_id");
  requireIdentifier(checkpoint.run_id, "checkpoint.run_id");
  requirePositiveInteger(checkpoint.generation, "checkpoint.generation");
  requirePositiveInteger(checkpoint.run_revision, "checkpoint.run_revision");
  requirePositiveInteger(checkpoint.sequence, "checkpoint.sequence");
  requireDigest(checkpoint.payload_digest, "checkpoint.payload_digest");
  requireCanonicalTime(checkpoint.created_at, "checkpoint.created_at");
}

function validateCapabilities(
  capabilities: AgentFleetMemberV1["capability_manifest"]["capabilities"],
): void {
  if (capabilities.length > 64) {
    throw new AgentFleetContractError("capability manifest exceeds its bound");
  }
  const identities = new Set<string>();
  for (const capability of capabilities) {
    requireIdentifier(capability.capability_id, "capability_id");
    requireIdentifier(capability.version, "capability.version");
    if (capability.level !== "required" && capability.level !== "optional") {
      throw new AgentFleetContractError("capability level is unsupported");
    }
    const identity = `${capability.capability_id}\u0000${capability.version}`;
    if (identities.has(identity)) {
      throw new AgentFleetContractError("capability manifest has duplicates");
    }
    identities.add(identity);
  }
}

function validateSchemaCompatibility(
  compatibility: AgentFleetMemberV1["schema_compatibility"],
): void {
  requireIdentifier(compatibility.current_version, "current_version");
  requireIdentifier(compatibility.rolling_upgrade_rule, "rolling_upgrade_rule");
  validateStringSet(compatibility.read_versions, "read_versions");
  validateStringSet(compatibility.write_versions, "write_versions");
  const decisions = new Set(compatibility.capability_decisions);
  if (
    decisions.size < 1 ||
    decisions.size > 4 ||
    decisions.size !== compatibility.capability_decisions.length ||
    [...decisions].some(
      (decision) =>
        decision !== "supported" &&
        decision !== "degraded" &&
        decision !== "blocked" &&
        decision !== "incompatible",
    )
  ) {
    throw new AgentFleetContractError(
      "schema compatibility has unsupported capability decisions",
    );
  }
  if (
    !compatibility.read_versions.includes(compatibility.current_version) ||
    !compatibility.write_versions.includes(compatibility.current_version)
  ) {
    throw new AgentFleetContractError(
      "schema compatibility must read and write its current version",
    );
  }
}

function validateStringSet(values: string[], field: string): void {
  if (values.length < 1 || values.length > 16) {
    throw new AgentFleetContractError(`${field} exceeds its bound`);
  }
  const seen = new Set<string>();
  for (const value of values) {
    requireIdentifier(value, field);
    if (seen.has(value)) {
      throw new AgentFleetContractError(`${field} has duplicates`);
    }
    seen.add(value);
  }
}

function canonicalMessageIdentity(input: AgentFleetMessageIdentityInput) {
  return {
    created_at: input.created_at,
    idempotency_key: input.idempotency_key,
    message_sequence: input.message_sequence,
    packet_id: input.packet_id,
    payload: input.payload,
    protocol_version: input.protocol_version,
    resume: input.resume,
    run_id: input.run_id,
    sender_generation: input.sender_generation,
    sender_member_id: input.sender_member_id,
  };
}

function digestReference(scheme: string, digest: string): string {
  requireDigest(digest, `${scheme}_digest`);
  return `${scheme}://sha256/${digest.slice("sha256:".length)}`;
}

function requireDigest(value: string, field: string): void {
  requirePattern(value, SHA256_DIGEST, field);
}

function requirePattern(
  value: string,
  pattern: RegExp,
  field: string,
): void {
  if (!pattern.test(value)) {
    throw new AgentFleetContractError(`${field} has an invalid format`);
  }
}

function requireIdentifier(value: string, field: string): void {
  if (
    value.length < 1 ||
    value.length > MAX_IDENTIFIER_LENGTH ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new AgentFleetContractError(`${field} must be a bounded opaque value`);
  }
}

function requirePositiveInteger(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new AgentFleetContractError(`${field} must be a positive integer`);
  }
}

function requireCanonicalTime(value: string, field: string): void {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new AgentFleetContractError(
      `${field} must be a canonical ISO-8601 timestamp`,
    );
  }
}

function requireExactKeys(
  value: object,
  allowed: readonly string[],
  label: string,
  optional: readonly string[] = [],
): void {
  if (Object.getPrototypeOf(value) !== Object.prototype) {
    throw new AgentFleetContractError(`${label} must be a plain record`);
  }
  const keys = Object.keys(value).sort();
  const allowedSet = new Set(allowed);
  if (keys.some((key) => !allowedSet.has(key))) {
    throw new AgentFleetContractError(`${label} contains unsupported fields`);
  }
  const optionalSet = new Set(optional);
  if (
    allowed.some(
      (key) => !optionalSet.has(key) && !Object.prototype.hasOwnProperty.call(value, key),
    )
  ) {
    throw new AgentFleetContractError(`${label} is missing required fields`);
  }
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${stableStringify(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function sameValue(left: unknown, right: unknown): boolean {
  return stableStringify(left) === stableStringify(right);
}
