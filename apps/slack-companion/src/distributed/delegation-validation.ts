import { createHash } from "node:crypto";
import type { CapabilityRequirement, WorkLeaseV1 } from "@writer/cerebro-sdk";
import {
  MAX_DISTRIBUTED_WORK_CAPABILITIES,
  MAX_DISTRIBUTED_WORK_DELIVERABLES,
} from "./contracts.js";
import type {
  DistributedWorkDeliverableV1,
  DistributedWorkPacketV1,
} from "./contracts.js";
import {
  DISTRIBUTED_WORK_DELEGATION_SCHEMA_VERSION,
  DISTRIBUTED_WORK_DELEGATION_CANONICALIZATION,
  MAX_DELEGATION_LIFETIME_MS,
  MAX_DELEGATION_TOOL_REFS,
  SIGNED_DISTRIBUTED_WORK_DELEGATION_SCHEMA_VERSION,
} from "./delegation-contracts.js";
import type {
  DistributedWorkDelegationIdentityInput,
  DistributedWorkDelegationManifestDraft,
  DistributedWorkDelegationManifestV1,
  DistributedWorkDelegationUse,
  SignedDistributedWorkDelegationV1,
} from "./delegation-contracts.js";
import type {
  DistributedWorkDelegationRevocationPort,
  DistributedWorkDelegationSigningPort,
  DistributedWorkDelegationVerificationPort,
} from "./delegation-ports.js";
import {
  DistributedWorkContractError,
  distributedWorkLeaseReference,
  validateDistributedWorkPacket,
} from "./validation.js";

const SHA256_DIGEST = /^sha256:[a-f0-9]{64}$/;
const DELEGATION_ID =
  /^distributed-work-delegation:\/\/sha256\/[a-f0-9]{64}$/;
const OPAQUE_REFERENCE = /^[a-z][a-z0-9+.-]*:\/\/\S+$/;
const MAX_ID_LENGTH = 256;
const MAX_REF_LENGTH = 1_024;
const MAX_SIGNATURE_LENGTH = 16_384;

export function distributedWorkDelegationIntentDigest(
  input: DistributedWorkDelegationIdentityInput,
): string {
  validateDelegationIdentityInput(input);
  return sha256(stableStringify(canonicalDelegationIdentity(input)));
}

export function distributedWorkDelegationIdentity(
  input: DistributedWorkDelegationIdentityInput,
): string {
  const digest = distributedWorkDelegationIntentDigest(input).slice(
    "sha256:".length,
  );
  return `distributed-work-delegation://sha256/${digest}`;
}

export function distributedWorkDelegationManifestDigest(
  manifest: DistributedWorkDelegationManifestV1,
): string {
  validateDistributedWorkDelegationManifest(manifest);
  return sha256(canonicalDistributedWorkDelegationManifest(manifest));
}

export function canonicalDistributedWorkDelegationManifest(
  manifest: DistributedWorkDelegationManifestV1,
): string {
  return stableStringify({
    ...canonicalDelegationIdentity(manifest),
    delegation_id: manifest.delegation_id,
    delegation_intent_digest: manifest.delegation_intent_digest,
    expires_at: manifest.expires_at,
    issued_at: manifest.issued_at,
    not_before: manifest.not_before,
    schema_version: manifest.schema_version,
  });
}

export function createDistributedWorkDelegationManifest(
  draft: DistributedWorkDelegationManifestDraft,
): DistributedWorkDelegationManifestV1 {
  validateDistributedWorkPacket(draft.packet);
  validateLeaseForPacket(draft.packet, draft.lease);
  const identity: DistributedWorkDelegationIdentityInput = {
    allowed_capabilities: structuredClone(draft.allowed_capabilities),
    allowed_deliverables: structuredClone(draft.allowed_deliverables),
    allowed_tool_refs: [...draft.allowed_tool_refs],
    child_run_id: draft.packet.child_run.run_id,
    fencing_token: draft.lease.fencing_token,
    generation: draft.lease.generation,
    idempotency_key: draft.packet.idempotency_key,
    issuer_ref: draft.issuer_ref,
    lease_ref: distributedWorkLeaseReference(draft.lease),
    packet_id: draft.packet.packet_id,
    parent_run_id: draft.packet.parent_run_id,
    revocation_ref: draft.revocation_ref,
    subject_ref: draft.packet.parent_subject_ref,
    tenant_id: draft.packet.tenant_id,
    work_intent_digest: draft.packet.intent_digest,
  };
  validateAuthorityAgainstPacket(draft.packet, identity);
  const delegationIntentDigest = distributedWorkDelegationIntentDigest(identity);
  const manifest: DistributedWorkDelegationManifestV1 = {
    ...identity,
    delegation_id: distributedWorkDelegationIdentity(identity),
    delegation_intent_digest: delegationIntentDigest,
    expires_at: draft.expires_at,
    issued_at: draft.issued_at,
    not_before: draft.not_before,
    schema_version: DISTRIBUTED_WORK_DELEGATION_SCHEMA_VERSION,
  };
  validateDistributedWorkDelegationManifest(manifest);
  return manifest;
}

export async function signDistributedWorkDelegation(
  manifest: DistributedWorkDelegationManifestV1,
  keyRef: string,
  signer: DistributedWorkDelegationSigningPort,
): Promise<SignedDistributedWorkDelegationV1> {
  validateDistributedWorkDelegationManifest(manifest);
  requireOpaqueRef(keyRef, "key_ref");
  const canonicalManifest = canonicalDistributedWorkDelegationManifest(manifest);
  const manifestDigest = sha256(canonicalManifest);
  const signature = await signer.sign({
    canonical_manifest: canonicalManifest,
    issuer_ref: manifest.issuer_ref,
    key_ref: keyRef,
    manifest_digest: manifestDigest,
  });
  validateIdentifier(signature.signature_suite, "signature_suite");
  validateSignatureValue(signature.signature_value);
  return {
    canonicalization: DISTRIBUTED_WORK_DELEGATION_CANONICALIZATION,
    manifest: structuredClone(manifest),
    manifest_digest: manifestDigest,
    schema_version: SIGNED_DISTRIBUTED_WORK_DELEGATION_SCHEMA_VERSION,
    signature: {
      key_ref: keyRef,
      signature_suite: signature.signature_suite,
      signature_value: signature.signature_value,
    },
  };
}

export async function authorizeSignedDistributedWorkDelegation(
  signed: SignedDistributedWorkDelegationV1,
  use: DistributedWorkDelegationUse,
  verifier: DistributedWorkDelegationVerificationPort,
  revocations: DistributedWorkDelegationRevocationPort,
): Promise<void> {
  validateSignedEnvelope(signed);
  validateDistributedWorkPacket(use.packet);
  validateLeaseForPacket(use.packet, use.lease);
  requireTimestamp(use.now, "now");
  if (Date.parse(use.now) >= Date.parse(use.lease.lease_expires_at)) {
    throw new DistributedWorkContractError(
      "signed delegation requires an active work lease",
    );
  }

  const canonicalManifest = canonicalDistributedWorkDelegationManifest(
    signed.manifest,
  );
  const expectedManifestDigest = sha256(canonicalManifest);
  if (signed.manifest_digest !== expectedManifestDigest) {
    throw new DistributedWorkContractError(
      "signed delegation manifest digest does not match its contents",
    );
  }
  const verified = await verifier.verify({
    canonical_manifest: canonicalManifest,
    issuer_ref: signed.manifest.issuer_ref,
    key_ref: signed.signature.key_ref,
    manifest_digest: signed.manifest_digest,
    signature: structuredClone(signed.signature),
  });
  if (!verified) {
    throw new DistributedWorkContractError(
      "signed delegation signature is invalid",
    );
  }

  const revoked = await revocations.isRevoked({
    delegation_id: signed.manifest.delegation_id,
    observed_at: use.now,
    revocation_ref: signed.manifest.revocation_ref,
  });
  if (revoked) {
    throw new DistributedWorkContractError("signed delegation is revoked");
  }

  validateDelegationWindow(signed.manifest, use.now);
  validateManifestScope(signed.manifest, use.packet, use.lease);
  validateRequestedAuthority(signed.manifest, use);
}

export function validateDistributedWorkDelegationManifest(
  manifest: DistributedWorkDelegationManifestV1,
): void {
  if (manifest.schema_version !== DISTRIBUTED_WORK_DELEGATION_SCHEMA_VERSION) {
    throw new DistributedWorkContractError(
      "distributed work delegation schema version is unsupported",
    );
  }
  validateDelegationIdentityInput(manifest);
  requirePattern(manifest.delegation_id, DELEGATION_ID, "delegation_id");
  requirePattern(
    manifest.delegation_intent_digest,
    SHA256_DIGEST,
    "delegation_intent_digest",
  );
  requireTimestamp(manifest.issued_at, "issued_at");
  requireTimestamp(manifest.not_before, "not_before");
  requireTimestamp(manifest.expires_at, "expires_at");
  requireOpaqueRef(manifest.revocation_ref, "revocation_ref");

  const issuedAt = Date.parse(manifest.issued_at);
  const notBefore = Date.parse(manifest.not_before);
  const expiresAt = Date.parse(manifest.expires_at);
  if (
    notBefore < issuedAt ||
    expiresAt <= notBefore ||
    expiresAt - issuedAt > MAX_DELEGATION_LIFETIME_MS
  ) {
    throw new DistributedWorkContractError(
      "signed delegation validity must be positive and bounded",
    );
  }

  const expectedIntentDigest = distributedWorkDelegationIntentDigest(manifest);
  if (
    manifest.delegation_intent_digest !== expectedIntentDigest ||
    manifest.delegation_id !== distributedWorkDelegationIdentity(manifest)
  ) {
    throw new DistributedWorkContractError(
      "distributed work delegation identity does not match its immutable intent",
    );
  }
}

function validateSignedEnvelope(
  signed: SignedDistributedWorkDelegationV1,
): void {
  if (
    signed.schema_version !==
    SIGNED_DISTRIBUTED_WORK_DELEGATION_SCHEMA_VERSION
  ) {
    throw new DistributedWorkContractError(
      "signed distributed work delegation schema version is unsupported",
    );
  }
  if (
    signed.canonicalization !== DISTRIBUTED_WORK_DELEGATION_CANONICALIZATION
  ) {
    throw new DistributedWorkContractError(
      "signed delegation canonicalization is unsupported",
    );
  }
  validateDistributedWorkDelegationManifest(signed.manifest);
  requirePattern(signed.manifest_digest, SHA256_DIGEST, "manifest_digest");
  requireOpaqueRef(signed.signature.key_ref, "signature.key_ref");
  validateIdentifier(
    signed.signature.signature_suite,
    "signature.signature_suite",
  );
  validateSignatureValue(signed.signature.signature_value);
}

function validateDelegationIdentityInput(
  input: DistributedWorkDelegationIdentityInput,
): void {
  requireOpaqueRef(input.issuer_ref, "issuer_ref");
  requireOpaqueRef(input.subject_ref, "subject_ref");
  requirePattern(input.packet_id, /^distributed-work-packet:\/\/sha256\/[a-f0-9]{64}$/, "packet_id");
  requirePattern(input.work_intent_digest, SHA256_DIGEST, "work_intent_digest");
  requirePattern(input.lease_ref, /^work-lease:\/\/sha256\/[a-f0-9]{64}$/, "lease_ref");
  requireOpaqueRef(input.revocation_ref, "revocation_ref");
  for (const [value, label] of [
    [input.tenant_id, "tenant_id"],
    [input.parent_run_id, "parent_run_id"],
    [input.child_run_id, "child_run_id"],
    [input.idempotency_key, "idempotency_key"],
  ] as const) {
    validateIdentifier(value, label);
  }
  requirePositiveInteger(input.generation, "generation");
  requirePositiveInteger(input.fencing_token, "fencing_token");
  validateCapabilities(input.allowed_capabilities, "allowed_capabilities");
  validateTools(input.allowed_tool_refs);
  validateDeliverables(input.allowed_deliverables);
}

function validateAuthorityAgainstPacket(
  packet: DistributedWorkPacketV1,
  authority: DistributedWorkDelegationIdentityInput,
): void {
  const packetCapabilities = new Set(
    packet.required_capabilities.map(capabilityIdentity),
  );
  if (
    authority.allowed_capabilities.some(
      (capability) => !packetCapabilities.has(capabilityIdentity(capability)),
    )
  ) {
    throw new DistributedWorkContractError(
      "delegation capability exceeds the admitted packet",
    );
  }
  const packetDeliverables = new Map(
    packet.deliverables.map((deliverable) => [deliverable.deliverable_id, deliverable]),
  );
  for (const deliverable of authority.allowed_deliverables) {
    const admitted = packetDeliverables.get(deliverable.deliverable_id);
    if (admitted === undefined || deliverableIdentity(admitted) !== deliverableIdentity(deliverable)) {
      throw new DistributedWorkContractError(
        "delegation deliverable exceeds the admitted packet",
      );
    }
  }
}

function validateManifestScope(
  manifest: DistributedWorkDelegationManifestV1,
  packet: DistributedWorkPacketV1,
  lease: WorkLeaseV1,
): void {
  if (
    manifest.tenant_id !== packet.tenant_id ||
    manifest.subject_ref !== packet.parent_subject_ref ||
    manifest.parent_run_id !== packet.parent_run_id ||
    manifest.packet_id !== packet.packet_id ||
    manifest.child_run_id !== packet.child_run.run_id ||
    manifest.idempotency_key !== packet.idempotency_key ||
    manifest.work_intent_digest !== packet.intent_digest
  ) {
    throw new DistributedWorkContractError(
      "signed delegation does not match the admitted packet scope and intent",
    );
  }
  validateAuthorityAgainstPacket(packet, manifest);
  if (
    manifest.generation !== lease.generation ||
    manifest.fencing_token !== lease.fencing_token ||
    manifest.lease_ref !== distributedWorkLeaseReference(lease)
  ) {
    throw new DistributedWorkContractError(
      "signed delegation does not match the active lease generation and fence",
    );
  }
}

function validateDelegationWindow(
  manifest: DistributedWorkDelegationManifestV1,
  now: string,
): void {
  const observedAt = Date.parse(now);
  if (
    observedAt < Date.parse(manifest.not_before) ||
    observedAt >= Date.parse(manifest.expires_at)
  ) {
    throw new DistributedWorkContractError("signed delegation is not active");
  }
}

function validateRequestedAuthority(
  manifest: DistributedWorkDelegationManifestV1,
  use: DistributedWorkDelegationUse,
): void {
  validateCapabilities(use.requested_capabilities, "requested_capabilities");
  validateTools(use.requested_tool_refs);
  requireArrayBound(
    use.requested_deliverable_ids,
    1,
    MAX_DISTRIBUTED_WORK_DELIVERABLES,
    "requested_deliverable_ids",
  );
  const allowedCapabilities = new Set(
    manifest.allowed_capabilities.map(capabilityIdentity),
  );
  const allowedTools = new Set(manifest.allowed_tool_refs);
  const allowedDeliverables = new Set(
    manifest.allowed_deliverables.map((deliverable) => deliverable.deliverable_id),
  );
  if (
    use.requested_capabilities.some(
      (capability) => !allowedCapabilities.has(capabilityIdentity(capability)),
    ) ||
    use.requested_tool_refs.some((toolRef) => !allowedTools.has(toolRef)) ||
    use.requested_deliverable_ids.some(
      (deliverableId) => !allowedDeliverables.has(deliverableId),
    )
  ) {
    throw new DistributedWorkContractError(
      "requested authority exceeds the signed delegation",
    );
  }
  if (new Set(use.requested_deliverable_ids).size !== use.requested_deliverable_ids.length) {
    throw new DistributedWorkContractError(
      "requested deliverables must not repeat",
    );
  }
}

function validateLeaseForPacket(
  packet: DistributedWorkPacketV1,
  lease: WorkLeaseV1,
): void {
  if (
    lease.schema_version !== "work-lease/v1" ||
    lease.run_id !== packet.child_run.run_id
  ) {
    throw new DistributedWorkContractError(
      "delegation lease does not own the packet child run",
    );
  }
  requirePositiveInteger(lease.generation, "lease.generation");
  requirePositiveInteger(lease.fencing_token, "lease.fencing_token");
  validateIdentifier(lease.lease_token, "lease.lease_token");
  validateIdentifier(lease.owner_id, "lease.owner_id");
  requireTimestamp(lease.heartbeat_at, "lease.heartbeat_at");
  requireTimestamp(lease.lease_expires_at, "lease.lease_expires_at");
}

function validateCapabilities(
  capabilities: CapabilityRequirement[],
  label: string,
): void {
  requireArrayBound(capabilities, 1, MAX_DISTRIBUTED_WORK_CAPABILITIES, label);
  const identities = new Set<string>();
  for (const capability of capabilities) {
    validateIdentifier(capability.capability_id, `${label}.capability_id`);
    validateIdentifier(capability.version, `${label}.version`);
    if (capability.level !== "required" && capability.level !== "optional") {
      throw new DistributedWorkContractError(
        `${label} contains an unsupported level`,
      );
    }
    const identity = capabilityIdentity(capability);
    if (identities.has(identity)) {
      throw new DistributedWorkContractError(`${label} must not repeat`);
    }
    identities.add(identity);
  }
}

function validateTools(toolRefs: string[]): void {
  requireArrayBound(toolRefs, 0, MAX_DELEGATION_TOOL_REFS, "tool_refs");
  const unique = new Set<string>();
  for (const toolRef of toolRefs) {
    requireOpaqueRef(toolRef, "tool_ref");
    if (unique.has(toolRef)) {
      throw new DistributedWorkContractError("tool refs must not repeat");
    }
    unique.add(toolRef);
  }
}

function validateDeliverables(
  deliverables: DistributedWorkDeliverableV1[],
): void {
  requireArrayBound(
    deliverables,
    1,
    MAX_DISTRIBUTED_WORK_DELIVERABLES,
    "allowed_deliverables",
  );
  const ids = new Set<string>();
  const refs = new Set<string>();
  const sequences = new Set<number>();
  for (const deliverable of deliverables) {
    validateIdentifier(deliverable.deliverable_id, "deliverable_id");
    requirePositiveInteger(deliverable.sequence, "deliverable.sequence");
    requireOpaqueRef(deliverable.requirement_ref, "deliverable.requirement_ref");
    requirePattern(
      deliverable.requirement_digest,
      SHA256_DIGEST,
      "deliverable.requirement_digest",
    );
    if (
      ids.has(deliverable.deliverable_id) ||
      refs.has(deliverable.requirement_ref) ||
      sequences.has(deliverable.sequence)
    ) {
      throw new DistributedWorkContractError(
        "delegation deliverables must not repeat",
      );
    }
    ids.add(deliverable.deliverable_id);
    refs.add(deliverable.requirement_ref);
    sequences.add(deliverable.sequence);
  }
}

function canonicalDelegationIdentity(
  input: DistributedWorkDelegationIdentityInput,
) {
  return {
    allowed_capabilities: [...input.allowed_capabilities]
      .map((capability) => ({ ...capability }))
      .sort((left, right) =>
        capabilityIdentity(left).localeCompare(capabilityIdentity(right)),
      ),
    allowed_deliverables: [...input.allowed_deliverables]
      .map((deliverable) => ({ ...deliverable }))
      .sort((left, right) => left.sequence - right.sequence),
    allowed_tool_refs: [...input.allowed_tool_refs].sort(),
    child_run_id: input.child_run_id,
    fencing_token: input.fencing_token,
    generation: input.generation,
    idempotency_key: input.idempotency_key,
    issuer_ref: input.issuer_ref,
    lease_ref: input.lease_ref,
    packet_id: input.packet_id,
    parent_run_id: input.parent_run_id,
    revocation_ref: input.revocation_ref,
    subject_ref: input.subject_ref,
    tenant_id: input.tenant_id,
    work_intent_digest: input.work_intent_digest,
  };
}

function capabilityIdentity(capability: CapabilityRequirement): string {
  return stableStringify([
    capability.capability_id,
    capability.version,
    capability.level,
  ]);
}

function deliverableIdentity(
  deliverable: DistributedWorkDeliverableV1,
): string {
  return stableStringify([
    deliverable.deliverable_id,
    deliverable.sequence,
    deliverable.requirement_ref,
    deliverable.requirement_digest,
  ]);
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

function validateIdentifier(value: string, label: string): void {
  if (
    value.trim() === "" ||
    Buffer.byteLength(value, "utf8") > MAX_ID_LENGTH
  ) {
    throw new DistributedWorkContractError(`${label} must be a bounded identifier`);
  }
}

function requireOpaqueRef(value: string, label: string): void {
  if (
    Buffer.byteLength(value, "utf8") > MAX_REF_LENGTH ||
    !OPAQUE_REFERENCE.test(value)
  ) {
    throw new DistributedWorkContractError(
      `${label} must be a bounded opaque reference`,
    );
  }
}

function requirePattern(value: string, pattern: RegExp, label: string): void {
  if (!pattern.test(value)) {
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

function validateSignatureValue(value: string): void {
  if (
    value.trim() === "" ||
    Buffer.byteLength(value, "utf8") > MAX_SIGNATURE_LENGTH
  ) {
    throw new DistributedWorkContractError(
      "signature value must be present and bounded",
    );
  }
}

function sha256(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
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
