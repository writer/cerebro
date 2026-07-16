import type {
  CapabilityCompatibilityDecision,
  CapabilityManifestV1,
  CapabilityRequirement,
  PresenceSnapshotV1,
  SchemaCompatibility,
  WorkLeaseV1,
} from "@writer/cerebro-sdk";

export interface CompatibilityAssessment {
  decision: CapabilityCompatibilityDecision;
  negotiated_write_version?: string;
  reasons: string[];
}

export interface CompatibilityInput {
  companion_manifest: CapabilityManifestV1;
  companion_schema: SchemaCompatibility;
  core_manifest: CapabilityManifestV1;
  core_schema: SchemaCompatibility;
}

export interface ContinuityGate {
  allowed: boolean;
  reason: string;
}

/**
 * Lease policy for one admitted distributed-work child run. The worker uses
 * the canonical service presence, capability manifest, and work lease records;
 * it does not have a separate lifecycle.
 */
export interface PacketLeaseGateInput {
  assessment: CompatibilityAssessment;
  expected_route_generation: number;
  now: string;
  packet_required_capabilities: readonly CapabilityRequirement[];
  presence: PresenceSnapshotV1;
  prior_lease?: WorkLeaseV1;
  proposed_fencing_token: number;
  proposed_generation: number;
  run_id: string;
  worker_manifest: CapabilityManifestV1;
}

export function assessCompatibility(
  input: CompatibilityInput,
): CompatibilityAssessment {
  const reasons: string[] = [];
  const schemaReadable =
    input.core_schema.read_versions.includes(input.companion_schema.current_version) &&
    input.companion_schema.read_versions.includes(input.core_schema.current_version);
  const sharedContractVersions = input.core_manifest.contract_versions.filter(
    (version) => input.companion_manifest.contract_versions.includes(version),
  );

  if (!schemaReadable || sharedContractVersions.length === 0) {
    if (!schemaReadable) {
      reasons.push("contract_version_not_readable");
    }
    if (sharedContractVersions.length === 0) {
      reasons.push("manifest_contract_version_not_shared");
    }
    return { decision: "incompatible", reasons };
  }

  const negotiatedWriteVersion = input.core_schema.write_versions.find((version) =>
    input.companion_schema.write_versions.includes(version),
  );
  if (negotiatedWriteVersion === undefined) {
    return { decision: "blocked", reasons: ["no_shared_write_version"] };
  }

  const missingRequired = [
    ...missingCapabilities(
      input.core_manifest.capabilities,
      input.companion_manifest.capabilities,
      "companion",
    ),
    ...missingCapabilities(
      input.companion_manifest.capabilities,
      input.core_manifest.capabilities,
      "core",
    ),
  ];
  if (missingRequired.length > 0) {
    return {
      decision: "blocked",
      negotiated_write_version: negotiatedWriteVersion,
      reasons: missingRequired,
    };
  }

  const optionalMismatches = [
    ...optionalCapabilityMismatches(
      input.core_manifest.capabilities,
      input.companion_manifest.capabilities,
      "companion",
    ),
    ...optionalCapabilityMismatches(
      input.companion_manifest.capabilities,
      input.core_manifest.capabilities,
      "core",
    ),
  ];
  return {
    decision: optionalMismatches.length > 0 ? "degraded" : "supported",
    negotiated_write_version: negotiatedWriteVersion,
    reasons: optionalMismatches,
  };
}

export function readinessGate(
  presence: PresenceSnapshotV1,
  assessment: CompatibilityAssessment,
  now: string,
): ContinuityGate {
  const expiresAt = Date.parse(presence.expires_at);
  const observedAt = Date.parse(now);
  if (!Number.isFinite(expiresAt) || !Number.isFinite(observedAt)) {
    return { allowed: false, reason: "presence_time_invalid" };
  }
  if (expiresAt <= observedAt) {
    return { allowed: false, reason: "presence_expired" };
  }
  if (assessment.decision === "blocked" || assessment.decision === "incompatible") {
    return { allowed: false, reason: "compatibility_blocked" };
  }
  if (presence.compatibility === "blocked" || presence.compatibility === "incompatible") {
    return { allowed: false, reason: "presence_compatibility_blocked" };
  }
  if (presence.service_state !== "ready" && presence.service_state !== "degraded") {
    return { allowed: false, reason: `service_${presence.service_state}` };
  }
  return { allowed: true, reason: "ready" };
}

export function newLeaseGate(
  presence: PresenceSnapshotV1,
  assessment: CompatibilityAssessment,
  expectedGeneration: number,
  expectedRouteGeneration: number,
  now: string,
): ContinuityGate {
  const readiness = readinessGate(presence, assessment, now);
  if (!readiness.allowed) {
    return readiness;
  }
  if (presence.active_generation !== expectedGeneration) {
    return { allowed: false, reason: "generation_changed" };
  }
  if (presence.route_generation !== expectedRouteGeneration) {
    return { allowed: false, reason: "route_generation_changed" };
  }
  return { allowed: true, reason: "lease_allowed" };
}

export function packetLeaseGate(
  input: PacketLeaseGateInput,
): ContinuityGate {
  const priorLease = input.prior_lease;
  const serviceGate = newLeaseGate(
    input.presence,
    input.assessment,
    input.proposed_generation,
    input.expected_route_generation,
    input.now,
  );
  const reclaimDuringRecovery =
    priorLease !== undefined &&
    input.presence.service_state === "recovering" &&
    serviceGate.reason === "service_recovering";
  if (!serviceGate.allowed && !reclaimDuringRecovery) {
    return serviceGate;
  }
  if (input.presence.active_generation !== input.proposed_generation) {
    return { allowed: false, reason: "generation_changed" };
  }
  if (input.presence.route_generation !== input.expected_route_generation) {
    return { allowed: false, reason: "route_generation_changed" };
  }
  if (!Number.isSafeInteger(input.proposed_generation) || input.proposed_generation <= 0) {
    return { allowed: false, reason: "proposed_generation_invalid" };
  }
  if (input.worker_manifest.generation !== input.proposed_generation) {
    return { allowed: false, reason: "worker_manifest_generation_changed" };
  }

  const missingRequired = missingCapabilities(
    input.packet_required_capabilities,
    input.worker_manifest.capabilities,
    "worker",
  );
  if (missingRequired.length > 0) {
    return { allowed: false, reason: missingRequired[0] ?? "worker_capability_missing" };
  }
  if (!Number.isSafeInteger(input.proposed_fencing_token) || input.proposed_fencing_token <= 0) {
    return { allowed: false, reason: "proposed_fencing_token_invalid" };
  }

  if (priorLease === undefined) {
    return { allowed: true, reason: "packet_lease_allowed" };
  }
  if (priorLease.run_id !== input.run_id) {
    return { allowed: false, reason: "prior_lease_run_changed" };
  }

  const priorExpiry = Date.parse(priorLease.lease_expires_at);
  const observedAt = Date.parse(input.now);
  if (!Number.isFinite(priorExpiry) || !Number.isFinite(observedAt)) {
    return { allowed: false, reason: "prior_lease_time_invalid" };
  }
  if (priorExpiry > observedAt) {
    return { allowed: false, reason: "prior_lease_active" };
  }
  if (input.proposed_generation <= priorLease.generation) {
    return { allowed: false, reason: "reclaim_generation_not_newer" };
  }
  if (input.proposed_fencing_token <= priorLease.fencing_token) {
    return { allowed: false, reason: "reclaim_fence_not_newer" };
  }
  return { allowed: true, reason: "packet_reclaim_allowed" };
}

function missingCapabilities(
  requirements: readonly CapabilityRequirement[],
  offered: readonly CapabilityRequirement[],
  provider: string,
): string[] {
  return requirements
    .filter((requirement) => requirement.level === "required")
    .filter((requirement) => !hasCapability(offered, requirement))
    .map(
      (requirement) =>
        `${provider}_missing_${requirement.capability_id}@${requirement.version}`,
    );
}

function optionalCapabilityMismatches(
  requirements: readonly CapabilityRequirement[],
  offered: readonly CapabilityRequirement[],
  provider: string,
): string[] {
  return requirements
    .filter((requirement) => requirement.level === "optional")
    .filter((requirement) => !hasCapability(offered, requirement))
    .map(
      (requirement) =>
        `${provider}_optional_${requirement.capability_id}@${requirement.version}`,
    );
}

function hasCapability(
  offered: readonly CapabilityRequirement[],
  requirement: CapabilityRequirement,
): boolean {
  return offered.some(
    (capability) =>
      capability.capability_id === requirement.capability_id &&
      capability.version === requirement.version,
  );
}
