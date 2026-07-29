import sourceLock from "../public-source-lock.json" with { type: "json" };
import { REQUIRED_CANONICAL_WORK_TOOL_IDS } from "./policy.js";
import { createCanonicalWorkHostTools, type CanonicalWorkToolDependencies } from "./tools.js";
import type { CanonicalWorkEvidencePort, SlackToolPackRegistry } from "./types.js";

const REQUIRED_CANONICAL_WORK_RECEIPT_KEYS = Object.freeze([
  "approval_digest_binding",
  "credential_binding",
  "durable_store",
  "goal_runner",
  "idempotent_command",
  "route_probe",
  "unknown_result_recovery",
]);

export interface CanonicalWorkHostRuntimeEvidenceV1 {
  generation: number;
  observed_at: string;
  package_tree_sha: string;
  public_commit_sha: string;
  receipt_refs: {
    approval_digest_binding: string;
    credential_binding: string;
    durable_store: string;
    goal_runner: string;
    idempotent_command: string;
    route_probe: string;
    unknown_result_recovery: string;
  };
  schema_version: "canonical-work-host-runtime-evidence/v1";
  tool_ids: string[];
}

export interface CanonicalWorkHostActivationGate {
  eligible: boolean;
  reason_code: string;
}

export function verifyCanonicalWorkHostEvidence(
  evidence: CanonicalWorkHostRuntimeEvidenceV1,
): CanonicalWorkHostActivationGate {
  if (evidence.schema_version !== "canonical-work-host-runtime-evidence/v1") {
    return blocked("unsupported_evidence_version");
  }
  if (!Number.isSafeInteger(evidence.generation) || evidence.generation < 1) {
    return blocked("invalid_generation");
  }
  if (
    evidence.public_commit_sha !== sourceLock.commit_sha ||
    evidence.package_tree_sha !== sourceLock.package_tree_sha
  ) {
    return blocked("public_source_mismatch");
  }
  const observed = Date.parse(evidence.observed_at);
  if (!Number.isFinite(observed)) return blocked("invalid_observed_at");
  if (
    !Array.isArray(evidence.tool_ids) ||
    evidence.tool_ids.some((toolId) => typeof toolId !== "string")
  ) {
    return blocked("tool_pack_incomplete");
  }
  const toolIds = [...new Set(evidence.tool_ids)].sort();
  if (
    toolIds.length !== evidence.tool_ids.length ||
    JSON.stringify(toolIds) !== JSON.stringify(REQUIRED_CANONICAL_WORK_TOOL_IDS)
  ) {
    return blocked("tool_pack_incomplete");
  }
  if (
    evidence.receipt_refs === null ||
    typeof evidence.receipt_refs !== "object" ||
    JSON.stringify(Object.keys(evidence.receipt_refs).sort()) !==
      JSON.stringify(REQUIRED_CANONICAL_WORK_RECEIPT_KEYS)
  ) {
    return blocked("runtime_receipt_missing");
  }
  if (Object.values(evidence.receipt_refs).some((value) => !isReceiptRef(value))) {
    return blocked("runtime_receipt_missing");
  }
  return { eligible: true, reason_code: "verified" };
}

export async function installCanonicalWorkHost(input: {
  deps: CanonicalWorkToolDependencies;
  evidence: CanonicalWorkHostRuntimeEvidenceV1;
  evidence_port: CanonicalWorkEvidencePort;
  registry: SlackToolPackRegistry;
}): Promise<CanonicalWorkHostActivationGate & { registration_receipt_ref?: string }> {
  const gate = verifyCanonicalWorkHostEvidence(input.evidence);
  if (!gate.eligible) return gate;
  const tools = createCanonicalWorkHostTools(input.deps);
  const registered = await input.registry.register({
    generation: input.evidence.generation,
    route_id: "slack.canonical-work",
    tool_pack_id: "operator.canonical-work/v1",
    tools,
  });
  await input.evidence_port.record({
    kind: "route_registered",
    occurred_at: input.deps.clock.now().toISOString(),
    receipt_ref: registered.registration_receipt_ref,
  });
  return {
    eligible: true,
    reason_code: "registered",
    registration_receipt_ref: registered.registration_receipt_ref,
  };
}

export const PINNED_PUBLIC_CANONICAL_WORK_SOURCE = Object.freeze({ ...sourceLock });

function blocked(reasonCode: string): CanonicalWorkHostActivationGate {
  return { eligible: false, reason_code: reasonCode };
}

function isReceiptRef(value: string): boolean {
  return typeof value === "string" && /^receipt:\/\/[A-Za-z0-9._~:/-]+$/.test(value);
}
