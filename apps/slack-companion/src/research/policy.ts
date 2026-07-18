import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import type {
  CapabilityManifestV1,
  CapabilityRequirement,
} from "@writer/cerebro-sdk";

import {
  SLACK_RESEARCH_LIMITS,
  type SlackResearchCapabilityDecisionV1,
  type SlackResearchRequestV1,
  type SlackResearchResultV1,
  type SlackResearchSummaryPlanV1,
  type SlackResearchSummaryPolicyInputV1,
} from "./contracts.js";

const CAPABILITY_ID = /^[a-z][a-z0-9_.:-]{0,95}$/;
const CAPABILITY_VERSION = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;
const SHA256_DIGEST = /^sha256:[a-f0-9]{64}$/;
const UNSAFE_CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;

export class SlackResearchPolicyError extends Error {}

export function slackResearchIdentity(subjectRef: string, requestKey: string): string {
  requireRef(subjectRef, "subject_ref");
  requireRequestKey(requestKey);
  return `slack-research:${stableDigest([subjectRef, requestKey]).slice(0, 32)}`;
}

export function decideSlackResearchCapabilities(
  request: SlackResearchRequestV1,
  capabilityManifest: CapabilityManifestV1,
): SlackResearchCapabilityDecisionV1 {
  const normalizedRequest = normalizeRequest(request);
  const manifest = normalizeCapabilityManifest(capabilityManifest);
  const offered = manifest.capabilities;
  const researchId = slackResearchIdentity(
    normalizedRequest.subject_ref,
    normalizedRequest.request_key,
  );
  const requestDigest = researchRequestDigest(normalizedRequest);
  const missing = normalizedRequest.capabilities.filter(
    (requirement) => !offered.some((capability) => sameCapability(requirement, capability)),
  );
  const missingRequired = freezeCapabilities(
    missing.filter((capability) => capability.level === "required"),
  );
  const missingOptional = freezeCapabilities(
    missing.filter((capability) => capability.level === "optional"),
  );
  const status = !manifest.contract_versions.includes(normalizedRequest.contract_version)
    ? "incompatible"
    : missingRequired.length > 0
      ? "blocked"
      : missingOptional.length > 0
        ? "degraded"
        : "supported";
  return Object.freeze({
    capability_manifest_digest: manifest.digest,
    capability_manifest_generation: manifest.generation,
    capability_manifest_service_id: manifest.service_id,
    contract_version: normalizedRequest.contract_version,
    decision_id: capabilityDecisionIdentity(
      researchId,
      requestDigest,
      manifest,
      normalizedRequest.contract_version,
      status,
      missingRequired,
      missingOptional,
    ),
    missing_optional: missingOptional,
    missing_required: missingRequired,
    request_digest: requestDigest,
    research_id: researchId,
    schema_version: "slack-research-capability-decision/v1",
    status,
  });
}

/**
 * Selects bounded successful result references for a summary. It does not call
 * a provider, read results, or generate summary text.
 */
export function planSlackResearchSummary(
  input: SlackResearchSummaryPolicyInputV1,
): SlackResearchSummaryPlanV1 {
  exactKeys(input, [
    "capability_decision",
    "capability_manifest",
    "max_summary_items",
    "max_summary_utf8_bytes",
    "request",
    "results",
    "schema_version",
  ], "research summary policy input");
  if (input.schema_version !== "slack-research-summary-policy-input/v1") {
    throw new SlackResearchPolicyError("The research summary policy version is unsupported.");
  }
  const request = normalizeRequest(input.request);
  const manifest = normalizeCapabilityManifest(input.capability_manifest);
  const decision = validateCapabilityDecision(
    input.capability_decision,
    request,
    manifest,
  );
  const results = canonicalResults(input.results, decision.research_id, request.capabilities);
  const maxItems = boundedOptionalInteger(
    input.max_summary_items,
    SLACK_RESEARCH_LIMITS.summary_items,
    "max_summary_items",
  );
  const maxBytes = boundedOptionalInteger(
    input.max_summary_utf8_bytes,
    SLACK_RESEARCH_LIMITS.summary_utf8_bytes,
    "max_summary_utf8_bytes",
  );
  const summaryId = `slack-research-summary:${stableDigest([
    decision.research_id,
    decision.decision_id,
    String(maxItems),
    String(maxBytes),
    ...results.map(resultIdentity),
  ])}`;

  if (decision.status === "incompatible") {
    return Object.freeze({
      completeness: "none",
      disposition: "unavailable",
      reason_code: "incompatible_contract",
      schema_version: "slack-research-summary-plan/v1",
      summary_id: summaryId,
    });
  }
  if (decision.status === "blocked") {
    return Object.freeze({
      completeness: "none",
      disposition: "unavailable",
      reason_code: "missing_required_capability",
      schema_version: "slack-research-summary-plan/v1",
      summary_id: summaryId,
    });
  }

  const resultByCapability = new Map(
    results.map((result) => [resultCapabilityIdentity(result), result]),
  );
  const missingResult = request.capabilities.some(
    (capability) => !resultByCapability.has(capabilityVersionIdentity(capability)),
  );
  const successful = results.filter(
    (result): result is SlackResearchResultV1 & { result_ref: string } =>
      result.state === "succeeded",
  );
  const pending = results.some((result) => result.state === "pending");
  if (missingResult || pending) {
    return Object.freeze({
      completeness: "pending",
      disposition: "wait",
      reason_code: "results_pending",
      schema_version: "slack-research-summary-plan/v1",
      summary_id: summaryId,
    });
  }
  const requiredUnavailable = request.capabilities.some((capability) => {
    if (capability.level !== "required") return false;
    return resultByCapability.get(capabilityVersionIdentity(capability))?.state !== "succeeded";
  });
  if (requiredUnavailable) {
    return Object.freeze({
      completeness: "none",
      disposition: "unavailable",
      reason_code: "required_result_unavailable",
      schema_version: "slack-research-summary-plan/v1",
      summary_id: summaryId,
    });
  }

  const selected = successful.slice(0, maxItems);
  const partial =
    decision.status === "degraded"
    || pending
    || successful.length !== results.length
    || selected.length !== successful.length;
  return Object.freeze({
    completeness: partial ? "partial" : "complete",
    disposition: "summarize",
    max_summary_utf8_bytes: maxBytes,
    result_refs: Object.freeze(selected.map((result) => result.result_ref)),
    schema_version: "slack-research-summary-plan/v1",
    summary_id: summaryId,
  });
}

function normalizeRequest(request: SlackResearchRequestV1): SlackResearchRequestV1 {
  exactKeys(
    request,
    ["capabilities", "contract_version", "request_key", "schema_version", "subject_ref"],
    "research request",
  );
  if (request.schema_version !== "slack-research-request/v1") {
    throw new SlackResearchPolicyError("The research request version is unsupported.");
  }
  requireRef(request.subject_ref, "subject_ref");
  requireRequestKey(request.request_key);
  if (!CAPABILITY_VERSION.test(request.contract_version)) {
    throw new SlackResearchPolicyError("The research contract version is invalid.");
  }
  const capabilities = canonicalCapabilities(request.capabilities, "research capabilities");
  if (capabilities.length === 0) {
    throw new SlackResearchPolicyError("The research request requires a capability.");
  }
  return Object.freeze({
    capabilities,
    contract_version: request.contract_version,
    request_key: request.request_key,
    schema_version: "slack-research-request/v1",
    subject_ref: request.subject_ref,
  });
}

function validateCapabilityDecision(
  decision: SlackResearchCapabilityDecisionV1,
  request: SlackResearchRequestV1,
  manifest: CapabilityManifestV1,
): SlackResearchCapabilityDecisionV1 {
  exactKeys(decision, [
    "capability_manifest_digest",
    "capability_manifest_generation",
    "capability_manifest_service_id",
    "contract_version",
    "decision_id",
    "missing_optional",
    "missing_required",
    "request_digest",
    "research_id",
    "schema_version",
    "status",
  ], "research capability decision");
  if (decision.schema_version !== "slack-research-capability-decision/v1") {
    throw new SlackResearchPolicyError("The research capability decision version is unsupported.");
  }
  const researchId = slackResearchIdentity(request.subject_ref, request.request_key);
  if (
    decision.research_id !== researchId
    || decision.request_digest !== researchRequestDigest(request)
  ) {
    throw new SlackResearchPolicyError("The research capability decision request changed.");
  }
  requireRef(decision.decision_id, "decision_id");
  if (!SHA256_DIGEST.test(decision.request_digest)) {
    throw new SlackResearchPolicyError("The research request digest is invalid.");
  }
  const missingRequired = canonicalCapabilities(decision.missing_required, "missing required capabilities");
  const missingOptional = canonicalCapabilities(decision.missing_optional, "missing optional capabilities");
  if (
    missingRequired.some((item) => item.level !== "required")
    || missingOptional.some((item) => item.level !== "optional")
    || [...missingRequired, ...missingOptional].some(
      (item) => !request.capabilities.some((requested) => sameCapability(item, requested)),
    )
  ) {
    throw new SlackResearchPolicyError("The missing research capability set is invalid.");
  }
  const expected = decideSlackResearchCapabilities(request, manifest);
  if (
    decision.capability_manifest_digest !== expected.capability_manifest_digest
    || decision.capability_manifest_generation !== expected.capability_manifest_generation
    || decision.capability_manifest_service_id !== expected.capability_manifest_service_id
    || decision.contract_version !== expected.contract_version
    || decision.status !== expected.status
    || decision.decision_id !== expected.decision_id
    || !sameCapabilities(missingRequired, expected.missing_required)
    || !sameCapabilities(missingOptional, expected.missing_optional)
  ) {
    throw new SlackResearchPolicyError("The research capability decision is inconsistent with its manifest.");
  }
  return Object.freeze({
    ...decision,
    missing_optional: missingOptional,
    missing_required: missingRequired,
  });
}

function normalizeCapabilityManifest(
  manifest: CapabilityManifestV1,
): CapabilityManifestV1 {
  exactKeys(manifest, [
    "capabilities",
    "contract_versions",
    "digest",
    "generation",
    "produced_at",
    "schema_version",
    "service_id",
  ], "capability manifest");
  if (manifest.schema_version !== "capability-manifest/v1") {
    throw new SlackResearchPolicyError("The capability manifest version is unsupported.");
  }
  requireRef(manifest.service_id, "capability manifest service_id");
  requireRef(manifest.digest, "capability manifest digest");
  if (!Number.isSafeInteger(manifest.generation) || manifest.generation < 1) {
    throw new SlackResearchPolicyError("The capability manifest generation is invalid.");
  }
  if (
    !Array.isArray(manifest.contract_versions)
    || manifest.contract_versions.length === 0
    || manifest.contract_versions.length > SLACK_RESEARCH_LIMITS.contract_versions
  ) {
    throw new SlackResearchPolicyError("The capability manifest contract versions are out of bounds.");
  }
  const contractVersions = manifest.contract_versions.map((version) => {
    if (!CAPABILITY_VERSION.test(version)) {
      throw new SlackResearchPolicyError("A capability manifest contract version is invalid.");
    }
    return version;
  }).sort(compare);
  if (new Set(contractVersions).size !== contractVersions.length) {
    throw new SlackResearchPolicyError("The capability manifest contract versions are duplicated.");
  }
  Object.freeze(contractVersions);
  return Object.freeze({
    capabilities: canonicalCapabilities(manifest.capabilities, "manifest capabilities"),
    contract_versions: contractVersions,
    digest: manifest.digest,
    generation: manifest.generation,
    produced_at: canonicalTimestamp(manifest.produced_at, "capability manifest produced_at"),
    schema_version: "capability-manifest/v1",
    service_id: manifest.service_id,
  });
}

function canonicalCapabilities(
  values: readonly CapabilityRequirement[],
  label: string,
): CapabilityRequirement[] {
  if (!Array.isArray(values) || values.length > SLACK_RESEARCH_LIMITS.capabilities) {
    throw new SlackResearchPolicyError(`The ${label} are out of bounds.`);
  }
  const seen = new Set<string>();
  const capabilities = values.map((value) => {
    exactKeys(value, ["capability_id", "level", "version"], "research capability");
    if (!CAPABILITY_ID.test(value.capability_id)) {
      throw new SlackResearchPolicyError("The research capability id is invalid.");
    }
    if (!CAPABILITY_VERSION.test(value.version)) {
      throw new SlackResearchPolicyError("The research capability version is invalid.");
    }
    if (value.level !== "required" && value.level !== "optional") {
      throw new SlackResearchPolicyError("The research capability level is invalid.");
    }
    if (seen.has(value.capability_id)) {
      throw new SlackResearchPolicyError("The research capability id is duplicated.");
    }
    seen.add(value.capability_id);
    return Object.freeze({ ...value });
  });
  capabilities.sort((left, right) => compare(capabilityIdentity(left), capabilityIdentity(right)));
  Object.freeze(capabilities);
  return capabilities;
}

function freezeCapabilities(
  capabilities: readonly CapabilityRequirement[],
): readonly CapabilityRequirement[] {
  return Object.freeze(capabilities.map((capability) => Object.freeze({ ...capability })));
}

function canonicalResults(
  values: readonly SlackResearchResultV1[],
  researchId: string,
  capabilities: readonly CapabilityRequirement[],
): readonly SlackResearchResultV1[] {
  if (!Array.isArray(values) || values.length > SLACK_RESEARCH_LIMITS.results) {
    throw new SlackResearchPolicyError("The research result set is out of bounds.");
  }
  const seen = new Set<string>();
  const results = values.map((result) => {
    exactKeys(result, [
      "capability_id",
      "capability_version",
      "research_id",
      "result_digest",
      "result_ref",
      "schema_version",
      "state",
    ], "research result");
    if (result.schema_version !== "slack-research-result/v1") {
      throw new SlackResearchPolicyError("The research result version is unsupported.");
    }
    if (result.research_id !== researchId) {
      throw new SlackResearchPolicyError("The research result belongs to another request.");
    }
    if (!CAPABILITY_ID.test(result.capability_id) || !CAPABILITY_VERSION.test(result.capability_version)) {
      throw new SlackResearchPolicyError("The research result capability is invalid.");
    }
    const identity = `${result.capability_id}@${result.capability_version}`;
    if (seen.has(identity)) {
      throw new SlackResearchPolicyError("The research result capability is duplicated.");
    }
    seen.add(identity);
    if (!capabilities.some(
      (capability) =>
        capability.capability_id === result.capability_id
        && capability.version === result.capability_version,
    )) {
      throw new SlackResearchPolicyError("The research result capability was not requested.");
    }
    if (!["pending", "succeeded", "unavailable", "failed"].includes(result.state)) {
      throw new SlackResearchPolicyError("The research result state is unsupported.");
    }
    if (result.state === "succeeded") {
      requireRef(result.result_ref, "result_ref");
      if (typeof result.result_digest !== "string" || !SHA256_DIGEST.test(result.result_digest)) {
        throw new SlackResearchPolicyError("A successful research result requires a digest.");
      }
    } else if (result.result_ref !== undefined || result.result_digest !== undefined) {
      throw new SlackResearchPolicyError("Only successful research results may carry output references.");
    }
    return Object.freeze({ ...result });
  });
  results.sort((left, right) => compare(resultIdentity(left), resultIdentity(right)));
  return Object.freeze(results);
}

function researchRequestDigest(request: SlackResearchRequestV1): string {
  return sha256([
    request.schema_version,
    request.subject_ref,
    request.request_key,
    request.contract_version,
    ...request.capabilities.map(capabilityIdentity),
  ]);
}

function capabilityIdentity(capability: CapabilityRequirement): string {
  return `${capability.capability_id}@${capability.version}:${capability.level}`;
}

function capabilityDecisionIdentity(
  researchId: string,
  requestDigest: string,
  manifest: CapabilityManifestV1,
  contractVersion: string,
  status: SlackResearchCapabilityDecisionV1["status"],
  missingRequired: readonly CapabilityRequirement[],
  missingOptional: readonly CapabilityRequirement[],
): string {
  return `slack-research-capabilities:${stableDigest([
    researchId,
    requestDigest,
    manifest.service_id,
    String(manifest.generation),
    manifest.digest,
    contractVersion,
    status,
    ...missingRequired.map(capabilityIdentity),
    "optional",
    ...missingOptional.map(capabilityIdentity),
  ])}`;
}

function capabilityVersionIdentity(
  capability: Pick<CapabilityRequirement, "capability_id" | "version">,
): string {
  return `${capability.capability_id}@${capability.version}`;
}

function resultCapabilityIdentity(result: SlackResearchResultV1): string {
  return `${result.capability_id}@${result.capability_version}`;
}

function resultIdentity(result: SlackResearchResultV1): string {
  return [
    result.capability_id,
    result.capability_version,
    result.state,
    result.result_ref ?? "",
    result.result_digest ?? "",
  ].join(":");
}

function sameCapability(
  left: CapabilityRequirement,
  right: CapabilityRequirement,
): boolean {
  return left.capability_id === right.capability_id && left.version === right.version;
}

function sameCapabilities(
  left: readonly CapabilityRequirement[],
  right: readonly CapabilityRequirement[],
): boolean {
  return left.length === right.length && left.every(
    (capability, index) => capabilityIdentity(capability) === capabilityIdentity(right[index]!),
  );
}

function boundedOptionalInteger(
  value: number | undefined,
  maximum: number,
  label: string,
): number {
  if (value === undefined) return maximum;
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new SlackResearchPolicyError(`The ${label} is out of bounds.`);
  }
  return value;
}

function requireRef(value: unknown, label: string): asserts value is string {
  if (
    typeof value !== "string"
    || value.length === 0
    || Buffer.byteLength(value, "utf8") > SLACK_RESEARCH_LIMITS.ref_utf8_bytes
    || UNSAFE_CONTROL_CHARACTERS.test(value)
  ) {
    throw new SlackResearchPolicyError(`The ${label} is invalid.`);
  }
}

function requireRequestKey(value: unknown): asserts value is string {
  if (
    typeof value !== "string"
    || value.length === 0
    || Buffer.byteLength(value, "utf8") > SLACK_RESEARCH_LIMITS.request_key_utf8_bytes
    || UNSAFE_CONTROL_CHARACTERS.test(value)
    || /\s/.test(value)
  ) {
    throw new SlackResearchPolicyError("The research request key is invalid.");
  }
}

function canonicalTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string") {
    throw new SlackResearchPolicyError(`The ${label} is invalid.`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new SlackResearchPolicyError(`The ${label} must be a canonical timestamp.`);
  }
  return value;
}

function exactKeys(value: unknown, allowed: readonly string[], label: string): void {
  requirePlainRecord(value, label);
  const allowedKeys = new Set(allowed);
  if (Object.keys(value).some((key) => !allowedKeys.has(key))) {
    throw new SlackResearchPolicyError(`The ${label} contains unknown fields.`);
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
    throw new SlackResearchPolicyError(`The ${label} is invalid.`);
  }
}

function compare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function stableDigest(values: readonly string[]): string {
  return createHash("sha256").update(JSON.stringify(values), "utf8").digest("hex");
}

function sha256(values: readonly string[]): string {
  return `sha256:${stableDigest(values)}`;
}
