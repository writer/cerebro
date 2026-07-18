import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import type { CapabilityRequirement } from "@writer/cerebro-sdk";

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
  availableCapabilities: readonly CapabilityRequirement[],
): SlackResearchCapabilityDecisionV1 {
  const normalizedRequest = normalizeRequest(request);
  const offered = canonicalCapabilities(availableCapabilities, "available capabilities");
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
  const status = missingRequired.length > 0
    ? "blocked"
    : missingOptional.length > 0
      ? "degraded"
      : "supported";
  return Object.freeze({
    decision_id: capabilityDecisionIdentity(
      researchId,
      requestDigest,
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
  const decision = validateCapabilityDecision(input.capability_decision, request);
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

  if (decision.status === "blocked") {
    return Object.freeze({
      completeness: "none",
      disposition: "unavailable",
      reason_code: "missing_required_capability",
      schema_version: "slack-research-summary-plan/v1",
      summary_id: summaryId,
    });
  }

  const successful = results.filter(
    (result): result is SlackResearchResultV1 & { result_ref: string } =>
      result.state === "succeeded",
  );
  const pending = results.some((result) => result.state === "pending");
  if (successful.length === 0) {
    if (pending) {
      return Object.freeze({
        completeness: "pending",
        disposition: "wait",
        reason_code: "results_pending",
        schema_version: "slack-research-summary-plan/v1",
        summary_id: summaryId,
      });
    }
    return Object.freeze({
      completeness: "none",
      disposition: "unavailable",
      reason_code: "no_successful_results",
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
    ["capabilities", "request_key", "schema_version", "subject_ref"],
    "research request",
  );
  if (request.schema_version !== "slack-research-request/v1") {
    throw new SlackResearchPolicyError("The research request version is unsupported.");
  }
  requireRef(request.subject_ref, "subject_ref");
  requireRequestKey(request.request_key);
  return Object.freeze({
    capabilities: canonicalCapabilities(request.capabilities, "research capabilities"),
    request_key: request.request_key,
    schema_version: "slack-research-request/v1",
    subject_ref: request.subject_ref,
  });
}

function validateCapabilityDecision(
  decision: SlackResearchCapabilityDecisionV1,
  request: SlackResearchRequestV1,
): SlackResearchCapabilityDecisionV1 {
  exactKeys(decision, [
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
  const expectedStatus = missingRequired.length > 0
    ? "blocked"
    : missingOptional.length > 0
      ? "degraded"
      : "supported";
  if (decision.status !== expectedStatus) {
    throw new SlackResearchPolicyError("The research capability decision status is inconsistent.");
  }
  const expectedDecisionId = capabilityDecisionIdentity(
    researchId,
    decision.request_digest,
    expectedStatus,
    missingRequired,
    missingOptional,
  );
  if (decision.decision_id !== expectedDecisionId) {
    throw new SlackResearchPolicyError("The research capability decision identity is invalid.");
  }
  return Object.freeze({
    ...decision,
    missing_optional: missingOptional,
    missing_required: missingRequired,
  });
}

function canonicalCapabilities(
  values: readonly CapabilityRequirement[],
  label: string,
): readonly CapabilityRequirement[] {
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
  return Object.freeze(capabilities);
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
    ...request.capabilities.map(capabilityIdentity),
  ]);
}

function capabilityIdentity(capability: CapabilityRequirement): string {
  return `${capability.capability_id}@${capability.version}:${capability.level}`;
}

function capabilityDecisionIdentity(
  researchId: string,
  requestDigest: string,
  status: SlackResearchCapabilityDecisionV1["status"],
  missingRequired: readonly CapabilityRequirement[],
  missingOptional: readonly CapabilityRequirement[],
): string {
  return `slack-research-capabilities:${stableDigest([
    researchId,
    requestDigest,
    status,
    ...missingRequired.map(capabilityIdentity),
    "optional",
    ...missingOptional.map(capabilityIdentity),
  ])}`;
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

function exactKeys(value: object, allowed: readonly string[], label: string): void {
  const allowedKeys = new Set(allowed);
  if (Object.keys(value).some((key) => !allowedKeys.has(key))) {
    throw new SlackResearchPolicyError(`The ${label} contains unknown fields.`);
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
