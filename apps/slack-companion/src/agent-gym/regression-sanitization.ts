import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymRegressionLearningCandidate,
  type AgentGymRegressionLearningCandidateV1,
} from "./regression-learning-candidate.js";

export interface AgentGymRegressionSanitizationV1 {
  readonly candidate_digest: string;
  readonly evidence_refs: readonly string[];
  readonly prohibited_value_count: 0;
  readonly redaction_count: number;
  readonly sanitized_scenario_digest: string;
  readonly sanitizer_ref: string;
  readonly schema_version: "agent-gym-regression-sanitization/v1";
  readonly source_content_digest: string;
  readonly verified_at: string;
  readonly verification_digest: string;
  readonly verification_ref: string;
}

/** Seals proof that a regression scenario crossed the public corpus boundary safely. */
export function verifyAgentGymRegressionSanitization(
  candidateValue: AgentGymRegressionLearningCandidateV1,
  input: Omit<AgentGymRegressionSanitizationV1, "candidate_digest" | "schema_version" | "verification_digest">,
): AgentGymRegressionSanitizationV1 {
  const candidate = validateAgentGymRegressionLearningCandidate(candidateValue);
  validateInput(input);
  if (Date.parse(input.verified_at) < Date.parse(candidate.proposed_at)) invalid();
  const body = {
    candidate_digest: candidate.candidate_digest,
    evidence_refs: [...input.evidence_refs],
    prohibited_value_count: input.prohibited_value_count,
    redaction_count: input.redaction_count,
    sanitized_scenario_digest: input.sanitized_scenario_digest,
    sanitizer_ref: input.sanitizer_ref,
    schema_version: "agent-gym-regression-sanitization/v1" as const,
    source_content_digest: input.source_content_digest,
    verified_at: input.verified_at,
    verification_ref: input.verification_ref,
  };
  return freeze({ ...body, verification_digest: digestAgentGymJson(body) });
}

export function validateAgentGymRegressionSanitization(value: AgentGymRegressionSanitizationV1): AgentGymRegressionSanitizationV1 {
  if (value.schema_version !== "agent-gym-regression-sanitization/v1") invalid();
  validateInput(value); digest(value.candidate_digest); digest(value.verification_digest);
  const { verification_digest: _digest, ...body } = value;
  if (digestAgentGymJson(body) !== value.verification_digest) invalid();
  return freeze(value);
}

function validateInput(value: {
  readonly evidence_refs: readonly string[];
  readonly prohibited_value_count: number;
  readonly redaction_count: number;
  readonly sanitized_scenario_digest: string;
  readonly sanitizer_ref: string;
  readonly source_content_digest: string;
  readonly verified_at: string;
  readonly verification_ref: string;
}): void {
  references(value.evidence_refs); reference(value.sanitizer_ref); reference(value.verification_ref);
  digest(value.sanitized_scenario_digest); digest(value.source_content_digest); timestamp(value.verified_at);
  if (value.prohibited_value_count !== 0 || !Number.isSafeInteger(value.redaction_count)
    || value.redaction_count < 0 || value.redaction_count > 1_000_000) invalid();
}
function freeze(value: AgentGymRegressionSanitizationV1): AgentGymRegressionSanitizationV1 {
  return Object.freeze({ ...value, evidence_refs: Object.freeze([...value.evidence_refs]) });
}
function references(values: readonly string[]): void {
  if (!Array.isArray(values) || values.length === 0 || values.length > 128 || new Set(values).size !== values.length) invalid();
  for (const value of values) reference(value);
}
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) invalid();
}
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function invalid(): never { throw new AgentGymContractError("Agent gym regression sanitization is invalid."); }
