import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import { validateAgentGymRollbackActionReceipt, type AgentGymRollbackActionReceiptV1 } from "./rollback-action-receipt.js";
import { validateAgentGymRollbackStateObservation, type AgentGymRollbackStateObservationV1 } from "./rollback-state-observation.js";
import { validateAgentGymRollbackTrigger, type AgentGymRollbackTriggerV1 } from "./rollback-trigger.js";

export type AgentGymRollbackVerificationOutcome = "failed" | "indeterminate" | "verified";

export interface AgentGymRollbackVerificationV1 {
  readonly blocker_codes: readonly string[];
  readonly candidate_ref: string;
  readonly evidence_refs: readonly string[];
  readonly expected_candidate_ref: string;
  readonly observation_digest: string;
  readonly outcome: AgentGymRollbackVerificationOutcome;
  readonly rollback_action_receipt_digest: string;
  readonly rollback_trigger_digest: string;
  readonly schema_version: "agent-gym-rollback-verification/v1";
  readonly target_ref: string;
  readonly verification_digest: string;
  readonly verification_ref: string;
  readonly verified_at: string;
}

/** Verifies rollback from a fresh independent observation, not executor success. */
export function verifyAgentGymRollback(
  triggerValue: AgentGymRollbackTriggerV1,
  receiptValue: AgentGymRollbackActionReceiptV1,
  observationValue: AgentGymRollbackStateObservationV1,
  input: Pick<AgentGymRollbackVerificationV1, "evidence_refs" | "verification_ref" | "verified_at">,
): AgentGymRollbackVerificationV1 {
  const trigger = validateAgentGymRollbackTrigger(triggerValue);
  const receipt = validateAgentGymRollbackActionReceipt(receiptValue);
  const observation = validateAgentGymRollbackStateObservation(observationValue);
  references(input.evidence_refs); reference(input.verification_ref); timestamp(input.verified_at);
  if (receipt.rollback_trigger_digest !== trigger.trigger_digest
    || observation.rollback_action_receipt_digest !== receipt.receipt_digest
    || receipt.candidate_ref !== trigger.candidate_ref || observation.candidate_ref !== trigger.candidate_ref
    || receipt.target_ref !== trigger.target_ref || observation.target_ref !== trigger.target_ref
    || Date.parse(input.verified_at) < Date.parse(observation.observed_at)) invalid();
  let outcome: AgentGymRollbackVerificationOutcome;
  let blockerCodes: string[];
  if (observation.availability === "unavailable") {
    outcome = "indeterminate";
    blockerCodes = ["rollback_state_unavailable"];
  } else if (observation.observed_candidate_ref === trigger.fallback_candidate_ref) {
    outcome = "verified";
    blockerCodes = [];
  } else {
    outcome = "failed";
    blockerCodes = ["rollback_fallback_not_observed"];
  }
  const body = {
    blocker_codes: blockerCodes,
    candidate_ref: trigger.candidate_ref,
    evidence_refs: [...input.evidence_refs],
    expected_candidate_ref: trigger.fallback_candidate_ref,
    observation_digest: observation.observation_digest,
    outcome,
    rollback_action_receipt_digest: receipt.receipt_digest,
    rollback_trigger_digest: trigger.trigger_digest,
    schema_version: "agent-gym-rollback-verification/v1" as const,
    target_ref: trigger.target_ref,
    verification_ref: input.verification_ref,
    verified_at: input.verified_at,
  };
  return freeze({ ...body, verification_digest: digestAgentGymJson(body) });
}

export function validateAgentGymRollbackVerification(value: AgentGymRollbackVerificationV1): AgentGymRollbackVerificationV1 {
  if (value.schema_version !== "agent-gym-rollback-verification/v1") invalid();
  for (const ref of [value.candidate_ref, value.expected_candidate_ref, value.target_ref, value.verification_ref]) reference(ref);
  references(value.evidence_refs); timestamp(value.verified_at);
  if (!Array.isArray(value.blocker_codes) || value.blocker_codes.length > 128
    || new Set(value.blocker_codes).size !== value.blocker_codes.length
    || value.blocker_codes.some((code) => typeof code !== "string" || !code.trim() || code.length > 160)
    || (value.outcome === "verified" && value.blocker_codes.length !== 0)
    || (value.outcome !== "verified" && value.blocker_codes.length === 0)
    || !["failed", "indeterminate", "verified"].includes(value.outcome)) invalid();
  for (const digestValue of [value.observation_digest, value.rollback_action_receipt_digest,
    value.rollback_trigger_digest, value.verification_digest]) digest(digestValue);
  const { verification_digest: _digest, ...body } = value;
  if (digestAgentGymJson(body) !== value.verification_digest) invalid();
  return freeze(value);
}

function freeze(value: AgentGymRollbackVerificationV1): AgentGymRollbackVerificationV1 {
  return Object.freeze({ ...value, blocker_codes: Object.freeze([...value.blocker_codes]),
    evidence_refs: Object.freeze([...value.evidence_refs]) });
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
function invalid(): never { throw new AgentGymContractError("Agent gym rollback verification is invalid."); }
