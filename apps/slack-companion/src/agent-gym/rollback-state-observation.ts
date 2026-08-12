import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymRollbackActionReceipt,
  type AgentGymRollbackActionReceiptV1,
} from "./rollback-action-receipt.js";

export type AgentGymRollbackStateAvailability = "available" | "unavailable";

export interface AgentGymRollbackStateObservationV1 {
  readonly availability: AgentGymRollbackStateAvailability;
  readonly candidate_ref: string;
  readonly evidence_refs: readonly string[];
  readonly observation_digest: string;
  readonly observation_ref: string;
  readonly observed_at: string;
  readonly observed_candidate_ref: string | null;
  readonly observer_ref: string;
  readonly rollback_action_receipt_digest: string;
  readonly schema_version: "agent-gym-rollback-state-observation/v1";
  readonly target_ref: string;
}

/** Records fresh rollback state from an observer independent of the executor. */
export function observeAgentGymRollbackState(
  receiptValue: AgentGymRollbackActionReceiptV1,
  input: Omit<AgentGymRollbackStateObservationV1,
    "candidate_ref" | "observation_digest" | "rollback_action_receipt_digest" | "schema_version" | "target_ref">,
): AgentGymRollbackStateObservationV1 {
  const receipt = validateAgentGymRollbackActionReceipt(receiptValue);
  validateInput(input);
  if (input.observer_ref === receipt.executor_ref || Date.parse(input.observed_at) <= Date.parse(receipt.completed_at)) invalid();
  const body = {
    availability: input.availability,
    candidate_ref: receipt.candidate_ref,
    evidence_refs: [...input.evidence_refs],
    observation_ref: input.observation_ref,
    observed_at: input.observed_at,
    observed_candidate_ref: input.observed_candidate_ref,
    observer_ref: input.observer_ref,
    rollback_action_receipt_digest: receipt.receipt_digest,
    schema_version: "agent-gym-rollback-state-observation/v1" as const,
    target_ref: receipt.target_ref,
  };
  return freeze({ ...body, observation_digest: digestAgentGymJson(body) });
}

export function validateAgentGymRollbackStateObservation(
  value: AgentGymRollbackStateObservationV1,
): AgentGymRollbackStateObservationV1 {
  if (value.schema_version !== "agent-gym-rollback-state-observation/v1") invalid();
  validateInput(value); reference(value.candidate_ref); reference(value.target_ref);
  digest(value.rollback_action_receipt_digest); digest(value.observation_digest);
  const { observation_digest: _digest, ...body } = value;
  if (digestAgentGymJson(body) !== value.observation_digest) invalid();
  return freeze(value);
}

function validateInput(value: {
  readonly availability: AgentGymRollbackStateAvailability;
  readonly evidence_refs: readonly string[];
  readonly observation_ref: string;
  readonly observed_at: string;
  readonly observed_candidate_ref: string | null;
  readonly observer_ref: string;
}): void {
  reference(value.observation_ref); reference(value.observer_ref); timestamp(value.observed_at);
  if (!Array.isArray(value.evidence_refs) || value.evidence_refs.length === 0 || value.evidence_refs.length > 128
    || new Set(value.evidence_refs).size !== value.evidence_refs.length) invalid();
  for (const ref of value.evidence_refs) reference(ref);
  if (value.availability === "available") {
    if (value.observed_candidate_ref === null) invalid();
    reference(value.observed_candidate_ref);
  } else if (value.availability === "unavailable") {
    if (value.observed_candidate_ref !== null) invalid();
  } else invalid();
}
function freeze(value: AgentGymRollbackStateObservationV1): AgentGymRollbackStateObservationV1 {
  return Object.freeze({ ...value, evidence_refs: Object.freeze([...value.evidence_refs]) });
}
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) invalid();
}
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function invalid(): never { throw new AgentGymContractError("Agent gym rollback state observation is invalid."); }
