import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import { validateAgentGymRollbackTrigger, type AgentGymRollbackTriggerV1 } from "./rollback-trigger.js";

export type AgentGymRollbackActionOutcome = "applied" | "rejected" | "unknown";

export interface AgentGymRollbackActionReceiptV1 {
  readonly action_outcome: AgentGymRollbackActionOutcome;
  readonly candidate_ref: string;
  readonly completed_at: string;
  readonly evidence_refs: readonly string[];
  readonly executor_ref: string;
  readonly external_receipt_ref: string | null;
  readonly observed_candidate_ref: string | null;
  readonly receipt_digest: string;
  readonly receipt_ref: string;
  readonly rollback_trigger_digest: string;
  readonly schema_version: "agent-gym-rollback-action-receipt/v1";
  readonly target_ref: string;
}

/** Records the executor outcome without treating a request as proof of rollback. */
export function recordAgentGymRollbackActionReceipt(
  triggerValue: AgentGymRollbackTriggerV1,
  input: Omit<AgentGymRollbackActionReceiptV1,
    "candidate_ref" | "receipt_digest" | "rollback_trigger_digest" | "schema_version" | "target_ref">,
): AgentGymRollbackActionReceiptV1 {
  const trigger = validateAgentGymRollbackTrigger(triggerValue);
  validateInput(input);
  if (Date.parse(input.completed_at) < Date.parse(trigger.triggered_at)
    || (input.action_outcome === "applied" && input.observed_candidate_ref !== trigger.fallback_candidate_ref)
    || (input.action_outcome === "rejected" && input.observed_candidate_ref === trigger.fallback_candidate_ref)
    || (input.action_outcome === "unknown" && input.observed_candidate_ref !== null)) invalid();
  const body = {
    action_outcome: input.action_outcome,
    candidate_ref: trigger.candidate_ref,
    completed_at: input.completed_at,
    evidence_refs: [...input.evidence_refs],
    executor_ref: input.executor_ref,
    external_receipt_ref: input.external_receipt_ref,
    observed_candidate_ref: input.observed_candidate_ref,
    receipt_ref: input.receipt_ref,
    rollback_trigger_digest: trigger.trigger_digest,
    schema_version: "agent-gym-rollback-action-receipt/v1" as const,
    target_ref: trigger.target_ref,
  };
  return freeze({ ...body, receipt_digest: digestAgentGymJson(body) });
}

export function validateAgentGymRollbackActionReceipt(
  value: AgentGymRollbackActionReceiptV1,
): AgentGymRollbackActionReceiptV1 {
  if (value.schema_version !== "agent-gym-rollback-action-receipt/v1") invalid();
  validateInput(value); reference(value.candidate_ref); reference(value.target_ref);
  if (value.action_outcome === "unknown" && value.observed_candidate_ref !== null) invalid();
  digest(value.rollback_trigger_digest); digest(value.receipt_digest);
  const { receipt_digest: _digest, ...body } = value;
  if (digestAgentGymJson(body) !== value.receipt_digest) invalid();
  return freeze(value);
}

function validateInput(value: {
  readonly action_outcome: AgentGymRollbackActionOutcome;
  readonly completed_at: string;
  readonly evidence_refs: readonly string[];
  readonly executor_ref: string;
  readonly external_receipt_ref: string | null;
  readonly observed_candidate_ref: string | null;
  readonly receipt_ref: string;
}): void {
  if (!["applied", "rejected", "unknown"].includes(value.action_outcome)) invalid();
  timestamp(value.completed_at); reference(value.executor_ref); reference(value.receipt_ref);
  nullableReference(value.external_receipt_ref); nullableReference(value.observed_candidate_ref);
  if (!Array.isArray(value.evidence_refs) || value.evidence_refs.length === 0 || value.evidence_refs.length > 128
    || new Set(value.evidence_refs).size !== value.evidence_refs.length) invalid();
  for (const ref of value.evidence_refs) reference(ref);
  if (value.action_outcome === "applied" && (value.external_receipt_ref === null || value.observed_candidate_ref === null)) invalid();
}
function freeze(value: AgentGymRollbackActionReceiptV1): AgentGymRollbackActionReceiptV1 {
  return Object.freeze({ ...value, evidence_refs: Object.freeze([...value.evidence_refs]) });
}
function nullableReference(value: string | null): void { if (value !== null) reference(value); }
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) invalid();
}
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function invalid(): never { throw new AgentGymContractError("Agent gym rollback action receipt is invalid."); }
