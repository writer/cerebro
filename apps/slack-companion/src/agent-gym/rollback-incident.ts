import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import { validateAgentGymPostRolloutGate, type AgentGymPostRolloutGateV1 } from "./post-rollout-gate.js";
import { validateAgentGymRollbackTrigger, type AgentGymRollbackTriggerV1 } from "./rollback-trigger.js";
import { validateAgentGymRollbackVerification, type AgentGymRollbackVerificationV1 } from "./rollback-verification.js";

export type AgentGymRollbackIncidentStatus = "mitigated" | "unresolved";

export interface AgentGymRollbackIncidentV1 {
  readonly blocker_codes: readonly string[];
  readonly candidate_ref: string;
  readonly evidence_refs: readonly string[];
  readonly fallback_candidate_ref: string;
  readonly incident_digest: string;
  readonly incident_ref: string;
  readonly post_rollout_gate_digest: string;
  readonly recorded_at: string;
  readonly rollback_trigger_digest: string;
  readonly rollback_verification_digest: string;
  readonly schema_version: "agent-gym-rollback-incident/v1";
  readonly status: AgentGymRollbackIncidentStatus;
  readonly target_ref: string;
}

/** Records the regression and independently observed mitigation as one portable incident. */
export function recordAgentGymRollbackIncident(
  gateValue: AgentGymPostRolloutGateV1,
  triggerValue: AgentGymRollbackTriggerV1,
  verificationValue: AgentGymRollbackVerificationV1,
  input: Pick<AgentGymRollbackIncidentV1, "evidence_refs" | "incident_ref" | "recorded_at">,
): AgentGymRollbackIncidentV1 {
  const gate = validateAgentGymPostRolloutGate(gateValue);
  const trigger = validateAgentGymRollbackTrigger(triggerValue);
  const verification = validateAgentGymRollbackVerification(verificationValue);
  references(input.evidence_refs); reference(input.incident_ref); timestamp(input.recorded_at);
  if (gate.decision !== "rollback" || trigger.gate_digest !== gate.gate_digest
    || verification.rollback_trigger_digest !== trigger.trigger_digest
    || gate.candidate_ref !== trigger.candidate_ref || verification.candidate_ref !== trigger.candidate_ref
    || gate.target_ref !== trigger.target_ref || verification.target_ref !== trigger.target_ref
    || Date.parse(input.recorded_at) < Date.parse(verification.verified_at)) invalid();
  const status = verification.outcome === "verified" ? "mitigated" as const : "unresolved" as const;
  const blockerCodes = [...new Set([...gate.blocker_codes, ...verification.blocker_codes])].sort();
  if (blockerCodes.length === 0) invalid();
  const body = {
    blocker_codes: blockerCodes,
    candidate_ref: trigger.candidate_ref,
    evidence_refs: [...input.evidence_refs],
    fallback_candidate_ref: trigger.fallback_candidate_ref,
    incident_ref: input.incident_ref,
    post_rollout_gate_digest: gate.gate_digest,
    recorded_at: input.recorded_at,
    rollback_trigger_digest: trigger.trigger_digest,
    rollback_verification_digest: verification.verification_digest,
    schema_version: "agent-gym-rollback-incident/v1" as const,
    status,
    target_ref: trigger.target_ref,
  };
  return freeze({ ...body, incident_digest: digestAgentGymJson(body) });
}

export function validateAgentGymRollbackIncident(value: AgentGymRollbackIncidentV1): AgentGymRollbackIncidentV1 {
  if (value.schema_version !== "agent-gym-rollback-incident/v1" || !["mitigated", "unresolved"].includes(value.status)) invalid();
  for (const ref of [value.candidate_ref, value.fallback_candidate_ref, value.incident_ref, value.target_ref]) reference(ref);
  if (value.candidate_ref === value.fallback_candidate_ref) invalid();
  references(value.evidence_refs); timestamp(value.recorded_at);
  if (!Array.isArray(value.blocker_codes) || value.blocker_codes.length === 0 || value.blocker_codes.length > 256
    || new Set(value.blocker_codes).size !== value.blocker_codes.length
    || value.blocker_codes.some((code) => typeof code !== "string" || !code.trim() || code.length > 160)) invalid();
  for (const digestValue of [value.post_rollout_gate_digest, value.rollback_trigger_digest,
    value.rollback_verification_digest, value.incident_digest]) digest(digestValue);
  const { incident_digest: _digest, ...body } = value;
  if (digestAgentGymJson(body) !== value.incident_digest) invalid();
  return freeze(value);
}

function freeze(value: AgentGymRollbackIncidentV1): AgentGymRollbackIncidentV1 {
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
function invalid(): never { throw new AgentGymContractError("Agent gym rollback incident is invalid."); }
