import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymPostRolloutGate,
  type AgentGymPostRolloutGateV1,
} from "./post-rollout-gate.js";
import {
  validateAgentGymRollbackReserve,
  type AgentGymRollbackReserveV1,
} from "./rollback-reserve.js";

export interface AgentGymRollbackTriggerV1 {
  readonly candidate_ref: string;
  readonly evidence_refs: readonly string[];
  readonly executor_action_ref: string;
  readonly fallback_candidate_ref: string;
  readonly gate_digest: string;
  readonly reserve_digest: string;
  readonly schema_version: "agent-gym-rollback-trigger/v1";
  readonly state: "requested";
  readonly target_ref: string;
  readonly triggered_at: string;
  readonly trigger_digest: string;
  readonly trigger_ref: string;
}

/** Produces a provider-neutral rollback request from a regression gate and retained fallback. */
export function triggerAgentGymRollback(
  gateValue: AgentGymPostRolloutGateV1,
  reserveValue: AgentGymRollbackReserveV1,
  input: Pick<AgentGymRollbackTriggerV1, "evidence_refs" | "executor_action_ref" | "trigger_ref" | "triggered_at">,
): AgentGymRollbackTriggerV1 {
  const gate = validateAgentGymPostRolloutGate(gateValue);
  const reserve = validateAgentGymRollbackReserve(reserveValue);
  references(input.evidence_refs); reference(input.executor_action_ref); reference(input.trigger_ref); timestamp(input.triggered_at);
  if (gate.decision !== "rollback" || gate.candidate_ref !== reserve.candidate_ref
    || gate.target_ref !== reserve.target_ref || Date.parse(input.triggered_at) < Date.parse(gate.decided_at)
    || Date.parse(input.triggered_at) > Date.parse(reserve.expires_at)) invalid();
  const body = {
    candidate_ref: gate.candidate_ref,
    evidence_refs: [...input.evidence_refs],
    executor_action_ref: input.executor_action_ref,
    fallback_candidate_ref: reserve.fallback_candidate_ref,
    gate_digest: gate.gate_digest,
    reserve_digest: reserve.reserve_digest,
    schema_version: "agent-gym-rollback-trigger/v1" as const,
    state: "requested" as const,
    target_ref: gate.target_ref,
    triggered_at: input.triggered_at,
    trigger_ref: input.trigger_ref,
  };
  return freeze({ ...body, trigger_digest: digestAgentGymJson(body) });
}

export function validateAgentGymRollbackTrigger(value: AgentGymRollbackTriggerV1): AgentGymRollbackTriggerV1 {
  if (value.schema_version !== "agent-gym-rollback-trigger/v1" || value.state !== "requested") invalid();
  for (const ref of [value.candidate_ref, value.executor_action_ref, value.fallback_candidate_ref,
    value.target_ref, value.trigger_ref]) reference(ref);
  if (value.candidate_ref === value.fallback_candidate_ref) invalid();
  references(value.evidence_refs); timestamp(value.triggered_at);
  for (const digest of [value.gate_digest, value.reserve_digest, value.trigger_digest]) digestValue(digest);
  const { trigger_digest: _digest, ...body } = value;
  if (digestAgentGymJson(body) !== value.trigger_digest) invalid();
  return freeze(value);
}

function freeze(value: AgentGymRollbackTriggerV1): AgentGymRollbackTriggerV1 {
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
function digestValue(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function invalid(): never { throw new AgentGymContractError("Agent gym rollback trigger is invalid."); }
