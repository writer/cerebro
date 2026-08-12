import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymRolloutSummary,
  type AgentGymRolloutSummaryV1,
} from "./rollout-summary.js";

export interface AgentGymRollbackReserveV1 {
  readonly candidate_ref: string;
  readonly evidence_refs: readonly string[];
  readonly expires_at: string;
  readonly fallback_candidate_ref: string;
  readonly opened_at: string;
  readonly reserve_digest: string;
  readonly reserve_ref: string;
  readonly rollout_summary_digest: string;
  readonly schema_version: "agent-gym-rollback-reserve/v1";
  readonly target_ref: string;
}

/** Retains one evidenced fallback while a completed candidate is monitored. */
export function openAgentGymRollbackReserve(
  summaryValue: AgentGymRolloutSummaryV1,
  input: Omit<AgentGymRollbackReserveV1,
    "candidate_ref" | "reserve_digest" | "rollout_summary_digest" | "schema_version" | "target_ref">,
): AgentGymRollbackReserveV1 {
  const summary = validateAgentGymRolloutSummary(summaryValue);
  validateInput(input);
  if (!summary.terminal || summary.outcome !== "completed"
    || summary.active_candidate_ref !== summary.candidate_ref
    || input.fallback_candidate_ref === summary.candidate_ref
    || Date.parse(input.opened_at) < Date.parse(summary.completed_at)
    || Date.parse(input.expires_at) <= Date.parse(input.opened_at)) invalid();
  const body = {
    candidate_ref: summary.candidate_ref,
    evidence_refs: [...input.evidence_refs],
    expires_at: input.expires_at,
    fallback_candidate_ref: input.fallback_candidate_ref,
    opened_at: input.opened_at,
    reserve_ref: input.reserve_ref,
    rollout_summary_digest: summary.summary_digest,
    schema_version: "agent-gym-rollback-reserve/v1" as const,
    target_ref: summary.target_ref,
  };
  return Object.freeze({
    ...body,
    evidence_refs: Object.freeze(body.evidence_refs),
    reserve_digest: digestAgentGymJson(body),
  });
}

export function validateAgentGymRollbackReserve(
  value: AgentGymRollbackReserveV1,
): AgentGymRollbackReserveV1 {
  if (value.schema_version !== "agent-gym-rollback-reserve/v1") invalid();
  validateInput(value);
  for (const ref of [value.candidate_ref, value.target_ref]) reference(ref);
  if (value.fallback_candidate_ref === value.candidate_ref
    || Date.parse(value.expires_at) <= Date.parse(value.opened_at)) invalid();
  digest(value.reserve_digest);
  digest(value.rollout_summary_digest);
  const body = {
    candidate_ref: value.candidate_ref,
    evidence_refs: value.evidence_refs,
    expires_at: value.expires_at,
    fallback_candidate_ref: value.fallback_candidate_ref,
    opened_at: value.opened_at,
    reserve_ref: value.reserve_ref,
    rollout_summary_digest: value.rollout_summary_digest,
    schema_version: value.schema_version,
    target_ref: value.target_ref,
  };
  if (digestAgentGymJson(body) !== value.reserve_digest) invalid();
  return Object.freeze({ ...value, evidence_refs: Object.freeze([...value.evidence_refs]) });
}

function validateInput(value: {
  readonly evidence_refs: readonly string[];
  readonly expires_at: string;
  readonly fallback_candidate_ref: string;
  readonly opened_at: string;
  readonly reserve_ref: string;
}): void {
  reference(value.fallback_candidate_ref);
  reference(value.reserve_ref);
  timestamp(value.opened_at);
  timestamp(value.expires_at);
  if (!Array.isArray(value.evidence_refs) || value.evidence_refs.length === 0
    || value.evidence_refs.length > 64 || new Set(value.evidence_refs).size !== value.evidence_refs.length) invalid();
  for (const ref of value.evidence_refs) reference(ref);
}
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || !Number.isFinite(Date.parse(value))) invalid();
}
function invalid(): never { throw new AgentGymContractError("Agent gym rollback reserve is invalid."); }
