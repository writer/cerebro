import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymRolloutSummary,
  type AgentGymRolloutSummaryV1,
} from "./rollout-summary.js";

export type AgentGymPostRolloutOutcome = "failed" | "passed";

export interface AgentGymPostRolloutObservationV1 {
  readonly blocker_codes: readonly string[];
  readonly candidate_ref: string;
  readonly evidence_refs: readonly string[];
  readonly latency_ms: number;
  readonly observation_digest: string;
  readonly observation_ref: string;
  readonly observed_at: string;
  readonly outcome: AgentGymPostRolloutOutcome;
  readonly quality_score: number;
  readonly rollout_summary_digest: string;
  readonly sample_ref: string;
  readonly schema_version: "agent-gym-post-rollout-observation/v1";
  readonly target_ref: string;
}

/** Records one post-rollout sample without embedding provider or Slack topology. */
export function recordAgentGymPostRolloutObservation(
  summaryValue: AgentGymRolloutSummaryV1,
  input: Omit<AgentGymPostRolloutObservationV1,
    "candidate_ref" | "observation_digest" | "rollout_summary_digest" | "schema_version" | "target_ref">,
): AgentGymPostRolloutObservationV1 {
  const summary = validateAgentGymRolloutSummary(summaryValue);
  validateInput(input);
  if (!summary.terminal || summary.outcome !== "completed"
    || Date.parse(input.observed_at) < Date.parse(summary.completed_at)) invalid();
  const body = {
    blocker_codes: [...input.blocker_codes],
    candidate_ref: summary.candidate_ref,
    evidence_refs: [...input.evidence_refs],
    latency_ms: input.latency_ms,
    observation_ref: input.observation_ref,
    observed_at: input.observed_at,
    outcome: input.outcome,
    quality_score: input.quality_score,
    rollout_summary_digest: summary.summary_digest,
    sample_ref: input.sample_ref,
    schema_version: "agent-gym-post-rollout-observation/v1" as const,
    target_ref: summary.target_ref,
  };
  return Object.freeze({
    ...body,
    blocker_codes: Object.freeze(body.blocker_codes),
    evidence_refs: Object.freeze(body.evidence_refs),
    observation_digest: digestAgentGymJson(body),
  });
}

export function validateAgentGymPostRolloutObservation(
  value: AgentGymPostRolloutObservationV1,
): AgentGymPostRolloutObservationV1 {
  if (value.schema_version !== "agent-gym-post-rollout-observation/v1") invalid();
  validateInput(value);
  for (const ref of [value.candidate_ref, value.target_ref]) reference(ref);
  digest(value.observation_digest);
  digest(value.rollout_summary_digest);
  const body = {
    blocker_codes: value.blocker_codes,
    candidate_ref: value.candidate_ref,
    evidence_refs: value.evidence_refs,
    latency_ms: value.latency_ms,
    observation_ref: value.observation_ref,
    observed_at: value.observed_at,
    outcome: value.outcome,
    quality_score: value.quality_score,
    rollout_summary_digest: value.rollout_summary_digest,
    sample_ref: value.sample_ref,
    schema_version: value.schema_version,
    target_ref: value.target_ref,
  };
  if (digestAgentGymJson(body) !== value.observation_digest) invalid();
  return Object.freeze({
    ...value,
    blocker_codes: Object.freeze([...value.blocker_codes]),
    evidence_refs: Object.freeze([...value.evidence_refs]),
  });
}

function validateInput(value: {
  readonly blocker_codes: readonly string[];
  readonly evidence_refs: readonly string[];
  readonly latency_ms: number;
  readonly observation_ref: string;
  readonly observed_at: string;
  readonly outcome: AgentGymPostRolloutOutcome;
  readonly quality_score: number;
  readonly sample_ref: string;
}): void {
  reference(value.observation_ref);
  reference(value.sample_ref);
  timestamp(value.observed_at);
  finite(value.quality_score, 0, 1);
  if (!Number.isSafeInteger(value.latency_ms) || value.latency_ms < 0 || value.latency_ms > 3_600_000
    || !Array.isArray(value.blocker_codes) || value.blocker_codes.length > 64
    || new Set(value.blocker_codes).size !== value.blocker_codes.length
    || !Array.isArray(value.evidence_refs) || value.evidence_refs.length > 64
    || new Set(value.evidence_refs).size !== value.evidence_refs.length) invalid();
  for (const code of value.blocker_codes) text(code);
  for (const ref of value.evidence_refs) reference(ref);
  if (value.outcome === "passed") {
    if (value.blocker_codes.length !== 0 || value.evidence_refs.length === 0) invalid();
  } else if (value.outcome === "failed") {
    if (value.blocker_codes.length === 0) invalid();
  } else invalid();
}
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function finite(value: number, minimum: number, maximum: number): void {
  if (!Number.isFinite(value) || value < minimum || value > maximum) invalid();
}
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function text(value: string): void {
  if (typeof value !== "string" || !value.trim() || value.length > 160
    || /[\u0000-\u001f\u007f]/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || !Number.isFinite(Date.parse(value))) invalid();
}
function invalid(): never { throw new AgentGymContractError("Agent gym post-rollout observation is invalid."); }
