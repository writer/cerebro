import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymPostRolloutObservation,
  type AgentGymPostRolloutObservationV1,
} from "./post-rollout-observation.js";

export interface AgentGymPostRolloutWindowV1 {
  readonly blocker_codes: readonly string[];
  readonly candidate_ref: string;
  readonly evidence_refs: readonly string[];
  readonly failed_count: number;
  readonly mean_quality_score: number;
  readonly observation_count: number;
  readonly observation_digests: readonly string[];
  readonly opened_at: string;
  readonly p95_latency_ms: number;
  readonly rollout_summary_digest: string;
  readonly schema_version: "agent-gym-post-rollout-window/v1";
  readonly sealed_at: string;
  readonly target_ref: string;
  readonly window_digest: string;
  readonly window_ref: string;
}

/** Seals a chronological set of live observations into a portable monitoring window. */
export function sealAgentGymPostRolloutWindow(
  observationsValue: readonly AgentGymPostRolloutObservationV1[],
  input: Pick<AgentGymPostRolloutWindowV1, "evidence_refs" | "sealed_at" | "window_ref">,
): AgentGymPostRolloutWindowV1 {
  if (observationsValue.length === 0 || observationsValue.length > 10_000) invalid();
  const observations = observationsValue.map(validateAgentGymPostRolloutObservation);
  reference(input.window_ref);
  timestamp(input.sealed_at);
  references(input.evidence_refs, true);
  const first = observations[0];
  if (!first) invalid();
  for (let index = 0; index < observations.length; index += 1) {
    const observation = observations[index];
    const previous = observations[index - 1];
    if (!observation || observation.candidate_ref !== first.candidate_ref
      || observation.target_ref !== first.target_ref
      || observation.rollout_summary_digest !== first.rollout_summary_digest
      || (previous && Date.parse(observation.observed_at) <= Date.parse(previous.observed_at))) invalid();
  }
  const last = observations.at(-1);
  if (!last || Date.parse(input.sealed_at) < Date.parse(last.observed_at)) invalid();
  const blockerCodes = [...new Set(observations.flatMap((item) => item.blocker_codes))].sort();
  const latencies = observations.map((item) => item.latency_ms).sort((left, right) => left - right);
  const p95 = latencies[Math.ceil(latencies.length * 0.95) - 1];
  if (p95 === undefined) invalid();
  const body = {
    blocker_codes: blockerCodes,
    candidate_ref: first.candidate_ref,
    evidence_refs: [...input.evidence_refs],
    failed_count: observations.filter((item) => item.outcome === "failed").length,
    mean_quality_score: Math.round(
      observations.reduce((sum, item) => sum + item.quality_score, 0) / observations.length * 1_000_000,
    ) / 1_000_000,
    observation_count: observations.length,
    observation_digests: observations.map((item) => item.observation_digest),
    opened_at: first.observed_at,
    p95_latency_ms: p95,
    rollout_summary_digest: first.rollout_summary_digest,
    schema_version: "agent-gym-post-rollout-window/v1" as const,
    sealed_at: input.sealed_at,
    target_ref: first.target_ref,
    window_ref: input.window_ref,
  };
  return freeze({ ...body, window_digest: digestAgentGymJson(body) });
}

export function validateAgentGymPostRolloutWindow(
  value: AgentGymPostRolloutWindowV1,
): AgentGymPostRolloutWindowV1 {
  if (value.schema_version !== "agent-gym-post-rollout-window/v1") invalid();
  reference(value.candidate_ref); reference(value.target_ref); reference(value.window_ref);
  timestamp(value.opened_at); timestamp(value.sealed_at);
  if (Date.parse(value.sealed_at) < Date.parse(value.opened_at)) invalid();
  references(value.evidence_refs, true); references(value.blocker_codes, false);
  if (!Number.isSafeInteger(value.observation_count) || value.observation_count < 1
    || !Number.isSafeInteger(value.failed_count) || value.failed_count < 0
    || value.failed_count > value.observation_count
    || !Number.isSafeInteger(value.p95_latency_ms) || value.p95_latency_ms < 0
    || !Number.isFinite(value.mean_quality_score) || value.mean_quality_score < 0
    || value.mean_quality_score > 1 || value.observation_digests.length !== value.observation_count
    || new Set(value.observation_digests).size !== value.observation_digests.length) invalid();
  for (const digest of [...value.observation_digests, value.rollout_summary_digest, value.window_digest]) digestValue(digest);
  const { window_digest: _digest, ...body } = value;
  if (digestAgentGymJson(body) !== value.window_digest) invalid();
  return freeze(value);
}

function freeze(value: AgentGymPostRolloutWindowV1): AgentGymPostRolloutWindowV1 {
  return Object.freeze({
    ...value,
    blocker_codes: Object.freeze([...value.blocker_codes]),
    evidence_refs: Object.freeze([...value.evidence_refs]),
    observation_digests: Object.freeze([...value.observation_digests]),
  });
}
function references(values: readonly string[], required: boolean): void {
  if (!Array.isArray(values) || (required && values.length === 0) || values.length > 128
    || new Set(values).size !== values.length) invalid();
  for (const value of values) required ? reference(value) : text(value);
}
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function text(value: string): void {
  if (typeof value !== "string" || !value.trim() || value.length > 160 || /[\u0000-\u001f\u007f]/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) invalid();
}
function digestValue(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function invalid(): never { throw new AgentGymContractError("Agent gym post-rollout window is invalid."); }
