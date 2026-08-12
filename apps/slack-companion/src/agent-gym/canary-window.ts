import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymCanaryObservation,
  type AgentGymCanaryObservationV1,
} from "./canary-observation.js";

export interface AgentGymCanaryWindowV1 {
  readonly blocker_codes: readonly string[];
  readonly candidate_ref: string;
  readonly ended_at: string;
  readonly failed_count: number;
  readonly mean_quality_score: number;
  readonly observation_count: number;
  readonly observation_digests: readonly string[];
  readonly p95_latency_ms: number;
  readonly passed_count: number;
  readonly schema_version: "agent-gym-canary-window/v1";
  readonly started_at: string;
  readonly target_ref: string;
  readonly transition_digest: string;
  readonly window_digest: string;
  readonly window_ref: string;
}

/** Seals a chronological canary sample window for deterministic gating. */
export function sealAgentGymCanaryWindow(
  observationValues: readonly AgentGymCanaryObservationV1[],
  input: { readonly ended_at: string; readonly started_at: string; readonly window_ref: string },
): AgentGymCanaryWindowV1 {
  timestamp(input.started_at);
  timestamp(input.ended_at);
  reference(input.window_ref);
  if (Date.parse(input.ended_at) < Date.parse(input.started_at)
    || !Array.isArray(observationValues) || observationValues.length === 0
    || observationValues.length > 1_000_000) invalid();
  const observations = observationValues.map(validateAgentGymCanaryObservation).sort((left, right) =>
    left.observed_at.localeCompare(right.observed_at) || left.observation_ref.localeCompare(right.observation_ref));
  const first = observations[0]!;
  const refs = new Set<string>();
  const samples = new Set<string>();
  const digests = new Set<string>();
  for (const observation of observations) {
    if (observation.transition_digest !== first.transition_digest
      || observation.candidate_ref !== first.candidate_ref || observation.target_ref !== first.target_ref
      || Date.parse(observation.observed_at) < Date.parse(input.started_at)
      || Date.parse(observation.observed_at) > Date.parse(input.ended_at)
      || refs.has(observation.observation_ref) || samples.has(observation.sample_ref)
      || digests.has(observation.observation_digest)) invalid();
    refs.add(observation.observation_ref);
    samples.add(observation.sample_ref);
    digests.add(observation.observation_digest);
  }
  const passedCount = observations.filter((entry) => entry.outcome === "passed").length;
  const failedCount = observations.length - passedCount;
  const quality = observations.reduce((sum, entry) => sum + entry.quality_score, 0) / observations.length;
  const latencies = observations.map((entry) => entry.latency_ms).sort((left, right) => left - right);
  const p95 = latencies[Math.ceil(latencies.length * 0.95) - 1]!;
  const blockers = [...new Set(observations.flatMap((entry) => entry.blocker_codes))].sort();
  const body = {
    blocker_codes: blockers,
    candidate_ref: first.candidate_ref,
    ended_at: input.ended_at,
    failed_count: failedCount,
    mean_quality_score: quality,
    observation_count: observations.length,
    observation_digests: observations.map((entry) => entry.observation_digest),
    p95_latency_ms: p95,
    passed_count: passedCount,
    schema_version: "agent-gym-canary-window/v1" as const,
    started_at: input.started_at,
    target_ref: first.target_ref,
    transition_digest: first.transition_digest,
    window_ref: input.window_ref,
  };
  return Object.freeze({
    ...body,
    blocker_codes: Object.freeze(blockers),
    observation_digests: Object.freeze(body.observation_digests),
    window_digest: digestAgentGymJson(body),
  });
}

export function validateAgentGymCanaryWindow(value: AgentGymCanaryWindowV1): AgentGymCanaryWindowV1 {
  if (value.schema_version !== "agent-gym-canary-window/v1") invalid();
  for (const ref of [value.candidate_ref, value.target_ref, value.window_ref]) reference(ref);
  timestamp(value.started_at);
  timestamp(value.ended_at);
  if (Date.parse(value.ended_at) < Date.parse(value.started_at)) invalid();
  digest(value.transition_digest);
  digest(value.window_digest);
  integer(value.observation_count, 1_000_000, false);
  integer(value.passed_count, value.observation_count);
  integer(value.failed_count, value.observation_count);
  integer(value.p95_latency_ms, 3_600_000);
  finite(value.mean_quality_score, 0, 1);
  if (value.passed_count + value.failed_count !== value.observation_count
    || !Array.isArray(value.observation_digests)
    || value.observation_digests.length !== value.observation_count
    || new Set(value.observation_digests).size !== value.observation_digests.length
    || !Array.isArray(value.blocker_codes) || value.blocker_codes.length > 64
    || new Set(value.blocker_codes).size !== value.blocker_codes.length
    || value.blocker_codes.some((code, index) => index > 0 && value.blocker_codes[index - 1]! >= code)) invalid();
  for (const valueDigest of value.observation_digests) digest(valueDigest);
  for (const code of value.blocker_codes) text(code);
  const body = {
    blocker_codes: value.blocker_codes,
    candidate_ref: value.candidate_ref,
    ended_at: value.ended_at,
    failed_count: value.failed_count,
    mean_quality_score: value.mean_quality_score,
    observation_count: value.observation_count,
    observation_digests: value.observation_digests,
    p95_latency_ms: value.p95_latency_ms,
    passed_count: value.passed_count,
    schema_version: value.schema_version,
    started_at: value.started_at,
    target_ref: value.target_ref,
    transition_digest: value.transition_digest,
    window_ref: value.window_ref,
  };
  if (digestAgentGymJson(body) !== value.window_digest) invalid();
  return Object.freeze({
    ...value,
    blocker_codes: Object.freeze([...value.blocker_codes]),
    observation_digests: Object.freeze([...value.observation_digests]),
  });
}

function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function finite(value: number, minimum: number, maximum: number): void {
  if (!Number.isFinite(value) || value < minimum || value > maximum) invalid();
}
function integer(value: number, maximum: number, allowZero = true): void {
  if (!Number.isSafeInteger(value) || value < (allowZero ? 0 : 1) || value > maximum) invalid();
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
function invalid(): never { throw new AgentGymContractError("Agent gym canary window is invalid."); }
