import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymPairedCaseDeltaReport,
  type AgentGymPairedCaseDeltaReportV1,
} from "./paired-case-deltas.js";

export interface AgentGymPairedBootstrapPolicyV1 {
  readonly confidence_level: number;
  readonly policy_ref: string;
  readonly resample_count: number;
  readonly schema_version: "agent-gym-paired-bootstrap-policy/v1";
  readonly seed_digest: string;
}

export interface AgentGymPairedUncertaintyV1 {
  readonly confidence_level: number;
  readonly delta_report_digest: string;
  readonly lower_bound: number;
  readonly method: "paired_bootstrap";
  readonly observed_mean_delta: number;
  readonly policy_ref: string;
  readonly probability_positive: number;
  readonly resample_count: number;
  readonly schema_version: "agent-gym-paired-uncertainty/v1";
  readonly seed_digest: string;
  readonly uncertainty_digest: string;
  readonly upper_bound: number;
}

/** Computes a reproducible paired bootstrap without model or wall-clock variance. */
export function estimateAgentGymPairedUncertainty(
  deltaInput: AgentGymPairedCaseDeltaReportV1,
  policy: AgentGymPairedBootstrapPolicyV1,
): AgentGymPairedUncertaintyV1 {
  const deltaReport = validateAgentGymPairedCaseDeltaReport(deltaInput);
  validatePolicy(policy);
  const random = xorshift32(Number.parseInt(policy.seed_digest.slice(7, 15), 16));
  const means: number[] = [];
  for (let sample = 0; sample < policy.resample_count; sample += 1) {
    let total = 0;
    for (let index = 0; index < deltaReport.case_count; index += 1) {
      total += deltaReport.cases[Math.floor(random() * deltaReport.case_count)]!.delta;
    }
    means.push(total / deltaReport.case_count);
  }
  means.sort((left, right) => left - right);
  const alpha = (1 - policy.confidence_level) / 2;
  const lowerIndex = Math.floor(alpha * (means.length - 1));
  const upperIndex = Math.ceil((1 - alpha) * (means.length - 1));
  const body = {
    confidence_level: policy.confidence_level,
    delta_report_digest: deltaReport.report_digest,
    lower_bound: means[lowerIndex]!,
    method: "paired_bootstrap" as const,
    observed_mean_delta: deltaReport.mean_delta,
    policy_ref: policy.policy_ref,
    probability_positive: means.filter((value) => value > 0).length / means.length,
    resample_count: policy.resample_count,
    schema_version: "agent-gym-paired-uncertainty/v1" as const,
    seed_digest: policy.seed_digest,
    upper_bound: means[upperIndex]!,
  };
  return Object.freeze({ ...body, uncertainty_digest: digestAgentGymJson(body) });
}

export function validateAgentGymPairedUncertainty(
  value: AgentGymPairedUncertaintyV1,
): AgentGymPairedUncertaintyV1 {
  if (value.schema_version !== "agent-gym-paired-uncertainty/v1"
    || value.method !== "paired_bootstrap") invalid();
  reference(value.policy_ref);
  for (const digest of [value.delta_report_digest, value.seed_digest, value.uncertainty_digest]) digestValue(digest);
  confidence(value.confidence_level);
  unit(value.probability_positive);
  finite(value.lower_bound, -1, 1);
  finite(value.upper_bound, -1, 1);
  finite(value.observed_mean_delta, -1, 1);
  if (value.lower_bound > value.upper_bound
    || !Number.isSafeInteger(value.resample_count)
    || value.resample_count < 100 || value.resample_count > 100_000) invalid();
  const body = {
    confidence_level: value.confidence_level,
    delta_report_digest: value.delta_report_digest,
    lower_bound: value.lower_bound,
    method: value.method,
    observed_mean_delta: value.observed_mean_delta,
    policy_ref: value.policy_ref,
    probability_positive: value.probability_positive,
    resample_count: value.resample_count,
    schema_version: value.schema_version,
    seed_digest: value.seed_digest,
    upper_bound: value.upper_bound,
  };
  if (digestAgentGymJson(body) !== value.uncertainty_digest) invalid();
  return Object.freeze({ ...value });
}

function validatePolicy(value: AgentGymPairedBootstrapPolicyV1): void {
  if (value.schema_version !== "agent-gym-paired-bootstrap-policy/v1") invalid();
  reference(value.policy_ref);
  digestValue(value.seed_digest);
  confidence(value.confidence_level);
  if (!Number.isSafeInteger(value.resample_count)
    || value.resample_count < 100 || value.resample_count > 100_000) invalid();
}

function xorshift32(seed: number): () => number {
  let state = seed === 0 ? 0x9e3779b9 : seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 0x1_0000_0000;
  };
}
function digestValue(value: string): void {
  if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid();
}
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function confidence(value: number): void {
  if (!Number.isFinite(value) || value < 0.8 || value >= 1) invalid();
}
function finite(value: number, minimum: number, maximum: number): void {
  if (!Number.isFinite(value) || value < minimum || value > maximum) invalid();
}
function unit(value: number): void { finite(value, 0, 1); }
function invalid(): never {
  throw new AgentGymContractError("Agent gym paired uncertainty is invalid.");
}
