import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymCandidateManifest,
  type AgentGymCandidateManifestV1,
} from "./candidate-manifest.js";
import {
  validateAgentGymPromotionAuthorization,
  type AgentGymPromotionAuthorizationV1,
} from "./promotion-authorization.js";

export type AgentGymActivationMode = "canary" | "direct";

export interface AgentGymActivationPlanV1 {
  readonly activation_ref: string;
  readonly authorization_digest: string;
  readonly baseline_candidate_ref: string;
  readonly candidate_manifest_digest: string;
  readonly candidate_ref: string;
  readonly expires_at: string;
  readonly idempotency_key: string;
  readonly initial_traffic_percent: number;
  readonly mode: AgentGymActivationMode;
  readonly plan_digest: string;
  readonly planned_at: string;
  readonly schema_version: "agent-gym-activation-plan/v1";
  readonly target_ref: string;
  readonly verdict_digest: string;
}

/** Plans an authorized candidate activation without owning environment routes. */
export function planAgentGymCandidateActivation(
  authorizationValue: AgentGymPromotionAuthorizationV1,
  candidateValue: AgentGymCandidateManifestV1,
  input: {
    readonly activation_ref: string;
    readonly baseline_candidate_ref: string;
    readonly initial_traffic_percent: number;
    readonly mode: AgentGymActivationMode;
    readonly planned_at: string;
    readonly target_ref: string;
  },
): AgentGymActivationPlanV1 {
  const authorization = validateAgentGymPromotionAuthorization(authorizationValue);
  const candidate = validateAgentGymCandidateManifest(candidateValue);
  validateInput(input);
  if (authorization.outcome !== "authorized" || authorization.candidate_ref !== candidate.candidate_ref
    || input.baseline_candidate_ref === candidate.candidate_ref
    || Date.parse(input.planned_at) < Date.parse(authorization.issued_at)
    || Date.parse(input.planned_at) >= Date.parse(authorization.expires_at)) invalid();
  const candidateBody = {
    candidate_ref: candidate.candidate_ref,
    max_output_tokens: candidate.max_output_tokens,
    model_id: candidate.model_id,
    policy_digest: candidate.policy_digest,
    prompt_digest: candidate.prompt_digest,
    provider: candidate.provider,
    ...(candidate.region === undefined ? {} : { region: candidate.region }),
    schema_version: candidate.schema_version,
    source_revision: candidate.source_revision,
    tool_catalog_digest: candidate.tool_catalog_digest,
    tool_ids: candidate.tool_ids,
  };
  const identity = {
    activation_ref: input.activation_ref,
    authorization_digest: authorization.authorization_digest,
    candidate_ref: candidate.candidate_ref,
    target_ref: input.target_ref,
  };
  const body = {
    activation_ref: input.activation_ref,
    authorization_digest: authorization.authorization_digest,
    baseline_candidate_ref: input.baseline_candidate_ref,
    candidate_manifest_digest: digestAgentGymJson(candidateBody),
    candidate_ref: candidate.candidate_ref,
    expires_at: authorization.expires_at,
    idempotency_key: digestAgentGymJson(identity),
    initial_traffic_percent: input.initial_traffic_percent,
    mode: input.mode,
    planned_at: input.planned_at,
    schema_version: "agent-gym-activation-plan/v1" as const,
    target_ref: input.target_ref,
    verdict_digest: authorization.verdict_digest,
  };
  return Object.freeze({ ...body, plan_digest: digestAgentGymJson(body) });
}

export function validateAgentGymActivationPlan(value: AgentGymActivationPlanV1): AgentGymActivationPlanV1 {
  if (value.schema_version !== "agent-gym-activation-plan/v1") invalid();
  for (const ref of [value.activation_ref, value.baseline_candidate_ref, value.candidate_ref,
    value.target_ref]) reference(ref);
  if (value.baseline_candidate_ref === value.candidate_ref) invalid();
  for (const valueDigest of [value.authorization_digest, value.candidate_manifest_digest,
    value.idempotency_key, value.plan_digest, value.verdict_digest]) digest(valueDigest);
  timestamp(value.planned_at);
  timestamp(value.expires_at);
  if (Date.parse(value.planned_at) >= Date.parse(value.expires_at)) invalid();
  modeAndTraffic(value.mode, value.initial_traffic_percent);
  const identity = {
    activation_ref: value.activation_ref,
    authorization_digest: value.authorization_digest,
    candidate_ref: value.candidate_ref,
    target_ref: value.target_ref,
  };
  if (digestAgentGymJson(identity) !== value.idempotency_key) invalid();
  const body = {
    activation_ref: value.activation_ref,
    authorization_digest: value.authorization_digest,
    baseline_candidate_ref: value.baseline_candidate_ref,
    candidate_manifest_digest: value.candidate_manifest_digest,
    candidate_ref: value.candidate_ref,
    expires_at: value.expires_at,
    idempotency_key: value.idempotency_key,
    initial_traffic_percent: value.initial_traffic_percent,
    mode: value.mode,
    planned_at: value.planned_at,
    schema_version: value.schema_version,
    target_ref: value.target_ref,
    verdict_digest: value.verdict_digest,
  };
  if (digestAgentGymJson(body) !== value.plan_digest) invalid();
  return Object.freeze({ ...value });
}

function validateInput(value: {
  readonly activation_ref: string;
  readonly baseline_candidate_ref: string;
  readonly initial_traffic_percent: number;
  readonly mode: AgentGymActivationMode;
  readonly planned_at: string;
  readonly target_ref: string;
}): void {
  for (const ref of [value.activation_ref, value.baseline_candidate_ref, value.target_ref]) reference(ref);
  timestamp(value.planned_at);
  modeAndTraffic(value.mode, value.initial_traffic_percent);
}
function modeAndTraffic(mode: AgentGymActivationMode, percent: number): void {
  if (!Number.isSafeInteger(percent) || percent < 1 || percent > 100) invalid();
  if (mode === "canary") { if (percent > 50) invalid(); }
  else if (mode === "direct") { if (percent !== 100) invalid(); }
  else invalid();
}
function digest(value: string): void {
  if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid();
}
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || !Number.isFinite(Date.parse(value))) invalid();
}
function invalid(): never {
  throw new AgentGymContractError("Agent gym activation plan is invalid.");
}
