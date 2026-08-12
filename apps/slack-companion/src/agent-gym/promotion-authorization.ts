import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymPromotionVerdict,
  type AgentGymPromotionVerdictDisposition,
  type AgentGymPromotionVerdictV1,
} from "./promotion-verdict.js";

export type AgentGymPromotionAuthorizationOutcome = "authorized" | "denied";

export interface AgentGymPromotionAuthorizationV1 {
  readonly authorization_digest: string;
  readonly authorization_ref: string;
  readonly authority_ref: string;
  readonly candidate_ref: string;
  readonly expires_at: string;
  readonly issued_at: string;
  readonly issued_by_ref: string;
  readonly outcome: AgentGymPromotionAuthorizationOutcome;
  readonly permission: "activate_candidate";
  readonly reason_codes: readonly string[];
  readonly schema_version: "agent-gym-promotion-authorization/v1";
  readonly verdict_digest: string;
  readonly verdict_disposition: AgentGymPromotionVerdictDisposition;
}

/** Records activation authority separately from the evaluation verdict. */
export function issueAgentGymPromotionAuthorization(
  verdictValue: AgentGymPromotionVerdictV1,
  input: Omit<AgentGymPromotionAuthorizationV1,
    "authorization_digest" | "candidate_ref" | "permission" | "schema_version"
    | "verdict_digest" | "verdict_disposition">,
): AgentGymPromotionAuthorizationV1 {
  const verdict = validateAgentGymPromotionVerdict(verdictValue);
  validateInput(input);
  if (Date.parse(input.issued_at) < Date.parse(verdict.decided_at)
    || Date.parse(input.expires_at) <= Date.parse(input.issued_at)
    || (input.outcome === "authorized" && verdict.disposition !== "promote")) invalid();
  const body = {
    authorization_ref: input.authorization_ref,
    authority_ref: input.authority_ref,
    candidate_ref: verdict.candidate_ref,
    expires_at: input.expires_at,
    issued_at: input.issued_at,
    issued_by_ref: input.issued_by_ref,
    outcome: input.outcome,
    permission: "activate_candidate" as const,
    reason_codes: [...input.reason_codes],
    schema_version: "agent-gym-promotion-authorization/v1" as const,
    verdict_digest: verdict.verdict_digest,
    verdict_disposition: verdict.disposition,
  };
  return Object.freeze({
    ...body,
    authorization_digest: digestAgentGymJson(body),
    reason_codes: Object.freeze(body.reason_codes),
  });
}

export function validateAgentGymPromotionAuthorization(
  value: AgentGymPromotionAuthorizationV1,
): AgentGymPromotionAuthorizationV1 {
  if (value.schema_version !== "agent-gym-promotion-authorization/v1"
    || value.permission !== "activate_candidate") invalid();
  validateInput(value);
  digest(value.authorization_digest);
  digest(value.verdict_digest);
  if (!(["blocked", "promote"] as const).includes(value.verdict_disposition)) invalid();
  if (Date.parse(value.expires_at) <= Date.parse(value.issued_at)
    || (value.outcome === "authorized" && value.verdict_disposition !== "promote")) invalid();
  const body = {
    authorization_ref: value.authorization_ref,
    authority_ref: value.authority_ref,
    candidate_ref: value.candidate_ref,
    expires_at: value.expires_at,
    issued_at: value.issued_at,
    issued_by_ref: value.issued_by_ref,
    outcome: value.outcome,
    permission: value.permission,
    reason_codes: value.reason_codes,
    schema_version: value.schema_version,
    verdict_digest: value.verdict_digest,
    verdict_disposition: value.verdict_disposition,
  };
  if (digestAgentGymJson(body) !== value.authorization_digest) invalid();
  return Object.freeze({ ...value, reason_codes: Object.freeze([...value.reason_codes]) });
}

function validateInput(value: {
  readonly authorization_ref: string;
  readonly authority_ref: string;
  readonly candidate_ref?: string;
  readonly expires_at: string;
  readonly issued_at: string;
  readonly issued_by_ref: string;
  readonly outcome: AgentGymPromotionAuthorizationOutcome;
  readonly reason_codes: readonly string[];
}): void {
  for (const ref of [value.authorization_ref, value.authority_ref, value.issued_by_ref]) reference(ref);
  if (value.candidate_ref !== undefined) reference(value.candidate_ref);
  timestamp(value.issued_at);
  timestamp(value.expires_at);
  if (!(["authorized", "denied"] as const).includes(value.outcome)
    || !Array.isArray(value.reason_codes) || value.reason_codes.length === 0
    || value.reason_codes.length > 64 || new Set(value.reason_codes).size !== value.reason_codes.length) invalid();
  for (const code of value.reason_codes) text(code);
}
function digest(value: string): void {
  if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid();
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
function invalid(): never {
  throw new AgentGymContractError("Agent gym promotion authorization is invalid.");
}
