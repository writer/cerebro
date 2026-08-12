import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymPromotionInput,
  type AgentGymPromotionInputReceiptV1,
} from "./promotion-input.js";

export type AgentGymPromotionVerdictDisposition = "blocked" | "promote";

export interface AgentGymPromotionVerdictV1 {
  readonly baseline_candidate_ref: string;
  readonly candidate_ref: string;
  readonly decided_at: string;
  readonly decision_ref: string;
  readonly disposition: AgentGymPromotionVerdictDisposition;
  readonly promotion_input_digest: string;
  readonly reason_codes: readonly string[];
  readonly schema_version: "agent-gym-promotion-verdict/v1";
  readonly verdict_digest: string;
}

/** Converts a policy-bound comparison receipt into a deterministic verdict. */
export function decideAgentGymPromotionVerdict(
  inputValue: AgentGymPromotionInputReceiptV1,
  decision: { readonly decided_at: string; readonly decision_ref: string },
): AgentGymPromotionVerdictV1 {
  const input = validateAgentGymPromotionInput(inputValue);
  timestamp(decision.decided_at);
  reference(decision.decision_ref);
  if (Date.parse(decision.decided_at) < Date.parse(input.evaluated_at)) invalid();
  const disposition: AgentGymPromotionVerdictDisposition = input.eligible ? "promote" : "blocked";
  const reasonCodes = input.eligible
    ? ["comparison.eligible"]
    : [...input.blocker_codes];
  const body = {
    baseline_candidate_ref: input.baseline_candidate_ref,
    candidate_ref: input.candidate_ref,
    decided_at: decision.decided_at,
    decision_ref: decision.decision_ref,
    disposition,
    promotion_input_digest: input.receipt_digest,
    reason_codes: reasonCodes,
    schema_version: "agent-gym-promotion-verdict/v1" as const,
  };
  return Object.freeze({
    ...body,
    reason_codes: Object.freeze(reasonCodes),
    verdict_digest: digestAgentGymJson(body),
  });
}

export function validateAgentGymPromotionVerdict(
  value: AgentGymPromotionVerdictV1,
): AgentGymPromotionVerdictV1 {
  if (value.schema_version !== "agent-gym-promotion-verdict/v1") invalid();
  for (const ref of [value.baseline_candidate_ref, value.candidate_ref, value.decision_ref]) reference(ref);
  if (value.baseline_candidate_ref === value.candidate_ref) invalid();
  timestamp(value.decided_at);
  digest(value.promotion_input_digest);
  digest(value.verdict_digest);
  if (!Array.isArray(value.reason_codes) || value.reason_codes.length === 0
    || value.reason_codes.length > 64 || new Set(value.reason_codes).size !== value.reason_codes.length
    || value.reason_codes.some((code) => !code || code.length > 160)) invalid();
  if (value.disposition === "promote") {
    if (value.reason_codes.length !== 1 || value.reason_codes[0] !== "comparison.eligible") invalid();
  } else if (value.disposition === "blocked") {
    if (value.reason_codes.includes("comparison.eligible")) invalid();
  } else invalid();
  const body = {
    baseline_candidate_ref: value.baseline_candidate_ref,
    candidate_ref: value.candidate_ref,
    decided_at: value.decided_at,
    decision_ref: value.decision_ref,
    disposition: value.disposition,
    promotion_input_digest: value.promotion_input_digest,
    reason_codes: value.reason_codes,
    schema_version: value.schema_version,
  };
  if (digestAgentGymJson(body) !== value.verdict_digest) invalid();
  return Object.freeze({ ...value, reason_codes: Object.freeze([...value.reason_codes]) });
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
  throw new AgentGymContractError("Agent gym promotion verdict is invalid.");
}
