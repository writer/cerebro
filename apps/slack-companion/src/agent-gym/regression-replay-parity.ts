import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import { validateAgentGymRegressionReplayRequestPair, type AgentGymRegressionReplayRequestPairV1 } from "./regression-replay-request-pair.js";

export interface AgentGymRegressionReplayParityV1 {
  readonly blocker_codes: readonly string[];
  readonly checked_at: string;
  readonly max_output_tokens_equal: boolean;
  readonly messages_equal: boolean;
  readonly pair_digest: string;
  readonly passed: boolean;
  readonly report_digest: string;
  readonly report_ref: string;
  readonly schema_version: "agent-gym-regression-replay-parity/v1";
}

/** Proves both candidates receive the same case messages and output allowance. */
export function checkAgentGymRegressionReplayParity(
  pairValue: AgentGymRegressionReplayRequestPairV1,
  input: Pick<AgentGymRegressionReplayParityV1, "checked_at" | "report_ref">,
): AgentGymRegressionReplayParityV1 {
  const pair = validateAgentGymRegressionReplayRequestPair(pairValue);
  reference(input.report_ref); timestamp(input.checked_at);
  const messagesEqual = pair.baseline_messages_digest === pair.challenger_messages_digest;
  const maxOutputTokensEqual = pair.baseline_max_output_tokens === pair.challenger_max_output_tokens;
  const blockerCodes = Object.freeze([
    ...(messagesEqual ? [] : ["case_messages_differ"]),
    ...(maxOutputTokensEqual ? [] : ["max_output_tokens_differ"]),
  ]);
  const body = {
    blocker_codes: blockerCodes, checked_at: input.checked_at, max_output_tokens_equal: maxOutputTokensEqual,
    messages_equal: messagesEqual, pair_digest: pair.pair_digest, passed: blockerCodes.length === 0,
    report_ref: input.report_ref, schema_version: "agent-gym-regression-replay-parity/v1" as const,
  };
  return Object.freeze({ ...body, report_digest: digestAgentGymJson(body) });
}

export function validateAgentGymRegressionReplayParity(value: AgentGymRegressionReplayParityV1): AgentGymRegressionReplayParityV1 {
  if (value.schema_version !== "agent-gym-regression-replay-parity/v1") invalid();
  reference(value.report_ref); timestamp(value.checked_at); digest(value.pair_digest); digest(value.report_digest);
  if (!Array.isArray(value.blocker_codes) || new Set(value.blocker_codes).size !== value.blocker_codes.length
    || value.blocker_codes.some((code) => !["case_messages_differ", "max_output_tokens_differ"].includes(code))
    || value.passed !== (value.blocker_codes.length === 0)
    || value.messages_equal !== !value.blocker_codes.includes("case_messages_differ")
    || value.max_output_tokens_equal !== !value.blocker_codes.includes("max_output_tokens_differ")) invalid();
  const body = { blocker_codes: value.blocker_codes, checked_at: value.checked_at,
    max_output_tokens_equal: value.max_output_tokens_equal, messages_equal: value.messages_equal,
    pair_digest: value.pair_digest, passed: value.passed, report_ref: value.report_ref, schema_version: value.schema_version };
  if (digestAgentGymJson(body) !== value.report_digest) invalid();
  return Object.freeze({ ...value, blocker_codes: Object.freeze([...value.blocker_codes]) });
}

function reference(value: string): void { if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid(); }
function timestamp(value: string): void { if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) invalid(); }
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function invalid(): never { throw new AgentGymContractError("Agent gym regression replay parity is invalid."); }
