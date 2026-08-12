import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import { agentGymModelRequestDigest, validateAgentGymModelRequest, type AgentGymModelInvocationRequestV1 } from "./model-runtime.js";
import { validateAgentGymRegressionReplayPlan, type AgentGymRegressionReplayPlanV1 } from "./regression-replay-plan.js";

export interface AgentGymRegressionReplayRequestPairV1 {
  readonly baseline_candidate_ref: string;
  readonly baseline_messages_digest: string;
  readonly baseline_request_digest: string;
  readonly challenger_candidate_ref: string;
  readonly challenger_messages_digest: string;
  readonly challenger_request_digest: string;
  readonly pair_digest: string;
  readonly pair_ref: string;
  readonly plan_digest: string;
  readonly schema_version: "agent-gym-regression-replay-request-pair/v1";
}

/** Binds the exact two model requests authorized by a regression replay plan. */
export function bindAgentGymRegressionReplayRequests(
  planValue: AgentGymRegressionReplayPlanV1,
  baselineValue: AgentGymModelInvocationRequestV1,
  challengerValue: AgentGymModelInvocationRequestV1,
  pairRef: string,
): AgentGymRegressionReplayRequestPairV1 {
  const plan = validateAgentGymRegressionReplayPlan(planValue);
  const baseline = validateAgentGymModelRequest(baselineValue);
  const challenger = validateAgentGymModelRequest(challengerValue);
  reference(pairRef);
  if (baseline.invocation_ref !== plan.baseline_invocation_ref
    || challenger.invocation_ref !== plan.challenger_invocation_ref
    || baseline.candidate_ref === challenger.candidate_ref) invalid();
  const body = {
    baseline_candidate_ref: baseline.candidate_ref,
    baseline_messages_digest: messagesDigest(baseline),
    baseline_request_digest: agentGymModelRequestDigest(baseline),
    challenger_candidate_ref: challenger.candidate_ref,
    challenger_messages_digest: messagesDigest(challenger),
    challenger_request_digest: agentGymModelRequestDigest(challenger),
    pair_ref: pairRef,
    plan_digest: plan.plan_digest,
    schema_version: "agent-gym-regression-replay-request-pair/v1" as const,
  };
  return Object.freeze({ ...body, pair_digest: digestAgentGymJson(body) });
}

export function validateAgentGymRegressionReplayRequestPair(
  value: AgentGymRegressionReplayRequestPairV1,
): AgentGymRegressionReplayRequestPairV1 {
  if (value.schema_version !== "agent-gym-regression-replay-request-pair/v1") invalid();
  for (const ref of [value.baseline_candidate_ref, value.challenger_candidate_ref, value.pair_ref]) reference(ref);
  for (const item of [value.baseline_messages_digest, value.baseline_request_digest,
    value.challenger_messages_digest, value.challenger_request_digest, value.pair_digest, value.plan_digest]) digest(item);
  if (value.baseline_candidate_ref === value.challenger_candidate_ref
    || value.baseline_request_digest === value.challenger_request_digest) invalid();
  const { pair_digest: _digest, ...body } = value;
  if (digestAgentGymJson(body) !== value.pair_digest) invalid();
  return Object.freeze({ ...value });
}

function messagesDigest(request: AgentGymModelInvocationRequestV1): string {
  return digestAgentGymJson(request.messages.map((message) => ({ role: message.role, text: message.text })));
}
function reference(value: string): void { if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid(); }
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function invalid(): never { throw new AgentGymContractError("Agent gym regression replay request pair is invalid."); }
