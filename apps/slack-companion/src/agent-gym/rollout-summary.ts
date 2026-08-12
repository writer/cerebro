import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymRolloutCompletion,
  type AgentGymRolloutCompletionOutcome,
  type AgentGymRolloutCompletionV1,
} from "./rollout-completion.js";
import {
  validateAgentGymRolloutState,
  type AgentGymRolloutStateV1,
} from "./rollout-state.js";

export interface AgentGymRolloutSummaryV1 {
  readonly active_candidate_ref: string;
  readonly candidate_ref: string;
  readonly completed_at: string;
  readonly completion_decision_digest: string;
  readonly outcome: AgentGymRolloutCompletionOutcome;
  readonly schema_version: "agent-gym-rollout-summary/v1";
  readonly started_at: string;
  readonly state_count: number;
  readonly state_digests: readonly string[];
  readonly summary_digest: string;
  readonly summary_ref: string;
  readonly target_ref: string;
  readonly terminal: boolean;
}

/** Seals the complete verified rollout state chain and its closure decision. */
export function summarizeAgentGymRollout(
  stateValues: readonly AgentGymRolloutStateV1[],
  completionValue: AgentGymRolloutCompletionV1,
  summaryRef: string,
): AgentGymRolloutSummaryV1 {
  reference(summaryRef);
  if (!Array.isArray(stateValues) || stateValues.length === 0 || stateValues.length > 10_000) invalid();
  const states = stateValues.map(validateAgentGymRolloutState);
  const completion = validateAgentGymRolloutCompletion(completionValue);
  const first = states[0]!;
  for (let index = 0; index < states.length; index += 1) {
    const state = states[index]!;
    const previous = states[index - 1];
    if (state.sequence !== index + 1 || state.target_ref !== first.target_ref
      || state.candidate_ref !== first.candidate_ref
      || (previous === undefined ? state.previous_state_digest !== null
        : state.previous_state_digest !== previous.state_digest
          || Date.parse(state.effective_at) < Date.parse(previous.effective_at))) invalid();
  }
  const finalState = states.at(-1)!;
  if (completion.state_digest !== finalState.state_digest
    || completion.candidate_ref !== finalState.candidate_ref
    || completion.active_candidate_ref !== finalState.active_candidate_ref
    || completion.target_ref !== finalState.target_ref
    || Date.parse(completion.decided_at) < Date.parse(finalState.effective_at)) invalid();
  const body = {
    active_candidate_ref: completion.active_candidate_ref,
    candidate_ref: completion.candidate_ref,
    completed_at: completion.decided_at,
    completion_decision_digest: completion.decision_digest,
    outcome: completion.outcome,
    schema_version: "agent-gym-rollout-summary/v1" as const,
    started_at: first.effective_at,
    state_count: states.length,
    state_digests: states.map((state) => state.state_digest),
    summary_ref: summaryRef,
    target_ref: completion.target_ref,
    terminal: completion.terminal,
  };
  return Object.freeze({
    ...body,
    state_digests: Object.freeze(body.state_digests),
    summary_digest: digestAgentGymJson(body),
  });
}

export function validateAgentGymRolloutSummary(
  value: AgentGymRolloutSummaryV1,
): AgentGymRolloutSummaryV1 {
  if (value.schema_version !== "agent-gym-rollout-summary/v1") invalid();
  for (const ref of [value.active_candidate_ref, value.candidate_ref, value.summary_ref,
    value.target_ref]) reference(ref);
  timestamp(value.started_at);
  timestamp(value.completed_at);
  if (Date.parse(value.completed_at) < Date.parse(value.started_at)) invalid();
  digest(value.completion_decision_digest);
  digest(value.summary_digest);
  if (!Number.isSafeInteger(value.state_count) || value.state_count < 1 || value.state_count > 10_000
    || !Array.isArray(value.state_digests) || value.state_digests.length !== value.state_count
    || new Set(value.state_digests).size !== value.state_digests.length) invalid();
  for (const stateDigest of value.state_digests) digest(stateDigest);
  if (value.outcome === "completed") {
    if (!value.terminal || value.active_candidate_ref !== value.candidate_ref) invalid();
  } else if (value.outcome === "rolled_back") {
    if (!value.terminal || value.active_candidate_ref === value.candidate_ref) invalid();
  } else if (value.outcome === "incomplete") {
    if (value.terminal || value.active_candidate_ref !== value.candidate_ref) invalid();
  } else invalid();
  const body = {
    active_candidate_ref: value.active_candidate_ref,
    candidate_ref: value.candidate_ref,
    completed_at: value.completed_at,
    completion_decision_digest: value.completion_decision_digest,
    outcome: value.outcome,
    schema_version: value.schema_version,
    started_at: value.started_at,
    state_count: value.state_count,
    state_digests: value.state_digests,
    summary_ref: value.summary_ref,
    target_ref: value.target_ref,
    terminal: value.terminal,
  };
  if (digestAgentGymJson(body) !== value.summary_digest) invalid();
  return Object.freeze({ ...value, state_digests: Object.freeze([...value.state_digests]) });
}

function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || !Number.isFinite(Date.parse(value))) invalid();
}
function invalid(): never { throw new AgentGymContractError("Agent gym rollout summary is invalid."); }
