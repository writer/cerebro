import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymRolloutState,
  type AgentGymRolloutStateV1,
} from "./rollout-state.js";

export type AgentGymRolloutCompletionOutcome = "completed" | "incomplete" | "rolled_back";
export type AgentGymRolloutCompletionBlockerCode = "rollout.canary_in_progress";

export interface AgentGymRolloutCompletionV1 {
  readonly active_candidate_ref: string;
  readonly blocker_codes: readonly AgentGymRolloutCompletionBlockerCode[];
  readonly candidate_ref: string;
  readonly decided_at: string;
  readonly decision_digest: string;
  readonly decision_ref: string;
  readonly outcome: AgentGymRolloutCompletionOutcome;
  readonly schema_version: "agent-gym-rollout-completion/v1";
  readonly state_digest: string;
  readonly target_ref: string;
  readonly terminal: boolean;
}

/** Closes a rollout only after verified full traffic or verified rollback. */
export function decideAgentGymRolloutCompletion(
  stateValue: AgentGymRolloutStateV1,
  input: { readonly decided_at: string; readonly decision_ref: string },
): AgentGymRolloutCompletionV1 {
  const state = validateAgentGymRolloutState(stateValue);
  timestamp(input.decided_at);
  reference(input.decision_ref);
  if (Date.parse(input.decided_at) < Date.parse(state.effective_at)) invalid();
  const outcome: AgentGymRolloutCompletionOutcome = state.phase === "active"
    ? "completed"
    : state.phase === "rolled_back" ? "rolled_back" : "incomplete";
  const blockerCodes: AgentGymRolloutCompletionBlockerCode[] = outcome === "incomplete"
    ? ["rollout.canary_in_progress"]
    : [];
  const body = {
    active_candidate_ref: state.active_candidate_ref,
    blocker_codes: blockerCodes,
    candidate_ref: state.candidate_ref,
    decided_at: input.decided_at,
    decision_ref: input.decision_ref,
    outcome,
    schema_version: "agent-gym-rollout-completion/v1" as const,
    state_digest: state.state_digest,
    target_ref: state.target_ref,
    terminal: outcome !== "incomplete",
  };
  return Object.freeze({
    ...body,
    blocker_codes: Object.freeze(blockerCodes),
    decision_digest: digestAgentGymJson(body),
  });
}

export function validateAgentGymRolloutCompletion(
  value: AgentGymRolloutCompletionV1,
): AgentGymRolloutCompletionV1 {
  if (value.schema_version !== "agent-gym-rollout-completion/v1") invalid();
  for (const ref of [value.active_candidate_ref, value.candidate_ref, value.decision_ref,
    value.target_ref]) reference(ref);
  timestamp(value.decided_at);
  digest(value.decision_digest);
  digest(value.state_digest);
  if (!Array.isArray(value.blocker_codes) || value.blocker_codes.length > 1
    || new Set(value.blocker_codes).size !== value.blocker_codes.length
    || value.blocker_codes.some((code) => code !== "rollout.canary_in_progress")) invalid();
  if (value.outcome === "completed") {
    if (!value.terminal || value.blocker_codes.length !== 0
      || value.active_candidate_ref !== value.candidate_ref) invalid();
  } else if (value.outcome === "rolled_back") {
    if (!value.terminal || value.blocker_codes.length !== 0
      || value.active_candidate_ref === value.candidate_ref) invalid();
  } else if (value.outcome === "incomplete") {
    if (value.terminal || value.blocker_codes.length !== 1
      || value.blocker_codes[0] !== "rollout.canary_in_progress"
      || value.active_candidate_ref !== value.candidate_ref) invalid();
  } else invalid();
  const body = {
    active_candidate_ref: value.active_candidate_ref,
    blocker_codes: value.blocker_codes,
    candidate_ref: value.candidate_ref,
    decided_at: value.decided_at,
    decision_ref: value.decision_ref,
    outcome: value.outcome,
    schema_version: value.schema_version,
    state_digest: value.state_digest,
    target_ref: value.target_ref,
    terminal: value.terminal,
  };
  if (digestAgentGymJson(body) !== value.decision_digest) invalid();
  return Object.freeze({ ...value, blocker_codes: Object.freeze([...value.blocker_codes]) });
}

function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || !Number.isFinite(Date.parse(value))) invalid();
}
function invalid(): never { throw new AgentGymContractError("Agent gym rollout completion is invalid."); }
