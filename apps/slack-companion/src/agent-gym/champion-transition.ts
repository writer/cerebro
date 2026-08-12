import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymActivationReceipt,
  type AgentGymActivationReceiptV1,
} from "./activation-receipt.js";

export type AgentGymChampionTransitionMode = "promote" | "rollback";

export interface AgentGymChampionTransitionV1 {
  readonly activation_receipt_digest: string;
  readonly active_candidate_ref: string;
  readonly effective_at: string;
  readonly from_candidate_ref: string;
  readonly mode: AgentGymChampionTransitionMode;
  readonly previous_transition_digest: string | null;
  readonly rollback_of_transition_digest: string | null;
  readonly schema_version: "agent-gym-champion-transition/v1";
  readonly sequence: number;
  readonly target_ref: string;
  readonly traffic_percent: number;
  readonly transition_digest: string;
  readonly transition_ref: string;
}

/** Advances an append-only champion lineage from an observed activation receipt. */
export function recordAgentGymChampionTransition(
  receiptValue: AgentGymActivationReceiptV1,
  previousValue: AgentGymChampionTransitionV1 | undefined,
  input: {
    readonly effective_at: string;
    readonly mode: AgentGymChampionTransitionMode;
    readonly rollback_target?: AgentGymChampionTransitionV1;
    readonly transition_ref: string;
  },
): AgentGymChampionTransitionV1 {
  const receipt = validateAgentGymActivationReceipt(receiptValue);
  const previous = previousValue === undefined
    ? undefined
    : validateAgentGymChampionTransition(previousValue);
  const rollbackTarget = input.rollback_target === undefined
    ? undefined
    : validateAgentGymChampionTransition(input.rollback_target);
  timestamp(input.effective_at);
  reference(input.transition_ref);
  if (receipt.status !== "applied"
    || Date.parse(input.effective_at) < Date.parse(receipt.completed_at)) invalid();
  if (previous === undefined) {
    if (input.mode !== "promote" || rollbackTarget !== undefined) invalid();
  } else if (previous.target_ref !== receipt.target_ref
    || previous.active_candidate_ref !== receipt.previous_candidate_ref
    || Date.parse(input.effective_at) < Date.parse(previous.effective_at)) invalid();
  if (input.mode === "rollback") {
    if (previous === undefined || rollbackTarget === undefined
      || rollbackTarget.target_ref !== receipt.target_ref
      || rollbackTarget.active_candidate_ref !== receipt.candidate_ref
      || rollbackTarget.sequence >= previous.sequence) invalid();
  } else if (input.mode !== "promote" || rollbackTarget !== undefined) invalid();
  const body = {
    activation_receipt_digest: receipt.receipt_digest,
    active_candidate_ref: receipt.candidate_ref,
    effective_at: input.effective_at,
    from_candidate_ref: receipt.previous_candidate_ref,
    mode: input.mode,
    previous_transition_digest: previous?.transition_digest ?? null,
    rollback_of_transition_digest: rollbackTarget?.transition_digest ?? null,
    schema_version: "agent-gym-champion-transition/v1" as const,
    sequence: (previous?.sequence ?? 0) + 1,
    target_ref: receipt.target_ref,
    traffic_percent: receipt.observed_traffic_percent,
    transition_ref: input.transition_ref,
  };
  return Object.freeze({ ...body, transition_digest: digestAgentGymJson(body) });
}

export function validateAgentGymChampionTransition(
  value: AgentGymChampionTransitionV1,
): AgentGymChampionTransitionV1 {
  if (value.schema_version !== "agent-gym-champion-transition/v1") invalid();
  for (const ref of [value.active_candidate_ref, value.from_candidate_ref,
    value.target_ref, value.transition_ref]) reference(ref);
  if (value.active_candidate_ref === value.from_candidate_ref) invalid();
  timestamp(value.effective_at);
  digest(value.activation_receipt_digest);
  digest(value.transition_digest);
  if (value.previous_transition_digest !== null) digest(value.previous_transition_digest);
  if (value.rollback_of_transition_digest !== null) digest(value.rollback_of_transition_digest);
  if (!Number.isSafeInteger(value.sequence) || value.sequence < 1 || value.sequence > 1_000_000
    || !Number.isSafeInteger(value.traffic_percent) || value.traffic_percent < 1
    || value.traffic_percent > 100) invalid();
  if (value.sequence === 1 && value.previous_transition_digest !== null) invalid();
  if (value.sequence > 1 && value.previous_transition_digest === null) invalid();
  if (value.mode === "rollback") {
    if (value.rollback_of_transition_digest === null || value.sequence < 2) invalid();
  } else if (value.mode === "promote") {
    if (value.rollback_of_transition_digest !== null) invalid();
  } else invalid();
  const body = {
    activation_receipt_digest: value.activation_receipt_digest,
    active_candidate_ref: value.active_candidate_ref,
    effective_at: value.effective_at,
    from_candidate_ref: value.from_candidate_ref,
    mode: value.mode,
    previous_transition_digest: value.previous_transition_digest,
    rollback_of_transition_digest: value.rollback_of_transition_digest,
    schema_version: value.schema_version,
    sequence: value.sequence,
    target_ref: value.target_ref,
    traffic_percent: value.traffic_percent,
    transition_ref: value.transition_ref,
  };
  if (digestAgentGymJson(body) !== value.transition_digest) invalid();
  return Object.freeze({ ...value });
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
  throw new AgentGymContractError("Agent gym champion transition is invalid.");
}
