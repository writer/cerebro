import { AgentGymContractError } from "./index.js";
import type { AgentGymSlackEffectV1 } from "./slack-effects.js";

export interface AgentGymSlackEffectAdmissionV1 {
  readonly disposition: "accepted" | "duplicate";
  readonly effect_ref: string;
  readonly idempotency_key: string;
  readonly schema_version: "agent-gym-slack-effect-admission/v1";
}

export interface AgentGymSlackEffectPlanEntryV1 {
  readonly after_effect_refs: readonly string[];
  readonly effect: AgentGymSlackEffectV1;
}

/** Returns a deterministic dependency-respecting outbound effect order. */
export function orderAgentGymSlackEffects(
  entries: readonly AgentGymSlackEffectPlanEntryV1[],
): readonly AgentGymSlackEffectV1[] {
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > 1_000) {
    invalidEffectPlan();
  }
  const entryByRef = new Map<string, AgentGymSlackEffectPlanEntryV1>();
  for (const entry of entries) {
    if (entry.effect.schema_version !== "agent-gym-slack-effect/v1"
      || entryByRef.has(entry.effect.effect_ref)
      || !Array.isArray(entry.after_effect_refs)
      || entry.after_effect_refs.length > 100
      || new Set(entry.after_effect_refs).size !== entry.after_effect_refs.length
      || entry.after_effect_refs.includes(entry.effect.effect_ref)) {
      invalidEffectPlan();
    }
    entryByRef.set(entry.effect.effect_ref, entry);
  }
  for (const entry of entries) {
    if (entry.after_effect_refs.some((reference) => !entryByRef.has(reference))) {
      invalidEffectPlan();
    }
  }
  const emitted = new Set<string>();
  const ordered: AgentGymSlackEffectV1[] = [];
  while (ordered.length < entries.length) {
    const ready = entries.filter((entry) =>
      !emitted.has(entry.effect.effect_ref)
      && entry.after_effect_refs.every((reference) => emitted.has(reference))
    ).sort((left, right) => left.effect.effect_ref.localeCompare(right.effect.effect_ref));
    if (ready.length === 0) invalidEffectPlan();
    for (const entry of ready) {
      emitted.add(entry.effect.effect_ref);
      ordered.push(entry.effect);
    }
  }
  return Object.freeze(ordered);
}

/** Enforces exact-effect reuse under one outbound idempotency key. */
export class AgentGymSlackEffectIdempotencyLedger {
  readonly #effectByKey = new Map<string, string>();

  admit(effect: AgentGymSlackEffectV1): AgentGymSlackEffectAdmissionV1 {
    if (effect.schema_version !== "agent-gym-slack-effect/v1") invalidEffect();
    const prior = this.#effectByKey.get(effect.idempotency_key);
    if (prior !== undefined && prior !== effect.effect_ref) {
      throw new AgentGymContractError(
        "Agent gym Slack idempotency key changed effect.",
      );
    }
    this.#effectByKey.set(effect.idempotency_key, effect.effect_ref);
    return Object.freeze({
      disposition: prior === undefined ? "accepted" : "duplicate",
      effect_ref: effect.effect_ref,
      idempotency_key: effect.idempotency_key,
      schema_version: "agent-gym-slack-effect-admission/v1",
    });
  }
}

export interface AgentGymSlackAcknowledgementInputV1 {
  readonly admitted_at?: string;
  readonly durable_admission: boolean;
  readonly event_received_at: string;
  readonly maximum_ack_latency_ms: number;
}

export interface AgentGymSlackAcknowledgementV1 {
  readonly ack_latency_ms?: number;
  readonly disposition: "acknowledge" | "deadline_missed" | "withhold";
  readonly planned_ack_at?: string;
  readonly schema_version: "agent-gym-slack-acknowledgement/v1";
}

/** Models Slack acknowledgement eligibility after durable event admission. */
export function planAgentGymSlackAcknowledgement(
  input: AgentGymSlackAcknowledgementInputV1,
): AgentGymSlackAcknowledgementV1 {
  timestamp(input.event_received_at);
  integer(input.maximum_ack_latency_ms, 10_000, false);
  if (!input.durable_admission) {
    if (input.admitted_at !== undefined) invalid();
    return Object.freeze({
      disposition: "withhold",
      schema_version: "agent-gym-slack-acknowledgement/v1",
    });
  }
  if (input.admitted_at === undefined) invalid();
  timestamp(input.admitted_at);
  const latency = Date.parse(input.admitted_at) - Date.parse(input.event_received_at);
  if (!Number.isSafeInteger(latency) || latency < 0 || latency > 5 * 60_000) invalid();
  return Object.freeze({
    ack_latency_ms: latency,
    disposition: latency <= input.maximum_ack_latency_ms
      ? "acknowledge"
      : "deadline_missed",
    planned_ack_at: input.admitted_at,
    schema_version: "agent-gym-slack-acknowledgement/v1",
  });
}

function integer(value: number, maximum: number, allowZero = true): void {
  if (!Number.isSafeInteger(value) || value < (allowZero ? 0 : 1) || value > maximum) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || !Number.isFinite(Date.parse(value))) invalid();
}
function invalid(): never {
  throw new AgentGymContractError("Agent gym Slack acknowledgement input is invalid.");
}
function invalidEffect(): never {
  throw new AgentGymContractError("Agent gym Slack effect is invalid.");
}
function invalidEffectPlan(): never {
  throw new AgentGymContractError("Agent gym Slack effect plan is invalid.");
}
