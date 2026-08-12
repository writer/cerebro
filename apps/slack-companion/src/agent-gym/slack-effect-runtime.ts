import { AgentGymContractError } from "./index.js";

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
