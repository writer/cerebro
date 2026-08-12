import { AgentGymContractError } from "./contract-error.js";
import type { AgentGymSlackInvocationV1 } from "./slack-simulator.js";

export interface AgentGymSlackDeliveryResultV1 {
  readonly disposition: "admitted" | "duplicate";
  readonly event_ref: string;
  readonly invocation_ref: string;
  readonly schema_version: "agent-gym-slack-delivery-result/v1";
}

/** Models Slack at-least-once delivery while rejecting changed retries. */
export class AgentGymSlackDeliveryLedger {
  readonly #invocationByEvent = new Map<string, string>();

  admit(invocation: AgentGymSlackInvocationV1): AgentGymSlackDeliveryResultV1 {
    if (invocation.schema_version !== "agent-gym-slack-invocation/v1") {
      throw new AgentGymContractError("Agent gym Slack invocation is invalid.");
    }
    const prior = this.#invocationByEvent.get(invocation.event_ref);
    if (prior !== undefined && prior !== invocation.invocation_ref) {
      throw new AgentGymContractError("Agent gym Slack event retry changed payload.");
    }
    this.#invocationByEvent.set(invocation.event_ref, invocation.invocation_ref);
    return Object.freeze({
      disposition: prior === undefined ? "admitted" : "duplicate",
      event_ref: invocation.event_ref,
      invocation_ref: invocation.invocation_ref,
      schema_version: "agent-gym-slack-delivery-result/v1",
    });
  }
}
