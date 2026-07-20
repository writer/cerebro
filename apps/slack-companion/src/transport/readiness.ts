import type { SlackIngressMode } from "./contracts.js";

export interface SlackIngressCapabilities {
  durable_presence_relay: boolean;
  public_ingress: boolean;
}

export type SlackIngressReadiness =
  | { ready: true }
  | {
      ready: false;
      reason_code:
        | "durable_presence_relay_required"
        | "public_ingress_required";
    };

export function evaluateSlackIngressReadiness(
  mode: SlackIngressMode,
  capabilities: SlackIngressCapabilities,
): SlackIngressReadiness {
  if (mode === "events_api" && !capabilities.public_ingress) {
    return { ready: false, reason_code: "public_ingress_required" };
  }
  if (mode === "socket_mode" && !capabilities.durable_presence_relay) {
    return {
      ready: false,
      reason_code: "durable_presence_relay_required",
    };
  }
  return { ready: true };
}
