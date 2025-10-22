import { apiPost } from "@/lib/api";

type ObservationPayload = {
  eventType: string;
  component?: string;
  agentSessionId?: string;
  context?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  occurredAt?: string;
};

const OBSERVATION_ENDPOINT = "/telemetry/frontend/observe";

export async function recordObservation(payload: ObservationPayload): Promise<void> {
  if (typeof window === "undefined") {
    return;
  }

  try {
    await apiPost(OBSERVATION_ENDPOINT, {
      event_type: payload.eventType,
      component: payload.component,
      agent_session_id: payload.agentSessionId,
      context: payload.context,
      metadata: payload.metadata,
      occurred_at: payload.occurredAt,
    });
  } catch (error) {
    if (process.env.NODE_ENV !== "production") {
      console.warn("Failed to record observation", error);
    }
  }
}
