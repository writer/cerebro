import type { HttpStream } from "../httpClient.js";
import { parseServerSentEvents, type ServerSentEvent } from "../streaming.js";
import { transformOpenApi, type Camelize } from "../serialization.js";

interface MessageEventPayload extends Record<string, unknown> {
  message_id: string;
  role: string;
  content: string;
  metadata?: Record<string, unknown> | null;
  sequence?: number | null;
}

interface ToolEventPayload extends Record<string, unknown> {
  invocation_id: string;
  status: string;
  input_data?: Record<string, unknown> | null;
  output_data?: Record<string, unknown> | null;
  error_message?: string | null;
  error_code?: string | null;
}

interface StatusEventPayload extends Record<string, unknown> {
  status: string;
  detail?: string | null;
}

export type AgentStreamEvent =
  | { type: "message"; payload: Camelize<MessageEventPayload>; raw: ServerSentEvent }
  | { type: "tool"; payload: Camelize<ToolEventPayload>; raw: ServerSentEvent }
  | { type: "status"; payload: Camelize<StatusEventPayload>; raw: ServerSentEvent }
  | { type: "heartbeat"; raw: ServerSentEvent }
  | { type: "unknown"; raw: ServerSentEvent; data: unknown };

export async function* parseAgentEventStream(
  stream: HttpStream,
): AsyncGenerator<AgentStreamEvent, void, undefined> {
  for await (const event of parseServerSentEvents(stream)) {
    if (!event.event && (!event.data || event.data.trim() === "")) {
      yield { type: "heartbeat", raw: event };
      continue;
    }

    let payload: unknown = event.data;
    if (event.data) {
      try {
        payload = JSON.parse(event.data);
      } catch {
        payload = event.data;
      }
    }

    switch (event.event) {
      case "message":
        if (isRecord(payload)) {
          yield {
            type: "message",
            payload: transformOpenApi(payload as MessageEventPayload, (record) => record, {
              deep: true,
            }),
            raw: event,
          };
        } else {
          yield { type: "unknown", raw: event, data: payload };
        }
        break;
      case "tool":
        if (isRecord(payload)) {
          yield {
            type: "tool",
            payload: transformOpenApi(payload as ToolEventPayload, (record) => record, {
              deep: true,
            }),
            raw: event,
          };
        } else {
          yield { type: "unknown", raw: event, data: payload };
        }
        break;
      case "status":
        if (isRecord(payload)) {
          yield {
            type: "status",
            payload: transformOpenApi(payload as StatusEventPayload, (record) => record),
            raw: event,
          };
        } else {
          yield { type: "unknown", raw: event, data: payload };
        }
        break;
      default:
        yield { type: "unknown", raw: event, data: payload };
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
