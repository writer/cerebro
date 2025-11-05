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

export type AgentMessage = Camelize<MessageEventPayload>;
export type ToolCallDelta = Camelize<ToolEventPayload>;

export interface CompletionUpdate {
  status: string;
  detail?: string | null;
  done: boolean;
  raw: Camelize<StatusEventPayload>;
}

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

const TERMINAL_STATUSES = new Set([
  "completed",
  "complete",
  "done",
  "failed",
  "error",
  "errored",
  "canceled",
  "cancelled",
]);

function toCompletionUpdate(payload: Camelize<StatusEventPayload>): CompletionUpdate {
  const status = `${payload.status ?? ""}`;
  const normalized = status.toLowerCase();
  return {
    status,
    detail: payload.detail ?? null,
    done: TERMINAL_STATUSES.has(normalized),
    raw: payload,
  };
}

export function isMessageEvent(event: AgentStreamEvent): event is Extract<AgentStreamEvent, { type: "message" }> {
  return event.type === "message";
}

export function isToolEvent(event: AgentStreamEvent): event is Extract<AgentStreamEvent, { type: "tool" }> {
  return event.type === "tool";
}

export function isStatusEvent(event: AgentStreamEvent): event is Extract<AgentStreamEvent, { type: "status" }> {
  return event.type === "status";
}

export interface AgentStreamConsumers {
  onMessage?(message: AgentMessage, event: Extract<AgentStreamEvent, { type: "message" }>): Promise<void> | void;
  onTool?(delta: ToolCallDelta, event: Extract<AgentStreamEvent, { type: "tool" }>): Promise<void> | void;
  onStatus?(update: CompletionUpdate, event: Extract<AgentStreamEvent, { type: "status" }>): Promise<void> | void;
  onHeartbeat?(event: Extract<AgentStreamEvent, { type: "heartbeat" }>): Promise<void> | void;
  onUnknown?(event: Extract<AgentStreamEvent, { type: "unknown" }>): Promise<void> | void;
}

export async function consumeAgentStream(stream: HttpStream, consumers: AgentStreamConsumers = {}): Promise<void> {
  for await (const event of parseAgentEventStream(stream)) {
    switch (event.type) {
      case "message":
        await consumers.onMessage?.(event.payload, event);
        break;
      case "tool":
        await consumers.onTool?.(event.payload, event);
        break;
      case "status":
        await consumers.onStatus?.(toCompletionUpdate(event.payload), event);
        break;
      case "heartbeat":
        await consumers.onHeartbeat?.(event);
        break;
      default:
        await consumers.onUnknown?.(event);
    }
  }
}

export interface AgentStreamConsumption {
  messages: AgentMessage[];
  toolCalls: ToolCallDelta[];
  completions: CompletionUpdate[];
  unknown: AgentStreamEvent[];
}

export async function collectAgentStream(stream: HttpStream): Promise<AgentStreamConsumption> {
  const result: AgentStreamConsumption = {
    messages: [],
    toolCalls: [],
    completions: [],
    unknown: [],
  };

  await consumeAgentStream(stream, {
    onMessage: async (message) => {
      result.messages.push(message);
    },
    onTool: async (delta) => {
      result.toolCalls.push(delta);
    },
    onStatus: async (update) => {
      result.completions.push(update);
    },
    onUnknown: async (event) => {
      result.unknown.push(event);
    },
  });

  return result;
}
