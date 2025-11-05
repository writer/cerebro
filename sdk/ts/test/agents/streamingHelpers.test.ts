import { describe, expect, it } from "vitest";

import {
  collectAgentStream,
  consumeAgentStream,
  parseAgentEventStream,
  type ToolCallDelta,
  type CompletionUpdate,
} from "../../src/agents/streaming";
import type { HttpStream } from "../../src/httpClient";

describe("parseAgentEventStream", () => {
  it("emits typed events", async () => {
    const stream = createStream(
      "event: message\n" +
        "data: {\"message_id\":\"m1\",\"role\":\"assistant\",\"content\":\"Hi\"}\n\n" +
        "event: status\n" +
        "data: {\"status\":\"completed\"}\n\n",
    );

    const events: unknown[] = [];
    for await (const evt of parseAgentEventStream(stream)) {
      events.push(evt);
    }

    expect(events).toHaveLength(2);
    const [message, status] = events as [
      { type: "message"; payload: { content: string } },
      { type: "status"; payload: { status: string } },
    ];
    expect(message.payload.content).toBe("Hi");
    expect(status.payload.status).toBe("completed");
  });

  it("consumes tool deltas and completion updates", async () => {
    const payload =
      "event: tool\n" +
      "data: {\"invocation_id\":\"tool-1\",\"status\":\"running\"}\n\n" +
      "event: status\n" +
      "data: {\"status\":\"completed\",\"detail\":\"Done\"}\n\n";

    const stream = createStream(payload);
    const toolCalls: ToolCallDelta[] = [];
    const completions: CompletionUpdate[] = [];

    await consumeAgentStream(stream, {
      onTool(delta) {
        toolCalls.push(delta);
      },
      onStatus(update) {
        completions.push(update);
      },
    });

    expect(toolCalls).toHaveLength(1);
    expect(toolCalls[0]?.invocationId).toBe("tool-1");
    expect(completions).toHaveLength(1);
    expect(completions[0]?.done).toBe(true);
    expect(completions[0]?.detail).toBe("Done");
  });

  it("collects agent stream state", async () => {
    const payload =
      "event: message\n" +
      "data: {\"message_id\":\"m1\",\"role\":\"assistant\",\"content\":\"Hello\"}\n\n" +
      "event: tool\n" +
      "data: {\"invocation_id\":\"tool-1\",\"status\":\"completed\"}\n\n" +
      "event: status\n" +
      "data: {\"status\":\"completed\"}\n\n";

    const stream = createStream(payload);
    const snapshot = await collectAgentStream(stream);

    expect(snapshot.messages).toHaveLength(1);
    expect(snapshot.messages[0]?.content).toBe("Hello");
    expect(snapshot.toolCalls).toHaveLength(1);
    expect(snapshot.toolCalls[0]?.invocationId).toBe("tool-1");
    expect(snapshot.completions.some((entry) => entry.done)).toBe(true);
    expect(snapshot.unknown).toHaveLength(0);
  });
});

function bufferToString(buffer: Uint8Array): string {
  return new TextDecoder().decode(buffer);
}

function createStream(sequence: string): HttpStream {
  const encoder = new TextEncoder();
  const buffer = encoder.encode(sequence);
  return {
    response: new Response(null, { status: 200 }),
    cancel: async () => undefined,
    async *[Symbol.asyncIterator]() {
      yield buffer;
    },
    text() {
      let sent = false;
      return {
        async *[Symbol.asyncIterator]() {
          if (!sent) {
            sent = true;
            yield bufferToString(buffer);
          }
        },
      };
    },
  };
}
