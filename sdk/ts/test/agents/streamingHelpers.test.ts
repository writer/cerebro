import { describe, expect, it } from "vitest";

import { parseAgentEventStream } from "../../src/agents/streaming";
import type { HttpStream } from "../../src/httpClient";

describe("parseAgentEventStream", () => {
  it("emits typed events", async () => {
    const encoder = new TextEncoder();
    const buffer = encoder.encode(
      "event: message\n" +
        "data: {\"message_id\":\"m1\",\"role\":\"assistant\",\"content\":\"Hi\"}\n\n" +
        "event: status\n" +
        "data: {\"status\":\"completed\"}\n\n",
    );

    const stream: HttpStream = {
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
});

function bufferToString(buffer: Uint8Array): string {
  return new TextDecoder().decode(buffer);
}
