import { describe, expect, it } from "vitest";

import { toServerSentEventIterator } from "../src/streaming";

describe("streaming", () => {
  it("parses server-sent events", async () => {
    const encoder = new TextEncoder();
    const raw = encoder.encode("event: update\ndata: {\"value\":1}\n\n");
    const httpStream = {
      response: new Response(null),
      cancel: async () => undefined,
      async *[Symbol.asyncIterator]() {
        yield raw;
      },
      text() {
        let emitted = false;
        return {
          async *[Symbol.asyncIterator]() {
            if (!emitted) {
              emitted = true;
              yield "event: update\ndata: {\"value\":1}\n\n";
            }
          },
        };
      },
    };

    const iterator = toServerSentEventIterator(httpStream);
    const events: string[] = [];
    for await (const event of iterator) {
      events.push(`${event.event}:${event.data}`);
    }

    expect(events).toEqual(["update:{\"value\":1}"]);
  });
});
