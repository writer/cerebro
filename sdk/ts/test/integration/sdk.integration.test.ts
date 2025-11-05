import { beforeEach, describe, expect, it, vi } from "vitest";

import CerebroSDK from "../../src/sdk";

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
});

describe("CerebroSDK integration", () => {
  it("streams agent responses while invoking middleware", async () => {
    const encoder = new TextEncoder();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode("payload"));
        controller.close();
      },
    });

    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "text/event-stream" }),
      body: stream,
    });

    const before = vi.fn(({ init }: { init: RequestInit }) => {
      const headers = new Headers(init.headers);
      headers.set("x-sdk", "integration");
      init.headers = headers;
    });
    const after = vi.fn();

    const sdk = new CerebroSDK({
      baseUrl: "https://api.example.com",
      fetch: fetchMock,
      beforeRequest: before,
      afterResponse: after,
    });

    const result = await sdk.agents.sendSessionMessage("session-42", {
      message: "stream please",
      stream: true,
    });

    expect(result.kind).toBe("stream");
    let combined = "";
    for await (const chunk of result.stream.text()) {
      combined += chunk;
    }

    expect(combined).toBe("payload");
    expect(before).toHaveBeenCalledTimes(1);
    expect(after).toHaveBeenCalledTimes(1);

    const [, init] = fetchMock.mock.calls[0];
    const headers = new Headers((init as RequestInit).headers);
    expect(headers.get("x-sdk")).toBe("integration");
  });
});
