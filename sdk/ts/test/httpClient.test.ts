import { beforeEach, describe, expect, it, vi } from "vitest";

import HttpClient, { HttpError, HttpTimeoutError } from "../src/httpClient";

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  // @ts-expect-error - assign test double
  globalThis.fetch = fetchMock;
});

describe("HttpClient", () => {
  it("attaches bearer tokens and parses JSON", async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({ success: true }),
    });

    const client = new HttpClient({
      baseUrl: "https://api.example.com",
      getAccessToken: () => "token123",
    });

    const result = await client.get<{ success: boolean }>("/hello");
    expect(result.success).toBe(true);

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://api.example.com/hello");
    const headers = new Headers((init as RequestInit).headers);
    expect(headers.get("authorization")).toBe("Bearer token123");
  });

  it("builds URLs with query parameters", async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({}),
    });

    const client = new HttpClient({ baseUrl: "https://api.example.com/" });
    await client.get("foo", { searchParams: { hours: 24, skip: undefined } });

    const [url] = fetchMock.mock.calls[0];
    expect(url).toBe("https://api.example.com/foo?hours=24");
  });

  it("throws HttpError on non-OK responses", async () => {
    fetchMock.mockResolvedValue({
      ok: false,
      status: 500,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({ error: "boom" }),
    });

    const client = new HttpClient({ baseUrl: "https://api.example.com" });

    await expect(client.get("/fail"))
      .rejects.toBeInstanceOf(HttpError);
  });

  it("retries transient failures when configured", async () => {
    fetchMock
      .mockResolvedValueOnce({
        ok: false,
        status: 502,
        headers: new Headers({ "content-type": "text/plain" }),
        text: async () => "maintenance",
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => ({ recovered: true }),
      });

    const client = new HttpClient({
      baseUrl: "https://api.example.com",
      retry: { retries: 1, delayMs: 0 },
    });

    const result = await client.get<{ recovered: boolean }>("/flaky");

    expect(result.recovered).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("runs middleware hooks", async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({ ok: true }),
    });

    const before = vi.fn(({ init }: { init: RequestInit }) => {
      const headers = new Headers(init.headers);
      headers.set("x-middleware", "yes");
      init.headers = headers;
    });
    const after = vi.fn();

    const client = new HttpClient({
      baseUrl: "https://api.example.com",
      beforeRequest: before,
      afterResponse: after,
    });

    await client.post("/middleware", { body: { ping: true } });

    expect(before).toHaveBeenCalledTimes(1);
    expect(after).toHaveBeenCalledTimes(1);
    const [, init] = fetchMock.mock.calls[0];
    const headers = new Headers((init as RequestInit).headers);
    expect(headers.get("x-middleware")).toBe("yes");
  });

  it("aborts requests that exceed timeout", async () => {
    fetchMock.mockImplementation((_: string, init?: RequestInit) => new Promise((_, reject) => {
      init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
    }));

    const client = new HttpClient({ baseUrl: "https://api.example.com", timeoutMs: 10 });

    await expect(client.get("/slow")).rejects.toBeInstanceOf(HttpTimeoutError);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("exposes streaming responses", async () => {
    const encoder = new TextEncoder();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode("chunk-1"));
        controller.enqueue(encoder.encode("-chunk-2"));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "text/event-stream" }),
      body: stream,
    });

    const client = new HttpClient({ baseUrl: "https://api.example.com" });
    const responseStream = await client.stream("/events");

    let combined = "";
    for await (const fragment of responseStream.text()) {
      combined += fragment;
    }

    expect(combined).toBe("chunk-1-chunk-2");
  });
});
