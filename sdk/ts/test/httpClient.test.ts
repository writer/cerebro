import { describe, expect, it, beforeEach, vi } from "vitest";

import HttpClient, { HttpError } from "../src/httpClient";

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
});
