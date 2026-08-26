import { afterEach, describe, expect, it, vi } from "vitest";

import { fetchCerebro } from "./cerebro-client";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("fetchCerebro", () => {
  it("does not turn ordinary product reads into cache bypass requests", async () => {
    const fetchMock = vi.fn<typeof fetch>();
    fetchMock.mockResolvedValue(new Response("{}", {
      status: 200,
      headers: { "content-type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);

    await fetchCerebro("/grc/policy-lifecycle");

    const init = fetchMock.mock.calls[0]?.[1] as RequestInit | undefined;
    expect(init?.cache).toBeUndefined();
    expect(new Headers(init?.headers).get("cache-control")).toBeNull();
  });

  it("preserves an explicit operator cache bypass", async () => {
    const fetchMock = vi.fn<typeof fetch>();
    fetchMock.mockResolvedValue(new Response("{}", {
      status: 200,
      headers: { "content-type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);

    await fetchCerebro("/grc/policy-lifecycle", undefined, { cache: "no-store" });

    const init = fetchMock.mock.calls[0]?.[1] as RequestInit | undefined;
    expect(init?.cache).toBe("no-store");
  });

  it("preserves caller-supplied tenant and workspace selectors", async () => {
    const fetchMock = vi.fn<typeof fetch>();
    fetchMock.mockResolvedValue(new Response("{}", {
      status: 200,
      headers: { "content-type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);

    await fetchCerebro("/grc/dashboard", undefined, {
      headers: {
        "X-Cerebro-Tenant": "tenant-a",
        "X-Cerebro-Workspace": "workspace-a",
      },
    });

    const headers = new Headers(fetchMock.mock.calls[0]?.[1]?.headers);
    expect(headers.get("x-cerebro-tenant")).toBe("tenant-a");
    expect(headers.get("x-cerebro-workspace")).toBe("workspace-a");
  });
});
