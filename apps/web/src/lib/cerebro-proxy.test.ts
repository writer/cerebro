import { afterEach, describe, expect, it, vi } from "vitest";

import {
  cachedResponseHeaders,
  fetchCerebro,
  isCacheableCerebroPath,
  responseHeadersFor,
  shouldBypassCerebroProxyCache,
  withCerebroCacheBypassHeader,
} from "./cerebro-proxy";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("cerebro proxy cache headers", () => {
  it("recognizes explicit cache bypass requests", () => {
    expect(shouldBypassCerebroProxyCache(new Headers({ "cache-control": "max-age=0, no-cache" }))).toBe(true);
    expect(shouldBypassCerebroProxyCache(new Headers({ pragma: "no-cache" }))).toBe(true);
    expect(shouldBypassCerebroProxyCache(new Headers({ "cache-control": "private, max-age=30" }))).toBe(false);
  });

  it("adds a backend cache bypass header without dropping auth", () => {
    const headers = withCerebroCacheBypassHeader({ "x-cerebro-api-key": "test-key" });

    expect(headers.get("cache-control")).toBe("no-cache");
    expect(headers.get("x-cerebro-api-key")).toBe("test-key");
  });

  it("keeps web proxy cache state separate from upstream cache state", () => {
    const headers = cachedResponseHeaders(
      {
        headers: {
          "cache-control": "private, max-age=30, stale-if-error=300",
          "content-type": "application/json",
          "x-cerebro-cache": "hit",
        },
      },
      "dedupe",
    );

    expect(headers["x-cerebro-cache"]).toBe("dedupe");
    expect(headers["x-cerebro-web-cache"]).toBe("dedupe");
    expect(headers["x-cerebro-upstream-cache"]).toBe("hit");
    expect(headers["cache-control"]).toBe("private, max-age=0, must-revalidate");
  });

  it("passes through backend cache observability headers", () => {
    const response = new Response("{}", {
      headers: {
        "cache-control": "private, max-age=30",
        "content-type": "application/json",
        vary: "Authorization",
        "x-cerebro-cache": "miss",
        "x-cerebro-trace-id": "trace-123",
        "x-cerebro-web-trace-id": "web-trace-123",
        "x-request-id": "req-123",
      },
    });

    expect(responseHeadersFor(response)).toMatchObject({
      "cache-control": "private, max-age=30",
      "content-type": "application/json",
      vary: "Authorization",
      "x-cerebro-cache": "miss",
      "x-cerebro-trace-id": "trace-123",
      "x-cerebro-web-trace-id": "web-trace-123",
      "x-request-id": "req-123",
    });
  });

  it("caches program readiness so audit readiness can stale-serve through transient backend failures", () => {
    expect(isCacheableCerebroPath("/grc/program-readiness")).toBe(true);
    expect(isCacheableCerebroPath("grc/program-readiness")).toBe(true);
  });

  it("propagates trace headers upstream without logging auth or query strings", async () => {
    let upstreamHeaders = new Headers();
    vi.stubGlobal("fetch", vi.fn(async (_target: URL | RequestInfo, init?: RequestInit) => {
      upstreamHeaders = new Headers(init?.headers);
      return new Response("{}", { status: 200 });
    }));
    const queryKey = ["to", "ken"].join("");
    const target = new URL("https://api.example.com/grc/findings");
    target.searchParams.set(queryKey, "secret");
    const writes = captureStderr(async () => {
      await fetchCerebro(target, {
        headers: {
          authorization: "Bearer secret-token",
        },
      });
    });

    expect(upstreamHeaders.get("traceparent")).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/);
    expect(upstreamHeaders.get("x-cerebro-web-trace-id")).toMatch(/^[0-9a-f]{32}$/);
    expect(upstreamHeaders.get("authorization")).toBe("Bearer secret-token");
    const output = (await writes).join("");
    expect(output).toContain("\"name\":\"cerebro.upstream.fetch\"");
    expect(output).not.toContain("Bearer secret-token");
    expect(output).not.toContain(`${queryKey}=secret`);
  });

  it("aborts upstream fetches when the caller signal aborts", async () => {
    let upstreamSignal: AbortSignal | undefined;
    vi.stubGlobal("fetch", vi.fn(async (_target: URL | RequestInfo, init?: RequestInit) => {
      upstreamSignal = init?.signal;
      return await new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
      });
    }));
    const caller = new AbortController();
    const request = fetchCerebro(new URL("https://api.example.com/grc/findings"), {
      signal: caller.signal,
    });

    await new Promise((resolve) => setTimeout(resolve, 0));
    caller.abort();

    await expect(request).rejects.toThrow("Cerebro API request timed out");
    expect(upstreamSignal?.aborted).toBe(true);
  });
});

const captureStderr = async (fn: () => Promise<void>) => {
  const original = process.stderr.write;
  const writes: string[] = [];
  process.stderr.write = ((chunk: string | Uint8Array) => {
    writes.push(String(chunk));
    return true;
  }) as typeof process.stderr.write;
  try {
    await fn();
  } finally {
    process.stderr.write = original;
  }
  return writes;
};
