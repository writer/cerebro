import { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  authHeadersFor,
  buildCerebroUrl,
  cachedResponseHeaders,
  cerebroProxyCacheKey,
  configuredOrganizationalGraphTenant,
  configuredRustPlatformApiBase,
  fetchCerebro,
  getCerebroPublicConfig,
  isCacheableCerebroPath,
  responseHeadersFor,
  rustTenantAuthHeaders,
  rustOwnsWebAuthority,
  shouldRetryUpstreamResponse,
  shouldBypassCerebroProxyCache,
  warmCerebroProxyCache,
  withCerebroCacheBypassHeader,
} from "./cerebro-proxy";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe("cerebro proxy cache headers", () => {
  it("rejects dot segments before constructing an upstream URL", () => {
    expect(() => buildCerebroUrl("other/../sources/preview")).toThrow(/dot segments/);
    expect(() => buildCerebroUrl("../sources/preview")).toThrow(/dot segments/);
  });

  it("partitions cached responses by the resolved user request context", () => {
    const target = new URL("https://api.example.com/grc/findings");
    const first = cerebroProxyCacheKey(target, {
      "x-cerebro-api-key": "shared-key",
      "x-cerebro-user-id": "user-one",
    });
    const second = cerebroProxyCacheKey(target, {
      "x-cerebro-api-key": "shared-key",
      "x-cerebro-user-id": "user-two",
    });

    expect(first).not.toBe(second);
    expect(first).toMatch(/^[0-9a-f]{64}$/);
    expect(second).toMatch(/^[0-9a-f]{64}$/);
  });

  it("warms only server-authenticated cacheable reads", async () => {
    await expect(warmCerebroProxyCache("v1/actions", "?limit=1")).resolves.toBe("skipped");
  });

  it("keeps internal upstream addresses out of the browser config", () => {
    expect(getCerebroPublicConfig().apiBase).toBe("/api/cerebro");
  });

  it.each([
    "platform/graph/neighborhood",
    "grc/inventory/categories",
    "grc/vendors",
    "grc/policy-lifecycle",
  ])("adds the server-owned tenant header to %s", (path) => {
    vi.stubEnv("CEREBRO_ORGANIZATIONAL_GRAPH_TENANT_ID", " tenant-demo ");

    const request = new NextRequest("http://localhost/graph");
    const headers = new Headers(authHeadersFor(request, path));

    expect(headers.get("x-cerebro-tenant")).toBe("tenant-demo");
  });

  it("keeps explicit tenant selection and unrelated routes independent of the graph tenant", () => {
    vi.stubEnv("CEREBRO_ORGANIZATIONAL_GRAPH_TENANT_ID", "tenant-demo");

    const selectedTenantRequest = new NextRequest("http://localhost/api/cerebro/grc/vendors?tenant_id=tenant-selected");

    expect(new Headers(authHeadersFor(selectedTenantRequest, "grc/vendors")).get("x-cerebro-tenant")).toBeNull();
    expect(new Headers(authHeadersFor(selectedTenantRequest, "user/preferences")).get("x-cerebro-tenant")).toBeNull();
  });

  it("routes only runtime health to the configured Rust platform origin", () => {
    vi.stubEnv("CEREBRO_RUST_PLATFORM_API_BASE", "http://rust-platform.internal:8080");

    expect(buildCerebroUrl("/v1/source-runtimes/health", "?limit=500").toString()).toBe(
      "http://rust-platform.internal:8080/v1/source-runtimes/health?limit=500",
    );
    expect(buildCerebroUrl("/grc/dashboard").origin).not.toBe("http://rust-platform.internal:8080");
  });

  it("matches the shared Go and Rust tenant-auth test vector", () => {
    const headers = new Headers(rustTenantAuthHeaders(
      "tenant-a",
      "test-organizational-graph-secret-32-bytes",
    ));

    expect(headers.get("x-cerebro-tenant")).toBe("tenant-a");
    expect(headers.get("authorization")).toBe(
      "Bearer 34b1625abbaa7a28cbca5f0a4803c1ba5360a998e5cc2f5b28d37bd32ba131d6",
    );
  });

  it("uses only server-owned Rust tenant auth for runtime health", () => {
    vi.stubEnv("CEREBRO_RUST_PLATFORM_API_BASE", "http://rust-platform.internal:8080");
    vi.stubEnv("CEREBRO_ORGANIZATIONAL_GRAPH_TENANT_ID", "tenant-a");
    vi.stubEnv(
      "CEREBRO_ORGANIZATIONAL_GRAPH_SHARED_SECRET",
      "test-organizational-graph-secret-32-bytes",
    );
    const headers = new Headers(authHeadersFor(new NextRequest("http://localhost"), "v1/source-runtimes/health"));

    expect(headers.get("x-cerebro-tenant")).toBe("tenant-a");
    expect(headers.get("authorization")).toMatch(/^Bearer [0-9a-f]{64}$/);
    expect(headers.get("x-cerebro-api-key")).toBeNull();
  });

  it("rejects an invalid server-owned tenant header", () => {
    expect(() => configuredOrganizationalGraphTenant("tenant-demo\nforged")).toThrow(
      "is not a valid header value",
    );
    expect(configuredOrganizationalGraphTenant("   ")).toBeUndefined();
  });

  it("rejects credential-bearing Rust platform origins and short shared secrets", () => {
    expect(() => configuredRustPlatformApiBase("https://user:pass@rust.example.com")).toThrow(
      "without credentials",
    );
    expect(() => rustTenantAuthHeaders("tenant-a", "too-short")).toThrow("at least 32 bytes");
  });

  it("enables Rust authority only through an explicit deployment mode", () => {
    vi.stubEnv("CEREBRO_AUTHORITY_MODE", "rust");
    expect(rustOwnsWebAuthority()).toBe(true);
    vi.stubEnv("CEREBRO_AUTHORITY_MODE", "legacy");
    expect(rustOwnsWebAuthority()).toBe(false);
  });

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

  it("does not amplify an unqualified unavailable response", () => {
    expect(shouldRetryUpstreamResponse(new Response(null, { status: 503 }))).toBe(false);
    expect(shouldRetryUpstreamResponse(new Response(null, {
      status: 503,
      headers: { "retry-after": "1" },
    }))).toBe(true);
    expect(shouldRetryUpstreamResponse(new Response(null, { status: 502 }))).toBe(true);
    expect(shouldRetryUpstreamResponse(new Response(null, { status: 504 }))).toBe(true);
  });

  it("returns an unqualified unavailable response after one upstream attempt", async () => {
    const upstreamFetch = vi.fn(async () => new Response(null, { status: 503 }));
    vi.stubGlobal("fetch", upstreamFetch);

    const response = await fetchCerebro(new URL("https://api.example.com/grc/dashboard"));

    expect(response.status).toBe(503);
    expect(upstreamFetch).toHaveBeenCalledTimes(1);
  });

  it("caches program readiness so audit readiness can stale-serve through transient backend failures", () => {
    expect(isCacheableCerebroPath("/grc/program-readiness")).toBe(true);
    expect(isCacheableCerebroPath("grc/program-readiness")).toBe(true);
  });

  it("caches the bounded Rust graph neighborhood contract", () => {
    expect(isCacheableCerebroPath("/platform/graph/neighborhood")).toBe(true);
    expect(isCacheableCerebroPath("/platform/graph/neighborhood?root_urn=urn%3Acerebro%3Atenant-demo%3Aentity%3Aone")).toBe(true);
  });

  it("keeps live finding previews fresh while immutable packets remain cacheable", () => {
    expect(isCacheableCerebroPath("/grc/findings/finding-123/audit-preview")).toBe(false);
    expect(isCacheableCerebroPath("/grc/findings/finding-123")).toBe(false);
    expect(isCacheableCerebroPath("/grc/findings/finding-123/audit-preview/export")).toBe(false);
    expect(isCacheableCerebroPath("/grc/audit-packets/packet-123")).toBe(true);
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
      upstreamSignal = init?.signal ?? undefined;
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
