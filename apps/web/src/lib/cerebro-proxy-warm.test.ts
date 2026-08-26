import { afterEach, describe, expect, it, vi } from "vitest";

const loadServerAuthenticatedProxy = async () => {
  vi.resetModules();
  vi.stubEnv("CEREBRO_API_BASE", "https://api.example.com");
  vi.stubEnv("CEREBRO_API_KEY", "server-owned-test-key");
  vi.stubEnv("CEREBRO_FORWARD_AUTH_HEADERS", "false");
  vi.stubEnv("CEREBRO_ORGANIZATIONAL_GRAPH_TENANT_ID", "tenant-default");
  return import("./cerebro-proxy");
};

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.resetModules();
});

describe("server-authenticated Cerebro cache warming", () => {
  it("shares the dashboard cache across authorized user stamps without crossing tenant or workspace scope", async () => {
    const proxy = await loadServerAuthenticatedProxy();
    const base = new URL("https://api.example.com/grc/dashboard?tenant_id=tenant-a&workspace_id=workspace-a");
    const first = proxy.cerebroProxyCacheKey(base, {
      "x-cerebro-api-key": "server-owned-test-key",
      "x-cerebro-user-id": "user-one",
    });
    const second = proxy.cerebroProxyCacheKey(base, {
      "x-cerebro-api-key": "server-owned-test-key",
      "x-cerebro-user-id": "user-two",
    });
    const otherWorkspace = proxy.cerebroProxyCacheKey(
      new URL("https://api.example.com/grc/dashboard?tenant_id=tenant-a&workspace_id=workspace-b"),
      { "x-cerebro-api-key": "server-owned-test-key" },
    );
    const otherTenant = proxy.cerebroProxyCacheKey(
      new URL("https://api.example.com/grc/dashboard?tenant_id=tenant-b&workspace_id=workspace-a"),
      { "x-cerebro-api-key": "server-owned-test-key" },
    );

    expect(first).toBe(second);
    expect(first).not.toBe(otherWorkspace);
    expect(first).not.toBe(otherTenant);
  });

  it("warms the exact scoped dashboard request and reuses the cached response", async () => {
    let observedTarget = "";
    let observedHeaders = new Headers();
    const upstreamFetch = vi.fn(async (target: RequestInfo | URL, init?: RequestInit) => {
      observedTarget = String(target);
      observedHeaders = new Headers(init?.headers);
      return new Response(JSON.stringify({ status: "ready" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", upstreamFetch);
    const proxy = await loadServerAuthenticatedProxy();
    const search = "?tenant_id=tenant-a&workspace_id=workspace-a&limit=12&enrichments=deferred&view=summary";

    await expect(proxy.warmCerebroProxyCache("grc/dashboard", search)).resolves.toBe("miss");
    await expect(proxy.warmCerebroProxyCache("grc/dashboard", search)).resolves.toBe("hit");

    expect(upstreamFetch).toHaveBeenCalledTimes(1);
    expect(observedTarget).toBe(`https://api.example.com/grc/dashboard${search}`);
    expect(observedHeaders.get("x-cerebro-api-key")).toBe("server-owned-test-key");
    expect(observedHeaders.get("x-cerebro-tenant")).toBeNull();
  });

  it("does not warm legacy service credentials while Rust owns web authority", async () => {
    vi.stubEnv("CEREBRO_AUTHORITY_MODE", "rust");
    const proxy = await loadServerAuthenticatedProxy();
    vi.stubEnv("CEREBRO_AUTHORITY_MODE", "rust");

    await expect(proxy.warmCerebroProxyCache("grc/dashboard")).resolves.toBe("skipped");
  });
});
