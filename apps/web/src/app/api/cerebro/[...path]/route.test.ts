import { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import { DELETE, GET, PATCH, POST, PUT } from "./route";

const originalFixtureMode = process.env.CEREBRO_WEB_FIXTURE_MODE;
const originalAuthorityMode = process.env.CEREBRO_AUTHORITY_MODE;
const originalIdentityRequired = process.env.CEREBRO_IDENTITY_REQUIRED;
const originalLocalIdentityFallback = process.env.CEREBRO_LOCAL_IDENTITY_FALLBACK;

afterEach(() => {
  if (originalFixtureMode === undefined) delete process.env.CEREBRO_WEB_FIXTURE_MODE;
  else process.env.CEREBRO_WEB_FIXTURE_MODE = originalFixtureMode;
  if (originalAuthorityMode === undefined) delete process.env.CEREBRO_AUTHORITY_MODE;
  else process.env.CEREBRO_AUTHORITY_MODE = originalAuthorityMode;
  if (originalIdentityRequired === undefined) delete process.env.CEREBRO_IDENTITY_REQUIRED;
  else process.env.CEREBRO_IDENTITY_REQUIRED = originalIdentityRequired;
  if (originalLocalIdentityFallback === undefined) delete process.env.CEREBRO_LOCAL_IDENTITY_FALLBACK;
  else process.env.CEREBRO_LOCAL_IDENTITY_FALLBACK = originalLocalIdentityFallback;
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("Cerebro proxy route", () => {
  it("does not force ordinary GET reads to bypass the upstream query cache", async () => {
    delete process.env.CEREBRO_WEB_FIXTURE_MODE;
    let upstreamInit: RequestInit | undefined;
    vi.stubGlobal("fetch", vi.fn(async (_url: URL | RequestInfo, init?: RequestInit) => {
      upstreamInit = init;
      return new Response(JSON.stringify({ policies: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }));

    const response = await GET(
      new NextRequest("http://localhost/api/cerebro/grc/policy-lifecycle?cache_regression=ordinary"),
      { params: Promise.resolve({ path: ["grc", "policy-lifecycle"] }) },
    );

    expect(response.status).toBe(200);
    expect(upstreamInit?.cache).toBeUndefined();
    expect(new Headers(upstreamInit?.headers).get("cache-control")).toBeNull();
  });

  it("distinguishes cold, warm, tenant, and workspace dashboard reads", async () => {
    delete process.env.CEREBRO_WEB_FIXTURE_MODE;
    const fetchMock = vi.fn(async (url: URL | RequestInfo) => new Response(
      JSON.stringify({ target: url.toString() }),
      { status: 200, headers: { "content-type": "application/json" } },
    ));
    vi.stubGlobal("fetch", fetchMock);
    const context = { params: Promise.resolve({ path: ["grc", "dashboard"] }) };
    const request = (tenant: string, workspace: string) => new NextRequest(
      `http://localhost/api/cerebro/grc/dashboard?cache_contract=cold-warm-scope&tenant_id=${tenant}&workspace_id=${workspace}`,
    );

    const cold = await GET(request("tenant-a", "workspace-a"), context);
    const warm = await GET(request("tenant-a", "workspace-a"), context);
    const otherTenant = await GET(request("tenant-b", "workspace-a"), context);
    const otherWorkspace = await GET(request("tenant-a", "workspace-b"), context);

    expect(cold.headers.get("x-cerebro-web-cache")).toBe("miss");
    expect(warm.headers.get("x-cerebro-web-cache")).toBe("hit");
    expect(otherTenant.headers.get("x-cerebro-web-cache")).toBe("miss");
    expect(otherWorkspace.headers.get("x-cerebro-web-cache")).toBe("miss");
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("forwards header-selected tenant and workspace scope into the upstream cache boundary", async () => {
    delete process.env.CEREBRO_WEB_FIXTURE_MODE;
    let upstreamHeaders = new Headers();
    const fetchMock = vi.fn(async (_url: URL | RequestInfo, init?: RequestInit) => {
      upstreamHeaders = new Headers(init?.headers);
      return new Response(JSON.stringify({ findings: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const response = await GET(
      new NextRequest("http://localhost/api/cerebro/grc/findings?scope_contract=header", {
        headers: {
          "X-Cerebro-Tenant": "tenant-a",
          "X-Cerebro-Workspace": "workspace-a",
        },
      }),
      { params: Promise.resolve({ path: ["grc", "findings"] }) },
    );

    expect(response.status).toBe(200);
    expect(upstreamHeaders.get("x-cerebro-tenant")).toBe("tenant-a");
    expect(upstreamHeaders.get("x-cerebro-workspace")).toBe("workspace-a");
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("forwards tenant and workspace scope for connector coverage", async () => {
    delete process.env.CEREBRO_WEB_FIXTURE_MODE;
    let upstreamHeaders = new Headers();
    const fetchMock = vi.fn(async (_url: URL | RequestInfo, init?: RequestInit) => {
      upstreamHeaders = new Headers(init?.headers);
      return new Response(JSON.stringify({ records: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const response = await GET(
      new NextRequest(
        "http://localhost/api/cerebro/connectors/coverage?tenant_id=tenant-a&workspace_id=workspace-a",
      ),
      { params: Promise.resolve({ path: ["connectors", "coverage"] }) },
    );

    expect(response.status).toBe(200);
    expect(upstreamHeaders.get("x-cerebro-tenant")).toBe("tenant-a");
    expect(upstreamHeaders.get("x-cerebro-workspace")).toBe("workspace-a");
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it.each([
    ["orphan workspace", "http://localhost/api/cerebro/grc/dashboard?workspace_id=workspace-a", {}],
    ["mismatched workspace", "http://localhost/api/cerebro/grc/dashboard?tenant_id=tenant-a&workspace_id=workspace-a", { "X-Cerebro-Workspace": "workspace-b" }],
  ])("rejects %s without an upstream read", async (_name, url, headers) => {
    delete process.env.CEREBRO_WEB_FIXTURE_MODE;
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const response = await GET(
      new NextRequest(url, { headers }),
      { params: Promise.resolve({ path: ["grc", "dashboard"] }) },
    );

    expect(response.status).toBe(400);
    expect(response.headers.get("cache-control")).toBe("private, no-store");
    expect(fetchMock).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toMatchObject({
      error: "Provide one matching tenant and workspace selector. A workspace requires an explicit tenant.",
    });
  });

  it("passes a tenant-workspace authorization failure through without an unscoped fallback", async () => {
    delete process.env.CEREBRO_WEB_FIXTURE_MODE;
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ code: "forbidden" }), {
      status: 403,
      headers: { "content-type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);

    const response = await GET(
      new NextRequest("http://localhost/api/cerebro/grc/dashboard?tenant_id=tenant-a&workspace_id=workspace-b&scope_contract=forbidden"),
      { params: Promise.resolve({ path: ["grc", "dashboard"] }) },
    );

    expect(response.status).toBe(403);
    expect(fetchMock).toHaveBeenCalledOnce();
    await expect(response.json()).resolves.toEqual({ code: "forbidden" });
  });

  it.each([
    ["POST", POST],
    ["PATCH", PATCH],
    ["PUT", PUT],
  ] as const)("does not read a %s body for an invalid workspace scope", async (method, handler) => {
    delete process.env.CEREBRO_WEB_FIXTURE_MODE;
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const request = new NextRequest("http://localhost/api/cerebro/grc/findings?workspace_id=workspace-a", {
      method,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ status: "resolved" }),
    });
    const readBody = vi.spyOn(request, "text");

    const response = await handler(request, {
      params: Promise.resolve({ path: ["grc", "findings"] }),
    });

    expect(response.status).toBe(400);
    expect(readBody).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    ["GET", GET],
    ["POST", POST],
    ["PATCH", PATCH],
    ["PUT", PUT],
    ["DELETE", DELETE],
  ] as const)("returns 400 for dot segments on %s requests", async (method, handler) => {
    const response = await handler(
      new NextRequest("http://localhost/api/cerebro/%2e%2e/sources", { method }),
      { params: Promise.resolve({ path: ["..", "sources"] }) },
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "Cerebro proxy paths cannot contain dot segments.",
    });
  });

  it("translates a shared inflight rejection for every deduplicated request", async () => {
    delete process.env.CEREBRO_WEB_FIXTURE_MODE;
    let rejectFetch: ((reason?: unknown) => void) | undefined;
    const pendingFetch = new Promise<Response>((_resolve, reject) => {
      rejectFetch = reject;
    });
    const fetchMock = vi.fn(() => pendingFetch);
    vi.stubGlobal("fetch", fetchMock);
    const context = { params: Promise.resolve({ path: ["grc", "dashboard"] }) };
    const requestURL = "http://localhost/api/cerebro/grc/dashboard?dedupe=rejection";

    const first = GET(new NextRequest(requestURL), context);
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
    const second = GET(new NextRequest(requestURL), context);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(fetchMock).toHaveBeenCalledOnce();

    rejectFetch?.(new Error("network failed"));
    const [firstResponse, secondResponse] = await Promise.all([first, second]);

    expect(firstResponse.status).toBe(502);
    expect(secondResponse.status).toBe(502);
    expect(firstResponse.headers.get("x-cerebro-web-trace-id")).toMatch(/^[0-9a-f]{32}$/);
    expect(secondResponse.headers.get("x-cerebro-web-trace-id")).toMatch(/^[0-9a-f]{32}$/);
    await expect(secondResponse.json()).resolves.toMatchObject({ error: "Unable to reach Cerebro API" });
  });

  it("serves stale GRC data immediately while one background refresh runs", async () => {
    delete process.env.CEREBRO_WEB_FIXTURE_MODE;
    vi.useFakeTimers();
    const refreshed = Promise.withResolvers<Response>();
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ version: 1 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }))
      .mockImplementationOnce(() => refreshed.promise);
    vi.stubGlobal("fetch", fetchMock);
    const context = { params: Promise.resolve({ path: ["grc", "dashboard"] }) };
    const requestURL = "http://localhost/api/cerebro/grc/dashboard?stale_while_refresh=test";

    const first = await GET(new NextRequest(requestURL), context);
    expect(await first.json()).toEqual({ version: 1 });
    await vi.advanceTimersByTimeAsync(61_000);

    const second = await GET(new NextRequest(requestURL), context);
    expect(second.headers.get("x-cerebro-cache")).toBe("stale");
    expect(await second.json()).toEqual({ version: 1 });
    expect(fetchMock).toHaveBeenCalledTimes(2);

    const third = await GET(new NextRequest(requestURL), context);
    expect(third.headers.get("x-cerebro-cache")).toBe("stale");
    expect(await third.json()).toEqual({ version: 1 });
    expect(fetchMock).toHaveBeenCalledTimes(2);

    refreshed.resolve(new Response(JSON.stringify({ version: 2 }), {
      status: 200,
      headers: { "content-type": "application/json" },
    }));
    let fourth: Response | undefined;
    await vi.waitFor(async () => {
      fourth = await GET(new NextRequest(requestURL), context);
      expect(fourth.headers.get("x-cerebro-cache")).toBe("hit");
    });
    if (!fourth) throw new Error("refreshed response was not observed");
    expect(fourth.headers.get("x-cerebro-cache")).toBe("hit");
    expect(await fourth.json()).toEqual({ version: 2 });
  });

  it("does not cache or stale-serve live finding responses when their authority is unavailable", async () => {
    delete process.env.CEREBRO_WEB_FIXTURE_MODE;
    vi.useFakeTimers();
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ version: 1 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ code: "unavailable" }), {
        status: 503,
        headers: { "content-type": "application/json" },
      }));
    vi.stubGlobal("fetch", fetchMock);
    const context = { params: Promise.resolve({ path: ["grc", "findings"] }) };
    const requestURL = "http://localhost/api/cerebro/grc/findings?live_cache_contract=unavailable";

    const first = await GET(new NextRequest(requestURL), context);
    expect(first.status).toBe(200);
    await vi.advanceTimersByTimeAsync(61_000);

    const unavailable = await GET(new NextRequest(requestURL), context);
    expect(unavailable.status).toBe(503);
    expect(unavailable.headers.get("x-cerebro-cache")).not.toBe("stale");
    expect(unavailable.headers.get("warning")).toBeNull();
    expect(await unavailable.json()).toEqual({ code: "unavailable" });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("does not retain a dashboard response the upstream marks no-store", async () => {
    delete process.env.CEREBRO_WEB_FIXTURE_MODE;
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ version: 1 }), {
        status: 200,
        headers: {
          "cache-control": "no-store",
          "content-type": "application/json",
        },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ code: "unavailable" }), {
        status: 503,
        headers: { "content-type": "application/json" },
      }));
    vi.stubGlobal("fetch", fetchMock);
    const context = { params: Promise.resolve({ path: ["grc", "dashboard"] }) };
    const requestURL = "http://localhost/api/cerebro/grc/dashboard?cache_contract=no-store";

    const first = await GET(new NextRequest(requestURL), context);
    expect(first.status).toBe(200);
    expect(first.headers.get("cache-control")).toBe("no-store");

    const unavailable = await GET(new NextRequest(requestURL), context);
    expect(unavailable.status).toBe(503);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("relays signed Rust-authority reads without deriving or stamping identity", async () => {
    process.env.CEREBRO_AUTHORITY_MODE = "rust";
    process.env.CEREBRO_IDENTITY_REQUIRED = "true";
    process.env.CEREBRO_LOCAL_IDENTITY_FALLBACK = "false";
    let upstreamHeaders = new Headers();
    vi.stubGlobal("fetch", vi.fn(async (_url: URL | RequestInfo, init?: RequestInit) => {
      upstreamHeaders = new Headers(init?.headers);
      return new Response(JSON.stringify({ records: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }));

    const response = await GET(
      new NextRequest("http://localhost/api/cerebro/v1/security/lifecycle", {
        headers: {
          authorization: "Bearer signed-browser-token",
          "x-cerebro-api-key": "legacy-server-identity",
        },
      }),
      { params: Promise.resolve({ path: ["v1", "security", "lifecycle"] }) },
    );

    expect(response.status).toBe(200);
    expect(upstreamHeaders.get("authorization")).toBe("Bearer signed-browser-token");
    expect(upstreamHeaders.get("x-cerebro-api-key")).toBeNull();
    expect(upstreamHeaders.get("x-cerebro-user-id")).toBeNull();
    expect(upstreamHeaders.get("x-cerebro-user-subject")).toBeNull();
  });

  it("routes runtime health to Rust with server-owned tenant authentication", async () => {
    vi.stubEnv("CEREBRO_RUST_PLATFORM_API_BASE", "http://rust-platform.internal:8080");
    vi.stubEnv("CEREBRO_ORGANIZATIONAL_GRAPH_TENANT_ID", "tenant-a");
    vi.stubEnv(
      "CEREBRO_ORGANIZATIONAL_GRAPH_SHARED_SECRET",
      "test-organizational-graph-secret-32-bytes",
    );
    let upstreamURL = "";
    let upstreamHeaders = new Headers();
    vi.stubGlobal("fetch", vi.fn(async (url: URL | RequestInfo, init?: RequestInit) => {
      upstreamURL = url.toString();
      upstreamHeaders = new Headers(init?.headers);
      return new Response(JSON.stringify({ runtimes: [], source_summaries: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }));

    const response = await GET(
      new NextRequest("http://localhost/api/cerebro/v1/source-runtimes/health?limit=500"),
      { params: Promise.resolve({ path: ["v1", "source-runtimes", "health"] }) },
    );

    expect(response.status).toBe(200);
    expect(upstreamURL).toBe("http://rust-platform.internal:8080/v1/source-runtimes/health?limit=500");
    expect(upstreamHeaders.get("x-cerebro-tenant")).toBe("tenant-a");
    expect(upstreamHeaders.get("authorization")).toBe(
      "Bearer 34b1625abbaa7a28cbca5f0a4803c1ba5360a998e5cc2f5b28d37bd32ba131d6",
    );
    expect(upstreamHeaders.get("x-cerebro-api-key")).toBeNull();
  });

  it("routes the graph neighborhood product response directly to Rust", async () => {
    vi.stubEnv("CEREBRO_RUST_PLATFORM_API_BASE", "http://rust-platform.internal:8080");
    vi.stubEnv("CEREBRO_ORGANIZATIONAL_GRAPH_TENANT_ID", "tenant-a");
    vi.stubEnv(
      "CEREBRO_ORGANIZATIONAL_GRAPH_SHARED_SECRET",
      "test-organizational-graph-secret-32-bytes",
    );
    const rootUrn = "urn:cerebro:tenant-a:asset:one";
    const neighborhood = {
      root: { urn: rootUrn, entity_type: "asset", label: "one" },
      neighbors: [{ urn: "urn:cerebro:tenant-a:user:alice", entity_type: "user", label: "Alice" }],
      relations: [{ from_urn: rootUrn, relation: "owned_by", to_urn: "urn:cerebro:tenant-a:user:alice" }],
    };
    let upstreamURL = "";
    let upstreamHeaders = new Headers();
    vi.stubGlobal("fetch", vi.fn(async (url: URL | RequestInfo, init?: RequestInit) => {
      upstreamURL = url.toString();
      upstreamHeaders = new Headers(init?.headers);
      return new Response(JSON.stringify(neighborhood), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }));

    const response = await GET(
      new NextRequest(
        `http://localhost/api/cerebro/platform/graph/neighborhood?root_urn=${encodeURIComponent(rootUrn)}&limit=50`,
        { headers: { "cache-control": "no-cache" } },
      ),
      { params: Promise.resolve({ path: ["platform", "graph", "neighborhood"] }) },
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual(neighborhood);
    expect(upstreamURL).toBe(
      `http://rust-platform.internal:8080/platform/graph/neighborhood?root_urn=${encodeURIComponent(rootUrn)}&limit=50`,
    );
    expect(upstreamHeaders.get("x-cerebro-tenant")).toBe("tenant-a");
    expect(upstreamHeaders.get("authorization")).toBe(
      "Bearer 34b1625abbaa7a28cbca5f0a4803c1ba5360a998e5cc2f5b28d37bd32ba131d6",
    );
    expect(upstreamHeaders.get("x-cerebro-api-key")).toBeNull();
    expect(upstreamHeaders.get("x-cerebro-workspace")).toBeNull();
  });

  it("relays signed Rust-authority writes without authorizing or stamping in Next", async () => {
    process.env.CEREBRO_AUTHORITY_MODE = "rust";
    process.env.CEREBRO_IDENTITY_REQUIRED = "true";
    process.env.CEREBRO_LOCAL_IDENTITY_FALLBACK = "false";
    let upstreamHeaders = new Headers();
    let upstreamBody = "";
    vi.stubGlobal("fetch", vi.fn(async (_url: URL | RequestInfo, init?: RequestInit) => {
      upstreamHeaders = new Headers(init?.headers);
      upstreamBody = String(init?.body);
      return new Response(JSON.stringify({ state: "proposed", version: 1 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }));
    const body = JSON.stringify({
      operation_id: "operation:web:one",
      tenant_id: "tenant:web:one",
      proposed_by: "actor:web:one",
    });

    const response = await POST(
      new NextRequest("http://localhost/api/cerebro/v1/actions", {
        method: "POST",
        headers: {
          authorization: "Bearer signed-browser-token",
          "x-cerebro-api-key": "legacy-server-identity",
          "content-type": "application/json",
        },
        body,
      }),
      { params: Promise.resolve({ path: ["v1", "actions"] }) },
    );

    expect(response.status).toBe(200);
    expect(upstreamHeaders.get("authorization")).toBe("Bearer signed-browser-token");
    expect(upstreamHeaders.get("x-cerebro-api-key")).toBeNull();
    expect(upstreamHeaders.get("x-cerebro-user-id")).toBeNull();
    expect(upstreamHeaders.get("x-cerebro-user-subject")).toBeNull();
    expect(upstreamBody).toBe(body);
  });

  it.each([
    ["PATCH", PATCH],
    ["PUT", PUT],
  ] as const)("does not read a %s body before authorization", async (method, handler) => {
    process.env.CEREBRO_IDENTITY_REQUIRED = "true";
    process.env.CEREBRO_LOCAL_IDENTITY_FALLBACK = "false";
    const request = new NextRequest("http://localhost/api/cerebro/grc/findings/finding-1", {
      method,
      body: JSON.stringify({ status: "resolved" }),
    });
    const readBody = vi.spyOn(request, "text");

    const response = await handler(request, {
      params: Promise.resolve({ path: ["grc", "findings", "finding-1"] }),
    });

    expect(response.status).toBe(401);
    expect(readBody).not.toHaveBeenCalled();
  });
});
