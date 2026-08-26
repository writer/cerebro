import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { isCerebroFixtureMode } from "@/lib/cerebro-fixtures";
import { GET } from "./route";

vi.mock("@/lib/cerebro-fixtures", () => ({
  isCerebroFixtureMode: vi.fn(() => false),
}));

const originalIdentityProfile = process.env.CEREBRO_IDENTITY_PROFILE;
const originalTrustedHeaders = process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS;

describe("audit events API", () => {
  beforeEach(() => {
    delete process.env.CEREBRO_IDENTITY_PROFILE;
    process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS = "x-user-email";
    vi.mocked(isCerebroFixtureMode).mockReturnValue(false);
  });

  afterEach(() => {
    if (originalIdentityProfile === undefined) delete process.env.CEREBRO_IDENTITY_PROFILE;
    else process.env.CEREBRO_IDENTITY_PROFILE = originalIdentityProfile;
    if (originalTrustedHeaders === undefined) delete process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS;
    else process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS = originalTrustedHeaders;
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it("requires a reader identity before calling the audit event adapter", async () => {
    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);

    const response = await GET(new NextRequest("http://localhost/api/audit-log"));

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toMatchObject({
      code: "identity_missing",
      permission: "cerebro:read",
    });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("still requires a reader identity in fixture mode", async () => {
    vi.mocked(isCerebroFixtureMode).mockReturnValue(true);
    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);

    const response = await GET(new NextRequest("http://localhost/api/audit-log"));

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toMatchObject({ code: "identity_missing" });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("still enforces reader entitlements in fixture mode", async () => {
    vi.mocked(isCerebroFixtureMode).mockReturnValue(true);
    vi.stubEnv("CEREBRO_AUTHZ_READ_ROLES", "auditor");
    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);

    const response = await GET(new NextRequest(
      "http://localhost/api/audit-log",
      { headers: { "x-user-email": "reader@example.com" } },
    ));

    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({ code: "entitlement_missing" });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("returns normalized events from the provider-neutral contract", async () => {
    const fetcher = vi.fn<typeof fetch>(async () => new Response(JSON.stringify({
      events: [{
        action: "resource.updated",
        actor: { id: "actor-1", kind: "user" },
        id: "event-1",
        occurred_at: "2026-07-18T08:00:00Z",
        outcome: "completed",
        resource: { id: "resource-1", type: "repository" },
        service: "service-a",
      }],
    }), {
      headers: { "content-type": "application/json" },
      status: 200,
    }));
    vi.stubGlobal("fetch", fetcher);

    const response = await GET(new NextRequest(
      "http://localhost/api/audit-log?limit=9000&minutes=1&service=service-a",
      { headers: { "x-user-email": "reader@example.com" } },
    ));
    const payload = await response.json();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("private, no-store");
    expect(payload).toMatchObject({
      events: [{ id: "event-1", outcome: "success", service: "service-a" }],
      summary: { total: 1 },
    });
    const [target] = fetcher.mock.calls[0];
    const requested = new URL(String(target));
    expect(requested.pathname).toBe("/platform/audit-events");
    expect(requested.searchParams.get("limit")).toBe("500");
    expect(requested.searchParams.get("minutes")).toBe("5");
    expect(requested.searchParams.get("service")).toBe("service-a");
  });

  it("returns an authorized empty page without an upstream request in fixture mode", async () => {
    vi.mocked(isCerebroFixtureMode).mockReturnValue(true);
    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);

    const response = await GET(new NextRequest(
      "http://localhost/api/audit-log",
      { headers: { "x-user-email": "reader@example.com" } },
    ));

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      events: [],
      status: "complete",
      summary: { total: 0 },
    });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("rejects an unsupported workspace selector before fixture or upstream reads", async () => {
    vi.mocked(isCerebroFixtureMode).mockReturnValue(true);
    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);

    const response = await GET(new NextRequest(
      "http://localhost/api/audit-log?tenant_id=tenant-a&workspace_id=workspace-a",
      { headers: { "x-user-email": "reader@example.com" } },
    ));

    expect(response.status).toBe(400);
    expect(response.headers.get("cache-control")).toBe("private, no-store");
    await expect(response.json()).resolves.toMatchObject({
      error: "Workspace scope is not supported for this Cerebro route.",
    });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("does not expose upstream response details", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(
      "provider-specific failure detail",
      { status: 500 },
    )));

    const response = await GET(new NextRequest(
      "http://localhost/api/audit-log",
      { headers: { "x-user-email": "reader@example.com" } },
    ));
    const payload = await response.json();

    expect(response.status).toBe(502);
    expect(payload).toEqual({ error: "Audit events are unavailable." });
    expect(JSON.stringify(payload)).not.toContain("provider-specific");
  });
});
