import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { GET } from "./route";

const originalIdentityProfile = process.env.CEREBRO_IDENTITY_PROFILE;
const originalTrustedHeaders = process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS;

describe("audit events API", () => {
  beforeEach(() => {
    delete process.env.CEREBRO_IDENTITY_PROFILE;
    process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS = "x-user-email";
  });

  afterEach(() => {
    if (originalIdentityProfile === undefined) delete process.env.CEREBRO_IDENTITY_PROFILE;
    else process.env.CEREBRO_IDENTITY_PROFILE = originalIdentityProfile;
    if (originalTrustedHeaders === undefined) delete process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS;
    else process.env.CEREBRO_TRUSTED_IDENTITY_HEADERS = originalTrustedHeaders;
    vi.unstubAllGlobals();
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

  it("returns normalized events from the provider-neutral contract", async () => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify({
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
