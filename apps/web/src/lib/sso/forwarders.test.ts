import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { CurrentUser } from "@/lib/identity";

const state = vi.hoisted(() => ({
  user: null as CurrentUser | null,
  calls: [] as { method: string; path: string; options: { search?: string; body?: string; headers?: Record<string, string> } }[],
  response: { status: 200, body: "{}", contentType: "application/json" },
}));

vi.mock("@/lib/identity-server", () => ({
  resolveCurrentUserFromHeadersWithFallback: vi.fn(async () => state.user),
  currentUserServerAuditFields: vi.fn(() => ({})),
}));

vi.mock("@/lib/sso/identity-api", () => ({
  identityApiRequest: vi.fn(async (method: string, path: string, options: Record<string, unknown> = {}) => {
    state.calls.push({ method, path, options });
    return state.response;
  }),
}));

const { forwardAdminIdentityRequest } = await import("./admin-routes");
const scimRoute = await import("@/app/scim/v2/[...path]/route");
const spInfoRoute = await import("@/app/api/admin/identity/sp-info/route");

const ssoUser = (roles: string[]): CurrentUser => ({
  actorId: "admin-subject",
  actorLabel: "admin@example.com",
  confidence: "signature-verified",
  displayName: "Admin",
  email: "admin@example.com",
  initials: "AD",
  provider: "oidc",
  source: "sso-session",
  subject: "admin-subject",
  entitlements: { roles },
});

const originalIdentityRequired = process.env.CEREBRO_IDENTITY_REQUIRED;
const originalPublicUrl = process.env.CEREBRO_WEB_PUBLIC_URL;

beforeEach(() => {
  state.user = null;
  state.calls = [];
  state.response = { status: 200, body: "{}", contentType: "application/json" };
  process.env.CEREBRO_IDENTITY_REQUIRED = "1";
  vi.spyOn(console, "warn").mockImplementation(() => undefined);
});

afterEach(() => {
  if (originalIdentityRequired === undefined) delete process.env.CEREBRO_IDENTITY_REQUIRED;
  else process.env.CEREBRO_IDENTITY_REQUIRED = originalIdentityRequired;
  if (originalPublicUrl === undefined) delete process.env.CEREBRO_WEB_PUBLIC_URL;
  else process.env.CEREBRO_WEB_PUBLIC_URL = originalPublicUrl;
  vi.restoreAllMocks();
});

const adminRequest = (method: string, path: string, body?: unknown) =>
  new Request(`http://localhost/api/admin/identity/${path}`, {
    method,
    ...(body === undefined ? {} : { body: JSON.stringify(body), headers: { "content-type": "application/json" } }),
  });

describe("admin identity forwarder", () => {
  it("rejects unauthenticated callers before reaching Go", async () => {
    const response = await forwardAdminIdentityRequest(adminRequest("GET", "connections"), ["connections"]);
    expect(response.status).toBe(401);
    expect(state.calls).toHaveLength(0);
  });

  it("denies writes to users without identity:admin", async () => {
    state.user = ssoUser(["cerebro.analyst"]);
    const response = await forwardAdminIdentityRequest(adminRequest("PUT", "policy", { enforced: true }), ["policy"]);
    expect(response.status).toBe(403);
    expect(state.calls).toHaveLength(0);
  });

  it("forwards admin writes with the acting user stamped over any client value", async () => {
    state.user = ssoUser(["cerebro.admin"]);
    const response = await forwardAdminIdentityRequest(
      adminRequest("PUT", "policy", { enforced: true, updatedBy: "someone-else" }),
      ["policy"],
    );
    expect(response.status).toBe(200);
    expect(state.calls).toEqual([
      expect.objectContaining({ method: "PUT", path: "sso/policy" }),
    ]);
    expect(JSON.parse(state.calls[0].options.body ?? "{}")).toEqual({ enforced: true, updatedBy: "admin-subject" });
  });

  it("refuses unknown paths, wrong methods, and admin-posted successful tests", async () => {
    state.user = ssoUser(["cerebro.admin"]);
    expect((await forwardAdminIdentityRequest(adminRequest("GET", "sessions/lookup"), ["sessions", "lookup"])).status).toBe(404);
    expect((await forwardAdminIdentityRequest(adminRequest("GET", "../../graph"), ["..", "..", "graph"])).status).toBe(404);
    expect((await forwardAdminIdentityRequest(adminRequest("DELETE", "policy"), ["policy"])).status).toBe(405);
    const forged = await forwardAdminIdentityRequest(
      adminRequest("POST", "connections/conn-1/test-result", { ok: true }),
      ["connections", "conn-1", "test-result"],
    );
    expect(forged.status).toBe(400);
    expect(state.calls).toHaveLength(0);
  });
});

const scimRequest = (method: string, path: string, init: { headers?: Record<string, string>; body?: string } = {}) =>
  new NextRequest(`https://cerebro.example.com/scim/v2/${path}`, { method, ...init });

const scimContext = (path: string[]) => ({ params: Promise.resolve({ path }) });

describe("SCIM forwarder", () => {
  it("requires a bearer token", async () => {
    const response = await scimRoute.GET(scimRequest("GET", "Users"), scimContext(["Users"]));
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toContain("Bearer");
    expect(state.calls).toHaveLength(0);
  });

  it("moves the bearer token to X-Cerebro-SCIM-Token and keeps the query", async () => {
    state.response = { status: 200, body: '{"Resources":[]}', contentType: "application/json" };
    const response = await scimRoute.GET(
      scimRequest("GET", "Users?filter=userName%20eq%20%22a%40example.com%22", {
        headers: { authorization: "Bearer scim-token-value", cookie: "__Host-cerebro_session=x" },
      }),
      scimContext(["Users"]),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/scim+json");
    expect(state.calls).toHaveLength(1);
    const call = state.calls[0];
    expect(call.path).toBe("scim/v2/Users");
    expect(call.options.search).toContain("filter=");
    expect(call.options.headers?.["X-Cerebro-SCIM-Token"]).toBe("scim-token-value");
    const forwardedNames = Object.keys(call.options.headers ?? {}).map((name) => name.toLowerCase());
    expect(forwardedNames).not.toContain("authorization");
    expect(forwardedNames).not.toContain("cookie");
  });

  it("forwards SCIM bodies as application/scim+json", async () => {
    state.response = { status: 201, body: '{"id":"u1"}', contentType: "application/scim+json" };
    const body = JSON.stringify({ userName: "a@example.com" });
    const response = await scimRoute.POST(
      scimRequest("POST", "Users", { headers: { authorization: "Bearer t", "content-type": "application/json" }, body }),
      scimContext(["Users"]),
    );
    expect(response.status).toBe(201);
    expect(state.calls[0].options.body).toBe(body);
    expect(state.calls[0].options.headers?.["Content-Type"]).toBe("application/scim+json");
  });

  it("rejects traversal segments", async () => {
    const response = await scimRoute.GET(
      scimRequest("GET", "Users", { headers: { authorization: "Bearer t" } }),
      scimContext(["..", "sessions"]),
    );
    expect(response.status).toBe(404);
    expect(state.calls).toHaveLength(0);
  });
});

describe("SP info", () => {
  it("returns connection-independent SP values before a connection exists", async () => {
    state.user = ssoUser(["cerebro.admin"]);
    process.env.CEREBRO_WEB_PUBLIC_URL = "https://cerebro.example.com";
    const response = await spInfoRoute.GET(new NextRequest("https://attacker.example.com/api/admin/identity/sp-info"));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      redirectUri: "https://cerebro.example.com/api/auth/oidc/callback",
      acsUrl: "https://cerebro.example.com/api/auth/saml/acs",
      entityId: "https://cerebro.example.com/api/auth/saml/metadata",
      metadataUrl: "https://cerebro.example.com/api/auth/saml/metadata",
      initiateLoginUrl: "",
      scimBaseUrl: "https://cerebro.example.com/scim/v2",
    });
    const withConnection = await spInfoRoute.GET(new NextRequest("https://cerebro.example.com/api/admin/identity/sp-info?connection=conn-1"));
    expect((await withConnection.json()).initiateLoginUrl).toBe("https://cerebro.example.com/api/auth/sso/start?connection=conn-1");
  });
});
