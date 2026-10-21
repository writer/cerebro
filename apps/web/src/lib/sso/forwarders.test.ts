import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { CurrentUser } from "@/lib/identity";

const state = vi.hoisted(() => ({
  user: null as CurrentUser | null,
  calls: [] as { method: string; path: string; options: { search?: string; body?: string; headers?: Record<string, string> } }[],
  response: { status: 200, body: "{}", contentType: "application/json" },
  currentPolicyEnforced: false,
  session: null as null | { connectionId: string },
  connectionStatus: "active" as string | null,
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
  fetchSsoPolicy: vi.fn(async () => ({ enforced: state.currentPolicyEnforced, sessionMaxLifetimeMinutes: 720, sessionIdleTimeoutMinutes: 60 })),
  fetchSsoConnection: vi.fn(async (id: string) => (state.connectionStatus ? { id, status: state.connectionStatus } : null)),
}));

vi.mock("@/lib/sso/session", () => ({
  resolveSsoSessionFromHeaders: vi.fn(async () =>
    state.session ? { session: { id: "s1", connectionId: state.session.connectionId }, tokenHash: "h" } : null,
  ),
}));

const { forwardAdminIdentityRequest } = await import("./admin-routes");
const scimRoute = await import("@/app/scim/v2/[...path]/route");
const spInfoRoute = await import("@/app/api/admin/identity/sp-info/route");
const discoverRoute = await import("@/app/api/admin/identity/oidc/discover/route");
const parseMetadataRoute = await import("@/app/api/admin/identity/saml/parse-metadata/route");

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

const PUBLIC_ORIGIN = "https://cerebro.example.com";

beforeEach(() => {
  state.user = null;
  state.calls = [];
  state.response = { status: 200, body: "{}", contentType: "application/json" };
  state.currentPolicyEnforced = false;
  state.session = { connectionId: "conn-1" };
  state.connectionStatus = "active";
  process.env.CEREBRO_IDENTITY_REQUIRED = "1";
  process.env.CEREBRO_WEB_PUBLIC_URL = PUBLIC_ORIGIN;
  vi.spyOn(console, "warn").mockImplementation(() => undefined);
});

afterEach(() => {
  if (originalIdentityRequired === undefined) delete process.env.CEREBRO_IDENTITY_REQUIRED;
  else process.env.CEREBRO_IDENTITY_REQUIRED = originalIdentityRequired;
  if (originalPublicUrl === undefined) delete process.env.CEREBRO_WEB_PUBLIC_URL;
  else process.env.CEREBRO_WEB_PUBLIC_URL = originalPublicUrl;
  vi.restoreAllMocks();
});

const adminRequest = (method: string, path: string, body?: unknown, headers: Record<string, string> = {}) =>
  new Request(`${PUBLIC_ORIGIN}/api/admin/identity/${path}`, {
    method,
    headers: {
      ...(method === "GET" ? {} : { origin: PUBLIC_ORIGIN, "content-type": "application/json" }),
      ...headers,
    },
    ...(body === undefined ? {} : { body: typeof body === "string" ? body : JSON.stringify(body) }),
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

describe("admin identity write guards", () => {
  it("refuses cross-origin writes and writes without an Origin or same-origin fetch metadata", async () => {
    state.user = ssoUser(["cerebro.admin"]);
    const crossSite = await forwardAdminIdentityRequest(
      adminRequest("PUT", "policy", { enforced: false }, { origin: "https://evil.example.com" }),
      ["policy"],
    );
    expect(crossSite.status).toBe(403);
    const noOrigin = new Request(`${PUBLIC_ORIGIN}/api/admin/identity/connections/conn-1`, { method: "DELETE" });
    expect((await forwardAdminIdentityRequest(noOrigin, ["connections", "conn-1"])).status).toBe(403);
    expect(state.calls).toHaveLength(0);
  });

  it("refuses non-JSON writes, which browsers send cross-site without a preflight", async () => {
    state.user = ssoUser(["cerebro.admin"]);
    const plain = await forwardAdminIdentityRequest(
      adminRequest("PUT", "policy", JSON.stringify({ enforced: false }), { "content-type": "text/plain" }),
      ["policy"],
    );
    expect(plain.status).toBe(415);
    const bodiless = await forwardAdminIdentityRequest(
      new Request(`${PUBLIC_ORIGIN}/api/admin/identity/connections/conn-1`, { method: "DELETE", headers: { origin: PUBLIC_ORIGIN } }),
      ["connections", "conn-1"],
    );
    expect(bodiless.status).toBe(415);
    expect(state.calls).toHaveLength(0);
  });

  it("applies the same guards to discovery and metadata import", async () => {
    state.user = ssoUser(["cerebro.admin"]);
    const crossSite = (path: string) =>
      new NextRequest(`${PUBLIC_ORIGIN}/api/admin/identity/${path}`, {
        method: "POST",
        headers: { origin: "https://evil.example.com", "content-type": "application/json" },
        body: JSON.stringify({ issuer: "https://idp.example.com", url: "https://idp.example.com/metadata" }),
      });
    expect((await discoverRoute.POST(crossSite("oidc/discover"))).status).toBe(403);
    expect((await parseMetadataRoute.POST(crossSite("saml/parse-metadata"))).status).toBe(403);
    const plain = new NextRequest(`${PUBLIC_ORIGIN}/api/admin/identity/oidc/discover`, {
      method: "POST",
      headers: { origin: PUBLIC_ORIGIN, "content-type": "text/plain" },
      body: JSON.stringify({ issuer: "https://idp.example.com" }),
    });
    expect((await discoverRoute.POST(plain)).status).toBe(415);
  });

  it("refuses to turn on enforcement for an admin signed in through proxy headers", async () => {
    state.user = { ...ssoUser(["cerebro.admin"]), source: "headers" };
    const response = await forwardAdminIdentityRequest(adminRequest("PUT", "policy", { enforced: true }), ["policy"]);
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({ code: "sso_session_required" });
    expect(state.calls).toHaveLength(0);
  });

  it("refuses to turn on enforcement when the admin's session connection is no longer active", async () => {
    state.user = ssoUser(["cerebro.admin"]);
    state.connectionStatus = "disabled";
    expect((await forwardAdminIdentityRequest(adminRequest("PUT", "policy", { enforced: true }), ["policy"])).status).toBe(409);
    state.connectionStatus = null;
    expect((await forwardAdminIdentityRequest(adminRequest("PUT", "policy", { enforced: true }), ["policy"])).status).toBe(409);
    state.connectionStatus = "active";
    state.session = null;
    expect((await forwardAdminIdentityRequest(adminRequest("PUT", "policy", { enforced: true }), ["policy"])).status).toBe(409);
    expect(state.calls).toHaveLength(0);
  });

  it("lets a header-authenticated admin edit an already enforced policy (break-glass recovery)", async () => {
    state.user = { ...ssoUser(["cerebro.admin"]), source: "headers" };
    state.currentPolicyEnforced = true;
    expect((await forwardAdminIdentityRequest(adminRequest("PUT", "policy", { enforced: true }), ["policy"])).status).toBe(200);
    state.currentPolicyEnforced = false;
    expect((await forwardAdminIdentityRequest(adminRequest("PUT", "policy", { enforced: false }), ["policy"])).status).toBe(200);
  });

  it("strips client-supplied tenant selectors from the body", async () => {
    state.user = ssoUser(["cerebro.admin"]);
    await forwardAdminIdentityRequest(
      adminRequest("POST", "connections", { name: "x", tenant_id: "other-tenant", tenantId: "other-tenant" }),
      ["connections"],
    );
    const body = JSON.parse(state.calls[0].options.body ?? "{}");
    expect(body).not.toHaveProperty("tenant_id");
    expect(body).not.toHaveProperty("tenantId");
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
