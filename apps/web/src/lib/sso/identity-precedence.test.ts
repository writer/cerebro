import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { DEFAULT_SSO_POLICY, type SSOSession } from "./types";

const enforcement = vi.hoisted(() => ({
  state: { enforced: false, unknown: false, breakGlass: false } as { enforced: boolean; unknown: boolean; breakGlass: boolean },
}));
const sessions = vi.hoisted(() => ({ byHash: new Map<string, unknown>(), lookups: 0 }));

vi.mock("@/lib/sso/policy", () => ({
  getSsoEnforcement: vi.fn(async () => ({ ...enforcement.state, policy: DEFAULT_SSO_POLICY })),
  getCachedSsoConnections: vi.fn(async () => [{ id: "conn-1", protocol: "saml", domains: ["example.com"], status: "active" }]),
  clearSsoPolicyCache: vi.fn(),
}));

vi.mock("@/lib/sso/identity-api", () => ({
  lookupSsoSession: vi.fn(async (hash: string) => {
    sessions.lookups += 1;
    return sessions.byHash.get(hash) ?? null;
  }),
}));

const { generateSessionToken, sessionTokenHash } = await import("./cookies");
const { clearSsoSessionCache } = await import("./session");
const { identityHealthFromHeaders, resolveCurrentUserFromHeaders, resolveCurrentUserFromHeadersWithFallback } = await import("@/lib/identity-server");
const { proxy } = await import("@/proxy");

const envNames = ["CEREBRO_TRUSTED_IDENTITY_HEADERS", "CEREBRO_LOCAL_IDENTITY_FALLBACK", "CEREBRO_IDENTITY_PROFILE"];
const originalEnv = new Map(envNames.map((name) => [name, process.env[name]]));

const token = generateSessionToken();
const tokenHash = sessionTokenHash(token);
const liveSession: SSOSession = {
  id: "session-1",
  connectionId: "conn-1",
  subject: "sso-subject",
  email: "sso.user@example.com",
  name: "Sso User",
  groups: ["security"],
  roles: ["viewer"],
  createdAt: "2026-01-01T00:00:00Z",
  lastSeenAt: "2026-01-01T00:00:00Z",
  expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
  idleTimeoutMinutes: 60,
};

const proxyHeaders = {
  "x-okta-email": "header.user@example.com",
  "x-okta-user": "header.user",
};

beforeEach(() => {
  process.env.CEREBRO_IDENTITY_PROFILE = "okta-proxy";
  enforcement.state = { enforced: false, unknown: false, breakGlass: false };
  sessions.byHash.clear();
  sessions.byHash.set(tokenHash, liveSession);
  sessions.lookups = 0;
  clearSsoSessionCache();
});

afterEach(() => {
  for (const name of envNames) {
    const original = originalEnv.get(name);
    if (original === undefined) delete process.env[name];
    else process.env[name] = original;
  }
});

const withSession = (extra: Record<string, string> = {}) =>
  new Headers({ cookie: `__Host-cerebro_session=${token}`, ...extra });

describe("identity precedence", () => {
  it("prefers the SSO session cookie over proxy headers", async () => {
    const user = await resolveCurrentUserFromHeaders(withSession(proxyHeaders));
    expect(user).toMatchObject({
      source: "sso-session",
      provider: "saml",
      email: "sso.user@example.com",
      confidence: "signature-verified",
    });
    expect(user?.entitlements?.roles).toEqual(["viewer"]);
  });

  it("falls back to proxy headers when SSO is not enforced and no session exists", async () => {
    const user = await resolveCurrentUserFromHeaders(new Headers(proxyHeaders));
    expect(user?.source).toBe("headers");
  });

  it("ignores proxy headers and the local fallback when SSO is enforced", async () => {
    enforcement.state = { enforced: true, unknown: false, breakGlass: false };
    process.env.CEREBRO_LOCAL_IDENTITY_FALLBACK = "1";
    await expect(resolveCurrentUserFromHeaders(new Headers(proxyHeaders))).resolves.toBeNull();
    await expect(resolveCurrentUserFromHeadersWithFallback(new Headers())).resolves.toBeNull();
    await expect(resolveCurrentUserFromHeaders(withSession(proxyHeaders))).resolves.toMatchObject({ source: "sso-session" });
  });

  it("fails closed when the policy cannot be read", async () => {
    enforcement.state = { enforced: true, unknown: true, breakGlass: false };
    await expect(resolveCurrentUserFromHeaders(new Headers(proxyHeaders))).resolves.toBeNull();
    const health = await identityHealthFromHeaders(new Headers(proxyHeaders));
    expect(health.issues).toContain("sso-policy-unavailable");
  });

  it("accepts legacy headers again under break-glass and reports it", async () => {
    enforcement.state = { enforced: false, unknown: false, breakGlass: true };
    await expect(resolveCurrentUserFromHeaders(new Headers(proxyHeaders))).resolves.toMatchObject({ source: "headers" });
    const health = await identityHealthFromHeaders(new Headers(proxyHeaders));
    expect(health.issues).toContain("sso-break-glass-active");
  });

  it("treats revoked, expired, and malformed cookies as no session", async () => {
    enforcement.state = { enforced: true, unknown: false, breakGlass: false };
    sessions.byHash.clear();
    await expect(resolveCurrentUserFromHeaders(withSession())).resolves.toBeNull();

    clearSsoSessionCache();
    sessions.byHash.set(tokenHash, { ...liveSession, expiresAt: new Date(Date.now() - 1000).toISOString() });
    await expect(resolveCurrentUserFromHeaders(withSession())).resolves.toBeNull();

    const before = sessions.lookups;
    await expect(resolveCurrentUserFromHeaders(new Headers({ cookie: "__Host-cerebro_session=not-a-token" }))).resolves.toBeNull();
    expect(sessions.lookups).toBe(before);
  });

  it("does not accept the session under the non-prefixed cookie name outside development", async () => {
    enforcement.state = { enforced: true, unknown: false, breakGlass: false };
    await expect(resolveCurrentUserFromHeaders(new Headers({ cookie: `cerebro_session=${token}` }))).resolves.toBeNull();
  });
});

const documentRequest = (path: string, headers?: Record<string, string>) =>
  new NextRequest(new URL(path, "http://localhost:3000"), { method: "GET", headers });

describe("proxy SSO enforcement", () => {
  it("redirects document requests without a session to /login with a returnTo", async () => {
    enforcement.state = { enforced: true, unknown: false, breakGlass: false };
    const response = await proxy(documentRequest("/findings?status=open"));
    expect(response.status).toBe(307);
    const location = new URL(response.headers.get("location") ?? "");
    expect(location.pathname).toBe("/login");
    expect(location.searchParams.get("returnTo")).toBe("/findings?status=open");
  });

  it("lets sessions, the login page, and API routes through", async () => {
    enforcement.state = { enforced: true, unknown: false, breakGlass: false };
    expect((await proxy(documentRequest("/findings", { cookie: `__Host-cerebro_session=${token}` }))).status).toBe(200);
    expect((await proxy(documentRequest("/login"))).status).toBe(200);
    expect((await proxy(documentRequest("/oauth2/idpresponse?code=x&state=y"))).status).toBe(200);
    expect((await proxy(documentRequest("/api/me"))).status).toBe(200);
  });

  it("does not redirect when SSO is not enforced or the policy is unknown", async () => {
    expect((await proxy(documentRequest("/findings"))).status).toBe(200);
    enforcement.state = { enforced: true, unknown: true, breakGlass: false };
    expect((await proxy(documentRequest("/findings"))).status).toBe(200);
  });
});
