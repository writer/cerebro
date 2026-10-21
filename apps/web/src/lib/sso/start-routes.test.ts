import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { CurrentUser } from "@/lib/identity";

const state = vi.hoisted(() => ({
  user: null as CurrentUser | null,
  begin: [] as ({ actor: string } | null)[],
}));

vi.mock("@/lib/identity-server", () => ({
  resolveCurrentUserFromHeadersWithFallback: vi.fn(async () => state.user),
  currentUserServerAuditFields: vi.fn(() => ({})),
}));

vi.mock("@/lib/sso/start", () => ({
  beginSsoLogin: vi.fn(async (_request: NextRequest, testLogin: { actor: string } | null) => {
    state.begin.push(testLogin);
    return new Response(null, { status: 302 });
  }),
}));

const startRoute = await import("@/app/api/auth/sso/start/route");
const testRoute = await import("@/app/api/auth/sso/test/route");

const user = (roles: string[]): CurrentUser => ({
  actorId: "subject",
  actorLabel: "user@example.com",
  confidence: "signature-verified",
  displayName: "User",
  email: "user@example.com",
  initials: "US",
  provider: "oidc",
  source: "sso-session",
  subject: "subject",
  entitlements: { roles },
});

const originalIdentityRequired = process.env.CEREBRO_IDENTITY_REQUIRED;

beforeEach(() => {
  state.user = null;
  state.begin = [];
  process.env.CEREBRO_IDENTITY_REQUIRED = "1";
  vi.spyOn(console, "warn").mockImplementation(() => undefined);
});

afterEach(() => {
  if (originalIdentityRequired === undefined) delete process.env.CEREBRO_IDENTITY_REQUIRED;
  else process.env.CEREBRO_IDENTITY_REQUIRED = originalIdentityRequired;
  vi.restoreAllMocks();
});

const request = (path: string) => new NextRequest(`https://cerebro.example.com${path}`);

describe("SSO start routes", () => {
  it("never starts a test sign-in from the public start route", async () => {
    await startRoute.GET(request("/api/auth/sso/start?connection=conn-1&test=1"));
    expect(state.begin).toEqual([null]);
  });

  it("refuses test sign-ins from anonymous callers and non-admins", async () => {
    expect((await testRoute.GET(request("/api/auth/sso/test?connection=conn-1"))).status).toBe(401);
    state.user = user(["viewer"]);
    expect((await testRoute.GET(request("/api/auth/sso/test?connection=conn-1"))).status).toBe(403);
    expect(state.begin).toEqual([]);
  });

  it("starts a test sign-in for identity admins and records the actor", async () => {
    state.user = user(["cerebro.admin"]);
    expect((await testRoute.GET(request("/api/auth/sso/test?connection=conn-1"))).status).toBe(302);
    expect(state.begin).toHaveLength(1);
    expect(state.begin[0]?.actor).toBeTruthy();
  });
});
