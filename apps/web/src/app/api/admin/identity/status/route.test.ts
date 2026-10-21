import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { DEFAULT_SSO_POLICY } from "@/lib/sso/types";

const state = vi.hoisted(() => ({
  enforcement: { enforced: false, unknown: false, unavailable: false, breakGlass: false },
  policyEnforced: false,
}));

vi.mock("@/lib/sso/admin-auth", () => ({
  authorizeIdentityRequest: vi.fn(async () => ({ ok: true, user: null })),
}));

vi.mock("@/lib/sso/policy", () => ({
  getSsoEnforcement: vi.fn(async () => ({ ...state.enforcement, policy: { ...DEFAULT_SSO_POLICY, enforced: state.policyEnforced } })),
  getCachedSsoConnections: vi.fn(async () => []),
}));

const { GET } = await import("./route");

const original = process.env.CEREBRO_SSO_REQUIRED;

beforeEach(() => {
  delete process.env.CEREBRO_SSO_REQUIRED;
  state.enforcement = { enforced: false, unknown: false, unavailable: false, breakGlass: false };
  state.policyEnforced = false;
});

afterEach(() => {
  if (original === undefined) delete process.env.CEREBRO_SSO_REQUIRED;
  else process.env.CEREBRO_SSO_REQUIRED = original;
});

const status = async () => (await GET(new NextRequest("https://cerebro.example.com/api/admin/identity/status"))).json();

describe("identity status", () => {
  it("reports unavailable instead of off when SSO cannot be used", async () => {
    state.enforcement = { enforced: false, unknown: false, unavailable: true, breakGlass: false };
    await expect(status()).resolves.toMatchObject({ state: "unavailable", enforced: false, legacyIdentityActive: true });
  });

  it("reports off, enforced, and unknown states", async () => {
    await expect(status()).resolves.toMatchObject({ state: "off", enforced: false });
    state.policyEnforced = true;
    state.enforcement = { enforced: true, unknown: false, unavailable: false, breakGlass: false };
    await expect(status()).resolves.toMatchObject({ state: "enforced", enforced: true, legacyIdentityActive: false });
    state.enforcement = { enforced: true, unknown: true, unavailable: false, breakGlass: false };
    await expect(status()).resolves.toMatchObject({ state: "unknown", legacyIdentityActive: false });
  });
});
