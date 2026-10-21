import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { DEFAULT_SSO_POLICY } from "./types";

const api = vi.hoisted(() => ({
  configured: true,
  policy: null as null | { enforced: boolean },
  fail: false,
  failWith: null as null | { status: number; code: string },
}));

vi.mock("@/lib/cerebro-proxy", () => ({
  getCerebroProxyConfig: () => ({ serverAuthConfigured: api.configured }),
}));

vi.mock("./identity-api", () => {
  class IdentityApiError extends Error {
    constructor(message: string, readonly status: number, readonly code = "") {
      super(message);
    }
  }
  return {
    IdentityApiError,
    fetchSsoConnections: vi.fn(async () => []),
    fetchSsoPolicy: vi.fn(async () => {
      if (api.failWith) throw new IdentityApiError("failed", api.failWith.status, api.failWith.code);
      if (api.fail) throw new Error("unreachable");
      return { ...DEFAULT_SSO_POLICY, ...api.policy };
    }),
  };
});

const { getSsoEnforcement, resetSsoPolicyStateForTests } = await import("./policy");
const { ssoEnforcementActive } = await import("./enforcement-signal");

const POLICY_TTL_MS = 30_000;

const envNames = ["CEREBRO_SSO_REQUIRED", "CEREBRO_SSO_BREAK_GLASS"];
const originalEnv = new Map(envNames.map((name) => [name, process.env[name]]));

beforeEach(() => {
  api.configured = true;
  api.policy = { enforced: false };
  api.fail = false;
  api.failWith = null;
  resetSsoPolicyStateForTests();
});

afterEach(() => {
  for (const name of envNames) {
    const original = originalEnv.get(name);
    if (original === undefined) delete process.env[name];
    else process.env[name] = original;
  }
});

describe("getSsoEnforcement with CEREBRO_SSO_REQUIRED", () => {
  it("follows the stored policy when not required", async () => {
    delete process.env.CEREBRO_SSO_REQUIRED;
    await expect(getSsoEnforcement()).resolves.toMatchObject({ enforced: false, unknown: false });
  });

  it("enforces even when the stored policy is off", async () => {
    process.env.CEREBRO_SSO_REQUIRED = "true";
    await expect(getSsoEnforcement()).resolves.toMatchObject({ enforced: true, unknown: false });
  });

  it("ignores break-glass and fails closed without a service credential", async () => {
    process.env.CEREBRO_SSO_REQUIRED = "true";
    process.env.CEREBRO_SSO_BREAK_GLASS = "true";
    await expect(getSsoEnforcement()).resolves.toMatchObject({ enforced: true, breakGlass: false });
    api.configured = false;
    await expect(getSsoEnforcement()).resolves.toMatchObject({ enforced: true, unknown: true });
  });

  it("fails closed when the policy cannot be read", async () => {
    process.env.CEREBRO_SSO_REQUIRED = "true";
    api.fail = true;
    await expect(getSsoEnforcement()).resolves.toMatchObject({ enforced: true, unknown: true });
  });
});

describe("getSsoEnforcement edge states", () => {
  beforeEach(() => {
    delete process.env.CEREBRO_SSO_REQUIRED;
    delete process.env.CEREBRO_SSO_BREAK_GLASS;
  });

  it("reports unavailable (not off) without a service credential, keeping header identity", async () => {
    api.configured = false;
    await expect(getSsoEnforcement()).resolves.toMatchObject({ enforced: false, unknown: false, unavailable: true });
  });

  it("treats a Go API without an identity store as unavailable, not enforced", async () => {
    api.failWith = { status: 404, code: "identity_sso_unavailable" };
    await expect(getSsoEnforcement()).resolves.toMatchObject({ enforced: false, unavailable: true });
    process.env.CEREBRO_SSO_REQUIRED = "true";
    resetSsoPolicyStateForTests();
    await expect(getSsoEnforcement()).resolves.toMatchObject({ enforced: true, unavailable: true });
  });

  it("fails closed when a fetch error follows an expired non-enforcing cache", async () => {
    const start = 1_000_000;
    await expect(getSsoEnforcement(start)).resolves.toMatchObject({ enforced: false, unknown: false });
    api.fail = true;
    await expect(getSsoEnforcement(start + POLICY_TTL_MS + 1)).resolves.toMatchObject({ enforced: true, unknown: true });
  });

  it("fails closed on any later error, including unavailable, once enforcement was seen", async () => {
    const start = 2_000_000;
    api.policy = { enforced: true };
    await expect(getSsoEnforcement(start)).resolves.toMatchObject({ enforced: true });
    api.policy = { enforced: false };
    await expect(getSsoEnforcement(start + POLICY_TTL_MS + 1)).resolves.toMatchObject({ enforced: false });
    api.failWith = { status: 404, code: "identity_sso_unavailable" };
    await expect(getSsoEnforcement(start + 2 * (POLICY_TTL_MS + 1))).resolves.toMatchObject({ enforced: true, unknown: true });
  });

  it("publishes the decision for synchronous authorization checks", async () => {
    api.policy = { enforced: true };
    await getSsoEnforcement();
    expect(ssoEnforcementActive()).toBe(true);
    process.env.CEREBRO_SSO_BREAK_GLASS = "true";
    await getSsoEnforcement();
    expect(ssoEnforcementActive()).toBe(false);
  });
});
