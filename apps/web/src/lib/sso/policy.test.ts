import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { DEFAULT_SSO_POLICY } from "./types";

const api = vi.hoisted(() => ({ configured: true, policy: null as null | { enforced: boolean }, fail: false }));

vi.mock("@/lib/cerebro-proxy", () => ({
  getCerebroProxyConfig: () => ({ serverAuthConfigured: api.configured }),
}));

vi.mock("./identity-api", () => ({
  IdentityApiError: class extends Error {
    status = 500;
  },
  fetchSsoConnections: vi.fn(async () => []),
  fetchSsoPolicy: vi.fn(async () => {
    if (api.fail) throw new Error("unreachable");
    return { ...DEFAULT_SSO_POLICY, ...api.policy };
  }),
}));

const { clearSsoPolicyCache, getSsoEnforcement } = await import("./policy");

const envNames = ["CEREBRO_SSO_REQUIRED", "CEREBRO_SSO_BREAK_GLASS"];
const originalEnv = new Map(envNames.map((name) => [name, process.env[name]]));

beforeEach(() => {
  api.configured = true;
  api.policy = { enforced: false };
  api.fail = false;
  clearSsoPolicyCache();
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
