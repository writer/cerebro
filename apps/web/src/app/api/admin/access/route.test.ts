import { NextRequest } from "next/server";
import { afterEach, describe, expect, it } from "vitest";

import { GET } from "./route";

const originalFixtureMode = process.env.CEREBRO_WEB_FIXTURE_MODE;
const originalApiBase = process.env.CEREBRO_API_BASE;
const originalMappings = process.env.CEREBRO_AUTHZ_ROLE_CLAIM_MAPPINGS;

const restore = (key: string, value: string | undefined) => {
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
};

afterEach(() => {
  restore("CEREBRO_WEB_FIXTURE_MODE", originalFixtureMode);
  restore("CEREBRO_API_BASE", originalApiBase);
  restore("CEREBRO_AUTHZ_ROLE_CLAIM_MAPPINGS", originalMappings);
});

const get = async () => GET(new NextRequest("http://localhost/api/admin/access"));

describe("admin access control fixture mode", () => {
  it("answers without an identity so the console is usable with no backend", async () => {
    process.env.CEREBRO_WEB_FIXTURE_MODE = "1";
    delete process.env.CEREBRO_AUTHZ_ROLE_CLAIM_MAPPINGS;

    const payload = await (await get()).json();

    expect(payload.roles.length).toBeGreaterThan(0);
    expect(payload.permissions.length).toBeGreaterThan(0);
    expect(payload.viewer.entitlements.roles).toContain("cerebro.admin");
  });

  it("shows sample mappings so the claim model is visible before any stack config exists", async () => {
    process.env.CEREBRO_WEB_FIXTURE_MODE = "1";
    delete process.env.CEREBRO_AUTHZ_ROLE_CLAIM_MAPPINGS;

    const payload = await (await get()).json();

    expect(payload.roleClaimMappings.length).toBeGreaterThan(0);
    expect(payload.roleClaimMappings.every((mapping: { claim: string }) => mapping.claim === "groups")).toBe(true);
  });

  it("prefers real configured mappings over the samples", async () => {
    process.env.CEREBRO_WEB_FIXTURE_MODE = "1";
    process.env.CEREBRO_AUTHZ_ROLE_CLAIM_MAPPINGS = JSON.stringify({ groups: { Platform: ["cerebro.viewer"] } });

    const payload = await (await get()).json();

    expect(payload.roleClaimMappings).toEqual([{ claim: "groups", roles: ["cerebro.viewer"], value: "platform" }]);
  });

  it("renders sample values the way real parsed mappings render, lowercased", async () => {
    process.env.CEREBRO_WEB_FIXTURE_MODE = "1";
    delete process.env.CEREBRO_AUTHZ_ROLE_CLAIM_MAPPINGS;

    const payload = await (await get()).json();

    for (const mapping of payload.roleClaimMappings as { value: string }[]) {
      expect(mapping.value).toBe(mapping.value.toLowerCase());
    }
  });

  it("grants the admin bundle rather than silently granting every permission", async () => {
    process.env.CEREBRO_WEB_FIXTURE_MODE = "1";

    const payload = await (await get()).json();
    const admin = payload.roles.find((role: { role: string }) => role.role === "cerebro.admin");
    const granted = payload.permissions.filter((entry: { granted: boolean }) => entry.granted);

    expect(granted).toHaveLength(admin.permissions.length);
  });

  it("carries no real organization group names", async () => {
    process.env.CEREBRO_WEB_FIXTURE_MODE = "1";

    const body = JSON.stringify(await (await get()).json());

    expect(body).not.toMatch(/DEPT\s*-\s*SECURITY/i);
  });

  it("stays off unless fixture mode is asked for", async () => {
    delete process.env.CEREBRO_WEB_FIXTURE_MODE;
    delete process.env.CEREBRO_API_BASE;

    const payload = await (await get()).json();

    expect(payload.viewer?.entitlements?.roles ?? []).not.toContain("cerebro.admin");
  });
});
