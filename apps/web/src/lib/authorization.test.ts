import { afterEach, describe, expect, it } from "vitest";

import { authorizeCurrentUser } from "./authorization";
import type { CurrentUser } from "./identity";

const identityEnvNames = [
  "CEREBRO_AUTHZ_REQUIRED_GROUPS",
  "CEREBRO_AUTHZ_REQUIRED_ROLES",
  "CEREBRO_AUTHZ_REQUIRED_SCOPES",
  "CEREBRO_AUTHZ_BUILTIN_RBAC",
  "CEREBRO_AUTHZ_WRITE_GROUPS",
  "CEREBRO_AUTHZ_WRITE_ROLES",
  "CEREBRO_AUTHZ_WRITE_SCOPES",
  "CEREBRO_AUTHZ_FINDINGS_WRITE_GROUPS",
  "CEREBRO_AUTHZ_FINDINGS_WRITE_ROLES",
  "CEREBRO_AUTHZ_FINDINGS_WRITE_SCOPES",
  "CEREBRO_IDENTITY_REQUIRED",
];

const originalIdentityEnv = new Map(identityEnvNames.map((name) => [name, process.env[name]]));

const user = (overrides: Partial<CurrentUser> = {}): CurrentUser => ({
  actorId: "subject-1",
  actorLabel: "person@example.com",
  confidence: "signature-verified",
  displayName: "Person Example",
  initials: "PE",
  provider: "okta",
  source: "jwt",
  subject: "subject-1",
  ...overrides,
});

afterEach(() => {
  for (const name of identityEnvNames) {
    const original = originalIdentityEnv.get(name);
    if (original === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = original;
    }
  }
});

describe("identity authorization", () => {
  it("allows identity-optional deployments without a current user", () => {
    expect(authorizeCurrentUser(null, "cerebro:read")).toMatchObject({
      allowed: true,
      code: "allowed_without_identity",
    });
  });

  it("fails closed when identity is required and missing", () => {
    process.env.CEREBRO_IDENTITY_REQUIRED = "1";

    expect(authorizeCurrentUser(null, "cerebro:read")).toMatchObject({
      allowed: false,
      code: "identity_missing",
      status: 401,
    });
  });

  it("denies conflicting identity signals before entitlement checks", () => {
    expect(authorizeCurrentUser(user({
      confidence: "conflict",
      conflicts: ["email a@example.com != b@example.com"],
    }), "cerebro:write")).toMatchObject({
      allowed: false,
      code: "identity_conflict",
      status: 409,
    });
  });

  it("does not use unverified claims for configured entitlement policy", () => {
    process.env.CEREBRO_AUTHZ_WRITE_SCOPES = "evidence:write";

    expect(authorizeCurrentUser(user({
      confidence: "unverified",
      entitlements: { scopes: ["evidence:write"] },
    }), "cerebro:write")).toMatchObject({
      allowed: false,
      code: "identity_unverified",
      status: 401,
    });
  });

  it("authorizes with configured roles, groups, and scopes", () => {
    process.env.CEREBRO_AUTHZ_WRITE_GROUPS = "security";
    process.env.CEREBRO_AUTHZ_WRITE_ROLES = "analyst";
    process.env.CEREBRO_AUTHZ_WRITE_SCOPES = "evidence:write";

    expect(authorizeCurrentUser(user({
      entitlements: {
        groups: ["security"],
        roles: ["analyst"],
        scopes: ["evidence:write"],
      },
    }), "cerebro:write")).toMatchObject({
      allowed: true,
      code: "allowed",
    });
  });

  it("denies missing configured entitlements", () => {
    process.env.CEREBRO_AUTHZ_WRITE_GROUPS = "security";

    expect(authorizeCurrentUser(user({
      entitlements: { groups: ["engineering"] },
    }), "cerebro:write")).toMatchObject({
      allowed: false,
      code: "entitlement_missing",
      status: 403,
    });
  });

  it("enforces explicit Cerebro roles as built-in RBAC grants", () => {
    expect(authorizeCurrentUser(user({
      entitlements: { roles: ["cerebro.viewer"] },
    }), "cerebro:read")).toMatchObject({
      allowed: true,
      code: "allowed",
    });

    expect(authorizeCurrentUser(user({
      entitlements: { roles: ["cerebro.viewer"] },
    }), "findings:write")).toMatchObject({
      allowed: false,
      code: "permission_missing",
      status: 403,
    });
  });

  it("expands backend scopes into web permissions", () => {
    expect(authorizeCurrentUser(user({
      entitlements: { scopes: ["cerebro.source_runtimes.write"] },
    }), "source-runtimes:write")).toMatchObject({
      allowed: true,
      code: "allowed",
    });
  });

  it("can enforce backend role aliases when built-in RBAC is enabled", () => {
    process.env.CEREBRO_AUTHZ_BUILTIN_RBAC = "true";

    expect(authorizeCurrentUser(user({
      entitlements: { roles: ["analyst"] },
    }), "findings:write")).toMatchObject({
      allowed: true,
      code: "allowed",
    });
  });
});
