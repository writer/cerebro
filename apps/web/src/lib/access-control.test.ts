import { describe, expect, it } from "vitest";

import { accessRoleRows, deniedPermissions, type AccessControl } from "./access-control";

const permission = (name: string, granted: boolean) => ({
  granted,
  permission: name,
  requiredGroups: [],
  requiredRoles: [],
  requiredScopes: [],
  restricted: false,
});

const access = (overrides: Partial<AccessControl> = {}): AccessControl => ({
  deployment: { builtinRbacRequired: true, globalRequiredGroups: [], identityRequired: true },
  permissions: [permission("cerebro:read", true), permission("cerebro:write", false)],
  roleClaimMappings: [
    { claim: "groups", roles: ["cerebro.viewer"], value: "engineering" },
    { claim: "department", roles: ["cerebro.viewer"], value: "security" },
  ],
  roles: [
    { description: "Everything.", permissions: ["cerebro:read", "cerebro:write"], role: "cerebro.admin" },
    { description: "Read only.", permissions: ["cerebro:read"], role: "cerebro.viewer" },
  ],
  viewer: {
    confidence: "trusted-proxy",
    entitlements: { groups: ["Engineering"] },
    mappedRoles: ["cerebro.viewer"],
    permissions: ["cerebro:read"],
    provider: "alb-oidc",
  },
  ...overrides,
});

describe("accessRoleRows", () => {
  it("lists the groups that grant each role, naming non-group claims", () => {
    const viewer = accessRoleRows(access()).find((row) => row.role === "cerebro.viewer");
    expect(viewer?.grantedTo).toEqual(["engineering", "department: security"]);
  });

  it("puts roles some group grants ahead of roles nobody is given", () => {
    expect(accessRoleRows(access()).map((row) => row.role)).toEqual(["cerebro.viewer", "cerebro.admin"]);
  });

  it("marks roles the viewer holds directly or through a mapping", () => {
    const rows = accessRoleRows(
      access({
        viewer: { ...access().viewer, entitlements: { roles: ["Cerebro.Admin"] }, mappedRoles: ["cerebro.viewer"] },
      }),
    );
    expect(rows.every((row) => row.yours)).toBe(true);
  });
});

describe("deniedPermissions", () => {
  it("returns only the permissions the viewer is refused", () => {
    expect(deniedPermissions(access())).toEqual(["cerebro:write"]);
  });
});
