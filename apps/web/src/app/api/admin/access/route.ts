import { NextRequest, NextResponse } from "next/server";

import { authorizationErrorResponse, authorizeCurrentUser, entitlementPolicyFor } from "@/lib/authorization";
import { isCerebroFixtureMode } from "@/lib/cerebro-fixtures";
import { identityRequired } from "@/lib/identity";
import { resolveCurrentUserFromHeadersWithFallback } from "@/lib/identity";
import {
  authorizationPermissionCatalog,
  authorizationRoleCatalog,
  effectiveAuthorizationPermissionsForUser,
  roleClaimMappings,
  rolesFromClaimMappings,
  type RoleClaimMapping,
} from "@/lib/rbac";

export async function GET(request: NextRequest) {
  if (isCerebroFixtureMode()) {
    return fixtureAccessControlResponse();
  }

  const user = await resolveCurrentUserFromHeadersWithFallback(request.headers);
  const decision = authorizeCurrentUser(user, "admin:read");
  if (!decision.allowed) return authorizationErrorResponse(decision);

  const mappings = roleClaimMappings();
  const permissions = authorizationPermissionCatalog().map((permission) => {
    const policy = entitlementPolicyFor(permission);
    return {
      permission,
      requiredGroups: policy.groups,
      requiredRoles: policy.roles,
      requiredScopes: policy.scopes,
      // An unconfigured permission is open to anyone who clears the global gate.
      restricted: policy.groups.length > 0 || policy.roles.length > 0 || policy.scopes.length > 0,
      granted: effectiveAuthorizationPermissionsForUser(user).includes(permission),
    };
  });

  return NextResponse.json(
    {
      deployment: {
        builtinRbacRequired: process.env.CEREBRO_AUTHZ_BUILTIN_RBAC?.trim().toLowerCase() === "true",
        globalRequiredGroups: (process.env.CEREBRO_AUTHZ_REQUIRED_GROUPS ?? "")
          .split(",")
          .map((value) => value.trim())
          .filter(Boolean),
        identityRequired: identityRequired(),
      },
      permissions,
      roleClaimMappings: mappings,
      roles: authorizationRoleCatalog(),
      viewer: {
        confidence: user?.confidence ?? "none",
        entitlements: user?.entitlements ?? {},
        mappedRoles: rolesFromClaimMappings(user, mappings),
        permissions: effectiveAuthorizationPermissionsForUser(user),
        provider: user?.provider ?? "none",
      },
    },
    { headers: { "cache-control": "private, no-store" } },
  );
}

// Sample mappings so the panel demonstrates the claim-to-role model locally, where no stack config exists.
// Values are lowercased because claim matching is case-insensitive and real parsed mappings render that way.
const fixtureRoleClaimMappings: RoleClaimMapping[] = [
  { claim: "groups", roles: ["cerebro.admin"], value: "security team" },
  { claim: "groups", roles: ["cerebro.grc_reviewer"], value: "compliance team" },
  { claim: "groups", roles: ["cerebro.viewer"], value: "engineering" },
];

function fixtureAccessControlResponse() {
  const allPermissions = authorizationPermissionCatalog();
  const roles = authorizationRoleCatalog();
  const configured = roleClaimMappings();
  const mappings = configured.length > 0 ? configured : fixtureRoleClaimMappings;

  const fixtureRole = "cerebro.admin";
  const fixturePermissions = roles.find((r) => r.role === fixtureRole)?.permissions ?? allPermissions;

  const permissions = allPermissions.map((permission) => ({
    permission,
    requiredGroups: [] as string[],
    requiredRoles: [] as string[],
    requiredScopes: [] as string[],
    restricted: false,
    granted: fixturePermissions.includes(permission),
  }));

  return NextResponse.json(
    {
      deployment: {
        builtinRbacRequired: false,
        globalRequiredGroups: [] as string[],
        identityRequired: false,
      },
      permissions,
      roleClaimMappings: mappings,
      roles,
      viewer: {
        confidence: "fallback" as const,
        entitlements: {
          groups: ["Security Team"],
          roles: [fixtureRole],
        },
        mappedRoles: [fixtureRole],
        permissions: fixturePermissions,
        provider: "local" as const,
      },
    },
    { headers: { "cache-control": "private, no-store" } },
  );
}
