import { NextRequest, NextResponse } from "next/server";

import { authorizationErrorResponse, authorizeCurrentUser, entitlementPolicyFor } from "@/lib/authorization";
import { identityRequired } from "@/lib/identity";
import { resolveCurrentUserFromHeadersWithFallback } from "@/lib/identity";
import {
  authorizationPermissionCatalog,
  authorizationRoleCatalog,
  effectiveAuthorizationPermissionsForUser,
  roleClaimMappings,
  rolesFromClaimMappings,
} from "@/lib/rbac";

export async function GET(request: NextRequest) {
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
