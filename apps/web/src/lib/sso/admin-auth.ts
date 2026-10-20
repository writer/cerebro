import { NextResponse } from "next/server";

import {
  authorizationErrorResponse,
  authorizeCurrentUser,
  entitlementPolicyFor,
  type AuthorizationPermission,
} from "@/lib/authorization";
import { identityRequired, type CurrentUser } from "@/lib/identity";
import { currentUserServerAuditFields, resolveCurrentUserFromHeadersWithFallback } from "@/lib/identity-server";
import { userHasAuthorizationPermission } from "@/lib/rbac";

export type IdentityAdminAuthorization =
  | { ok: true; user: CurrentUser | null }
  | { ok: false; response: NextResponse };

const policyConfigured = (permission: AuthorizationPermission) => {
  const policy = entitlementPolicyFor(permission);
  return policy.groups.length > 0 || policy.roles.length > 0 || policy.scopes.length > 0;
};

/**
 * SSO configuration decides who can sign in and with which roles, so identity:admin is never granted by
 * default. Where identity is required it needs either an explicit CEREBRO_AUTHZ_IDENTITY_ADMIN_* policy or a
 * built-in role that carries the permission (cerebro.admin/admin/owner).
 */
export const decideIdentityPermission = (user: CurrentUser | null, permission: AuthorizationPermission) => {
  const decision = authorizeCurrentUser(user, permission);
  if (!decision.allowed) return decision;
  if (permission !== "identity:admin" || !identityRequired()) return decision;
  if (policyConfigured(permission) || userHasAuthorizationPermission(user, permission)) return decision;
  return {
    ...decision,
    allowed: false,
    code: "permission_missing",
    reason: "Current user is missing a required permission.",
    status: 403 as const,
  };
};

export const authorizeIdentityRequest = async (
  request: Request,
  permission: AuthorizationPermission,
): Promise<IdentityAdminAuthorization> => {
  const user = await resolveCurrentUserFromHeadersWithFallback(request.headers);
  const decision = decideIdentityPermission(user, permission);
  if (!decision.allowed) {
    console.warn("identity admin request denied", { ...currentUserServerAuditFields(user), permission });
    return { ok: false, response: authorizationErrorResponse(decision) };
  }
  return { ok: true, user };
};
