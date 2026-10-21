import { NextResponse } from "next/server";

import {
  authorizationErrorResponse,
  authorizeCurrentUser,
  effectiveIdentityRequired,
  entitlementPolicyFor,
  type AuthorizationPermission,
} from "@/lib/authorization";
import type { CurrentUser } from "@/lib/identity";
import { currentUserServerAuditFields, resolveCurrentUserFromHeadersWithFallback } from "@/lib/identity-server";
import { userHasAuthorizationPermission } from "@/lib/rbac";

import { isSameOriginRequest } from "./http";

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
  if (permission !== "identity:admin" || !effectiveIdentityRequired()) return decision;
  if (policyConfigured(permission) || userHasAuthorizationPermission(user, permission)) return decision;
  return {
    ...decision,
    allowed: false,
    code: "permission_missing",
    reason: "Current user is missing a required permission.",
    status: 403 as const,
  };
};

const isJsonContentType = (value: string | null) => {
  const mediaType = (value ?? "").split(";")[0].trim().toLowerCase();
  return mediaType === "application/json";
};

/**
 * Identity admin writes must come from the console itself: same-origin (like /api/auth/logout) and JSON, so
 * a cross-site "simple" request (text/plain form or fetch, no CORS preflight) never reaches Go.
 */
export const rejectUnsafeIdentityWrite = (request: Request): NextResponse | null => {
  const method = request.method.toUpperCase();
  if (method === "GET" || method === "HEAD") return null;
  const headers = { "cache-control": "private, no-store" };
  if (!isSameOriginRequest(request)) {
    return NextResponse.json({ error: "Cross-origin requests are not allowed.", code: "cross_origin" }, { status: 403, headers });
  }
  if (!isJsonContentType(request.headers.get("content-type"))) {
    return NextResponse.json({ error: "Content-Type must be application/json.", code: "unsupported_media_type" }, { status: 415, headers });
  }
  return null;
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
