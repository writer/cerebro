import { createHash } from "crypto";

import {
  currentUserActor,
  currentUserAuditFields,
  identityHealthForUser,
  localCurrentUserFallback,
  localIdentityFallbackEnabled,
  resolveProxyCurrentUserFromHeaders,
  type CurrentUser,
  type IdentityHealth,
} from "@/lib/identity";
import { logSsoStartupNotice } from "@/lib/sso/config";
import { getSsoEnforcement } from "@/lib/sso/policy";
import { currentUserForSsoSession, resolveSsoSessionFromHeaders } from "@/lib/sso/session";

const actorKey = (user: CurrentUser | null | undefined) => {
  const actor = currentUserActor(user);
  if (!actor) return "";
  return createHash("sha256").update(`${user?.provider ?? "unknown"}:${actor}`).digest("hex").slice(0, 16);
};

export const currentUserServerAuditFields = (user: CurrentUser | null | undefined) => ({
  ...currentUserAuditFields(user),
  actorKey: actorKey(user),
  actorIdPresent: Boolean(user?.actorId),
  actorLabelPresent: Boolean(user?.actorLabel),
});

type Resolution = {
  user: CurrentUser | null;
  /** The legacy header/JWT/fallback path was skipped because SSO is enforced (or its policy is unreadable). */
  legacyDisabled: boolean;
  issues: string[];
};

const resolveSsoUser = async (headers: Headers): Promise<{ user: CurrentUser | null; issues: string[] }> => {
  try {
    const resolved = await resolveSsoSessionFromHeaders(headers);
    if (!resolved) return { user: null, issues: [] };
    return { user: await currentUserForSsoSession(resolved.session), issues: [] };
  } catch {
    return { user: null, issues: ["sso-session-lookup-failed"] };
  }
};

const resolveIdentity = async (headers: Headers, allowFallback: boolean): Promise<Resolution> => {
  logSsoStartupNotice();
  const [sso, enforcement] = await Promise.all([resolveSsoUser(headers), getSsoEnforcement()]);
  const issues = [...sso.issues];
  if (enforcement.unknown) issues.push("sso-policy-unavailable");
  if (enforcement.breakGlass) issues.push("sso-break-glass-active");
  if (sso.user) return { user: sso.user, legacyDisabled: enforcement.enforced, issues };
  if (enforcement.enforced) {
    return { user: null, legacyDisabled: true, issues: [...issues, "sso-session-required"] };
  }
  const proxyUser = await resolveProxyCurrentUserFromHeaders(headers);
  if (proxyUser) return { user: proxyUser, legacyDisabled: false, issues };
  if (allowFallback && localIdentityFallbackEnabled()) {
    return { user: localCurrentUserFallback(), legacyDisabled: false, issues };
  }
  return { user: null, legacyDisabled: false, issues };
};

/**
 * Current user for a route handler. An SSO session cookie wins over every other signal. When the SSO policy
 * is enforced (and break-glass is off) proxy headers, identity JWTs, and the local fallback are never consulted.
 */
export const resolveCurrentUserFromHeaders = async (headers: Headers): Promise<CurrentUser | null> =>
  (await resolveIdentity(headers, false)).user;

export const resolveCurrentUserFromHeadersWithFallback = async (headers: Headers): Promise<CurrentUser | null> =>
  (await resolveIdentity(headers, true)).user;

export const identityHealthFromHeaders = async (headers: Headers): Promise<IdentityHealth> => {
  const resolution = await resolveIdentity(headers, true);
  return identityHealthForUser(resolution.user, resolution.issues);
};
