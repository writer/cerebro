import { NextResponse } from "next/server";

import { keyedHash } from "./config";
import { clearTxCookie, generateSessionToken, sessionTokenHash, setSessionCookie } from "./cookies";
import {
  createSsoSession,
  deleteSsoSession,
  IdentityApiError,
  lookupDirectoryUser,
  postConnectionTestResult,
  upsertJitDirectoryUser,
} from "./identity-api";
import { getSsoPolicyState } from "./policy";
import { sanitizeReturnTo } from "./return-to";
import { computeSessionRoles, connectionAllowsEmail } from "./roles";
import { clearSsoSessionCache } from "./session";
import type { LoginTransaction } from "./tx";
import { LoginError, type AssertedIdentity, type DirectoryUser, type LoginErrorCode, type SSOConnection } from "./types";

const noStore = { "cache-control": "no-store" };

const redirect = (origin: string, path: string) => {
  const response = NextResponse.redirect(new URL(path, origin), { status: 303, headers: noStore });
  return response;
};

/** Sends the browser back to /login with an error code. The code is the only detail exposed to the user. */
export const loginErrorRedirect = (origin: string, code: LoginErrorCode, returnTo?: string) => {
  const params = new URLSearchParams({ error: code });
  const safeReturnTo = sanitizeReturnTo(returnTo, "");
  if (safeReturnTo && safeReturnTo !== "/") params.set("returnTo", safeReturnTo);
  const response = redirect(origin, `/login?${params.toString()}`);
  clearTxCookie(response);
  return response;
};

export const testResultRedirect = (origin: string, connectionId: string, ok: boolean, reason?: LoginErrorCode) => {
  const params = new URLSearchParams({ tab: "sso", tested: connectionId, ok: ok ? "1" : "0" });
  if (!ok && reason) params.set("reason", reason);
  const response = redirect(origin, `/admin/access?${params.toString()}`);
  clearTxCookie(response);
  return response;
};

export type DirectoryDecision = {
  groups: string[];
};

const DIRECTORY_DENIAL_CODES = new Set(["subject_mismatch", "user_deprovisioned", "user_inactive"]);

/** Directory refusals become one generic login failure; the specific reason is not shown to the browser. */
const mapDirectoryError = (error: unknown): never => {
  if (error instanceof IdentityApiError && (error.status === 403 || DIRECTORY_DENIAL_CODES.has(error.code))) {
    throw new LoginError("access_denied", "Sign-in is not allowed for this account.");
  }
  throw error;
};

const recordLogin = async (connection: SSOConnection, identity: AssertedIdentity) => {
  try {
    return await upsertJitDirectoryUser({ connectionId: connection.id, ...identity });
  } catch (error) {
    return mapDirectoryError(error);
  }
};

const cleanGroups = (values: unknown) =>
  Array.isArray(values) ? values.filter((value): value is string => typeof value === "string" && value.trim() !== "") : [];

/**
 * Role-granting groups are the groups in this assertion plus SCIM-managed memberships. Stored JIT groups (and
 * the combined `groups` list) are never used, so removing a user from an IdP group drops the role at the next
 * sign-in.
 */
const sessionGroups = (identity: AssertedIdentity, user: DirectoryUser | null) =>
  Array.from(new Set([...identity.groups, ...cleanGroups(user?.scimGroups)]));

/**
 * A user must be known to the directory (SCIM-provisioned and active), or the connection must allow JIT
 * provisioning, in which case the user is upserted. Every real login goes through the JIT endpoint, which
 * binds the IdP subject to the directory user and refuses mismatched subjects and deprovisioned users.
 */
export const checkDirectory = async (connection: SSOConnection, identity: AssertedIdentity, dryRun: boolean): Promise<DirectoryDecision> => {
  const existing = await lookupDirectoryUser(connection.id, identity.email, identity.subject);
  if (existing) {
    if (!existing.active) throw new LoginError("access_denied", "The directory user is deactivated.");
    if (dryRun) return { groups: sessionGroups(identity, existing) };
    const recorded = await recordLogin(connection, identity);
    if (!recorded.active) throw new LoginError("access_denied", "Sign-in is not allowed for this account.");
    return { groups: sessionGroups(identity, recorded) };
  }
  if (!connection.jitProvisioning) {
    throw new LoginError("not_provisioned", "The user has not been provisioned for this connection.");
  }
  if (dryRun) return { groups: sessionGroups(identity, null) };
  const created = await recordLogin(connection, identity);
  if (!created.active) throw new LoginError("access_denied", "Sign-in is not allowed for this account.");
  return { groups: sessionGroups(identity, created) };
};

export type FinishContext = {
  origin: string;
  userAgent?: string | null;
  clientIp?: string | null;
  /** Session cookie the browser already held; revoked once the new session exists. */
  previousSessionToken?: string | null;
};

const describeOutcome = (identity: AssertedIdentity, roles: string[]) =>
  `Signed in as ${identity.email}; ${identity.groups.length} group(s); roles: ${roles.length ? roles.join(", ") : "none"}.`;

const recordTestResult = async (connection: Pick<SSOConnection, "id">, tx: LoginTransaction, ok: boolean, detail: string) => {
  try {
    await postConnectionTestResult(connection.id, { ok, actor: tx.testActor ?? "", detail: detail.slice(0, 500) });
  } catch {
    // The redirect still reports the outcome to the admin.
  }
};

/** Failure before or during protocol validation: tests record the failure, normal logins go back to /login. */
export const loginFailureResponse = async (origin: string, tx: LoginTransaction, error: unknown) => {
  const code: LoginErrorCode = error instanceof LoginError ? error.code : "misconfigured";
  if (tx.test) {
    const detail = error instanceof LoginError ? error.message : "Login could not be completed.";
    await recordTestResult({ id: tx.connectionId }, tx, false, detail);
    return testResultRedirect(origin, tx.connectionId, false, code);
  }
  return loginErrorRedirect(origin, code, tx.returnTo);
};

/** A copied earlier cookie must not outlive a fresh sign-in. Best effort: the new login still succeeds. */
const revokePreviousSession = async (previousToken: string | null | undefined, newHash: string) => {
  if (!previousToken) return;
  const previousHash = sessionTokenHash(previousToken);
  if (previousHash === newHash) return;
  clearSsoSessionCache(previousHash);
  try {
    await deleteSsoSession(previousHash);
  } catch {
    // Go still expires the old session on its own lifetime and idle timeout.
  }
};

/**
 * Applies Cerebro policy to a protocol-validated identity, then either creates a session (normal login) or
 * records a test result (admin test mode, which never creates a session).
 */
export const finishLogin = async (
  connection: SSOConnection,
  identity: AssertedIdentity,
  tx: LoginTransaction,
  context: FinishContext,
): Promise<NextResponse> => {
  try {
    if (!tx.test && connection.status !== "active") {
      throw new LoginError("misconfigured", "The connection is not active.");
    }
    if (connection.status === "disabled") throw new LoginError("misconfigured", "The connection is disabled.");
    if (!connectionAllowsEmail(connection, identity.email)) {
      throw new LoginError("domain_not_allowed", "The email domain is not routed to this connection.");
    }
    const directory = await checkDirectory(connection, identity, tx.test);
    const roles = computeSessionRoles(connection, directory.groups);

    if (tx.test) {
      await recordTestResult(connection, tx, true, describeOutcome({ ...identity, groups: directory.groups }, roles));
      return testResultRedirect(context.origin, connection.id, true);
    }

    const { policy } = await getSsoPolicyState();
    const token = generateSessionToken();
    const tokenHash = sessionTokenHash(token);
    const maxLifetimeMs = policy.sessionMaxLifetimeMinutes * 60_000;
    const session = await createSsoSession({
      tokenHash,
      connectionId: connection.id,
      subject: identity.subject,
      email: identity.email,
      name: identity.name,
      groups: directory.groups,
      roles,
      expiresAt: new Date(Date.now() + maxLifetimeMs).toISOString(),
      idleTimeoutMinutes: policy.sessionIdleTimeoutMinutes,
      ...(context.userAgent ? { userAgent: context.userAgent.slice(0, 512) } : {}),
      ...(context.clientIp ? { ipHash: keyedHash(context.clientIp) } : {}),
    }).catch(mapDirectoryError);
    clearSsoSessionCache(tokenHash);
    await revokePreviousSession(context.previousSessionToken, tokenHash);
    const response = redirect(context.origin, sanitizeReturnTo(tx.returnTo));
    // Go may shorten the lifetime (admin sessions are capped), so the cookie follows the stored expiry.
    const storedExpiryMs = Date.parse(session?.expiresAt ?? "");
    const cookieLifetimeMs = Number.isFinite(storedExpiryMs) ? Math.min(maxLifetimeMs, storedExpiryMs - Date.now()) : maxLifetimeMs;
    setSessionCookie(response, token, cookieLifetimeMs / 1000);
    clearTxCookie(response);
    return response;
  } catch (error) {
    return loginFailureResponse(context.origin, tx, error);
  }
};

const DEFAULT_TRUSTED_PROXY_HOPS = 1;
const MAX_TRUSTED_PROXY_HOPS = 10;

const trustedProxyHops = () => {
  const raw = (process.env.CEREBRO_WEB_TRUSTED_PROXY_HOPS ?? "").trim();
  if (!/^\d+$/.test(raw)) return DEFAULT_TRUSTED_PROXY_HOPS;
  const hops = Number.parseInt(raw, 10);
  return hops >= 1 && hops <= MAX_TRUSTED_PROXY_HOPS ? hops : DEFAULT_TRUSTED_PROXY_HOPS;
};

/**
 * Client address for the hashed session audit field. Proxies append to X-Forwarded-For, so entries left of
 * the ones our CEREBRO_WEB_TRUSTED_PROXY_HOPS proxies added are client-supplied; the address is read that many
 * entries from the right.
 */
export const clientIpFrom = (headers: Headers) => {
  const hops = (headers.get("x-forwarded-for") ?? "").split(",").map((entry) => entry.trim());
  if (hops.length === 1 && hops[0] === "") return null;
  const hopCount = trustedProxyHops();
  if (hops.length < hopCount) return null;
  return hops[hops.length - hopCount] || null;
};
