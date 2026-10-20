import { NextResponse } from "next/server";

import { keyedHash } from "./config";
import { clearTxCookie, generateSessionToken, sessionTokenHash, setSessionCookie } from "./cookies";
import {
  createSsoSession,
  lookupDirectoryUser,
  postConnectionTestResult,
  upsertJitDirectoryUser,
} from "./identity-api";
import { getSsoPolicyState } from "./policy";
import { sanitizeReturnTo } from "./return-to";
import { computeSessionRoles, connectionAllowsEmail } from "./roles";
import { clearSsoSessionCache } from "./session";
import type { LoginTransaction } from "./tx";
import { LoginError, type AssertedIdentity, type LoginErrorCode, type SSOConnection } from "./types";

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

/**
 * A user must be known to the directory (SCIM-provisioned and active), or the connection must allow JIT
 * provisioning, in which case the user is upserted.
 */
export const checkDirectory = async (connection: SSOConnection, identity: AssertedIdentity, dryRun: boolean): Promise<DirectoryDecision> => {
  const existing = await lookupDirectoryUser(connection.id, identity.email);
  if (existing) {
    if (!existing.active) throw new LoginError("access_denied", "The directory user is deactivated.");
    const groups = Array.from(new Set([...identity.groups, ...(existing.groups ?? [])]));
    if (existing.source === "jit" && !dryRun) {
      await upsertJitDirectoryUser({ connectionId: connection.id, ...identity });
    }
    return { groups };
  }
  if (!connection.jitProvisioning) {
    throw new LoginError("not_provisioned", "The user has not been provisioned for this connection.");
  }
  if (!dryRun) {
    await upsertJitDirectoryUser({ connectionId: connection.id, ...identity });
  }
  return { groups: identity.groups };
};

export type FinishContext = {
  origin: string;
  userAgent?: string | null;
  clientIp?: string | null;
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
    await createSsoSession({
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
    });
    clearSsoSessionCache(tokenHash);
    const response = redirect(context.origin, sanitizeReturnTo(tx.returnTo));
    setSessionCookie(response, token, maxLifetimeMs / 1000);
    clearTxCookie(response);
    return response;
  } catch (error) {
    return loginFailureResponse(context.origin, tx, error);
  }
};

/** First address in X-Forwarded-For (set by the load balancer), used only for the hashed session audit field. */
export const clientIpFrom = (headers: Headers) => headers.get("x-forwarded-for")?.split(",")[0]?.trim() || null;
