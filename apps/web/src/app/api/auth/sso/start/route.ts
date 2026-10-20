import { NextRequest, NextResponse } from "next/server";
import { randomBytes } from "crypto";

import { currentUserActor } from "@/lib/identity";
import { authorizeIdentityRequest } from "@/lib/sso/admin-auth";
import { publicOrigin, sessionSecretBytes } from "@/lib/sso/config";
import { setTxCookie } from "@/lib/sso/cookies";
import { loginErrorRedirect } from "@/lib/sso/finish";
import { CONNECTION_ID_PATTERN, NO_STORE_HEADERS, relativeRedirect } from "@/lib/sso/http";
import { fetchSsoConnection, fetchSsoConnections } from "@/lib/sso/identity-api";
import { startOidcLogin } from "@/lib/sso/oidc";
import { sanitizeReturnTo } from "@/lib/sso/return-to";
import { connectionForEmail, emailDomain } from "@/lib/sso/roles";
import { startSamlLogin } from "@/lib/sso/saml";
import { sealTransaction, type LoginTransaction } from "@/lib/sso/tx";
import { LoginError, type SSOConnection } from "@/lib/sso/types";

const MAX_EMAIL_LENGTH = 320;

const selectConnection = async (connectionId: string, email: string, test: boolean): Promise<SSOConnection> => {
  if (connectionId) {
    if (!CONNECTION_ID_PATTERN.test(connectionId)) throw new LoginError("misconfigured", "Unknown connection.");
    const connection = await fetchSsoConnection(connectionId);
    if (!connection) throw new LoginError("misconfigured", "Unknown connection.");
    if (connection.status === "disabled") throw new LoginError("misconfigured", "Connection is disabled.");
    if (!test && connection.status !== "active") throw new LoginError("misconfigured", "Connection is not active.");
    return connection;
  }
  if (!email || email.length > MAX_EMAIL_LENGTH || !emailDomain(email)) {
    throw new LoginError("domain_not_allowed", "Enter a work email address.");
  }
  const connection = connectionForEmail(await fetchSsoConnections(), email);
  if (!connection) throw new LoginError("domain_not_allowed", "No sign-in connection serves this email domain.");
  return connection;
};

export async function GET(request: NextRequest) {
  const params = request.nextUrl.searchParams;
  const returnTo = sanitizeReturnTo(params.get("returnTo"));
  const test = params.get("test") === "1";
  const origin = publicOrigin(request.url);
  const secret = sessionSecretBytes();
  if (!origin || !secret) {
    return relativeRedirect(`/login?${new URLSearchParams({ error: "misconfigured" }).toString()}`);
  }

  let testActor: string | undefined;
  if (test) {
    const authorization = await authorizeIdentityRequest(request, "identity:admin");
    if (!authorization.ok) return authorization.response;
    testActor = currentUserActor(authorization.user) || "unknown";
  }

  const connectionId = (params.get("connection") ?? "").trim();
  const email = (params.get("email") ?? "").trim().toLowerCase();
  try {
    const connection = await selectConnection(connectionId, email, test);
    const base = {
      connectionId: connection.id,
      returnTo,
      test,
      ...(testActor ? { testActor } : {}),
      createdAt: new Date().toISOString(),
    };
    let target: URL;
    let tx: LoginTransaction;
    if (connection.protocol === "oidc") {
      const start = await startOidcLogin(connection, origin, email || undefined);
      target = start.url;
      tx = { ...base, state: start.state, nonce: start.nonce, codeVerifier: start.codeVerifier };
    } else if (connection.protocol === "saml") {
      const start = await startSamlLogin(connection, origin);
      target = start.url;
      tx = { ...base, state: randomBytes(16).toString("base64url"), samlRequestId: start.requestId };
    } else {
      throw new LoginError("misconfigured", "Unsupported connection protocol.");
    }
    const response = NextResponse.redirect(target, { status: 302, headers: NO_STORE_HEADERS });
    setTxCookie(response, await sealTransaction(tx, secret));
    return response;
  } catch (error) {
    const code = error instanceof LoginError ? error.code : "misconfigured";
    if (!(error instanceof LoginError)) {
      console.warn("sso login start failed", { error_kind: error instanceof Error ? error.constructor.name : typeof error });
    }
    return loginErrorRedirect(origin, code, returnTo);
  }
}
