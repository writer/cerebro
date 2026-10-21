import { NextRequest, NextResponse } from "next/server";
import { randomBytes } from "crypto";

import { publicOrigin, sessionSecretBytes } from "./config";
import { setTxCookie } from "./cookies";
import { loginErrorRedirect } from "./finish";
import { CONNECTION_ID_PATTERN, NO_STORE_HEADERS, relativeRedirect } from "./http";
import { fetchSsoConnection, fetchSsoConnections } from "./identity-api";
import { startOidcLogin } from "./oidc";
import { sanitizeReturnTo } from "./return-to";
import { connectionForEmail, emailDomain } from "./roles";
import { startSamlLogin } from "./saml";
import { sealTransaction, type LoginTransaction } from "./tx";
import { LoginError, type SSOConnection } from "./types";

const MAX_EMAIL_LENGTH = 320;

/** Set only by the admin test route after it has authorized the caller. */
export type TestLogin = { actor: string };

const selectConnection = async (connectionId: string, email: string, testLogin: TestLogin | null): Promise<SSOConnection> => {
  if (connectionId) {
    if (!CONNECTION_ID_PATTERN.test(connectionId)) throw new LoginError("misconfigured", "Unknown connection.");
    const connection = await fetchSsoConnection(connectionId);
    if (!connection) throw new LoginError("misconfigured", "Unknown connection.");
    if (connection.status === "disabled") throw new LoginError("misconfigured", "Connection is disabled.");
    if (!testLogin && connection.status !== "active") throw new LoginError("misconfigured", "Connection is not active.");
    return connection;
  }
  if (testLogin) throw new LoginError("misconfigured", "Choose a connection to test.");
  if (!email || email.length > MAX_EMAIL_LENGTH || !emailDomain(email)) {
    throw new LoginError("domain_not_allowed", "Enter a work email address.");
  }
  const connection = connectionForEmail(await fetchSsoConnections(), email);
  if (!connection) throw new LoginError("domain_not_allowed", "No sign-in connection serves this email domain.");
  return connection;
};

/** Redirects the browser to the IdP for one connection and seals the login transaction into a cookie. */
export const beginSsoLogin = async (request: NextRequest, testLogin: TestLogin | null) => {
  const params = request.nextUrl.searchParams;
  const returnTo = sanitizeReturnTo(params.get("returnTo"));
  const origin = publicOrigin(request.url);
  const secret = sessionSecretBytes();
  if (!origin || !secret) {
    return relativeRedirect(`/login?${new URLSearchParams({ error: "misconfigured" }).toString()}`);
  }

  const connectionId = (params.get("connection") ?? "").trim();
  const email = (params.get("email") ?? "").trim().toLowerCase();
  try {
    const connection = await selectConnection(connectionId, email, testLogin);
    const base = {
      connectionId: connection.id,
      returnTo,
      test: testLogin !== null,
      ...(testLogin ? { testActor: testLogin.actor } : {}),
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
};
