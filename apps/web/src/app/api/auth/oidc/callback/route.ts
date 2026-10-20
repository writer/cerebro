import { NextRequest } from "next/server";

import { publicOrigin, sessionSecretBytes } from "@/lib/sso/config";
import { readTxCookie } from "@/lib/sso/cookies";
import { clientIpFrom, finishLogin, loginErrorRedirect, loginFailureResponse } from "@/lib/sso/finish";
import { relativeRedirect } from "@/lib/sso/http";
import { fetchSsoConnection } from "@/lib/sso/identity-api";
import { finishOidcLogin } from "@/lib/sso/oidc";
import { openTransaction, TransactionError, type LoginTransaction } from "@/lib/sso/tx";
import { LoginError } from "@/lib/sso/types";

export async function GET(request: NextRequest) {
  const origin = publicOrigin(request.url);
  const secret = sessionSecretBytes();
  if (!origin || !secret) return relativeRedirect("/login?error=misconfigured");

  const sealed = readTxCookie(request.headers);
  if (!sealed) return loginErrorRedirect(origin, "expired");
  let tx: LoginTransaction;
  try {
    tx = await openTransaction(sealed, secret);
  } catch (error) {
    return loginErrorRedirect(origin, error instanceof TransactionError && error.expired ? "expired" : "invalid_response");
  }

  try {
    if (!tx.codeVerifier || !tx.nonce) throw new LoginError("invalid_response", "Login transaction is not an OIDC transaction.");
    const connection = await fetchSsoConnection(tx.connectionId);
    if (!connection || connection.protocol !== "oidc") throw new LoginError("misconfigured", "Connection is unavailable.");
    const identity = await finishOidcLogin(connection, origin, request.nextUrl.search, {
      state: tx.state,
      nonce: tx.nonce,
      codeVerifier: tx.codeVerifier,
    });
    return await finishLogin(connection, identity, tx, {
      origin,
      userAgent: request.headers.get("user-agent"),
      clientIp: clientIpFrom(request.headers),
    });
  } catch (error) {
    if (!(error instanceof LoginError)) {
      console.warn("oidc callback failed", { error_kind: error instanceof Error ? error.constructor.name : typeof error });
    }
    return loginFailureResponse(origin, tx, error);
  }
}
