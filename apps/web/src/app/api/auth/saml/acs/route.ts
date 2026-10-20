import { NextRequest } from "next/server";

import { publicOrigin, sessionSecretBytes } from "@/lib/sso/config";
import { readTxCookie } from "@/lib/sso/cookies";
import { clientIpFrom, finishLogin, loginErrorRedirect, loginFailureResponse } from "@/lib/sso/finish";
import { relativeRedirect } from "@/lib/sso/http";
import { fetchSsoConnection } from "@/lib/sso/identity-api";
import { finishSamlLogin } from "@/lib/sso/saml";
import { openTransaction, TransactionError, type LoginTransaction } from "@/lib/sso/tx";
import { LoginError } from "@/lib/sso/types";

const MAX_SAML_RESPONSE_CHARS = 1_500_000;

const readSamlResponse = async (request: NextRequest) => {
  const contentType = (request.headers.get("content-type") ?? "").toLowerCase();
  if (!contentType.startsWith("application/x-www-form-urlencoded")) return null;
  const body = await request.text();
  if (body.length > MAX_SAML_RESPONSE_CHARS) return null;
  const value = new URLSearchParams(body).get("SAMLResponse");
  if (!value || !/^[A-Za-z0-9+/=\r\n]+$/.test(value)) return null;
  return value.replace(/[\r\n]/g, "");
};

// The IdP posts here cross-site (HTTP-POST binding), so there is no Origin check. Login CSRF is prevented by
// binding InResponseTo to the encrypted transaction cookie set when this browser started the login.
export async function POST(request: NextRequest) {
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
    if (!tx.samlRequestId) throw new LoginError("invalid_response", "Login transaction is not a SAML transaction.");
    const samlResponse = await readSamlResponse(request);
    if (!samlResponse) throw new LoginError("invalid_response", "Missing or malformed SAMLResponse.");
    const connection = await fetchSsoConnection(tx.connectionId);
    if (!connection || connection.protocol !== "saml") throw new LoginError("misconfigured", "Connection is unavailable.");
    const identity = await finishSamlLogin(connection, origin, samlResponse, tx);
    return await finishLogin(connection, identity, tx, {
      origin,
      userAgent: request.headers.get("user-agent"),
      clientIp: clientIpFrom(request.headers),
    });
  } catch (error) {
    if (!(error instanceof LoginError)) {
      console.warn("saml acs failed", { error_kind: error instanceof Error ? error.constructor.name : typeof error });
    }
    return loginFailureResponse(origin, tx, error);
  }
}
