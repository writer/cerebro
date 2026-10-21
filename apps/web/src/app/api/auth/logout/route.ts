import { NextRequest, NextResponse } from "next/server";

import { publicOrigin } from "@/lib/sso/config";
import { clearSessionCookie, readSessionToken, sessionTokenHash } from "@/lib/sso/cookies";
import { isSameOriginRequest, jsonNoStore, NO_STORE_HEADERS } from "@/lib/sso/http";
import { deleteSsoSession, fetchSsoConnection } from "@/lib/sso/identity-api";
import { oidcEndSessionUrl } from "@/lib/sso/oidc";
import { clearSsoSessionCache, lookupSsoSessionCached } from "@/lib/sso/session";

const wantsJson = (request: NextRequest) => (request.headers.get("accept") ?? "").includes("application/json");

const endSessionTarget = async (connectionId: string, origin: string) => {
  try {
    const connection = await fetchSsoConnection(connectionId);
    return connection ? await oidcEndSessionUrl(connection, origin) : null;
  } catch {
    return null;
  }
};

/**
 * Ends the SSO session. Browsers apply CSP form-action to redirects after a form POST, so the console signs
 * out with fetch (Accept: application/json) and navigates to the returned `redirectTo`; a plain form POST
 * receives a 303 instead.
 */
export async function POST(request: NextRequest) {
  if (!isSameOriginRequest(request)) {
    return NextResponse.json({ error: "Cross-origin sign-out is not allowed." }, { status: 403, headers: NO_STORE_HEADERS });
  }
  const origin = publicOrigin(request.url) as string;
  let redirectTo = "/login";
  const token = readSessionToken(request.headers);
  if (token) {
    const tokenHash = sessionTokenHash(token);
    let connectionId = "";
    try {
      connectionId = (await lookupSsoSessionCached(tokenHash))?.connectionId ?? "";
    } catch {
      connectionId = "";
    }
    try {
      await deleteSsoSession(tokenHash);
    } catch {
      console.warn("sso session revocation failed during sign-out");
    }
    clearSsoSessionCache(tokenHash);
    if (connectionId) redirectTo = (await endSessionTarget(connectionId, origin)) ?? "/login";
  }
  const response = wantsJson(request)
    ? jsonNoStore({ redirectTo })
    : NextResponse.redirect(new URL(redirectTo, origin), { status: 303, headers: NO_STORE_HEADERS });
  clearSessionCookie(response);
  return response;
}
