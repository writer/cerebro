import { NextRequest } from "next/server";

import { authorizeIdentityRequest, rejectUnsafeIdentityWrite } from "@/lib/sso/admin-auth";
import { jsonNoStore } from "@/lib/sso/http";
import { discoverIssuer } from "@/lib/sso/oidc";
import { assertSafeOutboundUrl, UnsafeUrlError } from "@/lib/sso/safe-fetch";

export async function POST(request: NextRequest) {
  const unsafe = rejectUnsafeIdentityWrite(request);
  if (unsafe) return unsafe;
  const authorization = await authorizeIdentityRequest(request, "identity:admin");
  if (!authorization.ok) return authorization.response;
  let issuer = "";
  try {
    const body = (await request.json()) as { issuer?: unknown };
    issuer = typeof body?.issuer === "string" ? body.issuer.trim() : "";
  } catch {
    return jsonNoStore({ ok: false, error: "Request body must be JSON." }, 400);
  }
  if (!issuer || issuer.length > 2048) return jsonNoStore({ ok: false, error: "An issuer URL is required." }, 400);
  try {
    await assertSafeOutboundUrl(issuer);
    const metadata = await discoverIssuer(issuer);
    return jsonNoStore({
      ok: true,
      authorizationEndpoint: metadata.authorization_endpoint ?? "",
      tokenEndpoint: metadata.token_endpoint ?? "",
      ...(metadata.end_session_endpoint ? { endSessionEndpoint: metadata.end_session_endpoint } : {}),
      scopesSupported: Array.isArray(metadata.scopes_supported) ? metadata.scopes_supported : [],
    });
  } catch (error) {
    const message = error instanceof UnsafeUrlError
      ? error.message
      : "Discovery failed. Check that the issuer URL is correct and serves /.well-known/openid-configuration.";
    return jsonNoStore({ ok: false, error: message }, 200);
  }
}
