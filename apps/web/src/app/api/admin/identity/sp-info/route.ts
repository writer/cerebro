import { NextRequest } from "next/server";

import { authorizeIdentityRequest } from "@/lib/sso/admin-auth";
import { publicOrigin, ssoRoutes } from "@/lib/sso/config";
import { CONNECTION_ID_PATTERN, jsonNoStore } from "@/lib/sso/http";

/** Values the admin pastes into the IdP. `connection` is optional because the IdP asks for them first. */
export async function GET(request: NextRequest) {
  const authorization = await authorizeIdentityRequest(request, "admin:read");
  if (!authorization.ok) return authorization.response;
  const connectionId = request.nextUrl.searchParams.get("connection")?.trim() ?? "";
  if (connectionId && !CONNECTION_ID_PATTERN.test(connectionId)) {
    return jsonNoStore({ error: "Connection id is invalid." }, 400);
  }
  const origin = publicOrigin(request.url);
  if (!origin) return jsonNoStore({ error: "CEREBRO_WEB_PUBLIC_URL is not configured." }, 409);
  const routes = ssoRoutes(origin);
  return jsonNoStore({
    redirectUri: routes.oidcRedirectUri,
    acsUrl: routes.samlAcsUrl,
    entityId: routes.samlEntityId,
    metadataUrl: routes.samlMetadataUrl,
    initiateLoginUrl: connectionId ? routes.initiateLoginUrl(connectionId) : "",
    scimBaseUrl: routes.scimBaseUrl,
  });
}
