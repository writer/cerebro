import { NextRequest } from "next/server";

import { authorizeIdentityRequest } from "@/lib/sso/admin-auth";
import { publicUrlConfigured, sessionSecretConfigured, ssoBreakGlassEnabled, ssoRequired } from "@/lib/sso/config";
import { jsonNoStore } from "@/lib/sso/http";
import { getCachedSsoConnections, getSsoEnforcement } from "@/lib/sso/policy";

export async function GET(request: NextRequest) {
  const authorization = await authorizeIdentityRequest(request, "admin:read");
  if (!authorization.ok) return authorization.response;
  const enforcement = await getSsoEnforcement();
  let activeConnections = 0;
  try {
    activeConnections = (await getCachedSsoConnections()).filter((connection) => connection.status === "active").length;
  } catch {
    activeConnections = 0;
  }
  const breakGlass = ssoBreakGlassEnabled();
  const required = ssoRequired();
  return jsonNoStore({
    enforced: required || enforcement.policy.enforced,
    breakGlass,
    required,
    sessionSecretConfigured: sessionSecretConfigured(),
    publicUrlConfigured: publicUrlConfigured(),
    activeConnections,
    legacyIdentityActive: !enforcement.enforced,
  });
}
