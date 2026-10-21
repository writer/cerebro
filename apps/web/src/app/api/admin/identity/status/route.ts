import { NextRequest } from "next/server";

import { authorizeIdentityRequest } from "@/lib/sso/admin-auth";
import { publicUrlConfigured, sessionSecretConfigured, ssoBreakGlassEnabled, ssoRequired } from "@/lib/sso/config";
import { jsonNoStore } from "@/lib/sso/http";
import { getCachedSsoConnections, getSsoEnforcement, type EnforcementState } from "@/lib/sso/policy";

const enforcementStateLabel = (enforcement: EnforcementState, required: boolean) => {
  if (enforcement.unavailable) return "unavailable" as const;
  if (enforcement.unknown) return "unknown" as const;
  return required || enforcement.policy.enforced ? ("enforced" as const) : ("off" as const);
};

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
  const state = enforcementStateLabel(enforcement, required);
  return jsonNoStore({
    enforced: enforcement.unavailable ? required : required || enforcement.policy.enforced,
    state,
    breakGlass,
    required,
    sessionSecretConfigured: sessionSecretConfigured(),
    publicUrlConfigured: publicUrlConfigured(),
    activeConnections,
    legacyIdentityActive: !enforcement.enforced,
  });
}
