import { NextRequest } from "next/server";

import { currentUserActor } from "@/lib/identity";
import { authorizeIdentityRequest } from "@/lib/sso/admin-auth";
import { beginSsoLogin } from "@/lib/sso/start";

/** Admin test sign-in: may use a draft connection and records the result that lets it become active. */
export async function GET(request: NextRequest) {
  const authorization = await authorizeIdentityRequest(request, "identity:admin");
  if (!authorization.ok) return authorization.response;
  return beginSsoLogin(request, { actor: currentUserActor(authorization.user) || "unknown" });
}
