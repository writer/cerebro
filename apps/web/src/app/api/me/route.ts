import { NextRequest, NextResponse } from "next/server";

import { authorizationErrorResponse, authorizeCurrentUser } from "@/lib/authorization";
import { resolveCurrentUserFromHeadersWithFallback } from "@/lib/identity";
import { currentUserServerAuditFields } from "@/lib/identity-server";

export async function GET(request: NextRequest) {
  const user = await resolveCurrentUserFromHeadersWithFallback(request.headers);
  const decision = authorizeCurrentUser(user, "identity:read");
  if (!decision.allowed) {
    console.warn("current-user identity denied", currentUserServerAuditFields(user));
    return authorizationErrorResponse(decision);
  }
  const fallback = user?.source === "local-fallback";
  if (user?.conflicts?.length || user?.warnings?.length || user?.confidence === "unverified") {
    console.warn("current-user identity attention", currentUserServerAuditFields(user));
  }
  return NextResponse.json(
    {
      authenticated: Boolean(user && !fallback),
      fallback,
      user,
    },
    {
      headers: {
        "cache-control": "private, no-store",
      },
    },
  );
}
