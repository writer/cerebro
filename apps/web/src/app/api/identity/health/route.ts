import { NextRequest, NextResponse } from "next/server";

import { authorizationErrorResponse, authorizeCurrentUser } from "@/lib/authorization";
import { identityHealthFromHeaders, resolveCurrentUserFromHeadersWithFallback } from "@/lib/identity";

export async function GET(request: NextRequest) {
  const currentUser = await resolveCurrentUserFromHeadersWithFallback(request.headers);
  if (!currentUser) {
    return NextResponse.json(
      {
        code: "identity_missing",
        error: "Current user identity is required.",
        permission: "identity:read",
      },
      { status: 401 },
    );
  }
  const decision = authorizeCurrentUser(currentUser, "identity:read");
  if (!decision.allowed) return authorizationErrorResponse(decision);
  return NextResponse.json(
    await identityHealthFromHeaders(request.headers),
    {
      headers: {
        "cache-control": "private, no-store",
      },
    },
  );
}
