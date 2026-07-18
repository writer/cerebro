import { NextRequest, NextResponse } from "next/server";

import { authorizationErrorResponse, authorizeCurrentUser } from "@/lib/authorization";
import { resolveCurrentUserFromHeadersWithFallback } from "@/lib/identity";
import { runtimeSecurityProducers } from "@/lib/security-producers-runtime";

export async function GET(request: NextRequest) {
  const currentUser = await resolveCurrentUserFromHeadersWithFallback(request.headers);
  if (!currentUser) {
    return NextResponse.json(
      {
        code: "identity_missing",
        error: "Current user identity is required.",
        permission: "identity:read",
      },
      {
        status: 401,
        headers: { "cache-control": "private, no-store" },
      },
    );
  }
  const decision = authorizeCurrentUser(currentUser, "identity:read");
  if (!decision.allowed) return authorizationErrorResponse(decision);
  return NextResponse.json(
    { producers: runtimeSecurityProducers() },
    { headers: { "cache-control": "private, no-store" } },
  );
}
