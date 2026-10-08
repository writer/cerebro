import { NextRequest, NextResponse } from "next/server";

import { authorizationErrorResponse, authorizeCurrentUser } from "@/lib/authorization";
import { isCerebroFixtureMode } from "@/lib/cerebro-fixtures";
import { identityHealthFromHeaders, identityRuntimeConfig, resolveCurrentUserFromHeadersWithFallback } from "@/lib/identity";

export async function GET(request: NextRequest) {
  if (isCerebroFixtureMode()) {
    return fixtureIdentityHealthResponse();
  }

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

function fixtureIdentityHealthResponse() {
  const config = identityRuntimeConfig();
  return NextResponse.json(
    {
      checkedAt: new Date().toISOString(),
      config,
      current: {
        authenticated: false,
        claimCount: 0,
        confidence: "fallback" as const,
        conflictCount: 0,
        headerCount: 0,
        provider: "local" as const,
        source: "local-fallback" as const,
        warningCount: 0,
      },
      issues: [] as string[],
      status: "ready" as const,
    },
    {
      headers: {
        "cache-control": "private, no-store",
      },
    },
  );
}
