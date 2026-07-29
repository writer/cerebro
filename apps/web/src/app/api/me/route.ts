import { NextRequest, NextResponse } from "next/server";

import { authorizationErrorResponse, authorizeCurrentUser } from "@/lib/authorization";
import {
  authHeadersFor,
  buildCerebroUrl,
  fetchCerebro,
  proxyFetchError,
  responseHeadersFor,
  rustOwnsWebAuthority,
} from "@/lib/cerebro-proxy";
import { resolveCurrentUserFromHeadersWithFallback } from "@/lib/identity";
import { currentUserServerAuditFields } from "@/lib/identity-server";

export async function GET(request: NextRequest) {
  if (rustOwnsWebAuthority()) {
    try {
      const response = await fetchCerebro(buildCerebroUrl("v1/me"), {
        method: "GET",
        headers: authHeadersFor(request),
        cache: "no-store",
        signal: request.signal,
      });
      return new NextResponse(await response.text(), {
        status: response.status,
        headers: {
          ...responseHeadersFor(response),
          "cache-control": "private, no-store",
        },
      });
    } catch (error) {
      return proxyFetchError(error);
    }
  }
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
