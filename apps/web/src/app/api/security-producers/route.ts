import { NextRequest, NextResponse } from "next/server";

import { authorizationErrorResponse, authorizeCurrentUser } from "@/lib/authorization";
import { resolveCurrentUserFromHeadersWithFallback } from "@/lib/identity";
import { runtimeSecurityProducerCatalog } from "@/lib/security-producers-runtime";

export async function GET(request: NextRequest) {
  const currentUser = await resolveCurrentUserFromHeadersWithFallback(request.headers);
  if (!currentUser) {
    return NextResponse.json(
      {
        code: "identity_missing",
        error: "Current user identity is required.",
        permission: "cerebro:read",
      },
      {
        status: 401,
        headers: { "cache-control": "private, no-store" },
      },
    );
  }
  const decision = authorizeCurrentUser(currentUser, "cerebro:read");
  if (!decision.allowed) return authorizationErrorResponse(decision);
  const catalog = runtimeSecurityProducerCatalog();
  if (catalog.state === "invalid") {
    return NextResponse.json(
      {
        code: "security_producer_catalog_invalid",
        error: "Security producer catalog is unavailable.",
      },
      {
        status: 503,
        headers: { "cache-control": "private, no-store" },
      },
    );
  }
  return NextResponse.json(
    { producers: catalog.producers },
    { headers: { "cache-control": "private, no-store" } },
  );
}
