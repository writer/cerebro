import { NextRequest, NextResponse } from "next/server";
import { parse } from "yaml";

import { authorizationErrorResponse, authorizeCurrentUser } from "@/lib/authorization";
import { authHeadersFor, buildCerebroUrl, fetchCerebro, proxyFetchError } from "@/lib/cerebro-proxy";
import { cerebroFixtureResponseFor } from "@/lib/cerebro-fixtures";
import { resolveCurrentUserFromHeadersWithFallback } from "@/lib/identity";

export const parseOpenApiDocument = (raw: string): Record<string, unknown> | null => {
  try {
    const parsed = parse(raw);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
};

const invalidOpenApiResponse = () => NextResponse.json(
  { error: "The OpenAPI specification is invalid." },
  { status: 502 },
);

export async function GET(request: NextRequest) {
  const currentUser = await resolveCurrentUserFromHeadersWithFallback(request.headers);
  if (!currentUser) {
    return NextResponse.json(
      {
        code: "identity_missing",
        error: "Current user identity is required.",
        permission: "cerebro:read",
      },
      { status: 401 },
    );
  }
  const decision = authorizeCurrentUser(currentUser, "cerebro:read");
  if (!decision.allowed) return authorizationErrorResponse(decision);
  const fixture = cerebroFixtureResponseFor({
    method: "GET",
    path: "openapi.yaml",
    searchParams: request.nextUrl.searchParams,
  });
  if (fixture) {
    const spec = parseOpenApiDocument(fixture.body);
    return spec ? NextResponse.json(spec) : invalidOpenApiResponse();
  }

  let response: Response;
  try {
    response = await fetchCerebro(buildCerebroUrl("openapi.yaml"), {
      cache: "no-store",
      headers: authHeadersFor(request),
    });
  } catch (error) {
    return proxyFetchError(error);
  }

  if (!response.ok) {
    return NextResponse.json(
      { error: `Failed to load OpenAPI (${response.status})` },
      { status: response.status },
    );
  }

  const raw = await response.text();
  const spec = parseOpenApiDocument(raw);
  if (!spec) return invalidOpenApiResponse();

  return NextResponse.json(spec);
}
