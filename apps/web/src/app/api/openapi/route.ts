import { NextRequest, NextResponse } from "next/server";
import { parse } from "yaml";

import { authorizationErrorResponse, authorizeCurrentUser } from "@/lib/authorization";
import { authHeadersFor, buildCerebroUrl, fetchCerebro, proxyFetchError } from "@/lib/cerebro-proxy";
import { cerebroFixtureResponseFor } from "@/lib/cerebro-fixtures";
import { resolveCurrentUserFromHeadersWithFallback } from "@/lib/identity";

const OPENAPI_CACHE_TTL_MS = 5 * 60_000;
let cachedOpenApi: { expiresAt: number; spec: Record<string, unknown> } | null = null;
type OpenApiLoadResult = { spec: Record<string, unknown> | null; status: number };
let openApiInflight: Promise<OpenApiLoadResult> | null = null;

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

const openApiResponse = (spec: Record<string, unknown>) => NextResponse.json(spec, {
  headers: { "cache-control": "private, max-age=300" },
});

const loadOpenApi = async (request: NextRequest) => {
  if (cachedOpenApi && cachedOpenApi.expiresAt > Date.now()) {
    return { spec: cachedOpenApi.spec, status: 200 };
  }
  if (openApiInflight) return openApiInflight;
  openApiInflight = (async () => {
    const response = await fetchCerebro(buildCerebroUrl("openapi.yaml"), {
      cache: "no-store",
      headers: authHeadersFor(request),
    });
    if (!response.ok) return { spec: null, status: response.status };
    const spec = parseOpenApiDocument(await response.text());
    if (spec) cachedOpenApi = { expiresAt: Date.now() + OPENAPI_CACHE_TTL_MS, spec };
    return { spec, status: spec ? 200 : 502 };
  })();
  try {
    return await openApiInflight;
  } finally {
    openApiInflight = null;
  }
};

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
    return spec ? openApiResponse(spec) : invalidOpenApiResponse();
  }

  let loaded: OpenApiLoadResult;
  try {
    loaded = await loadOpenApi(request);
  } catch (error) {
    return proxyFetchError(error);
  }

  if (!loaded.spec) {
    return NextResponse.json(
      { error: "Failed to load OpenAPI." },
      { status: loaded.status },
    );
  }

  return openApiResponse(loaded.spec);
}
