import { NextRequest, NextResponse } from "next/server";
import { parse } from "yaml";

import { authHeadersFor, buildCerebroUrl, fetchCerebro, proxyFetchError } from "@/lib/cerebro-proxy";
import { cerebroFixtureResponseFor } from "@/lib/cerebro-fixtures";

export async function GET(request: NextRequest) {
  const fixture = cerebroFixtureResponseFor({
    method: "GET",
    path: "openapi.yaml",
    searchParams: request.nextUrl.searchParams,
  });
  if (fixture) {
    return NextResponse.json(parse(fixture.body));
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
  const spec = parse(raw);

  return NextResponse.json(spec);
}
