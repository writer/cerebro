import { NextRequest, NextResponse } from "next/server";

import { CerebroProxyError } from "@/lib/cerebro-proxy";
import { identityApiRequest } from "@/lib/sso/identity-api";

type RouteContext = {
  params: Promise<{ path?: string[] }>;
};

const SCIM_CONTENT_TYPE = "application/scim+json";
const MAX_SCIM_BODY_BYTES = 1024 * 1024;
const SEGMENT_PATTERN = /^[A-Za-z0-9._~:@-]{1,256}$/;

const scimError = (status: number, detail: string, scimType?: string) =>
  new NextResponse(
    JSON.stringify({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
      status: String(status),
      detail,
      ...(scimType ? { scimType } : {}),
    }),
    {
      status,
      headers: {
        "content-type": SCIM_CONTENT_TYPE,
        "cache-control": "no-store",
        ...(status === 401 ? { "www-authenticate": 'Bearer realm="cerebro-scim"' } : {}),
      },
    },
  );

const bearerToken = (authorization: string | null) => {
  const match = /^Bearer\s+(\S+)\s*$/i.exec(authorization ?? "");
  return match?.[1] ?? "";
};

const scimPath = (segments: string[] | undefined) => {
  const parts = segments ?? [];
  if (parts.length === 0 || parts.length > 4) return null;
  if (parts.some((segment) => segment === "." || segment === ".." || !SEGMENT_PATTERN.test(segment))) return null;
  return parts.map((segment) => encodeURIComponent(segment)).join("/");
};

/**
 * Public SCIM 2.0 endpoint for the IdP. Requests are forwarded verbatim to Go with the web service credential;
 * the IdP's bearer token travels only as X-Cerebro-SCIM-Token, which Go hashes and checks.
 */
const forward = async (request: NextRequest, context: RouteContext) => {
  const token = bearerToken(request.headers.get("authorization"));
  if (!token || token.length > 512) return scimError(401, "A SCIM bearer token is required.");
  const path = scimPath((await context.params).path);
  if (!path) return scimError(404, "Unknown SCIM resource.");

  const method = request.method.toUpperCase();
  let body: string | undefined;
  if (method !== "GET" && method !== "DELETE" && method !== "HEAD") {
    body = await request.text();
    if (Buffer.byteLength(body, "utf8") > MAX_SCIM_BODY_BYTES) return scimError(413, "SCIM request body is larger than 1 MB.");
  }
  try {
    const upstream = await identityApiRequest(method, `scim/v2/${path}`, {
      search: request.nextUrl.search,
      body,
      headers: {
        Accept: `${SCIM_CONTENT_TYPE}, application/json;q=0.9`,
        ...(body !== undefined ? { "Content-Type": SCIM_CONTENT_TYPE } : {}),
        "X-Cerebro-SCIM-Token": token,
      },
      timeoutMs: 30_000,
    });
    return new NextResponse(upstream.status === 204 ? null : upstream.body, {
      status: upstream.status,
      headers: {
        "content-type": upstream.contentType.includes("json") ? SCIM_CONTENT_TYPE : upstream.contentType,
        "cache-control": "no-store",
      },
    });
  } catch (error) {
    const status = error instanceof CerebroProxyError ? error.status : 502;
    return scimError(status, "The SCIM service is unavailable.");
  }
};

export const GET = forward;
export const POST = forward;
export const PUT = forward;
export const PATCH = forward;
export const DELETE = forward;
