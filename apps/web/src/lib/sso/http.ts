import { NextResponse } from "next/server";

import { publicOrigin } from "./config";

export const NO_STORE_HEADERS = { "cache-control": "no-store" } as const;

/** Redirect with a relative Location, for paths where no trusted public origin is available. */
export const relativeRedirect = (path: string, status = 303) =>
  new NextResponse(null, { status, headers: { location: path, ...NO_STORE_HEADERS } });

export const jsonNoStore = (payload: unknown, status = 200) =>
  NextResponse.json(payload, { status, headers: NO_STORE_HEADERS });

/**
 * State-changing auth endpoints accept only same-origin browser requests: the Origin header must equal the
 * public origin, or (when a browser omits Origin) Sec-Fetch-Site must be same-origin.
 */
export const isSameOriginRequest = (request: Request) => {
  const expected = publicOrigin(request.url);
  if (!expected) return false;
  const origin = request.headers.get("origin");
  if (origin) return origin === expected;
  return request.headers.get("sec-fetch-site") === "same-origin";
};

export const CONNECTION_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
