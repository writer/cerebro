import { NextRequest, NextResponse } from "next/server";

import { GRC_UPLOAD_MAX_BYTES, GRC_UPLOAD_MAX_LABEL } from "./lib/grc-upload-limits";
import { ASK_AGENT_REQUEST_MAX_BYTES } from "./lib/ask-images";
import {
  buildContentSecurityPolicy,
  CSP_HEADER,
  generateCspNonce,
  NONCE_HEADER,
} from "./lib/content-security-policy";

const MAX_API_BODY_BYTES = 2 * 1024 * 1024; // 2 MB

const GRC_UPLOAD_PATHS = new Set([
  "/api/cerebro/grc/policy-lifecycle/uploads",
  "/api/cerebro/grc/vendors/uploads",
]);

export function proxy(request: NextRequest) {
  const isApiRoute = request.nextUrl.pathname.startsWith("/api/");

  if (
    isApiRoute &&
    request.method !== "GET" &&
    request.method !== "HEAD" &&
    request.method !== "DELETE"
  ) {
    const contentLength = request.headers.get("content-length")?.trim();
    if (!contentLength) {
      return NextResponse.json(
        { error: "Content-Length is required for API request bodies." },
        { status: 411 },
      );
    }
    if (!/^\d+$/.test(contentLength)) {
      return NextResponse.json(
        { error: "Content-Length must be a non-negative integer." },
        { status: 400 },
      );
    }
    const bytes = Number(contentLength);
    const maxBytes = maxBodyBytesForRequest(request);
    if (!Number.isSafeInteger(bytes) || bytes > maxBytes) {
      return NextResponse.json(
        { error: bodyTooLargeMessage(maxBytes) },
        { status: 413 },
      );
    }
  }

  return withContentSecurityPolicy(request);
}

// A fresh nonce per request. Next.js reads it from the Content-Security-Policy
// *request* header and stamps it on every script tag it renders, so the page
// keeps working with no 'unsafe-inline' in script-src. Client-supplied values
// for these headers are overwritten, never trusted.
function withContentSecurityPolicy(request: NextRequest) {
  const nonce = generateCspNonce();
  const policy = buildContentSecurityPolicy({
    nonce,
    development: process.env.NODE_ENV === "development",
  });
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set(NONCE_HEADER, nonce);
  requestHeaders.set(CSP_HEADER, policy);
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set(CSP_HEADER, policy);
  return response;
}

function maxBodyBytesForRequest(request: NextRequest) {
  if (
    request.method === "POST" &&
    request.nextUrl.pathname === "/api/agent/ask" &&
    (request.headers.get("content-type") ?? "").toLowerCase().includes("application/json")
  ) {
    return ASK_AGENT_REQUEST_MAX_BYTES;
  }
  if (
    request.method === "POST" &&
    GRC_UPLOAD_PATHS.has(request.nextUrl.pathname) &&
    (request.headers.get("content-type") ?? "").toLowerCase().includes("multipart/form-data")
  ) {
    return GRC_UPLOAD_MAX_BYTES;
  }
  return MAX_API_BODY_BYTES;
}

function bodyTooLargeMessage(maxBytes: number) {
  if (maxBytes === ASK_AGENT_REQUEST_MAX_BYTES) {
    return "Ask request is larger than 12 MB.";
  }
  if (maxBytes === GRC_UPLOAD_MAX_BYTES) {
    return `Upload is larger than ${GRC_UPLOAD_MAX_LABEL}.`;
  }
  return "Request body is larger than 2 MB.";
}

export const config = {
  matcher: [
    "/api/:path*",
    // Every document route needs the CSP nonce. Static assets are not
    // documents, and router prefetches reuse the page's nonce, so both skip
    // the proxy.
    {
      source: "/((?!api|_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
