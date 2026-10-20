import { NextRequest, NextResponse } from "next/server";

import { GRC_UPLOAD_MAX_BYTES, GRC_UPLOAD_MAX_LABEL } from "./lib/grc-upload-limits";
import { ASK_AGENT_REQUEST_MAX_BYTES } from "./lib/ask-images";
import {
  buildContentSecurityPolicy,
  CSP_HEADER,
  generateCspNonce,
  NONCE_HEADER,
} from "./lib/content-security-policy";
import { readSessionToken, sessionTokenHash } from "./lib/sso/cookies";
import { getSsoEnforcement } from "./lib/sso/policy";
import { sanitizeReturnTo } from "./lib/sso/return-to";
import { lookupSsoSessionCached } from "./lib/sso/session";

const MAX_API_BODY_BYTES = 2 * 1024 * 1024; // 2 MB
const MAX_SCIM_BODY_BYTES = 1024 * 1024; // 1 MB

const GRC_UPLOAD_PATHS = new Set([
  "/api/cerebro/grc/policy-lifecycle/uploads",
  "/api/cerebro/grc/vendors/uploads",
]);

export async function proxy(request: NextRequest) {
  const pathname = request.nextUrl.pathname;
  const isApiRoute = pathname.startsWith("/api/");
  const isScimRoute = pathname.startsWith("/scim/");

  if (
    (isApiRoute || isScimRoute) &&
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

  if (!isApiRoute && !isScimRoute) {
    const loginRedirect = await ssoLoginRedirect(request);
    if (loginRedirect) return loginRedirect;
  }

  return withContentSecurityPolicy(request);
}

const SSO_EXEMPT_DOCUMENTS = new Set(["/login", "/oauth2/idpresponse", "/robots.txt", "/manifest.webmanifest"]);

const ssoExemptDocument = (pathname: string) =>
  SSO_EXEMPT_DOCUMENTS.has(pathname) || pathname.startsWith("/login/") || pathname.startsWith("/_next/");

/**
 * With SSO enforced, a document request without a live session goes to /login. API routes are not
 * redirected: they fail closed in their own authorization. When the policy cannot be read the document is
 * served, because every API call it makes is refused anyway.
 */
async function ssoLoginRedirect(request: NextRequest) {
  if (request.method !== "GET" && request.method !== "HEAD") return null;
  if (ssoExemptDocument(request.nextUrl.pathname)) return null;
  let enforced = false;
  try {
    const enforcement = await getSsoEnforcement();
    enforced = enforcement.enforced && !enforcement.unknown;
  } catch {
    enforced = false;
  }
  if (!enforced) return null;
  const token = readSessionToken(request.headers);
  if (token) {
    try {
      if (await lookupSsoSessionCached(sessionTokenHash(token))) return null;
    } catch {
      return null;
    }
  }
  const loginUrl = request.nextUrl.clone();
  loginUrl.pathname = "/login";
  loginUrl.search = "";
  const returnTo = sanitizeReturnTo(`${request.nextUrl.pathname}${request.nextUrl.search}`, "/");
  if (returnTo !== "/") loginUrl.searchParams.set("returnTo", returnTo);
  const response = NextResponse.redirect(loginUrl, { status: 307, headers: { "cache-control": "no-store" } });
  return response;
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
  if (request.nextUrl.pathname.startsWith("/scim/")) {
    return MAX_SCIM_BODY_BYTES;
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
  if (maxBytes === MAX_SCIM_BODY_BYTES) {
    return "Request body is larger than 1 MB.";
  }
  return "Request body is larger than 2 MB.";
}

export const config = {
  matcher: [
    "/api/:path*",
    "/scim/:path*",
    // Every document route needs the CSP nonce. Static assets are not
    // documents, and router prefetches reuse the page's nonce, so both skip
    // the proxy.
    {
      source: "/((?!api|_next/static|_next/image|favicon.ico|icon.svg|apple-icon.png).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
