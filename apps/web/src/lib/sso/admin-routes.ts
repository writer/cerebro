import { NextResponse } from "next/server";

import { CerebroProxyError } from "@/lib/cerebro-proxy";
import { currentUserActor, type CurrentUser } from "@/lib/identity";

import { authorizeIdentityRequest } from "./admin-auth";
import { identityApiRequest } from "./identity-api";
import { clearSsoPolicyCache } from "./policy";

const ID = "[A-Za-z0-9_-]{1,128}";

type AdminRoute = {
  pattern: RegExp;
  methods: string[];
  /** Go path under /platform/identity for the matched UI path. */
  upstream: (match: RegExpExecArray) => string;
  /** Field stamped with the acting admin on writes. */
  actorField?: "updatedBy" | "actor";
  invalidatesPolicy?: boolean;
};

const ADMIN_ROUTES: AdminRoute[] = [
  { pattern: /^connections$/, methods: ["GET", "POST"], upstream: () => "sso/connections", actorField: "updatedBy", invalidatesPolicy: true },
  {
    pattern: new RegExp(`^connections/(${ID})$`),
    methods: ["GET", "PUT", "DELETE"],
    upstream: (match) => `sso/connections/${match[1]}`,
    actorField: "updatedBy",
    invalidatesPolicy: true,
  },
  {
    pattern: new RegExp(`^connections/(${ID})/test-result$`),
    methods: ["POST"],
    upstream: (match) => `sso/connections/${match[1]}/test-result`,
    actorField: "actor",
    invalidatesPolicy: true,
  },
  { pattern: /^policy$/, methods: ["GET", "PUT"], upstream: () => "sso/policy", actorField: "updatedBy", invalidatesPolicy: true },
  { pattern: /^scim\/tokens$/, methods: ["GET", "POST"], upstream: () => "scim/tokens" },
  { pattern: new RegExp(`^scim/tokens/(${ID})$`), methods: ["DELETE"], upstream: (match) => `scim/tokens/${match[1]}` },
  { pattern: /^directory\/users$/, methods: ["GET"], upstream: () => "directory/users" },
  { pattern: /^directory\/groups$/, methods: ["GET"], upstream: () => "directory/groups" },
  { pattern: /^sessions$/, methods: ["GET", "DELETE"], upstream: () => "sessions" },
];

const MAX_BODY_BYTES = 256 * 1024;

const json = (payload: unknown, status: number) =>
  NextResponse.json(payload, { status, headers: { "cache-control": "private, no-store" } });

export const matchAdminRoute = (path: string, method: string) => {
  for (const route of ADMIN_ROUTES) {
    const match = route.pattern.exec(path);
    if (!match) continue;
    return { route, match, allowed: route.methods.includes(method) };
  }
  return null;
};

const stampedBody = (raw: string, field: AdminRoute["actorField"], user: CurrentUser | null) => {
  let parsed: unknown;
  try {
    parsed = raw ? JSON.parse(raw) : {};
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const body = { ...(parsed as Record<string, unknown>) };
  if (field) body[field] = currentUserActor(user) || "unknown";
  return JSON.stringify(body);
};

/** Forwards an Access Control request to Go after authorizing it (reads: admin:read, writes: identity:admin). */
export const forwardAdminIdentityRequest = async (request: Request, segments: string[] | undefined) => {
  const method = request.method.toUpperCase();
  const path = (segments ?? []).join("/");
  const resolved = matchAdminRoute(path, method);
  if (!resolved) return json({ error: "Not found." }, 404);
  if (!resolved.allowed) return json({ error: "Method not allowed." }, 405);

  const authorization = await authorizeIdentityRequest(request, method === "GET" ? "admin:read" : "identity:admin");
  if (!authorization.ok) return authorization.response;

  let body: string | undefined;
  if (method === "POST" || method === "PUT") {
    const raw = await request.text();
    if (Buffer.byteLength(raw, "utf8") > MAX_BODY_BYTES) return json({ error: "Request body is too large." }, 413);
    const stamped = stampedBody(raw, resolved.route.actorField, authorization.user);
    if (stamped === null) return json({ error: "Request body must be a JSON object." }, 400);
    // A passing test is what allows a connection to become active, so only the real login test flow
    // (/api/auth/sso/start?test=1) may record one.
    if (path.endsWith("/test-result") && (JSON.parse(stamped) as { ok?: unknown }).ok !== false) {
      return json({ error: "Successful tests are recorded only by the SSO test sign-in." }, 400);
    }
    body = stamped;
  }
  const search = method === "GET" || method === "DELETE" ? new URL(request.url).search : "";
  try {
    const upstream = await identityApiRequest(method, resolved.route.upstream(resolved.match), { search, body });
    if (method !== "GET" && resolved.route.invalidatesPolicy && upstream.status < 400) clearSsoPolicyCache();
    return new NextResponse(upstream.status === 204 ? null : upstream.body, {
      status: upstream.status,
      headers: {
        "content-type": upstream.contentType || "application/json",
        "cache-control": "private, no-store",
      },
    });
  } catch (error) {
    return json({ error: "Identity API is unavailable." }, error instanceof CerebroProxyError ? error.status : 502);
  }
};
