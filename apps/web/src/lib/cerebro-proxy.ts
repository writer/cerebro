import { NextRequest, NextResponse } from "next/server";
import { createHash, createHmac } from "crypto";

import { headersWithTrace, startWebSpan } from "./observability";
import { normalizeProxyPath } from "./identity-write-stamp";

const API_BASE =
  process.env.CEREBRO_API_BASE ??
  process.env.NEXT_PUBLIC_CEREBRO_API_BASE ??
  "http://localhost:8080";

const RUST_RUNTIME_HEALTH_PATH = "v1/source-runtimes/health";
const RUST_PRODUCT_GRAPH_NEIGHBORHOOD_PATH = "platform/graph/neighborhood";
const RUST_TENANT_AUTH_CONTEXT = Buffer.from(
  "cerebro-organizational-graph/tenant/v1\0",
  "utf8",
);
const MIN_RUST_SHARED_SECRET_BYTES = 32;

const firstConfiguredApiKey = (value?: string) =>
  value
    ?.split(",")
    .map((entry) => entry.trim().split(":", 1)[0]?.trim())
    .find(Boolean);

const parseBooleanEnv = (value?: string) => {
  if (value === undefined) {
    return undefined;
  }
  const normalized = value.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }
  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }
  return false;
};

const parseNonNegativeMs = (value: string | undefined, fallback: number) => {
  const parsed = Number.parseInt(value ?? String(fallback), 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
};

const SERVER_API_KEY =
  process.env.CEREBRO_API_KEY ??
  process.env.CEREBRO_API_TOKEN ??
  process.env.CEREBRO_X_API_KEY ??
  firstConfiguredApiKey(process.env.CEREBRO_API_KEYS);

const SERVER_AUTHORIZATION =
  process.env.CEREBRO_AUTHORIZATION ??
  (process.env.CEREBRO_BEARER_TOKEN
    ? `Bearer ${process.env.CEREBRO_BEARER_TOKEN}`
    : undefined);

export const configuredOrganizationalGraphTenant = (
  value = process.env.CEREBRO_ORGANIZATIONAL_GRAPH_TENANT_ID,
) => {
  const tenantID = value?.trim();
  if (!tenantID) return undefined;
  if (tenantID.length > 256 || /[\u0000-\u001f\u007f]/.test(tenantID)) {
    throw new Error("CEREBRO_ORGANIZATIONAL_GRAPH_TENANT_ID is not a valid header value");
  }
  return tenantID;
};

export const configuredRustPlatformApiBase = (
  value = process.env.CEREBRO_RUST_PLATFORM_API_BASE,
) => {
  const configured = value?.trim();
  if (!configured) return undefined;
  const base = new URL(configured);
  if (!["http:", "https:"].includes(base.protocol) || base.username || base.password || base.search || base.hash) {
    throw new Error("CEREBRO_RUST_PLATFORM_API_BASE must be an HTTP(S) origin without credentials, query, or fragment");
  }
  return base.toString();
};

export const rustTenantAuthHeaders = (tenantID: string, sharedSecret: string): HeadersInit => {
  const tenant = configuredOrganizationalGraphTenant(tenantID);
  if (!tenant) {
    throw new Error("CEREBRO_ORGANIZATIONAL_GRAPH_TENANT_ID is required for Rust platform authentication");
  }
  if (Buffer.byteLength(sharedSecret, "utf8") < MIN_RUST_SHARED_SECRET_BYTES) {
    throw new Error(
      `CEREBRO_ORGANIZATIONAL_GRAPH_SHARED_SECRET must be at least ${MIN_RUST_SHARED_SECRET_BYTES} bytes for Rust runtime health`,
    );
  }
  const tenantBytes = Buffer.from(tenant, "utf8");
  const tenantLength = Buffer.alloc(8);
  tenantLength.writeBigUInt64BE(BigInt(tenantBytes.length));
  const token = createHmac("sha256", sharedSecret)
    .update(RUST_TENANT_AUTH_CONTEXT)
    .update(tenantLength)
    .update(tenantBytes)
    .digest("hex");
  return {
    Authorization: `Bearer ${token}`,
    "X-Cerebro-Tenant": tenant,
  };
};

const isRustPlatformPath = (path: string) => {
  const normalizedPath = normalizeProxyPath(path);
  return normalizedPath === RUST_RUNTIME_HEALTH_PATH
    || normalizedPath === RUST_PRODUCT_GRAPH_NEIGHBORHOOD_PATH;
};

const usesOrganizationalGraphTenant = (path: string) => {
  const normalizedPath = normalizeProxyPath(path);
  return normalizedPath === RUST_PRODUCT_GRAPH_NEIGHBORHOOD_PATH || normalizedPath.startsWith("grc/");
};

const forwardRequestAuth =
  parseBooleanEnv(process.env.CEREBRO_FORWARD_AUTH_HEADERS) ??
  !Boolean(SERVER_API_KEY || SERVER_AUTHORIZATION);
const DEFAULT_PROXY_TIMEOUT_MS = 45000;
const proxyTimeoutMs = Number.parseInt(process.env.CEREBRO_PROXY_TIMEOUT_MS ?? String(DEFAULT_PROXY_TIMEOUT_MS), 10);
const PROXY_TIMEOUT_MS = Number.isFinite(proxyTimeoutMs) && proxyTimeoutMs > 0 ? proxyTimeoutMs : DEFAULT_PROXY_TIMEOUT_MS;
const PROXY_CACHE_TTL_MS = parseNonNegativeMs(process.env.CEREBRO_PROXY_CACHE_TTL_MS, 60000);
const PROXY_CACHE_STALE_MS = parseNonNegativeMs(process.env.CEREBRO_PROXY_CACHE_STALE_MS, 300000);
const PROXY_CACHE_MAX_ENTRIES = 400;
const RETRY_STATUSES = new Set([502, 504]);
const CEREBRO_TENANT_HEADER = "X-Cerebro-Tenant";
const CEREBRO_WORKSPACE_HEADER = "X-Cerebro-Workspace";
const MAX_TENANT_ID_BYTES = 256;
const MAX_WORKSPACE_ID_BYTES = 128;

export const shouldRetryUpstreamResponse = (response: Response) =>
  RETRY_STATUSES.has(response.status)
  || (response.status === 503 && Boolean(response.headers.get("retry-after")));

type CachedProxyResponse = {
  status: number;
  headers: Record<string, string>;
  body: string;
  expiresAt: number;
  staleAt: number;
};

export type ProxyResponsePayload = Pick<CachedProxyResponse, "status" | "headers" | "body"> & {
  state: "miss" | "stale";
};

const proxyResponseCache = new Map<string, CachedProxyResponse>();
const proxyResponseInflight = new Map<string, Promise<ProxyResponsePayload>>();
const USER_STAMP_HEADERS = [
  "x-cerebro-user-email",
  "x-cerebro-user-id",
  "x-cerebro-user-name",
  "x-cerebro-user-subject",
] as const;

export class CerebroProxyError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export type CerebroProxyScope =
  | {
      ok: true;
      headers: Record<string, string>;
      tenantID: string;
      workspaceID: string;
    }
  | {
      ok: false;
      error: string;
    };

const invalidScope = (): CerebroProxyScope => ({
  ok: false,
  error: "Provide one matching tenant and workspace selector. A workspace requires an explicit tenant.",
});

const validScopeID = (value: string, maxBytes: number) =>
  value !== "*"
  && !value.includes(",")
  && Buffer.byteLength(value, "utf8") <= maxBytes
  && !/[\u0000-\u001f\u007f]/.test(value);

const selectScopeID = (
  request: NextRequest,
  queryName: string,
  headerName: string,
  maxBytes: number,
) => {
  const queryValues = request.nextUrl.searchParams.getAll(queryName);
  if (queryValues.length > 1) return null;
  const queryValue = queryValues[0]?.trim() ?? "";
  const headerValue = request.headers.get(headerName)?.trim() ?? "";
  if (
    (queryValue !== "" && !validScopeID(queryValue, maxBytes))
    || (headerValue !== "" && !validScopeID(headerValue, maxBytes))
    || (queryValue !== "" && headerValue !== "" && queryValue !== headerValue)
  ) {
    return null;
  }
  return queryValue || headerValue;
};

// cerebroProxyScopeFor reconciles the public selector forms before the proxy
// can drop a header, inject a tenant, or construct a shared cache key.
export const cerebroProxyScopeFor = (request: NextRequest): CerebroProxyScope => {
  const tenantID = selectScopeID(request, "tenant_id", CEREBRO_TENANT_HEADER, MAX_TENANT_ID_BYTES);
  const workspaceID = selectScopeID(request, "workspace_id", CEREBRO_WORKSPACE_HEADER, MAX_WORKSPACE_ID_BYTES);
  if (tenantID === null || workspaceID === null || (workspaceID !== "" && tenantID === "")) {
    return invalidScope();
  }
  const headers: Record<string, string> = {};
  if (tenantID) headers[CEREBRO_TENANT_HEADER] = tenantID;
  if (workspaceID) headers[CEREBRO_WORKSPACE_HEADER] = workspaceID;
  return { ok: true, headers, tenantID, workspaceID };
};

const requiredCerebroProxyScope = (request: NextRequest) => {
  const scope = cerebroProxyScopeFor(request);
  if (!scope.ok) {
    throw new CerebroProxyError(scope.error, 400);
  }
  return scope;
};

export const supportsApplicationWorkspaceScope = (path: string) =>
  normalizeProxyPath(path).startsWith("grc/")
  || normalizeProxyPath(path) === "connectors/coverage";

export const getCerebroProxyConfig = () => ({
  apiBase: API_BASE,
  serverAuthConfigured: Boolean(SERVER_API_KEY || SERVER_AUTHORIZATION),
  forwardRequestAuth,
});

export const getCerebroPublicConfig = () => ({
  apiBase: "/api/cerebro",
  serverAuthConfigured: Boolean(SERVER_API_KEY || SERVER_AUTHORIZATION),
  forwardRequestAuth,
});

export const rustOwnsWebAuthority = () =>
  process.env.CEREBRO_AUTHORITY_MODE?.trim().toLowerCase() === "rust";

export const buildCerebroUrl = (path: string, search = "") => {
  const normalizedPath = normalizeProxyPath(path);
  const rustPlatformBase = configuredRustPlatformApiBase();
  const apiBase = rustPlatformBase && isRustPlatformPath(normalizedPath)
    ? rustPlatformBase
    : API_BASE;
  const base = new URL(apiBase.endsWith("/") ? apiBase : `${apiBase}/`);
  const basePath = base.pathname.endsWith("/") ? base.pathname.slice(0, -1) : base.pathname;
  const pathSegments = normalizedPath
    .split("/")
    .filter(Boolean)
    .map((segment) => encodeURIComponent(segment));
  base.pathname = [basePath, ...pathSegments].filter(Boolean).join("/");
  base.search = search;
  return base;
};

export const authHeadersFor = (request: NextRequest, upstreamPath = ""): HeadersInit => {
  const scope = requiredCerebroProxyScope(request);
  if (scope.workspaceID && !supportsApplicationWorkspaceScope(upstreamPath)) {
    throw new CerebroProxyError("Workspace scope is not supported for this Cerebro route.", 400);
  }
  const headers: Record<string, string> = {
    Accept: "application/json, text/plain;q=0.9, */*;q=0.8",
    ...scope.headers,
  };
  if (configuredRustPlatformApiBase() && isRustPlatformPath(upstreamPath)) {
    const configuredTenantID = configuredOrganizationalGraphTenant();
    if (scope.tenantID && scope.tenantID !== configuredTenantID) {
      throw new CerebroProxyError("The requested tenant does not match the active Cerebro authority.", 400);
    }
    return {
      ...headers,
      ...rustTenantAuthHeaders(
        configuredTenantID ?? "",
        process.env.CEREBRO_ORGANIZATIONAL_GRAPH_SHARED_SECRET ?? "",
      ),
    };
  }
  const requestApiKey =
    request.headers.get("x-cerebro-api-key") ?? request.headers.get("x-api-key");
  const requestAuthorization = request.headers.get("authorization");

  if (forwardRequestAuth && requestApiKey) {
    headers["X-Cerebro-API-Key"] = requestApiKey;
  } else if (SERVER_API_KEY) {
    headers["X-Cerebro-API-Key"] = SERVER_API_KEY;
  }

  if (forwardRequestAuth && requestAuthorization) {
    headers.Authorization = requestAuthorization;
  } else if (SERVER_AUTHORIZATION) {
    headers.Authorization = SERVER_AUTHORIZATION;
  }

  const organizationalGraphTenant = configuredOrganizationalGraphTenant();
  if (
    organizationalGraphTenant &&
    usesOrganizationalGraphTenant(upstreamPath) &&
    !scope.tenantID
  ) {
    headers[CEREBRO_TENANT_HEADER] = organizationalGraphTenant;
  }

  return headers;
};

export const signedIdentityHeadersFor = (request: NextRequest): HeadersInit => {
  const scope = requiredCerebroProxyScope(request);
  if (scope.workspaceID) {
    throw new CerebroProxyError("Workspace scope is not supported by the active Cerebro authority.", 400);
  }
  const headers: Record<string, string> = {
    Accept: "application/json, text/plain;q=0.9, */*;q=0.8",
    ...scope.headers,
  };
  const authorization = request.headers.get("authorization");
  if (authorization) {
    headers.Authorization = authorization;
  }
  return headers;
};

export const isCacheableCerebroPath = (path: string) => {
  if (PROXY_CACHE_TTL_MS <= 0) {
    return false;
  }
  const normalized = path.replace(/^\/+|\/+$/g, "").split("?", 1)[0];
  return [
    "grc/dashboard",
    "grc/program-readiness",
    "grc/controls",
    "grc/control-packets",
    "grc/control-packets/detail",
    "grc/findings",
    "grc/evidence",
    "grc/inventory/categories",
    "grc/inventory/assets",
    "grc/inventory/assets/detail",
    "grc/inventory/resource-scope",
    "grc/inventory/asset-reports",
    "platform/graph/neighborhood",
  ].includes(normalized) || normalized.startsWith("grc/inventory/asset-reports/") || normalized.startsWith("grc/entities/") || normalized.startsWith("grc/audit-packets/");
};

export const cerebroProxyCacheKey = (target: URL, headers: HeadersInit) => {
  const normalizedHeaders = new Headers(headers);
  const sharesServerOwnedDashboard = normalizeProxyPath(target.pathname).endsWith("grc/dashboard");
  if (
    sharesServerOwnedDashboard
    && !forwardRequestAuth
    && Boolean(SERVER_API_KEY || SERVER_AUTHORIZATION)
  ) {
    USER_STAMP_HEADERS.forEach((name) => normalizedHeaders.delete(name));
  }
  const authHeaders = Array.from(normalizedHeaders.entries()).sort(([left], [right]) => left.localeCompare(right));
  return createHash("sha256")
    .update(target.toString())
    .update(JSON.stringify(authHeaders))
    .digest("hex");
};

export const warmCerebroProxyCache = async (path: string, search = "") => {
  if (
    rustOwnsWebAuthority()
    || forwardRequestAuth
    || (!SERVER_API_KEY && !SERVER_AUTHORIZATION)
    || !isCacheableCerebroPath(path)
  ) {
    return "skipped" as const;
  }
  const target = buildCerebroUrl(path, search);
  const warmRequestURL = new URL("http://localhost/api/cerebro-cache-warm");
  warmRequestURL.search = search;
  const request = new NextRequest(warmRequestURL);
  const authHeaders = authHeadersFor(request, path);
  const key = cerebroProxyCacheKey(target, authHeaders);
  const cached = readCerebroProxyCache(key, true);
  if (cached) {
    return cached.state;
  }
  const inflight = readCerebroProxyInflight(key);
  if (inflight) {
    await inflight;
    return "dedupe" as const;
  }
  const load = async (): Promise<ProxyResponsePayload> => {
    const response = await fetchCerebro(target, { method: "GET", headers: authHeaders });
    const body = await response.text();
    const headers = responseHeadersFor(response);
    if (!("content-type" in headers)) {
      headers["content-type"] = "text/plain";
    }
    writeCerebroProxyCache(key, response, body, headers);
    return { body, headers, state: "miss", status: response.status };
  };
  const response = await trackCerebroProxyInflight(key, load());
  return response.status >= 200 && response.status < 300 ? response.state : "skipped" as const;
};

export const readCerebroProxyCache = (key: string, allowStale = false) => {
  const cached = proxyResponseCache.get(key);
  if (!cached) {
    return null;
  }
  const now = Date.now();
  if (cached.expiresAt > now) {
    return { ...cached, state: "hit" as const };
  }
  if (allowStale && cached.staleAt > now) {
    return { ...cached, state: "stale" as const };
  }
  if (cached.staleAt > now) {
    return null;
  }
  proxyResponseCache.delete(key);
  return null;
};

export const readCerebroProxyInflight = (key: string) => proxyResponseInflight.get(key) ?? null;

export const shouldBypassCerebroProxyCache = (headers: Headers) => {
  const cacheControl = (headers.get("cache-control") ?? "").toLowerCase();
  const pragma = (headers.get("pragma") ?? "").toLowerCase();
  return cacheControl
    .split(",")
    .map((token) => token.trim())
    .some((token) => token === "no-cache" || token === "no-store")
    || pragma.split(",").map((token) => token.trim()).includes("no-cache");
};

export const withCerebroCacheBypassHeader = (headers: HeadersInit): Headers => {
  const next = new Headers(headers);
  next.set("cache-control", "no-cache");
  return next;
};

export const trackCerebroProxyInflight = (key: string, request: Promise<ProxyResponsePayload>) => {
  const tracked = request.finally(() => {
    if (proxyResponseInflight.get(key) === tracked) {
      proxyResponseInflight.delete(key);
    }
  });
  proxyResponseInflight.set(key, tracked);
  return tracked;
};

export const writeCerebroProxyCache = (key: string, response: Response, body: string, headers: Record<string, string>) => {
  if (!response.ok || PROXY_CACHE_TTL_MS <= 0) {
    return;
  }
  if (proxyResponseCache.size >= PROXY_CACHE_MAX_ENTRIES) {
    const firstKey = proxyResponseCache.keys().next().value;
    if (firstKey) {
      proxyResponseCache.delete(firstKey);
    }
  }
  const now = Date.now();
  proxyResponseCache.set(key, {
    status: response.status,
    headers,
    body,
    expiresAt: now + PROXY_CACHE_TTL_MS,
    staleAt: now + PROXY_CACHE_TTL_MS + PROXY_CACHE_STALE_MS,
  });
};

export const cachedResponseHeaders = (cached: Pick<CachedProxyResponse, "headers">, state: "hit" | "miss" | "stale" | "dedupe"): Record<string, string> => {
  const upstreamCacheState = cached.headers["x-cerebro-cache"];
  const headers: Record<string, string> = {
    ...cached.headers,
    "cache-control": "private, max-age=0, must-revalidate",
    "x-cerebro-web-cache": state,
    "x-cerebro-cache": state,
  };
  if (upstreamCacheState) {
    headers["x-cerebro-upstream-cache"] = upstreamCacheState;
  }
  if (state === "stale") {
    headers.warning = "110 - Response is stale";
  }
  return headers;
};

export const fetchCerebro = async (target: URL, init: RequestInit = {}) => {
  const method = (init.method ?? "GET").toUpperCase();
  const maxAttempts = method === "GET" ? 2 : 1;
  const parentHeaders = new Headers(init.headers);
  const span = startWebSpan("cerebro.upstream.fetch", {
    component: "cerebro-proxy",
    operation: "fetch",
    "http.request.body.size": requestBodySize(init.body),
    "http.request.header.accept": parentHeaders.get("accept") ?? "",
    "http.request.header.content_type": parentHeaders.get("content-type") ?? "",
    "http.request.method": method,
    "server.port": target.port ? Number.parseInt(target.port, 10) : defaultPort(target),
    "server.address": target.hostname,
    "upstream.retry.max_attempts": maxAttempts,
    "url.scheme": target.protocol.replace(":", ""),
    "url.path_depth": target.pathname.split("/").filter(Boolean).length,
    "url.path_family": targetPathFamily(target),
  }, parentHeaders.get("traceparent"));
  const tracedHeaders = headersWithTrace(parentHeaders, span);

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const controller = new AbortController();
    const parentSignal = init.signal;
    const abortFromParent = () => controller.abort();
    if (parentSignal?.aborted) {
      controller.abort();
    } else {
      parentSignal?.addEventListener("abort", abortFromParent, { once: true });
    }
    const timeout = setTimeout(() => controller.abort(), PROXY_TIMEOUT_MS);

    try {
      const response = await fetch(target, {
        ...init,
        headers: tracedHeaders,
        signal: controller.signal,
      });

      if (attempt < maxAttempts && shouldRetryUpstreamResponse(response)) {
        span.increment("upstream.retry.count");
        span.event("cerebro.upstream.retry", {
          attempt,
          "http.response.status_code": response.status,
        });
        await response.body?.cancel();
        continue;
      }

      span.end(response.status >= 500 ? "failed" : "completed", {
        attempts: attempt,
        "http.response.header.content_type": response.headers.get("content-type") ?? "",
        "http.response.header.retry_after": response.headers.get("retry-after") ?? "",
        "http.response.status_code": response.status,
        upstream_trace_id_present: Boolean(response.headers.get("x-cerebro-trace-id")),
      });
      return response;
    } catch (error) {
      const timedOut = error instanceof Error && error.name === "AbortError";
      if (attempt < maxAttempts && !timedOut) {
        span.increment("upstream.retry.count");
        span.event("cerebro.upstream.retry", {
          attempt,
          error_kind: error instanceof Error ? error.constructor.name : typeof error,
        });
        continue;
      }
      const proxyError = new CerebroProxyError(
        timedOut ? "Cerebro API request timed out" : "Unable to reach Cerebro API",
        timedOut ? 504 : 502,
      );
      span.captureException(error, {
        component: "cerebro-proxy",
        operation: "fetch",
      });
      span.end("failed", {
        attempts: attempt,
        error_kind: timedOut ? "abort_error" : "fetch_error",
        "http.response.status_code": proxyError.status,
      });
      throw proxyError;
    } finally {
      parentSignal?.removeEventListener("abort", abortFromParent);
      clearTimeout(timeout);
    }
  }

  span.end("failed", {
    attempts: maxAttempts,
    error_kind: "retry_exhausted",
    "http.response.status_code": 502,
  });
  throw new CerebroProxyError("Unable to reach Cerebro API", 502);
};

export const proxyFetchError = (error: unknown) =>
  NextResponse.json(
    {
      error: error instanceof Error ? error.message : "Unable to reach Cerebro API",
    },
    { status: error instanceof CerebroProxyError ? error.status : 502 },
  );

export const responseHeadersFor = (response: Response): Record<string, string> => {
  const headers: Record<string, string> = {};
  [
    "content-type",
    "www-authenticate",
    "cache-control",
    "retry-after",
    "vary",
    "warning",
    "x-cerebro-cache",
    "x-cerebro-trace-id",
    "x-cerebro-web-trace-id",
    "x-request-id",
  ].forEach((name) => {
    const value = response.headers.get(name);
    if (value) {
      headers[name] = value;
    }
  });
  return headers;
};

const targetPathFamily = (target: URL) => {
  const segments = target.pathname.split("/").filter(Boolean).slice(0, 2);
  return segments.length ? `/${segments.join("/")}` : "/";
};

const requestBodySize = (body: BodyInit | null | undefined) => {
  if (!body) return 0;
  if (typeof body === "string") return new TextEncoder().encode(body).byteLength;
  if (body instanceof URLSearchParams) return new TextEncoder().encode(body.toString()).byteLength;
  if (body instanceof Blob) return body.size;
  if (body instanceof ArrayBuffer) return body.byteLength;
  if (ArrayBuffer.isView(body)) return body.byteLength;
  return undefined;
};

const defaultPort = (target: URL) => {
  if (target.protocol === "https:") return 443;
  if (target.protocol === "http:") return 80;
  return undefined;
};
