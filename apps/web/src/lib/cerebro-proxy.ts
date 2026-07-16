import { NextRequest, NextResponse } from "next/server";
import { createHash } from "crypto";

import { headersWithTrace, startWebSpan } from "./observability";

const API_BASE =
  process.env.CEREBRO_API_BASE ??
  process.env.NEXT_PUBLIC_CEREBRO_API_BASE ??
  "http://localhost:8080";

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

const forwardRequestAuth =
  parseBooleanEnv(process.env.CEREBRO_FORWARD_AUTH_HEADERS) ??
  !Boolean(SERVER_API_KEY || SERVER_AUTHORIZATION);
const DEFAULT_PROXY_TIMEOUT_MS = 45000;
const proxyTimeoutMs = Number.parseInt(process.env.CEREBRO_PROXY_TIMEOUT_MS ?? String(DEFAULT_PROXY_TIMEOUT_MS), 10);
const PROXY_TIMEOUT_MS = Number.isFinite(proxyTimeoutMs) && proxyTimeoutMs > 0 ? proxyTimeoutMs : DEFAULT_PROXY_TIMEOUT_MS;
const PROXY_CACHE_TTL_MS = parseNonNegativeMs(process.env.CEREBRO_PROXY_CACHE_TTL_MS, 60000);
const PROXY_CACHE_STALE_MS = parseNonNegativeMs(process.env.CEREBRO_PROXY_CACHE_STALE_MS, 300000);
const PROXY_CACHE_MAX_ENTRIES = 400;
const RETRY_STATUSES = new Set([502, 503, 504]);

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

class CerebroProxyError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export const getCerebroProxyConfig = () => ({
  apiBase: API_BASE,
  serverAuthConfigured: Boolean(SERVER_API_KEY || SERVER_AUTHORIZATION),
  forwardRequestAuth,
});

export const buildCerebroUrl = (path: string, search = "") => {
  const base = new URL(API_BASE.replace(/\/$/, "/"));
  const basePath = base.pathname.replace(/\/$/, "");
  const pathSegments = path
    .split("/")
    .filter(Boolean)
    .map((segment) => encodeURIComponent(segment));
  base.pathname = [basePath, ...pathSegments].filter(Boolean).join("/");
  base.search = search;
  return base;
};

export const authHeadersFor = (request: NextRequest): HeadersInit => {
  const headers: Record<string, string> = { Accept: "application/json, text/plain;q=0.9, */*;q=0.8" };
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

  return headers;
};

export const isCacheableCerebroPath = (path: string) => {
  if (PROXY_CACHE_TTL_MS <= 0) {
    return false;
  }
  const normalized = path.replace(/^\/+|\/+$/g, "");
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
  ].includes(normalized) || normalized.startsWith("grc/inventory/asset-reports/") || normalized.startsWith("grc/entities/") || normalized.startsWith("grc/audit-packets/");
};

export const cerebroProxyCacheKey = (target: URL, headers: HeadersInit) => {
  const authHeaders = Array.from(new Headers(headers).entries()).sort(([left], [right]) => left.localeCompare(right));
  return createHash("sha256")
    .update(target.toString())
    .update(JSON.stringify(authHeaders))
    .digest("hex");
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

      if (attempt < maxAttempts && RETRY_STATUSES.has(response.status)) {
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
