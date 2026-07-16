import { NextRequest, NextResponse } from "next/server";

import {
  authHeadersFor,
  buildCerebroUrl,
  cachedResponseHeaders,
  cerebroProxyCacheKey,
  fetchCerebro,
  isCacheableCerebroPath,
  ProxyResponsePayload,
  proxyFetchError,
  readCerebroProxyCache,
  readCerebroProxyInflight,
  responseHeadersFor,
  shouldBypassCerebroProxyCache,
  trackCerebroProxyInflight,
  withCerebroCacheBypassHeader,
  writeCerebroProxyCache,
} from "@/lib/cerebro-proxy";
import { cerebroFixtureResponseFor } from "@/lib/cerebro-fixtures";
import { normalizeAskModel } from "@/lib/ask";
import {
  authorizationErrorResponse,
  authorizeCurrentUser,
  type AuthorizationDecision,
} from "@/lib/authorization";
import { permissionForCerebroProxyRequest } from "@/lib/rbac";
import {
  currentUserActor,
  currentUserActorLabel,
  resolveCurrentUserFromHeadersWithFallback,
  type CurrentUser,
} from "@/lib/identity";
import { currentUserServerAuditFields } from "@/lib/identity-server";
import { normalizeProxyPath, stampCurrentUserOnWriteBody } from "@/lib/identity-write-stamp";
import {
  headersWithTrace,
  responseHeadersWithTrace,
  startWebSpan,
  type WebSpan,
} from "@/lib/observability";

type RouteContext = {
  params: Promise<{ path?: string[] }>;
};

export async function GET(request: NextRequest, context: RouteContext) {
  const [params, currentUser] = await Promise.all([
    context.params,
    resolveCurrentUserFromHeadersWithFallback(request.headers),
  ]);
  const path = (params.path ?? []).join("/");
  const span = startWebSpan("cerebro.proxy.request", proxySpanAttributes("GET", path, request), request.headers.get("traceparent"));
  const requiredPermission = permissionForCerebroProxyRequest("GET", path);
  const decision = authorizeCurrentUser(currentUser, requiredPermission);
  span.annotate(authorizationSpanAttributes(decision, currentUser));
  if (!decision.allowed) {
    console.warn("cerebro proxy read denied", { ...currentUserServerAuditFields(currentUser), permission: requiredPermission });
    return tracedAuthorizationError(decision, span);
  }
  const url = new URL(request.url);
  const fixture = tracedFixtureResponse("GET", path, request, span);
  if (fixture) {
    return fixture;
  }
  const target = buildCerebroUrl(path, url.search);
  const baseAuthHeaders = authHeadersFor(request);
  const authHeaders = {
    ...baseAuthHeaders,
    ...currentUserPreferenceHeaders(currentUser),
  };
  const bypassCache = shouldBypassCerebroProxyCache(request.headers);
  const cacheablePath = isCacheableCerebroPath(path);
  const upstreamHeaders = headersWithTrace(bypassCache ? withCerebroCacheBypassHeader(authHeaders) : authHeaders, span);
  const cacheKey = !bypassCache && cacheablePath ? cerebroProxyCacheKey(target, baseAuthHeaders) : null;
  span.annotate({
    proxy_cache_bypass: bypassCache,
    proxy_cache_configured: Boolean(cacheKey),
    proxy_cacheable_path: cacheablePath,
  });
  const cached = cacheKey ? readCerebroProxyCache(cacheKey) : null;
  if (cached) {
    span.increment("proxy.cache.lookup.count");
    span.increment("proxy.cache.hit.count");
    span.end("completed", {
      cache_state: cached.state,
      "http.response.status_code": cached.status,
      ...responseSpanAttributes(cached.status, cached.headers, cached.body),
    });
    return new NextResponse(cached.body, {
      status: cached.status,
      headers: responseHeadersWithTrace(cachedResponseHeaders(cached, cached.state), span),
    });
  }

  const inflight = cacheKey ? readCerebroProxyInflight(cacheKey) : null;
  if (inflight) {
    const payload = await inflight;
    span.increment("proxy.cache.dedupe.count");
    span.end(payload.status >= 500 ? "failed" : "completed", {
      cache_state: payload.state === "stale" ? "stale" : "dedupe",
      "http.response.status_code": payload.status,
      ...responseSpanAttributes(payload.status, payload.headers, payload.body),
    });
    return new NextResponse(payload.body, {
      status: payload.status,
      headers: responseHeadersWithTrace(cachedResponseHeaders(payload, payload.state === "stale" ? "stale" : "dedupe"), span),
    });
  }

  const load = async (): Promise<ProxyResponsePayload> => {
    let response: Response;
    try {
      response = await fetchCerebro(target, {
        method: "GET",
        headers: upstreamHeaders,
        cache: "no-store",
        signal: request.signal,
      });
    } catch (error) {
      const stale = cacheKey ? readCerebroProxyCache(cacheKey, true) : null;
      if (stale) {
        span.increment("proxy.cache.stale.count");
        return {
          body: stale.body,
          headers: cachedResponseHeaders(stale, "stale"),
          state: "stale" as const,
          status: stale.status,
        };
      }
      throw error;
    }

    if (cacheKey && [502, 503, 504].includes(response.status)) {
      const stale = readCerebroProxyCache(cacheKey, true);
      if (stale) {
        span.increment("proxy.cache.stale.count");
        return {
          body: stale.body,
          headers: cachedResponseHeaders(stale, "stale"),
          state: "stale" as const,
          status: stale.status,
        };
      }
    }

    const body = await response.text();
    const headers = responseHeadersFor(response);
    if (!("content-type" in headers)) {
      headers["content-type"] = "text/plain";
    }
    if (cacheKey) {
      writeCerebroProxyCache(cacheKey, response, body, headers);
      span.increment("proxy.cache.write.count");
    }
    return {
      body,
      headers,
      state: "miss" as const,
      status: response.status,
    };
  };

  let payload: Awaited<ReturnType<typeof load>>;
  try {
    payload = cacheKey ? await trackCerebroProxyInflight(cacheKey, load()) : await load();
  } catch (error) {
    const stale = cacheKey ? readCerebroProxyCache(cacheKey, true) : null;
    if (stale) {
      span.increment("proxy.cache.stale.count");
      span.end("completed", {
        cache_state: "stale",
        "http.response.status_code": stale.status,
        ...responseSpanAttributes(stale.status, stale.headers, stale.body),
      });
      return new NextResponse(stale.body, {
        status: stale.status,
        headers: responseHeadersWithTrace(cachedResponseHeaders(stale, "stale"), span),
      });
    }
    return tracedProxyError(error, span);
  }

  span.end(payload.status >= 500 ? "failed" : "completed", {
    cache_state: payload.state,
    "http.response.status_code": payload.status,
    ...responseSpanAttributes(payload.status, payload.headers, payload.body),
  });
  return new NextResponse(payload.body, {
    status: payload.status,
    headers: responseHeadersWithTrace(cachedResponseHeaders(payload, payload.state), span),
  });
}

export async function POST(request: NextRequest, context: RouteContext) {
  const [params, currentUser] = await Promise.all([
    context.params,
    resolveCurrentUserFromHeadersWithFallback(request.headers),
  ]);
  const path = (params.path ?? []).join("/");
  const span = startWebSpan(
    "cerebro.proxy.request",
    proxySpanAttributes("POST", path, request),
    request.headers.get("traceparent"),
  );
  const normalizedPath = normalizeProxyPath(path);
  const isMultipartUpload = isMultipartFormDataRequest(request);
  const requiredPermission = permissionForCerebroProxyRequest("POST", normalizedPath);
  const decision = authorizeCurrentUser(currentUser, requiredPermission);
  span.annotate(authorizationSpanAttributes(decision, currentUser));
  span.annotate({
    request_body_was_stamped_with_actor: decision.allowed && !isMultipartUpload,
    multipart_request: isMultipartUpload,
    normalized_proxy_path: normalizedPath,
  });
  if (!decision.allowed) {
    console.warn("cerebro proxy post denied", { ...currentUserServerAuditFields(currentUser), permission: requiredPermission });
    return tracedAuthorizationError(decision, span);
  }
  const url = new URL(request.url);
  let body: string | ArrayBuffer;
  const currentActor = currentUserActor(currentUser);
  const acceptsEventStream = (request.headers.get("accept") ?? "").includes("text/event-stream");
  const isAskStreamRequest = normalizedPath === "grc/ask" && acceptsEventStream;
  span.annotate({
    stream_requested: acceptsEventStream,
    stream_surface: isAskStreamRequest ? "ask" : "none",
  });
  if (isMultipartUpload) {
    body = await request.arrayBuffer();
  } else {
    let requestBody = await request.text();
    if (isAskStreamRequest) {
      requestBody = normalizeAskRequestBody(requestBody);
    }
    body = stampCurrentUserOnWriteBody(requestBody, normalizedPath, currentActor);
    const fixture = tracedFixtureResponse("POST", path, request, span, body);
    if (fixture) {
      return fixture;
    }
  }
  const target = buildCerebroUrl(path, url.search);
  const requestContentType = request.headers.get("content-type");
  const headers = new Headers(authHeadersFor(request));
  for (const [key, value] of Object.entries(currentUserPreferenceHeaders(currentUser))) {
    headers.set(key, value);
  }
  headers.set("accept", isAskStreamRequest ? "text/event-stream" : "application/json, text/plain;q=0.9, */*;q=0.8");
  if (isAskStreamRequest) {
    headers.set("x-cerebro-web-surface", "ask");
  }
  if (requestContentType) {
    headers.set("content-type", requestContentType);
  } else if (!isMultipartUpload) {
    headers.set("content-type", "application/json");
  }

  let response: Response;
  try {
    response = await fetchCerebro(target, {
      method: "POST",
      headers: headersWithTrace(headers, span),
      body,
      cache: "no-store",
      signal: request.signal,
    });
  } catch (error) {
    return tracedProxyError(error, span);
  }

  const passThroughHeaders = responseHeadersFor(response);
  const contentType = passThroughHeaders["content-type"] ?? response.headers.get("content-type") ?? "";

  if (isAskStreamRequest && contentType.includes("text/event-stream") && response.body) {
    span.end(response.status >= 500 ? "failed" : "completed", {
      stream: true,
      "http.response.status_code": response.status,
      "http.response.header.content_type": contentType,
    });
    return new NextResponse(response.body, {
      status: response.status,
      headers: {
        ...responseHeadersWithTrace(passThroughHeaders, span),
        "content-type": "text/event-stream",
        "cache-control": "no-cache, no-transform",
        connection: "keep-alive",
        "x-cerebro-web-surface": "ask",
      },
    });
  }

  const text = await response.text();
  span.end(response.status >= 500 ? "failed" : "completed", {
    "http.response.status_code": response.status,
    ...responseSpanAttributes(response.status, passThroughHeaders, text),
  });
  return new NextResponse(text, {
    status: response.status,
    headers: responseHeadersWithTrace(passThroughHeaders, span),
  });
}

export async function PATCH(request: NextRequest, context: RouteContext) {
  const [params, currentUser, requestBody] = await Promise.all([
    context.params,
    resolveCurrentUserFromHeadersWithFallback(request.headers),
    request.text(),
  ]);
  const path = (params.path ?? []).join("/");
  const normalizedPath = normalizeProxyPath(path);
  const requiredPermission = permissionForCerebroProxyRequest("PATCH", normalizedPath);
  const decision = authorizeCurrentUser(currentUser, requiredPermission);
  const span = startWebSpan(
    "cerebro.proxy.request",
    proxySpanAttributes("PATCH", path, request, requestBody),
    request.headers.get("traceparent"),
  );
  span.annotate(authorizationSpanAttributes(decision, currentUser));
  if (!decision.allowed) {
    console.warn("cerebro proxy write denied", { ...currentUserServerAuditFields(currentUser), permission: requiredPermission });
    return tracedAuthorizationError(decision, span);
  }
  const url = new URL(request.url);
  let body = requestBody;
  body = stampCurrentUserOnWriteBody(
    body,
    normalizedPath,
    currentUserActor(currentUser),
  );
  const fixture = tracedFixtureResponse("PATCH", path, request, span, body);
  if (fixture) {
    return fixture;
  }
  const target = buildCerebroUrl(path, url.search);
  const headers = {
    ...authHeadersFor(request),
    ...currentUserPreferenceHeaders(currentUser),
    "content-type": request.headers.get("content-type") ?? "application/json",
    accept: "application/json, text/plain;q=0.9, */*;q=0.8",
  };

  let response: Response;
  try {
    response = await fetchCerebro(target, {
      method: "PATCH",
      headers: headersWithTrace(headers, span),
      body,
      cache: "no-store",
      signal: request.signal,
    });
  } catch (error) {
    return tracedProxyError(error, span);
  }

  const text = await response.text();
  span.end(response.status >= 500 ? "failed" : "completed", {
    "http.response.status_code": response.status,
    ...responseSpanAttributes(response.status, responseHeadersFor(response), text),
  });
  return new NextResponse(text, {
    status: response.status,
    headers: responseHeadersWithTrace(responseHeadersFor(response), span),
  });
}

export async function PUT(request: NextRequest, context: RouteContext) {
  const [params, currentUser, requestBody] = await Promise.all([
    context.params,
    resolveCurrentUserFromHeadersWithFallback(request.headers),
    request.text(),
  ]);
  const path = (params.path ?? []).join("/");
  const normalizedPath = normalizeProxyPath(path);
  const requiredPermission = permissionForCerebroProxyRequest("PUT", normalizedPath);
  const decision = authorizeCurrentUser(currentUser, requiredPermission);
  const span = startWebSpan(
    "cerebro.proxy.request",
    proxySpanAttributes("PUT", path, request, requestBody),
    request.headers.get("traceparent"),
  );
  span.annotate(authorizationSpanAttributes(decision, currentUser));
  if (!decision.allowed) {
    console.warn("cerebro proxy put denied", { ...currentUserServerAuditFields(currentUser), permission: requiredPermission });
    return tracedAuthorizationError(decision, span);
  }
  const url = new URL(request.url);
  const body = stampCurrentUserOnWriteBody(
    requestBody,
    normalizedPath,
    currentUserActor(currentUser),
  );
  const fixture = tracedFixtureResponse("PUT", path, request, span, body);
  if (fixture) {
    return fixture;
  }
  const target = buildCerebroUrl(path, url.search);
  const headers = {
    ...authHeadersFor(request),
    ...currentUserPreferenceHeaders(currentUser),
    "content-type": request.headers.get("content-type") ?? "application/json",
    accept: "application/json, text/plain;q=0.9, */*;q=0.8",
  };

  let response: Response;
  try {
    response = await fetchCerebro(target, {
      method: "PUT",
      headers: headersWithTrace(headers, span),
      body,
      cache: "no-store",
      signal: request.signal,
    });
  } catch (error) {
    return tracedProxyError(error, span);
  }

  const text = await response.text();
  span.end(response.status >= 500 ? "failed" : "completed", {
    "http.response.status_code": response.status,
    ...responseSpanAttributes(response.status, responseHeadersFor(response), text),
  });
  return new NextResponse(text, {
    status: response.status,
    headers: responseHeadersWithTrace(responseHeadersFor(response), span),
  });
}

export async function DELETE(request: NextRequest, context: RouteContext) {
  const [params, currentUser] = await Promise.all([
    context.params,
    resolveCurrentUserFromHeadersWithFallback(request.headers),
  ]);
  const path = (params.path ?? []).join("/");
  const normalizedPath = normalizeProxyPath(path);
  const requiredPermission = permissionForCerebroProxyRequest("DELETE", normalizedPath);
  const decision = authorizeCurrentUser(currentUser, requiredPermission);
  const span = startWebSpan(
    "cerebro.proxy.request",
    proxySpanAttributes("DELETE", path, request),
    request.headers.get("traceparent"),
  );
  span.annotate(authorizationSpanAttributes(decision, currentUser));
  if (!decision.allowed) {
    console.warn("cerebro proxy delete denied", { ...currentUserServerAuditFields(currentUser), permission: requiredPermission });
    return tracedAuthorizationError(decision, span);
  }
  const url = new URL(request.url);
  const fixture = tracedFixtureResponse("DELETE", path, request, span);
  if (fixture) {
    return fixture;
  }
  const target = buildCerebroUrl(path, url.search);
  const headers = {
    ...authHeadersFor(request),
    ...currentUserPreferenceHeaders(currentUser),
    accept: "application/json, text/plain;q=0.9, */*;q=0.8",
  };

  let response: Response;
  try {
    response = await fetchCerebro(target, {
      method: "DELETE",
      headers: headersWithTrace(headers, span),
      cache: "no-store",
      signal: request.signal,
    });
  } catch (error) {
    return tracedProxyError(error, span);
  }

  const text = await response.text();
  const nullBodyStatus = response.status === 204 || response.status === 205 || response.status === 304;
  span.end(response.status >= 500 ? "failed" : "completed", {
    "http.response.status_code": response.status,
    ...responseSpanAttributes(response.status, responseHeadersFor(response), text),
  });
  return new NextResponse(nullBodyStatus ? null : text, {
    status: response.status,
    headers: responseHeadersWithTrace(responseHeadersFor(response), span),
  });
}

function normalizeAskRequestBody(body: string): string {
  try {
    const parsed = JSON.parse(body) as Record<string, unknown>;
    return JSON.stringify({
      ...parsed,
      model: normalizeAskModel(typeof parsed.model === "string" ? parsed.model : undefined),
    });
  } catch {
    return body;
  }
}

function isMultipartFormDataRequest(request: NextRequest) {
  return (request.headers.get("content-type") ?? "").toLowerCase().includes("multipart/form-data");
}

function tracedFixtureResponse(method: string, path: string, request: NextRequest, span: WebSpan, body?: string) {
  const url = new URL(request.url);
  const fixture = cerebroFixtureResponseFor({
    method,
    path,
    searchParams: url.searchParams,
    body,
  });
  if (!fixture) {
    return null;
  }
  span.increment("proxy.fixture.count");
  span.end(fixture.status >= 500 ? "failed" : "completed", {
    cache_state: "fixture",
    fixture_mode: true,
    "http.response.status_code": fixture.status,
    ...responseSpanAttributes(fixture.status, fixture.headers, fixture.body),
  });
  return new NextResponse(fixture.body, {
    status: fixture.status,
    headers: responseHeadersWithTrace({
      ...fixture.headers,
      "x-cerebro-cache": "fixture",
    }, span),
  });
}

function proxySpanAttributes(method: string, path: string, request: NextRequest, body?: string) {
  const url = new URL(request.url);
  return {
    main: true,
    wide_event: true,
    component: "cerebro-api-route",
    operation: method,
    "http.request.method": method,
    "http.request.body.size": body === undefined ? requestBodySize(request) : byteLength(body),
    "http.request.header.accept": request.headers.get("accept") ?? "",
    "http.request.header.content_type": request.headers.get("content-type") ?? "",
    "http.request.header.user_agent": request.headers.get("user-agent") ?? "",
    "network.protocol.name": url.protocol.replace(":", ""),
    "server.address": url.hostname,
    "url.path_depth": path.split("/").filter(Boolean).length,
    "url.path_family": proxyPathFamily(path),
    "user_agent.family": userAgentFamily(request.headers.get("user-agent")),
  };
}

function tracedProxyError(error: unknown, span: WebSpan) {
  span.captureException(error, {
    component: "cerebro-api-route",
    operation: "proxy",
  });
  const response = proxyFetchError(error);
  response.headers.set("x-cerebro-web-trace-id", span.traceId);
  span.end("failed", {
    error_kind: error instanceof Error ? error.constructor.name : typeof error,
    "http.response.status_code": response.status,
  });
  return response;
}

function tracedAuthorizationError(decision: AuthorizationDecision, span: WebSpan) {
  const response = authorizationErrorResponse(decision);
  response.headers.set("x-cerebro-web-trace-id", span.traceId);
  span.end("completed", {
    ...authorizationDecisionAttributes(decision),
    ...responseSpanAttributes(response.status, Object.fromEntries(response.headers.entries())),
    "http.response.status_code": response.status,
  });
  return response;
}

function currentUserPreferenceHeaders(user: CurrentUser | null | undefined): Record<string, string> {
  const headers: Record<string, string> = {};
  const actor = cleanPreferenceHeaderValue(currentUserActor(user));
  const label = cleanPreferenceHeaderValue(currentUserActorLabel(user));
  const email = cleanPreferenceHeaderValue(user?.email);
  const subject = cleanPreferenceHeaderValue(user?.subject);

  if (actor) headers["X-Cerebro-User-ID"] = actor;
  if (label) headers["X-Cerebro-User-Name"] = label;
  if (email) headers["X-Cerebro-User-Email"] = email;
  if (subject) headers["X-Cerebro-User-Subject"] = subject;
  return headers;
}

function cleanPreferenceHeaderValue(value: string | undefined) {
  return (value ?? "").replace(/[\u0000-\u001F\u007F]/g, "").trim().slice(0, 256);
}

function proxyPathFamily(path: string) {
  const segments = path.split("/").filter(Boolean).slice(0, 2);
  return segments.length ? `/${segments.join("/")}` : "/";
}

function authorizationSpanAttributes(decision: AuthorizationDecision, user: CurrentUser | null) {
  const audit = currentUserServerAuditFields(user);
  return {
    ...authorizationDecisionAttributes(decision),
    "enduser.id_hash": audit.actorKey,
    identity_authenticated: audit.authenticated,
    identity_claim_count: audit.claimCount,
    identity_confidence: audit.confidence,
    identity_conflict_count: audit.conflictCount,
    identity_group_count: audit.groupCount,
    identity_header_count: audit.headerCount,
    identity_provider: audit.provider,
    identity_role_count: audit.roleCount,
    identity_scope_count: audit.scopeCount,
    identity_source: audit.source,
    identity_warning_count: audit.warningCount,
  };
}

function authorizationDecisionAttributes(decision: AuthorizationDecision) {
  return {
    authorization_allowed: decision.allowed,
    authorization_code: decision.code,
    authorization_permission: decision.permission,
    authorization_status_code: decision.status,
  };
}

function responseSpanAttributes(status: number, headers: Record<string, string>, body?: string) {
  return {
    "http.response.body.size": body === undefined ? undefined : byteLength(body),
    "http.response.header.cache_control": headers["cache-control"] ?? "",
    "http.response.header.content_type": headers["content-type"] ?? "",
    "http.response.header.retry_after": headers["retry-after"] ?? "",
    upstream_cache_state: headers["x-cerebro-upstream-cache"] ?? headers["x-cerebro-cache"] ?? "",
    upstream_trace_id_present: Boolean(headers["x-cerebro-trace-id"]),
  };
}

function requestBodySize(request: NextRequest) {
  const raw = request.headers.get("content-length");
  if (!raw) {
    return 0;
  }
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
}

function byteLength(value: string) {
  return new TextEncoder().encode(value).byteLength;
}

function userAgentFamily(value: string | null) {
  const normalized = (value ?? "").toLowerCase();
  if (!normalized) return "none";
  if (normalized.includes("bot") || normalized.includes("crawler") || normalized.includes("spider")) return "bot";
  if (normalized.includes("edge") || normalized.includes("edg/")) return "edge";
  if (normalized.includes("chrome")) return "chrome";
  if (normalized.includes("safari")) return "safari";
  if (normalized.includes("firefox")) return "firefox";
  if (normalized.includes("curl")) return "curl";
  if (normalized.includes("node")) return "node";
  return "other";
}
