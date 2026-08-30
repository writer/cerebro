import { normalizeProxyPath } from "./identity-write-stamp";

export type CerebroProxyCachePolicy = {
  cacheable: boolean;
};

export type CerebroProxyCacheAdmission =
  | { cacheable: true }
  | {
      cacheable: false;
      reason: "upstream_status" | "upstream_cache_control" | "upstream_set_cookie" | "upstream_vary";
    };

// The dashboard is the only approved aggregate read model for the in-process
// cache. Findings, evidence, controls, packets, and graph results are live
// workflow state and must always be fetched from their authority.
const dashboardCachePolicy: CerebroProxyCachePolicy = {
  cacheable: true,
};

const noCachePolicy: CerebroProxyCachePolicy = {
  cacheable: false,
};

const cachePreventingDirectives = new Set(["no-cache", "no-store", "private"]);

// The proxy cache key includes these request headers. Any other Vary value
// risks reusing a response whose upstream representation depends on data the
// key does not capture.
const supportedVaryHeaders = new Set([
  "accept",
  "authorization",
  "x-cerebro-api-key",
  "x-cerebro-tenant",
  "x-cerebro-workspace",
]);

const normalizedPathForCachePolicy = (path: string) =>
  normalizeProxyPath(path.trim().split("?", 1)[0] ?? "");

const cacheControlDirectiveNames = (value: string | null) =>
  (value ?? "")
    .split(",")
    .map((directive) => directive.trim().split("=", 1)[0]?.trim().toLowerCase() ?? "")
    .filter(Boolean);

const upstreamVaryIsSupported = (value: string | null) => {
  if (!value?.trim()) return true;
  return value
    .split(",")
    .map((header) => header.trim().toLowerCase())
    .every((header) => Boolean(header) && supportedVaryHeaders.has(header));
};

export const cerebroProxyCachePolicyFor = (path: string): CerebroProxyCachePolicy =>
  normalizedPathForCachePolicy(path) === "grc/dashboard"
    ? dashboardCachePolicy
    : noCachePolicy;

export const upstreamCacheControlPreventsStorage = (value: string | null) =>
  cacheControlDirectiveNames(value).some((directive) => cachePreventingDirectives.has(directive));

export const upstreamCacheControlRequiresNoStore = (value: string | null) =>
  cacheControlDirectiveNames(value).includes("no-store");

export const cacheAdmissionForCerebroProxyResponse = (
  response: Response,
): CerebroProxyCacheAdmission => {
  if (!response.ok) return { cacheable: false, reason: "upstream_status" };
  if (upstreamCacheControlPreventsStorage(response.headers.get("cache-control"))) {
    return { cacheable: false, reason: "upstream_cache_control" };
  }
  if (response.headers.has("set-cookie")) {
    return { cacheable: false, reason: "upstream_set_cookie" };
  }
  if (!upstreamVaryIsSupported(response.headers.get("vary"))) {
    return { cacheable: false, reason: "upstream_vary" };
  }
  return { cacheable: true };
};
