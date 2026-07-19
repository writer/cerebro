"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { useApiKey } from "@/components/providers";
import { fetchCerebro } from "@/lib/cerebro-client";
import type { CustomDashboard, CustomDashboardWidget } from "@/lib/custom-dashboards";
import { grcResponseErrorMessage, useGRCQuery } from "@/lib/grc-client";

export const REPORT_CATALOG_PATH = "/grc/report-catalog";
export const REPORT_QUERY_PATH = "/grc/query";
export const REPORT_QUERY_DEFAULT_LIMIT = 100;
export const REPORT_QUERY_MAX_LIMIT = 500;

export type ReportParamType = "string" | "enum" | "int" | "bool";

export type ReportParam = {
  id: string;
  type: ReportParamType;
  required?: boolean;
  scope?: boolean;
  allowed_values?: string[];
  description?: string;
};

export type ReportSource = {
  id: string;
  domain: string;
  title: string;
  description: string;
  method: string;
  path: string;
  params: ReportParam[] | null;
  visualizations: string[];
  default_limit: number;
  max_limit: number;
  cache_scope?: string;
  exportable?: boolean;
};

export type ReportCatalogResponse = { sources: ReportSource[]; generated_at: string };

// WidgetReportQuery mirrors the backend POST /grc/query request body: a bound
// catalog source plus allowlisted parameter values and an optional row limit.
export type WidgetReportQuery = {
  source_id: string;
  params?: Record<string, string>;
  limit?: number;
};

export type ReportQueryResponse = { source_id: string; generated_at: string; data: unknown };

export type ReportTable = { columns: string[]; rows: Array<Record<string, unknown>> };

const isScalar = (value: unknown): value is string | number | boolean | null =>
  value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean";

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

// findSource returns the catalog source with the given id.
export const findSource = (sources: ReportSource[], sourceID: string): ReportSource | undefined =>
  sources.find((source) => source.id === sourceID.trim());

// validateWidgetReportQuery mirrors the backend grccatalog validator so the
// authoring UI can reject an unbindable widget before it is saved or run. It
// returns a human-readable error, or null when the query is well-formed.
export const validateWidgetReportQuery = (source: ReportSource | undefined, query: WidgetReportQuery): string | null => {
  if (!source) return `Unknown report source "${query.source_id.trim()}".`;
  const allowed = new Map((source.params ?? []).map((param) => [param.id, param]));
  for (const [key, value] of Object.entries(query.params ?? {})) {
    const param = allowed.get(key.trim());
    if (!param) return `Source "${source.id}" does not support parameter "${key.trim()}".`;
    const error = validateParamValue(param, value);
    if (error) return error;
  }
  for (const param of source.params ?? []) {
    if (param.required && (query.params?.[param.id] ?? "").trim() === "") {
      return `Source "${source.id}" requires parameter "${param.id}".`;
    }
  }
  const maxLimit = source.max_limit > 0 ? source.max_limit : REPORT_QUERY_MAX_LIMIT;
  if (typeof query.limit === "number" && query.limit > maxLimit) {
    return `Limit must be at most ${maxLimit}.`;
  }
  return null;
};

const validateParamValue = (param: ReportParam, raw: string): string | null => {
  const value = raw.trim();
  if (value === "") return null;
  switch (param.type) {
    case "int":
      if (!/^-?\d+$/.test(value)) return `Parameter "${param.id}" must be an integer.`;
      break;
    case "bool":
      if (value !== "true" && value !== "false") return `Parameter "${param.id}" must be true or false.`;
      break;
    case "enum":
      if (!(param.allowed_values ?? []).includes(value)) {
        return `Parameter "${param.id}" must be one of ${(param.allowed_values ?? []).join(", ")}.`;
      }
      break;
  }
  return null;
};

// buildWidgetReportQuery composes the query a widget will POST to /grc/query:
// dashboard filters provide defaults for any parameter the source declares, and
// the widget's own params override them. Only parameters the source actually
// declares are forwarded, so dashboard-wide filters never produce an unknown
// parameter rejection for a source that does not support them.
export const buildWidgetReportQuery = (
  source: ReportSource,
  filters: CustomDashboard["filters"],
  widget: CustomDashboardWidget,
): WidgetReportQuery => {
  const declared = new Set((source.params ?? []).map((param) => param.id));
  const params: Record<string, string> = {};
  for (const [key, value] of Object.entries(filters ?? {})) {
    if (declared.has(key) && value !== undefined && String(value).trim() !== "") {
      params[key] = String(value).trim();
    }
  }
  for (const [key, value] of Object.entries(widget.query?.params ?? {})) {
    if (declared.has(key) && value !== undefined && String(value).trim() !== "") {
      params[key] = String(value).trim();
    }
  }
  const limit = coerceLimit(widget.query?.limit);
  return limit === undefined ? { source_id: source.id, params } : { source_id: source.id, params, limit };
};

const coerceLimit = (value: unknown): number | undefined => {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
};

// catalogWidgetSourceID returns the catalog source a widget is bound to, or an
// empty string for legacy widgets that target a fixed endpoint instead.
export const catalogWidgetSourceID = (widget: CustomDashboardWidget): string =>
  typeof widget.query?.source_id === "string" ? widget.query.source_id.trim() : "";

const findFirstObjectArray = (data: unknown): Array<Record<string, unknown>> | null => {
  if (Array.isArray(data)) {
    return data.length > 0 && data.every(isPlainObject) ? (data as Array<Record<string, unknown>>) : null;
  }
  if (isPlainObject(data)) {
    for (const value of Object.values(data)) {
      if (Array.isArray(value) && value.length > 0 && value.every(isPlainObject)) {
        return value as Array<Record<string, unknown>>;
      }
    }
  }
  return null;
};

// extractReportTable shapes a /grc/query data envelope into a scalar-only table.
// GRC reads wrap their list under a single key (findings, controls, evidence,
// assets, ...), so the first array of objects becomes the rows and the union of
// scalar-valued keys becomes the columns, capped to stay readable.
export const extractReportTable = (data: unknown, maxColumns = 8): ReportTable | null => {
  const rows = findFirstObjectArray(data);
  if (!rows) return null;
  const columns: string[] = [];
  for (const row of rows) {
    for (const [key, value] of Object.entries(row)) {
      if (isScalar(value) && !columns.includes(key)) columns.push(key);
    }
  }
  if (columns.length === 0) return null;
  return { columns: columns.slice(0, maxColumns), rows };
};

// useReportCatalog loads the bounded GRC report source catalog. Pass enabled
// false to skip the fetch for dashboards that bind no catalog sources.
export const useReportCatalog = (enabled = true) => {
  const query = useGRCQuery<ReportCatalogResponse>(enabled ? REPORT_CATALOG_PATH : null);
  return { ...query, sources: query.data?.sources ?? [] };
};

const REPORT_QUERY_CACHE_TTL_MS = 30_000;
const REPORT_QUERY_CACHE_MAX_ENTRIES = 200;

type CachedReportQueryResponse = Awaited<ReturnType<typeof fetchCerebro<ReportQueryResponse>>>;

const reportQueryCache = new Map<string, { expiresAt: number; response: CachedReportQueryResponse }>();
const reportQueryInflight = new Map<string, Promise<CachedReportQueryResponse>>();

const reportQueryCacheKey = (body: string, apiKey?: string) => `${apiKey ?? ""}\n${body}`;

const reportQueryCached = (body: string, apiKey?: string) => {
  const cached = reportQueryCache.get(reportQueryCacheKey(body, apiKey));
  return cached && cached.expiresAt > Date.now() ? cached.response : null;
};

// fetchCachedReportQuery mirrors fetchCachedGRC for the POST /grc/query read:
// successful responses are cached briefly and concurrent identical queries are
// de-duplicated, so a dashboard with many report widgets (or remounts) does not
// multiply backend traffic. force bypasses both the cache and in-flight entry.
const fetchCachedReportQuery = (body: string, apiKey: string | undefined, force: boolean): Promise<CachedReportQueryResponse> => {
  const cacheKey = reportQueryCacheKey(body, apiKey);
  const cached = reportQueryCached(body, apiKey);
  if (!force && cached) {
    return Promise.resolve(cached);
  }
  const inflight = reportQueryInflight.get(cacheKey);
  if (!force && inflight) {
    return inflight;
  }
  const request = fetchCerebro<ReportQueryResponse>(REPORT_QUERY_PATH, apiKey, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  })
    .then((response) => {
      if (response.ok) {
        if (reportQueryCache.size >= REPORT_QUERY_CACHE_MAX_ENTRIES) {
          const firstKey = reportQueryCache.keys().next().value;
          if (firstKey) reportQueryCache.delete(firstKey);
        }
        reportQueryCache.set(cacheKey, { expiresAt: Date.now() + REPORT_QUERY_CACHE_TTL_MS, response });
      }
      return response;
    })
    .finally(() => {
      if (reportQueryInflight.get(cacheKey) === request) reportQueryInflight.delete(cacheKey);
    });
  reportQueryInflight.set(cacheKey, request);
  return request;
};

// useReportQuery runs one bounded report query through POST /grc/query. It
// re-runs whenever the query body changes, shares the brief response cache
// above, and ignores stale or post-unmount responses via a request counter.
export const useReportQuery = (query: WidgetReportQuery | null) => {
  const { apiKey } = useApiKey();
  const [data, setData] = useState<ReportQueryResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const requestID = useRef(0);
  const key = query ? JSON.stringify(query) : "";

  const load = useCallback(
    async (force = false) => {
      if (key === "") {
        setData(null);
        setError(null);
        setLoading(false);
        return;
      }
      const currentRequestID = requestID.current + 1;
      requestID.current = currentRequestID;
      setLoading(!(!force && reportQueryCached(key, apiKey)));
      setError(null);
      let response;
      try {
        response = await fetchCachedReportQuery(key, apiKey, force);
      } catch (err) {
        if (currentRequestID !== requestID.current) return;
        setError(err instanceof Error ? err.message : grcResponseErrorMessage(REPORT_QUERY_PATH, 0, null));
        setLoading(false);
        return;
      }
      if (currentRequestID !== requestID.current) return;
      if (!response.ok) {
        setError(grcResponseErrorMessage(REPORT_QUERY_PATH, response.status, response.data));
        setLoading(false);
        return;
      }
      setData(response.data);
      setLoading(false);
    },
    [apiKey, key],
  );

  useEffect(() => {
    const timer = window.setTimeout(() => void load(false), 0);
    return () => {
      window.clearTimeout(timer);
      requestID.current += 1;
    };
  }, [load]);

  const reload = useCallback(() => load(true), [load]);
  return { data, error, loading, reload };
};
