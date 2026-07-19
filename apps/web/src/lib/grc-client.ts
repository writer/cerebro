"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState } from "react";

import { useApiKey } from "@/components/providers";
import { fetchCerebro } from "@/lib/cerebro-client";
import { cacheGRCMetadata } from "@/lib/grc-metadata-cache";
import { runtimeStateForQuery } from "@/lib/runtime-state";

export const GRC_QUERY_CACHE_TTL_MS = 30_000;
const GRC_QUERY_CACHE_MAX_ENTRIES = 200;
const DEFAULT_GRC_QUERY_TIMEOUT_MS = 12_000;
const DEFAULT_GRC_FORM_MUTATION_TIMEOUT_MS = 120_000;

export const DASHBOARD_FINDING_LIMIT = 12;

const parsePositiveMs = (value: string | undefined, fallback: number) => {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

export const GRC_QUERY_TIMEOUT_MS = parsePositiveMs(process.env.NEXT_PUBLIC_GRC_QUERY_TIMEOUT_MS, DEFAULT_GRC_QUERY_TIMEOUT_MS);
export const GRC_FORM_MUTATION_TIMEOUT_MS = parsePositiveMs(process.env.NEXT_PUBLIC_GRC_FORM_MUTATION_TIMEOUT_MS, DEFAULT_GRC_FORM_MUTATION_TIMEOUT_MS);

type CachedGRCResponse = {
  expiresAt: number;
  response: Awaited<ReturnType<typeof fetchCerebro>>;
};

const grcQueryCache = new Map<string, CachedGRCResponse>();
const grcQueryInflight = new Map<string, Promise<Awaited<ReturnType<typeof fetchCerebro>>>>();

const grcQueryCacheKey = (path: string, apiKey?: string) => `${apiKey ?? ""}\n${path}`;

export const grcQueryKey = (path: string | null, apiKey?: string) =>
  ["grc", apiKey ?? "", path ?? "disabled"] as const;

export const readCachedGRC = <T,>(path: string, apiKey?: string) => {
  const cached = grcQueryCache.get(grcQueryCacheKey(path, apiKey));
  if (cached && cached.expiresAt > Date.now()) {
    return cached.response as Awaited<ReturnType<typeof fetchCerebro<T>>>;
  }
  return null;
};

const writeGRCQueryCache = (key: string, response: Awaited<ReturnType<typeof fetchCerebro>>) => {
  if (grcQueryCache.size >= GRC_QUERY_CACHE_MAX_ENTRIES) {
    const firstKey = grcQueryCache.keys().next().value;
    if (firstKey) {
      grcQueryCache.delete(firstKey);
    }
  }
  grcQueryCache.set(key, {
    expiresAt: Date.now() + GRC_QUERY_CACHE_TTL_MS,
    response,
  });
};

const withoutAbortSignal = (init: RequestInit) => {
  const rest = { ...init };
  delete rest.signal;
  return rest;
};

const withFreshCacheHeaders = (init: RequestInit) => {
  const headers = new Headers(init.headers);
  headers.set("Cache-Control", "no-cache");
  headers.set("Pragma", "no-cache");
  return { ...init, headers };
};

const timedAbortSignal = (parentSignal: AbortSignal | undefined, timeoutMs: number) => {
  const controller = new AbortController();
  let timedOut = false;
  const timeout = window.setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  const abortFromParent = () => controller.abort();

  if (parentSignal?.aborted) {
    controller.abort();
  } else {
    parentSignal?.addEventListener("abort", abortFromParent, { once: true });
  }

  return {
    signal: controller.signal,
    timedOut: () => timedOut,
    clear: () => {
      window.clearTimeout(timeout);
      parentSignal?.removeEventListener("abort", abortFromParent);
    },
  };
};

const durationLabel = (durationMs: number | null | undefined) => {
  if (typeof durationMs !== "number" || !Number.isFinite(durationMs)) return "";
  if (durationMs >= 1000) return `${(durationMs / 1000).toFixed(durationMs >= 10_000 ? 0 : 1)}s`;
  return `${Math.max(1, Math.round(durationMs))}ms`;
};

const responseDetail = (data: unknown) => {
  if (typeof data === "string") return data.trim();
  if (data && typeof data === "object") {
    const record = data as Record<string, unknown>;
    for (const key of ["error", "message", "detail"]) {
      const value = record[key];
      if (typeof value === "string" && value.trim()) return value.trim();
    }
  }
  return "";
};

export const grcTimeoutMessage = (path: string, timeoutMs: number) =>
  `Cerebro request timed out after ${durationLabel(timeoutMs)} for ${path}`;

export const grcResponseErrorMessage = (path: string, status: number, data: unknown, durationMs?: number | null) => {
  const elapsed = durationLabel(durationMs);
  const detail = responseDetail(data);
  const prefix = [
    `Cerebro request failed (${status})`,
    `for ${path}`,
    elapsed ? `after ${elapsed}` : "",
  ].filter(Boolean).join(" ");
  return detail ? `${prefix}: ${detail}` : prefix;
};

export const fetchCachedGRC = async <T,>(
  path: string,
  apiKey: string | undefined,
  force = false,
  init: RequestInit = {},
) => {
  const key = grcQueryCacheKey(path, apiKey);
  const cached = readCachedGRC<T>(path, apiKey);
  if (!force && cached) {
    return cached;
  }

  const inflight = grcQueryInflight.get(key);
  if (!force && inflight) {
    return inflight as Promise<Awaited<ReturnType<typeof fetchCerebro<T>>>>;
  }

  const requestInit = force ? withFreshCacheHeaders(init) : init.signal ? init : withoutAbortSignal(init);
  const request = fetchCerebro<T>(path, apiKey, requestInit).then((response) => {
    if (response.ok) {
      writeGRCQueryCache(key, response);
      cacheGRCMetadata(response.data);
    }
    return response;
  }).finally(() => {
    if (grcQueryInflight.get(key) === request) {
      grcQueryInflight.delete(key);
    }
  });
  if (!force && !init.signal) {
    grcQueryInflight.set(key, request);
  }
  return request;
};

type GRCQueryPayload<T> = {
  data: T;
  durationMs: number;
  successfulAt: number;
};

const fetchGRCQueryPayload = async <T,>(
  path: string,
  apiKey: string | undefined,
  signal: AbortSignal | undefined,
): Promise<GRCQueryPayload<T>> => {
  const startedAt = performance.now();
  const request = timedAbortSignal(signal, GRC_QUERY_TIMEOUT_MS);
  try {
    const response = await fetchCerebro<T>(path, apiKey, { signal: request.signal });
    const durationMs = Math.round(performance.now() - startedAt);
    if (!response.ok) {
      throw new Error(grcResponseErrorMessage(path, response.status, response.data, durationMs));
    }
    cacheGRCMetadata(response.data);
    return {
      data: response.data,
      durationMs,
      successfulAt: Date.now(),
    };
  } catch (error) {
    if (request.timedOut()) {
      throw new Error(grcTimeoutMessage(path, GRC_QUERY_TIMEOUT_MS));
    }
    throw error;
  } finally {
    request.clear();
  }
};

export const grcPath = (path: string, params: Record<string, string | number | undefined> = {}) => {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && String(value).trim() !== "") {
      query.set(key, String(value));
    }
  });
  const queryString = query.toString();
  return queryString ? `${path}?${queryString}` : path;
};

export const grcDashboardPath = (params: Record<string, string | number | undefined> = {}) =>
  grcPath("/grc/dashboard", { ...params, view: "summary" });

export const grcProgramReadinessPath = (params: Record<string, string | number | undefined> = {}) =>
  grcPath("/grc/program-readiness", { ...params, view: "summary" });

export const grcEntityImpactPath = (rootURN: string, params: Record<string, string | number | undefined> = {}) =>
  grcPath(`/grc/entities/${encodeURIComponent(rootURN)}/impact`, params);

export const grcExportFilename = (kind: string) =>
  `cerebro-${kind}-${new Date().toISOString().slice(0, 10)}.csv`;

export type GRCExportResult = { ok: true } | { ok: false; error: string };

// downloadGRCExport fetches a server-rendered CSV export and triggers a browser
// download. The auditor-grade CSV is produced by the backend, so the client only
// streams the body into a blob and saves it under a date-stamped filename.
export const downloadGRCExport = async (
  path: string,
  apiKey: string | undefined,
  filename: string,
): Promise<GRCExportResult> => {
  const response = await fetchCerebro<string>(path, apiKey);
  if (!response.ok) {
    return { ok: false, error: grcResponseErrorMessage(path, response.status, response.data) };
  }
  const contents = typeof response.data === "string" ? response.data : "";
  const blob = new Blob([contents], { type: "text/csv;charset=utf-8" });
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  window.URL.revokeObjectURL(url);
  return { ok: true };
};

export function useDebouncedValue<T>(value: T, delayMs = 300) {
  const [debouncedValue, setDebouncedValue] = useState(value);

  useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedValue(value), delayMs);
    return () => window.clearTimeout(timer);
  }, [delayMs, value]);

  return debouncedValue;
}

type GRCMutationRequest = {
  body: unknown;
  method: string;
  path: string;
};

export function useGRCMutation<T = unknown>() {
  const { apiKey } = useApiKey();
  const queryClient = useQueryClient();
  const [clientError, setError] = useState<string | null>(null);
  const mutation = useMutation<T, Error, GRCMutationRequest>({
    mutationFn: async ({ body, method, path }) => {
      const response = await fetchCerebro<T>(path, apiKey, {
        method,
        headers: { "Content-Type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      if (!response.ok) {
        throw new Error(grcResponseErrorMessage(path, response.status, response.data));
      }
      return response.data;
    },
    onMutate: () => {
      setError(null);
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["grc", apiKey ?? ""] });
    },
  });
  const { error, isPending, mutateAsync } = mutation;
  const mutate = useCallback((path: string, body: unknown, method = "POST") =>
    mutateAsync({ body, method, path }), [mutateAsync]);

  return { mutate, saving: isPending, error: clientError ?? error?.message ?? null, setError };
}

export function useGRCFormMutation<T = unknown>({ timeoutMs = GRC_FORM_MUTATION_TIMEOUT_MS } = {}) {
  const { apiKey } = useApiKey();
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  const cancel = useCallback(() => {
    abortControllerRef.current?.abort();
  }, []);

  const mutate = useCallback(async (path: string, body: FormData, method = "POST") => {
    abortControllerRef.current?.abort();
    const controller = new AbortController();
    abortControllerRef.current = controller;
    let timedOut = false;
    const timeout = window.setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
    setSaving(true);
    setError(null);
    try {
      const response = await fetchCerebro<T>(path, apiKey, {
        method,
        body,
        signal: controller.signal,
      });
      if (!response.ok) {
        throw new Error(grcResponseErrorMessage(path, response.status, response.data));
      }
      return response.data;
    } catch (err) {
      const message = controller.signal.aborted
        ? timedOut
          ? `Upload timed out after ${durationLabel(timeoutMs)}.`
          : "Upload canceled."
        : err instanceof Error ? err.message : grcResponseErrorMessage(path, 0, null);
      setError(message);
      throw err;
    } finally {
      window.clearTimeout(timeout);
      if (abortControllerRef.current === controller) {
        abortControllerRef.current = null;
      }
      setSaving(false);
    }
  }, [apiKey, timeoutMs]);

  return { mutate, saving, error, setError, cancel };
}

export function useGRCQuery<T>(path: string | null) {
  const { apiKey } = useApiKey();
  const query = useQuery<GRCQueryPayload<T>, Error>({
    enabled: Boolean(path),
    queryFn: ({ signal }) => fetchGRCQueryPayload<T>(path ?? "", apiKey, signal),
    queryKey: grcQueryKey(path, apiKey),
    staleTime: GRC_QUERY_CACHE_TTL_MS,
  });
  const data = path ? query.data?.data ?? null : null;
  const error = path && query.error ? query.error.message : null;
  const loading = Boolean(path) && (query.isPending || query.isFetching);
  const durationMs = path ? query.data?.durationMs ?? null : null;
  const lastSuccessfulAt = path ? query.data?.successfulAt ?? null : null;
  const { refetch } = query;
  const reload = useCallback(async () => {
    await refetch({ cancelRefetch: true });
  }, [refetch]);

  const state = runtimeStateForQuery({
    data,
    enabled: Boolean(path),
    error,
    loading,
  });

  return { data, error, loading, durationMs, lastSuccessfulAt, reload, state };
}
