"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { useApiKey, useCurrentUser } from "@/components/providers";
import { withQuery } from "@/lib/cerebro-data";
import type { ConnectorLibraryResponse } from "@/lib/connectors";
import {
  fetchCachedGRC,
  GRC_QUERY_TIMEOUT_MS,
  grcClientScopeKey,
  grcResponseErrorMessage,
  grcTimeoutMessage,
  type GRCQueryScope,
} from "@/lib/grc-client";

export const CONNECTOR_LIBRARY_PAGE_LIMIT = 200;
const CONNECTOR_LIBRARY_MAX_PAGES = 50;

type ConnectorLibraryView = "full" | "summary";

type ConnectorLibraryPagePathOptions = {
  tenantID?: string;
  view?: ConnectorLibraryView;
  limit?: number;
  cursor?: string;
};

type ConnectorLibraryQueryOptions = {
  tenantID?: string;
  view?: ConnectorLibraryView;
  limit?: number;
  enabled?: boolean;
};

const connectorLibraryLimit = (limit?: number) => {
  const parsed = Number.isFinite(limit) ? Math.trunc(limit ?? CONNECTOR_LIBRARY_PAGE_LIMIT) : CONNECTOR_LIBRARY_PAGE_LIMIT;
  return Math.min(CONNECTOR_LIBRARY_PAGE_LIMIT, Math.max(1, parsed));
};

export const connectorLibraryPagePath = ({
  tenantID = "",
  view = "full",
  limit = CONNECTOR_LIBRARY_PAGE_LIMIT,
  cursor = "",
}: ConnectorLibraryPagePathOptions = {}) =>
  withQuery("/connectors", {
    tenant_id: tenantID.trim(),
    view,
    limit: connectorLibraryLimit(limit),
    cursor,
  });

export const mergeConnectorLibraryPages = (pages: ConnectorLibraryResponse[]) => {
  const loadedPages = pages.filter(Boolean);
  if (loadedPages.length === 0) return null;

  const first = loadedPages[0];
  const lastPage = loadedPages[loadedPages.length - 1]?.page;
  const firstPage = first.page ?? lastPage;
  const connectors = loadedPages.flatMap((page) => page.connectors ?? []);
  const page = firstPage
    ? {
        ...firstPage,
        total: lastPage?.total ?? firstPage.total,
        returned: connectors.length,
        has_more: Boolean(lastPage?.has_more),
        next_cursor: lastPage?.next_cursor,
      }
    : undefined;

  return {
    ...first,
    connectors,
    page,
  };
};

export function useConnectorLibraryQuery({
  tenantID = "",
  view = "full",
  limit = CONNECTOR_LIBRARY_PAGE_LIMIT,
  enabled = true,
}: ConnectorLibraryQueryOptions = {}) {
  const { apiKey } = useApiKey();
  const { actor, loading: userLoading } = useCurrentUser();
  const [data, setData] = useState<ConnectorLibraryResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [durationMs, setDurationMs] = useState<number | null>(null);
  const [loadedScopeKey, setLoadedScopeKey] = useState("");
  const requestID = useRef(0);
  const pageLimit = useMemo(() => connectorLibraryLimit(limit), [limit]);
  const scope = useMemo<GRCQueryScope>(() => ({ actor, tenantID: tenantID.trim() }), [actor, tenantID]);
  const requestScopeKey = useMemo(() => grcClientScopeKey(scope, apiKey), [apiKey, scope]);
  const requestEnabled = enabled && !userLoading && Boolean(actor.trim());
  const firstPagePath = useMemo(
    () => requestEnabled ? connectorLibraryPagePath({ tenantID, view, limit: pageLimit }) : null,
    [pageLimit, requestEnabled, tenantID, view],
  );

  const load = useCallback(async (signal?: AbortSignal, force = false) => {
    if (!firstPagePath) {
      setData(null);
      setError(null);
      setLoading(false);
      setDurationMs(null);
      setLoadedScopeKey("");
      return;
    }

    const currentRequestID = requestID.current + 1;
    requestID.current = currentRequestID;
    const startedAt = performance.now();
    const controller = new AbortController();
    let timedOut = false;
    const abortFromCaller = () => controller.abort();
    signal?.addEventListener("abort", abortFromCaller, { once: true });
    const timeout = window.setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, GRC_QUERY_TIMEOUT_MS);

    setLoading(true);
    setError(null);

    try {
      const pages: ConnectorLibraryResponse[] = [];
      let cursor = "";
      const seenCursors = new Set<string>();

      for (let index = 0; index < CONNECTOR_LIBRARY_MAX_PAGES; index += 1) {
        const path = index === 0
          ? firstPagePath
          : connectorLibraryPagePath({ tenantID, view, limit: pageLimit, cursor });
        const response = await fetchCachedGRC<ConnectorLibraryResponse>(path, apiKey, force, { signal: controller.signal }, scope);

        if (!response.ok) {
          throw new Error(grcResponseErrorMessage(path, response.status, response.data, Math.round(performance.now() - startedAt)));
        }

        pages.push(response.data);
        const page = response.data.page;
        if (!page?.has_more) {
          cursor = "";
          break;
        }
        if (!page.next_cursor) {
          throw new Error("Connector catalog response is missing the next page cursor.");
        }
        if (seenCursors.has(page.next_cursor)) {
          throw new Error("Connector catalog pagination returned a repeated cursor.");
        }
        seenCursors.add(page.next_cursor);
        cursor = page.next_cursor;
      }

      if (cursor) {
        throw new Error("Connector catalog pagination exceeded the client page limit.");
      }
      if (signal?.aborted || currentRequestID !== requestID.current) return;
      setData(mergeConnectorLibraryPages(pages) ?? { connectors: [] });
      setLoadedScopeKey(requestScopeKey);
      setDurationMs(Math.round(performance.now() - startedAt));
      setLoading(false);
    } catch (err) {
      if (signal?.aborted || currentRequestID !== requestID.current) {
        return;
      }
      const elapsed = Math.round(performance.now() - startedAt);
      setError(timedOut ? grcTimeoutMessage(firstPagePath, GRC_QUERY_TIMEOUT_MS) : err instanceof Error ? err.message : grcResponseErrorMessage(firstPagePath, 0, null, elapsed));
      setDurationMs(elapsed);
      setLoading(false);
    } finally {
      window.clearTimeout(timeout);
      signal?.removeEventListener("abort", abortFromCaller);
    }
  }, [apiKey, firstPagePath, pageLimit, requestScopeKey, scope, tenantID, view]);

  const reload = useCallback(() => load(undefined, true), [load]);

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => void load(controller.signal, false), 0);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [load]);

  const visibleData = loadedScopeKey !== "" && loadedScopeKey === requestScopeKey ? data : null;
  return { data: visibleData, error, loading, durationMs, reload };
}
