"use client";

import Link from "next/link";
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";

import AskAboutLink from "@/components/ask/AskAboutLink";
import GraphViewer from "@/components/grc/LazyGraphViewer";
import { DataStateBanner, EmptyBlock, LoadingBlock, MetricCard, PageHeader, Panel } from "@/components/grc/Primitives";
import { useApiKey, useCurrentUser } from "@/components/providers";
import { fetchCerebro } from "@/lib/cerebro-client";
import { GRCFinding, GRCGraph, shortEntity } from "@/lib/grc";
import {
  GraphPathRow,
  graphPathCounts,
  graphPathRows,
  graphPathRowsToGraph,
  graphPathsTruncated,
  graphRevisionOf,
  graphViewpointFor,
  graphViewpointList,
} from "@/lib/graph-viewpoints";
import {
  fetchCachedGRC,
  grcClientScopeKey,
  grcPath,
  grcResponseErrorMessage,
  grcTimeoutMessage,
  GRC_QUERY_TIMEOUT_MS,
  organizationalGraphNeighborhoodPath,
  useDebouncedValue,
  useGRCQuery,
  type GRCQueryScope,
} from "@/lib/grc-client";
import {
  ExploreGraphState,
  emptyExploreState,
  exploreExpandedCount,
  exploreNodeCount,
  exploreRelationCount,
  isExploreNodeExpanded,
  mergeNeighborhood,
  removeExploreNode,
  toGRCGraph,
} from "@/lib/graph-explore";
import { grcScopeQuery, useGRCScopeQueryState } from "@/lib/grc-scope";
import { useQueryParamState } from "@/lib/query-params";
import { metricValueForState, runtimeStateForError, type RuntimeState } from "@/lib/runtime-state";

type FindingsResponse = { findings: GRCFinding[]; generated_at: string };

const NEIGHBORS_PER_EXPAND = 50;
const EXPLORE_NODE_LIMIT = 200;
const GRAPH_PATH_LIMIT = 50;

const inputClass = "mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30";
const labelClass = "text-[11px] font-medium uppercase tracking-wider text-slate-500";

const neighborhoodPath = (urn: string, tenantID = "", workspaceID = "") =>
  organizationalGraphNeighborhoodPath(urn, {
    ...grcScopeQuery({ tenantID, workspaceID }),
    limit: NEIGHBORS_PER_EXPAND,
  });

const isLikelyEntityURN = (value: string) => /^urn:[^\s:]+:.+/.test(value.trim());

const graphNodeURNs = (graph: GRCGraph | undefined) =>
  [graph?.root?.urn, ...(graph?.neighbors ?? []).map((node) => node.urn)].filter((urn): urn is string => Boolean(urn?.trim()));

export default function ExplorePage() {
  const { apiKey } = useApiKey();
  const { actor, loading: userLoading } = useCurrentUser();
  const { tenantID, workspaceID } = useGRCScopeQueryState();
  const normalizedTenantID = tenantID.trim();
  const normalizedWorkspaceID = workspaceID.trim();
  const invalidWorkspaceScope = Boolean(normalizedWorkspaceID && !normalizedTenantID);
  const scope = useMemo<GRCQueryScope>(() => ({
    actor,
    tenantID: normalizedTenantID,
    workspaceID: normalizedWorkspaceID,
  }), [actor, normalizedTenantID, normalizedWorkspaceID]);
  const activeScopeKey = useMemo(() => grcClientScopeKey(scope, apiKey), [apiKey, scope]);
  const activeScopeKeyRef = useRef(activeScopeKey);
  useLayoutEffect(() => {
    activeScopeKeyRef.current = activeScopeKey;
  }, [activeScopeKey]);
  const [rootURN, setRootURN] = useQueryParamState("root_urn");
  const debouncedRootURN = useDebouncedValue(rootURN.trim());
  const needsFallbackRoot = debouncedRootURN === "";

  const [viewpointParam, setViewpointParam] = useQueryParamState("view");
  const viewpoint = graphViewpointFor(viewpointParam);
  const isPathViewpoint = viewpoint.method !== null;
  const [pathQuery, setPathQuery] = useQueryParamState("path_q");
  const debouncedPathQuery = useDebouncedValue(pathQuery.trim());
  const [pathRows, setPathRows] = useState<GraphPathRow[] | null>(null);
  const [pathRevision, setPathRevision] = useState<number | undefined>(undefined);
  const [pathTruncated, setPathTruncated] = useState(false);
  const [pathLoading, setPathLoading] = useState(false);
  const [pathError, setPathError] = useState<string | null>(null);

  const fallbackFindings = useGRCQuery<FindingsResponse>(
    needsFallbackRoot && !invalidWorkspaceScope && !isPathViewpoint
      ? grcPath("/grc/findings", {
        ...grcScopeQuery({ tenantID: normalizedTenantID, workspaceID: normalizedWorkspaceID }),
        status: "open",
        limit: 10,
      })
      : null,
  );
  const fallbackRoot = fallbackFindings.data?.findings?.find((finding) => finding.entity || finding.resource_urns?.[0])?.entity ?? fallbackFindings.data?.findings?.find((finding) => finding.resource_urns?.[0])?.resource_urns?.[0] ?? "";
  const seedValidation = debouncedRootURN && !isLikelyEntityURN(debouncedRootURN) ? "Use a full entity URN, for example urn:cerebro:tenant:asset:id." : "";
  const selectedSeed = seedValidation ? "" : debouncedRootURN;

  const [state, setState] = useState<ExploreGraphState | null>(null);
  const [seedLoading, setSeedLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandingURN, setExpandingURN] = useState<string | null>(null);
  const [expandNotice, setExpandNotice] = useState<{ type: "success" | "info"; message: string } | null>(null);
  const [recentlyDiscoveredURNs, setRecentlyDiscoveredURNs] = useState<Set<string>>(new Set());
  const [reloadToken, setReloadToken] = useState(0);
  const [lastGraphLoadedAt, setLastGraphLoadedAt] = useState<number | null>(null);
  const [loadedScopeKey, setLoadedScopeKey] = useState("");
  const loadKeyRef = useRef("");

  const seedSuggestions = useMemo(() => {
    const seen = new Set<string>();
    return (fallbackFindings.data?.findings ?? []).flatMap((finding) => {
      const urn = (finding.entity || finding.resource_urns?.[0] || "").trim();
      if (!urn || seen.has(urn)) return [];
      seen.add(urn);
      return [{
        urn,
        label: shortEntity(urn),
        title: finding.title,
        detail: [finding.severity, typeof finding.risk_score === "number" ? `risk ${finding.risk_score}` : "", finding.source_id].filter(Boolean).join(" • "),
      }];
    }).slice(0, 6);
  }, [fallbackFindings.data?.findings]);

  const clearSeed = useCallback(() => {
    setState(null);
    setSeedLoading(false);
    setExpandingURN(null);
    setLoadedScopeKey("");
    setError(null);
    setExpandNotice(null);
    setRecentlyDiscoveredURNs(new Set());
  }, []);

  const fetchNeighborhood = useCallback(async (path: string, force: boolean, signal?: AbortSignal) => {
    const controller = new AbortController();
    const abort = () => controller.abort();
    signal?.addEventListener("abort", abort, { once: true });
    const timer = window.setTimeout(() => controller.abort(), GRC_QUERY_TIMEOUT_MS);
    try {
      return await fetchCachedGRC<GRCGraph>(path, apiKey, force, { signal: controller.signal }, scope);
    } catch (err) {
      if (controller.signal.aborted && !signal?.aborted) {
        throw new Error(grcTimeoutMessage(path, GRC_QUERY_TIMEOUT_MS));
      }
      throw err;
    } finally {
      signal?.removeEventListener("abort", abort);
      window.clearTimeout(timer);
    }
  }, [apiKey, scope]);

  const loadSeed = useCallback(
    async (seed: string, force: boolean, signal: AbortSignal, isCancelled: () => boolean) => {
      setSeedLoading(true);
      setExpandingURN(null);
      setError(null);
      setExpandNotice(null);
      const path = neighborhoodPath(seed, normalizedTenantID, normalizedWorkspaceID);
      try {
        const response = await fetchNeighborhood(path, force, signal);
        if (isCancelled()) return;
        if (!response.ok) {
          setError(grcResponseErrorMessage(path, response.status, response.data));
          setState(emptyExploreState(seed));
          return;
        }
        setState(mergeNeighborhood(emptyExploreState(seed), seed, response.data));
        setLoadedScopeKey(activeScopeKey);
        setLastGraphLoadedAt(Date.now());
        setRecentlyDiscoveredURNs(new Set(graphNodeURNs(response.data)));
      } catch (err) {
        if (isCancelled()) return;
        setError(err instanceof Error ? err.message : "Unable to load graph.");
        setState(emptyExploreState(seed));
      } finally {
        if (!isCancelled()) setSeedLoading(false);
      }
    },
    [activeScopeKey, fetchNeighborhood, normalizedTenantID, normalizedWorkspaceID],
  );

  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      if (cancelled) return;
      if (userLoading || !actor.trim() || invalidWorkspaceScope) {
        loadKeyRef.current = "";
        clearSeed();
        return;
      }
      if (selectedSeed === "") {
        loadKeyRef.current = "";
        clearSeed();
        return;
      }
      const loadKey = `${activeScopeKey}|${selectedSeed}|${reloadToken}`;
      if (loadKey === loadKeyRef.current) return;
      loadKeyRef.current = loadKey;
      void loadSeed(selectedSeed, reloadToken > 0, controller.signal, () => cancelled);
    }, 0);
    return () => {
      cancelled = true;
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [activeScopeKey, actor, clearSeed, invalidWorkspaceScope, loadSeed, reloadToken, selectedSeed, userLoading]);

  const scopedState = loadedScopeKey !== "" && loadedScopeKey === activeScopeKey ? state : null;

  const expand = useCallback(async (urn: string) => {
    const target = urn.trim();
    if (target === "") return;
    if (scopedState && isExploreNodeExpanded(scopedState, target)) return;
    const requestScopeKey = activeScopeKey;
    setExpandingURN(target);
    setError(null);
    setExpandNotice(null);
    const path = neighborhoodPath(target, normalizedTenantID, normalizedWorkspaceID);
    const controller = new AbortController();
    try {
      const response = await fetchNeighborhood(path, false, controller.signal);
      if (activeScopeKeyRef.current !== requestScopeKey) return;
      if (!response.ok) {
        setError(grcResponseErrorMessage(path, response.status, response.data));
        return;
      }
      if (!scopedState) return;
      const beforeNodes = exploreNodeCount(scopedState);
      const beforeRelations = exploreRelationCount(scopedState);
      const next = mergeNeighborhood(scopedState, target, response.data);
      const addedNodes = Math.max(0, exploreNodeCount(next) - beforeNodes);
      const addedRelations = Math.max(0, exploreRelationCount(next) - beforeRelations);
      const discovered = new Set([target, ...graphNodeURNs(response.data)]);
      setRecentlyDiscoveredURNs(discovered);
      setState(next);
      setLastGraphLoadedAt(Date.now());
      setExpandNotice({
        type: addedNodes > 0 || addedRelations > 0 ? "success" : "info",
        message: addedNodes > 0 || addedRelations > 0
          ? `Expanded ${shortEntity(target)}: added ${addedNodes} node${addedNodes === 1 ? "" : "s"} and ${addedRelations} relation${addedRelations === 1 ? "" : "s"}.`
          : `Expanded ${shortEntity(target)}: no new neighbors found.`,
      });
    } catch (err) {
      if (activeScopeKeyRef.current !== requestScopeKey) return;
      setError(err instanceof Error ? err.message : "Unable to expand node.");
    } finally {
      if (activeScopeKeyRef.current === requestScopeKey) {
        setExpandingURN(null);
      }
    }
  }, [activeScopeKey, fetchNeighborhood, normalizedTenantID, normalizedWorkspaceID, scopedState]);

  const removeNode = useCallback((urn: string) => {
    setState((current) => (current ? removeExploreNode(current, urn) : current));
  }, []);

  useEffect(() => {
    const method = viewpoint.method;
    let cancelled = false;
    const controller = new AbortController();
    // Connect unary rejects unknown fields, so only the fields this RPC declares are sent.
    const payload: Record<string, string | number> = { limit: GRAPH_PATH_LIMIT };
    if (normalizedTenantID) payload.tenant_id = normalizedTenantID;
    if (viewpoint.queryField && debouncedPathQuery) payload[viewpoint.queryField] = debouncedPathQuery;
    const timer = window.setTimeout(() => {
      if (cancelled) return;
      if (!method || invalidWorkspaceScope || userLoading || !actor.trim()) {
        setPathRows(null);
        setPathError(null);
        return;
      }
      setPathLoading(true);
      setPathError(null);
      void (async () => {
      try {
        const response = await fetchCerebro<unknown>(`/${method}`, apiKey, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
          signal: controller.signal,
        });
        if (cancelled) return;
        if (!response.ok) {
          setPathError(grcResponseErrorMessage(`/${method}`, response.status, response.data));
          setPathRows([]);
          return;
        }
        setPathRows(graphPathRows(viewpoint.id, response.data));
        setPathRevision(graphRevisionOf(response.data));
        setPathTruncated(graphPathsTruncated(response.data));
      } catch (err) {
        if (cancelled || controller.signal.aborted) return;
        setPathError(err instanceof Error ? err.message : "Unable to load paths.");
        setPathRows([]);
      } finally {
        if (!cancelled) setPathLoading(false);
      }
      })();
    }, 0);
    return () => {
      cancelled = true;
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [actor, apiKey, debouncedPathQuery, invalidWorkspaceScope, normalizedTenantID, userLoading, viewpoint.id, viewpoint.method, viewpoint.queryField]);

  const resetExploration = useCallback(() => {
    loadKeyRef.current = "";
    setState(null);
    setError(null);
    setExpandNotice(null);
    setRecentlyDiscoveredURNs(new Set());
    setReloadToken((token) => token + 1);
  }, []);

  const retryExplore = useCallback(() => {
    resetExploration();
    if (!selectedSeed && !invalidWorkspaceScope && !userLoading && actor.trim()) {
      void fallbackFindings.reload();
    }
  }, [actor, fallbackFindings, invalidWorkspaceScope, resetExploration, selectedSeed, userLoading]);

  const graph = useMemo(() => (scopedState ? toGRCGraph(scopedState) : undefined), [scopedState]);
  const expandedURNs = useMemo(() => new Set(scopedState ? Object.keys(scopedState.expanded) : []), [scopedState]);
  const pinnedURNs = useMemo(() => {
    const next = new Set(expandedURNs);
    recentlyDiscoveredURNs.forEach((urn) => next.add(urn));
    if (selectedSeed) next.add(selectedSeed);
    return next;
  }, [expandedURNs, recentlyDiscoveredURNs, selectedSeed]);
  const nodeCount = scopedState ? exploreNodeCount(scopedState) : 0;
  const relationCount = scopedState ? exploreRelationCount(scopedState) : 0;
  const expandedCount = scopedState ? exploreExpandedCount(scopedState) : 0;
  const visibleNodeCount = Math.min(nodeCount, EXPLORE_NODE_LIMIT);
  const hiddenNodeCount = Math.max(0, nodeCount - visibleNodeCount);

  const loading = fallbackFindings.loading || seedLoading;
  const loadError = fallbackFindings.error || error;
  const runtimeState = runtimeStateForError(loadError);
  const apiUnavailable = runtimeState === "unavailable";
  const graphDataState: RuntimeState = loading && !graph?.root ? "loading" : loadError && graph?.root ? "stale" : loadError ? runtimeState : "ready";
  const showUnavailableState = Boolean(loadError && apiUnavailable && !graph?.root);
  const metricState = graphDataState === "stale" ? "ready" : graphDataState;
  const showEmpty = !selectedSeed && !loading && !loadError;

  const pathCounts = useMemo(() => graphPathCounts(pathRows ?? []), [pathRows]);
  const pathGraph = useMemo(
    () => (pathRows ? graphPathRowsToGraph(pathRows, selectedSeed || undefined) : undefined),
    [pathRows, selectedSeed],
  );
  const viewpoints = graphViewpointList();

  const viewpointPicker = (
    <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
      {viewpoints.map((entry) => {
        const active = entry.id === viewpoint.id;
        return (
          <button
            key={entry.id}
            type="button"
            aria-pressed={active}
            onClick={() => setViewpointParam(entry.id === "entity" ? "" : entry.id)}
            className={`rounded-lg border px-4 py-3 text-left transition ${
              active
                ? "border-[color:var(--primary)] bg-[var(--primary-soft)] shadow-[var(--shadow-sm)]"
                : "border-[color:var(--border)] bg-[var(--surface)] hover:border-[color:var(--border-strong)]"
            }`}
          >
            <div className="text-[13px] font-semibold text-[var(--text-primary)]">{entry.label}</div>
            <div className="mt-1 text-[11px] leading-snug text-[var(--text-muted)]">{entry.question}</div>
          </button>
        );
      })}
    </div>
  );

  if (isPathViewpoint) {
    return (
      <div className="space-y-6">
        <PageHeader
          contractId="graph-explorer"
          title="Graph"
          description={viewpoint.question}
          action={
            <AskAboutLink
              variant="button"
              question={`${viewpoint.question} Summarise what the graph shows.`}
              title="Ask about this viewpoint"
            >
              Ask
            </AskAboutLink>
          }
        />

        {viewpointPicker}

        {viewpoint.queryField && (
          <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] px-5 py-4">
            <label className={labelClass}>
              {viewpoint.queryLabel}
              <input
                value={pathQuery}
                onChange={(event) => setPathQuery(event.target.value)}
                placeholder={`Narrow to one ${viewpoint.queryLabel?.toLowerCase()}, or leave blank for all`}
                className={inputClass}
              />
            </label>
          </div>
        )}

        {pathError && (
          <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-[13px] text-amber-800">{pathError}</div>
        )}

        <div className="grid gap-4 md:grid-cols-4">
          <MetricCard label="Paths" value={pathCounts.paths} detail={pathTruncated ? "more beyond the limit" : "returned by this read"} />
          <MetricCard label="Entities" value={pathCounts.nodes} detail="distinct across these paths" />
          <MetricCard label="Relation Kinds" value={pathCounts.relations} detail="distinct hop types" />
          <MetricCard label="Named Owners" value={pathCounts.owners} detail="observed on these paths" />
        </div>

        {typeof pathRevision === "number" && (
          <div className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2 text-[12px] text-[var(--text-muted)]">
            Read at graph revision {pathRevision.toLocaleString()}.
            {pathTruncated ? ` Showing the first ${GRAPH_PATH_LIMIT} paths; more matched.` : ""}
          </div>
        )}

        {pathLoading && <LoadingBlock label="Loading paths..." />}

        {!pathLoading && pathRows?.length === 0 && (
          <EmptyBlock label="No paths matched. Either nothing in the graph forms this pattern yet, or the sources feeding it have not projected the entities it needs." />
        )}

        {pathGraph && (
          <Panel title={`${viewpoint.label} Graph`}>
            <GraphViewer graph={pathGraph} nodeLimit={EXPLORE_NODE_LIMIT} />
          </Panel>
        )}

        {pathRows && pathRows.length > 0 && (
          <Panel title={`${viewpoint.label} Paths`}>
            <div className="space-y-3">
              {pathRows.map((row) => (
                <div key={row.id} className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] px-4 py-3">
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[13px]">
                    {row.nodes.map((node, index) => (
                      <span key={`${row.id}:${node.urn}`} className="flex items-center gap-2">
                        {index > 0 && (
                          <span className="font-mono text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
                            {row.relations[index - 1] || "reaches"} →
                          </span>
                        )}
                        <Link
                          href={`/inventory/${encodeURIComponent(node.urn)}`}
                          prefetch={false}
                          className="font-medium text-[var(--text-primary)] underline-offset-2 hover:underline"
                        >
                          {node.label}
                        </Link>
                      </span>
                    ))}
                  </div>
                  <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-[var(--text-muted)]">
                    {row.detail && <span>{row.detail}</span>}
                    {row.owners.length > 0 && <span>Owner: {row.owners.map((owner) => owner.label).join(", ")}</span>}
                    <span>
                      {row.evidence.length > 0
                        ? `${row.evidence.length} proof edge${row.evidence.length === 1 ? "" : "s"} from ${[...new Set(row.evidence.map((entry) => entry.sourceID).filter(Boolean))].join(", ") || "an unnamed source"}`
                        : "No proof edges returned"}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </Panel>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="graph-explorer"
        title="Graph"
        description="Start from an entity and expand nearby assets, findings, owners, and sources."
        action={
          <div className="flex items-center gap-2">
            {selectedSeed && (
              <AskAboutLink
                variant="button"
                question={`What is connected to ${selectedSeed} and which findings depend on it?`}
                scopeUrn={selectedSeed}
                title="Ask about this entity"
              >
                Ask
              </AskAboutLink>
            )}
            <button
              type="button"
              onClick={resetExploration}
              disabled={!rootURN && !state && !error}
              className="rounded-md border border-slate-200 bg-indigo-500 px-3 py-1.5 text-[13px] font-medium text-white transition hover:bg-indigo-600 disabled:opacity-50"
            >
              Reset
            </button>
          </div>
        }
      />

      {viewpointPicker}

      <div className="rounded-lg border border-slate-200 bg-white px-5 py-4">
        <div className="grid gap-3">
          <label className={labelClass}>Seed entity<input value={rootURN} onChange={(event) => setRootURN(event.target.value)} placeholder={fallbackRoot || "urn:cerebro:..."} className={inputClass} /></label>
        </div>
        {seedValidation && <div className="mt-2 text-[12px] text-amber-700">{seedValidation}</div>}
        {!rootURN && fallbackRoot && (
          <div className="mt-2 text-[12px] text-slate-500">
            Suggested start available: <span className="font-mono text-slate-700">{shortEntity(fallbackRoot)}</span>
          </div>
        )}
        <div className="mt-2 text-[12px] text-slate-500">Select a node in the graph, then choose <span className="font-medium text-slate-700">Expand neighbors</span> to grow the view or <span className="font-medium text-slate-700">Remove</span> to prune it.</div>
      </div>

      <DataStateBanner
        state={graphDataState}
        subject="Graph data"
        error={loadError}
        lastSuccessfulAt={lastGraphLoadedAt ?? fallbackFindings.lastSuccessfulAt}
        onRetry={retryExplore}
        detail={graphDataState === "loading" ? "Loading graph data." : showUnavailableState ? "Graph data will appear when the API is reachable." : undefined}
      />
      {expandNotice && (
        <div className={`rounded-lg border px-4 py-3 text-[13px] ${
          expandNotice.type === "success"
            ? "border-emerald-200 bg-emerald-50 text-emerald-800"
            : "border-slate-200 bg-slate-50 text-slate-700"
        }`}
        >
          {expandNotice.message}
          {hiddenNodeCount > 0 && <span className="ml-2 font-medium">{hiddenNodeCount} node{hiddenNodeCount === 1 ? "" : "s"} hidden by the visible cap.</span>}
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-4">
        <MetricCard label="Seed entity" value={metricValueForState({ state: metricState, value: selectedSeed ? shortEntity(selectedSeed) : "None" })} detail={showUnavailableState ? "waiting for API" : "exploration anchor"} />
        <MetricCard label="Nodes" value={metricValueForState({ state: metricState, value: nodeCount > 0 ? `${visibleNodeCount}/${nodeCount}` : "0" })} detail={hiddenNodeCount > 0 ? `${hiddenNodeCount} hidden by cap` : "visible / accumulated"} />
        <MetricCard label="Relations" value={metricValueForState({ state: metricState, value: relationCount })} detail={showUnavailableState ? "waiting for API" : "accumulated graph links"} />
        <MetricCard label="Expanded" value={metricValueForState({ state: metricState, value: expandedCount })} detail={showUnavailableState ? "waiting for API" : "entities explored"} />
      </div>

      {showEmpty && (
        <Panel title="Start an exploration">
          <div className="space-y-4">
            <EmptyBlock label="Enter an entity URN, or start from a suggested entity attached to an open finding." />
            {seedSuggestions.length > 0 && (
              <div className="grid gap-3 md:grid-cols-2">
                {seedSuggestions.map((suggestion) => (
                  <button
                    key={suggestion.urn}
                    type="button"
                    onClick={() => setRootURN(suggestion.urn)}
                    className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] px-4 py-3 text-left transition hover:border-[color:var(--border-strong)] hover:shadow-[var(--shadow-sm)]"
                  >
                    <div className="text-[13px] font-semibold text-[var(--text-primary)]">{suggestion.label}</div>
                    <div className="mt-1 line-clamp-2 text-[12px] text-[var(--text-muted)]">{suggestion.title}</div>
                    {suggestion.detail && <div className="mt-2 text-[11px] uppercase tracking-wider text-[var(--text-muted)]">{suggestion.detail}</div>}
                  </button>
                ))}
              </div>
            )}
            {!fallbackFindings.loading && seedSuggestions.length === 0 && (
              <div className="rounded-lg border border-dashed border-[color:var(--border)] bg-[var(--surface-muted)] px-4 py-3 text-[13px] text-[var(--text-muted)]">
                No suggested seeds are available yet. Paste a full entity URN to begin.
              </div>
            )}
          </div>
        </Panel>
      )}

      {graph?.root && (
        <Panel title="Exploration Graph">
          <GraphViewer
            graph={graph}
            onExpandNode={expand}
            onRemoveNode={removeNode}
            expandedURNs={expandedURNs}
            expandingURN={expandingURN}
            nodeLimit={EXPLORE_NODE_LIMIT}
            pinnedURNs={pinnedURNs}
          />
        </Panel>
      )}
    </div>
  );
}
