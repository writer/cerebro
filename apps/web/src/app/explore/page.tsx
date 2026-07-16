"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import AskAboutLink from "@/components/ask/AskAboutLink";
import GraphViewer from "@/components/grc/LazyGraphViewer";
import { DataStateBanner, EmptyBlock, MetricCard, PageHeader, Panel } from "@/components/grc/Primitives";
import { useApiKey } from "@/components/providers";
import { GRCEntityImpact, GRCFinding, shortEntity } from "@/lib/grc";
import { fetchCachedGRC, grcEntityImpactPath, grcPath, grcResponseErrorMessage, grcTimeoutMessage, GRC_QUERY_TIMEOUT_MS, useDebouncedValue, useGRCQuery } from "@/lib/grc-client";
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
import { useQueryParamState } from "@/lib/query-params";
import { metricValueForState, runtimeStateForError, type RuntimeState } from "@/lib/runtime-state";

type FindingsResponse = { findings: GRCFinding[]; generated_at: string };

const NEIGHBORS_PER_EXPAND = 50;
const EXPLORE_NODE_LIMIT = 200;

const inputClass = "mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30";
const labelClass = "text-[11px] font-medium uppercase tracking-wider text-slate-500";

const impactPath = (urn: string, tenantID: string) =>
  grcEntityImpactPath(urn, { tenant_id: tenantID, limit: NEIGHBORS_PER_EXPAND });

const isLikelyEntityURN = (value: string) => /^urn:[^\s:]+:.+/.test(value.trim());

const graphNodeURNs = (graph: GRCEntityImpact["graph"] | undefined) =>
  [graph?.root?.urn, ...(graph?.neighbors ?? []).map((node) => node.urn)].filter((urn): urn is string => Boolean(urn?.trim()));

export default function ExplorePage() {
  const { apiKey } = useApiKey();
  const [tenantID, setTenantID] = useQueryParamState("tenant_id");
  const [rootURN, setRootURN] = useQueryParamState("root_urn");
  const debouncedTenantID = useDebouncedValue(tenantID.trim());
  const debouncedRootURN = useDebouncedValue(rootURN.trim());
  const needsFallbackRoot = debouncedRootURN === "";

  const fallbackFindings = useGRCQuery<FindingsResponse>(
    needsFallbackRoot ? grcPath("/grc/findings", { tenant_id: debouncedTenantID, status: "open", limit: 10 }) : null,
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
    setError(null);
    setExpandNotice(null);
    setRecentlyDiscoveredURNs(new Set());
  }, []);

  const fetchImpact = useCallback(async (path: string, force: boolean, signal?: AbortSignal) => {
    const controller = new AbortController();
    const abort = () => controller.abort();
    signal?.addEventListener("abort", abort, { once: true });
    const timer = window.setTimeout(() => controller.abort(), GRC_QUERY_TIMEOUT_MS);
    try {
      return await fetchCachedGRC<GRCEntityImpact>(path, apiKey, force, { signal: controller.signal });
    } catch (err) {
      if (controller.signal.aborted && !signal?.aborted) {
        throw new Error(grcTimeoutMessage(path, GRC_QUERY_TIMEOUT_MS));
      }
      throw err;
    } finally {
      signal?.removeEventListener("abort", abort);
      window.clearTimeout(timer);
    }
  }, [apiKey]);

  const loadSeed = useCallback(
    async (seed: string, tenant: string, force: boolean, signal: AbortSignal, isCancelled: () => boolean) => {
      setSeedLoading(true);
      setError(null);
      setExpandNotice(null);
      const path = impactPath(seed, tenant);
      try {
        const response = await fetchImpact(path, force, signal);
        if (isCancelled()) return;
        if (!response.ok) {
          setError(grcResponseErrorMessage(path, response.status, response.data));
          setState(emptyExploreState(seed));
          return;
        }
        setState(mergeNeighborhood(emptyExploreState(seed), seed, response.data?.graph));
        setLastGraphLoadedAt(Date.now());
        setRecentlyDiscoveredURNs(new Set(graphNodeURNs(response.data?.graph)));
      } catch (err) {
        if (isCancelled()) return;
        setError(err instanceof Error ? err.message : "Unable to load graph.");
        setState(emptyExploreState(seed));
      } finally {
        if (!isCancelled()) setSeedLoading(false);
      }
    },
    [fetchImpact],
  );

  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      if (cancelled) return;
      if (selectedSeed === "") {
        loadKeyRef.current = "";
        clearSeed();
        return;
      }
      const loadKey = `${selectedSeed}|${debouncedTenantID}|${reloadToken}`;
      if (loadKey === loadKeyRef.current) return;
      loadKeyRef.current = loadKey;
      void loadSeed(selectedSeed, debouncedTenantID, reloadToken > 0, controller.signal, () => cancelled);
    }, 0);
    return () => {
      cancelled = true;
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [clearSeed, debouncedTenantID, loadSeed, reloadToken, selectedSeed]);

  const expand = useCallback(async (urn: string) => {
    const target = urn.trim();
    if (target === "") return;
    if (state && isExploreNodeExpanded(state, target)) return;
    setExpandingURN(target);
    setError(null);
    setExpandNotice(null);
    const path = impactPath(target, debouncedTenantID);
    const controller = new AbortController();
    try {
      const response = await fetchImpact(path, false, controller.signal);
      if (!response.ok) {
        setError(grcResponseErrorMessage(path, response.status, response.data));
        return;
      }
      if (!state) return;
      const beforeNodes = exploreNodeCount(state);
      const beforeRelations = exploreRelationCount(state);
      const next = mergeNeighborhood(state, target, response.data?.graph);
      const addedNodes = Math.max(0, exploreNodeCount(next) - beforeNodes);
      const addedRelations = Math.max(0, exploreRelationCount(next) - beforeRelations);
      const discovered = new Set([target, ...graphNodeURNs(response.data?.graph)]);
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
      setError(err instanceof Error ? err.message : "Unable to expand node.");
    } finally {
      setExpandingURN(null);
    }
  }, [debouncedTenantID, fetchImpact, state]);

  const removeNode = useCallback((urn: string) => {
    setState((current) => (current ? removeExploreNode(current, urn) : current));
  }, []);

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
    if (!selectedSeed) {
      void fallbackFindings.reload();
    }
  }, [fallbackFindings, resetExploration, selectedSeed]);

  const graph = useMemo(() => (state ? toGRCGraph(state) : undefined), [state]);
  const expandedURNs = useMemo(() => new Set(state ? Object.keys(state.expanded) : []), [state]);
  const pinnedURNs = useMemo(() => {
    const next = new Set(expandedURNs);
    recentlyDiscoveredURNs.forEach((urn) => next.add(urn));
    if (selectedSeed) next.add(selectedSeed);
    return next;
  }, [expandedURNs, recentlyDiscoveredURNs, selectedSeed]);
  const nodeCount = state ? exploreNodeCount(state) : 0;
  const relationCount = state ? exploreRelationCount(state) : 0;
  const expandedCount = state ? exploreExpandedCount(state) : 0;
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

      <div className="rounded-lg border border-slate-200 bg-white px-5 py-4">
        <div className="grid gap-3 md:grid-cols-[1fr_2fr]">
          <label className={labelClass}>Tenant<input value={tenantID} onChange={(event) => setTenantID(event.target.value)} placeholder="All" className={inputClass} /></label>
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
            tenantID={debouncedTenantID}
          />
        </Panel>
      )}
    </div>
  );
}
