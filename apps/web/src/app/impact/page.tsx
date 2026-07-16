"use client";

import Link from "next/link";
import { useMemo, useState } from "react";

import AskAboutLink from "@/components/ask/AskAboutLink";
import FindingTable from "@/components/grc/FindingTable";
import GraphViewer from "@/components/grc/LazyGraphViewer";
import { EmptyBlock, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel, RiskBadge } from "@/components/grc/Primitives";
import { averageRiskScore, GRCEntityImpact, GRCFinding, GRCGraph, riskSort, shortEntity } from "@/lib/grc";
import { grcEntityImpactPath, grcPath, useDebouncedValue, useGRCQuery } from "@/lib/grc-client";
import { GRC_DETAIL_LIMIT, grcBoundedRows } from "@/lib/grc-list";
import { useQueryParamState } from "@/lib/query-params";
import { metricValueForState, runtimeStateForError } from "@/lib/runtime-state";

type FindingsResponse = { findings: GRCFinding[]; generated_at: string };

const inputClass = "mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30";
const labelClass = "text-[11px] font-medium uppercase tracking-wider text-slate-500";
const IMPACT_FINDING_LIMIT = GRC_DETAIL_LIMIT;
const IMPACT_GRAPH_NEIGHBOR_LIMIT = 120;
const IMPACT_GRAPH_RELATION_LIMIT = 240;

const boundImpactGraph = (graph?: GRCGraph): GRCGraph | undefined => {
  if (!graph) return undefined;
  const neighbors = (graph.neighbors ?? []).slice(0, IMPACT_GRAPH_NEIGHBOR_LIMIT);
  const visibleURNs = new Set([
    graph.root?.urn,
    ...neighbors.map((node) => node.urn),
  ].filter(Boolean) as string[]);
  const relations = (graph.relations ?? [])
    .filter((relation) => visibleURNs.has(relation.from_urn) && visibleURNs.has(relation.to_urn))
    .slice(0, IMPACT_GRAPH_RELATION_LIMIT);
  return { ...graph, neighbors, relations };
};

export default function ImpactPage() {
  const [tenantID, setTenantID] = useState("");
  const [rootURN, setRootURN] = useQueryParamState("root_urn");
  const [limit, setLimit] = useState("75");
  const debouncedTenantID = useDebouncedValue(tenantID.trim());
  const debouncedRootURN = useDebouncedValue(rootURN.trim());
  const debouncedLimit = useDebouncedValue(limit.trim());
  const needsFallbackRoot = debouncedRootURN === "";
  const fallbackFindings = useGRCQuery<FindingsResponse>(
    needsFallbackRoot ? grcPath("/grc/findings", { tenant_id: debouncedTenantID, status: "open", limit: 10 }) : null,
  );
  const fallbackRoot = fallbackFindings.data?.findings?.find((f) => f.entity)?.entity ?? "";
  const selectedRoot = debouncedRootURN || fallbackRoot;
  const path = useMemo(
    () => selectedRoot ? grcEntityImpactPath(selectedRoot, { tenant_id: debouncedTenantID, limit: debouncedLimit }) : null,
    [debouncedLimit, debouncedTenantID, selectedRoot],
  );
  const { data, error, loading, reload } = useGRCQuery<GRCEntityImpact>(path);
  const boundedImpactFindings = useMemo(
    () => grcBoundedRows({ rows: data?.findings, limit: IMPACT_FINDING_LIMIT }),
    [data?.findings],
  );
  const findings = useMemo(() => boundedImpactFindings.rows.slice().sort(riskSort), [boundedImpactFindings.rows]);
  const graph = useMemo(() => boundImpactGraph(data?.graph), [data?.graph]);
  const nodeCount = (graph?.neighbors?.length ?? 0) + (graph?.root ? 1 : 0);
  const relationCount = graph?.relations?.length ?? 0;
  const loadError = fallbackFindings.error || error;
  const runtimeState = runtimeStateForError(loadError);
  const apiUnavailable = runtimeState === "unavailable";
  const showUnavailableState = Boolean(loadError && apiUnavailable && !data);
  const showHardError = Boolean(loadError && !showUnavailableState);
  const metricState = showUnavailableState ? runtimeState : "ready";
  const canRefresh = needsFallbackRoot || Boolean(selectedRoot);
  const refreshImpact = () => {
    if (needsFallbackRoot) void fallbackFindings.reload();
    if (selectedRoot) void reload();
  };

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="impact-map"
        title="Affected assets"
        description="Assets and relationships touched by a finding or entity."
        action={
          <div className="flex items-center gap-2">
            {selectedRoot && (
              <AskAboutLink
                variant="button"
                question={`Which entities are affected by ${selectedRoot} and which findings depend on it?`}
                scopeUrn={selectedRoot}
                title="Ask about this entity"
              >
                Ask
              </AskAboutLink>
            )}
            <button type="button" onClick={refreshImpact} disabled={!canRefresh} className="rounded-md border border-slate-200 bg-indigo-500 px-3 py-1.5 text-[13px] font-medium text-white transition hover:bg-indigo-600 disabled:opacity-50">
              Refresh
            </button>
          </div>
        }
      />

      <div className="rounded-lg border border-slate-200 bg-white px-5 py-4">
        <div className="grid gap-3 md:grid-cols-[1fr_2fr_120px]">
          <label className={labelClass}>Tenant<input value={tenantID} onChange={(e) => setTenantID(e.target.value)} placeholder="All" className={inputClass} /></label>
          <label className={labelClass}>Entity Root<input value={rootURN} onChange={(e) => setRootURN(e.target.value)} placeholder={fallbackRoot || "urn:cerebro:..."} className={inputClass} /></label>
          <label className={labelClass}>Limit<input value={limit} onChange={(e) => setLimit(e.target.value)} className={inputClass} /></label>
        </div>
        {!rootURN && fallbackRoot && (
          <div className="mt-2 text-[12px] text-slate-500">
            Showing highest-priority entity: <span className="font-mono text-slate-700">{shortEntity(fallbackRoot)}</span>
          </div>
        )}
      </div>

      {(fallbackFindings.loading || loading) && <LoadingBlock label="Loading affected assets..." />}
      {showUnavailableState && <ErrorBlock error={loadError || "Unable to load affected assets."} onRetry={refreshImpact} recoveryDetail="Affected assets will appear when the API is reachable." />}
      {showHardError && <ErrorBlock error={loadError || "Unable to load affected assets."} onRetry={refreshImpact} />}

      <div className="grid gap-4 md:grid-cols-4">
        <MetricCard label="Root Entity" value={metricValueForState({ state: metricState, value: shortEntity(selectedRoot) })} detail={showUnavailableState ? "waiting for API" : "impact anchor"} />
        <MetricCard
          label="Avg Risk"
          value={showUnavailableState ? metricValueForState({ state: metricState, value: "Unknown" }) : <RiskBadge score={averageRiskScore(findings)} />}
          detail={showUnavailableState ? "waiting for API" : "related risk"}
        />
        <MetricCard label="Nodes" value={metricValueForState({ state: metricState, value: nodeCount })} detail={showUnavailableState ? "waiting for API" : "entities in view"} />
        <MetricCard label="Relations" value={metricValueForState({ state: metricState, value: relationCount })} detail={showUnavailableState ? "waiting for API" : "graph links"} />
      </div>

      {!selectedRoot && !fallbackFindings.loading && !showHardError && (
        <EmptyBlock
          label={showUnavailableState
            ? "Enter an entity URN to query impact once Cerebro is reachable."
            : "No entities available. Enter an entity URN to query impact."}
        />
      )}

      {data && (
        <>
          <Panel
            title="Relationships"
            action={selectedRoot ? <Link href={`/evidence?graph_root_urn=${encodeURIComponent(selectedRoot)}`} className="text-[12px] font-medium text-indigo-600 hover:text-indigo-800">Evidence for root</Link> : undefined}
          >
            <GraphViewer graph={graph} />
          </Panel>
          <Panel title="Related Findings">
            <FindingTable findings={findings} empty="No findings directly attached to this entity." />
          </Panel>
        </>
      )}
    </div>
  );
}
