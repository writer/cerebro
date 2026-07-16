"use client";

import Link from "next/link";
import { useCallback, useMemo, useState } from "react";
import { FileText, GitBranch, Link2, PackageCheck, RefreshCw, Search, ShieldCheck } from "lucide-react";

import DataTable, { type TableColumn, WorklistTable } from "@/components/grc/DataTable";
import { AppliedFilterChips, DataStateBanner, PageHeader, ResultLimitNotice } from "@/components/grc/Primitives";
import { evidencePacketMetrics, evidencePacketReadinessLabel, evidenceReviewState } from "@/lib/evidence-packets";
import { countLabel } from "@/lib/format";
import type { GRCCollectionSource, GRCControlPosture, GRCEvidence, GRCEvidenceItemRecord, GRCEvidenceLineage, GRCListMeta, GRCEvidencePacketsResponse, GRCEvidenceRequest, GRCQuestionnaireEvidenceAnswer } from "@/lib/grc";
import { displayDate, shortEntity } from "@/lib/grc";
import { grcPath, useDebouncedValue, useGRCQuery } from "@/lib/grc-client";
import { useGRCFilterState } from "@/lib/grc-filters";
import { GRC_WORKLIST_LIMIT, grcBoundedRows, grcLoadedRows } from "@/lib/grc-list";
import { useQueryParamState } from "@/lib/query-params";
import { metricDetailForState, metricValueForState, runtimeStateDescription, type RuntimeState } from "@/lib/runtime-state";

type EvidenceResponse = { evidence: GRCEvidence[]; meta?: GRCListMeta; generated_at: string };
type EvidenceStat = {
  detail?: string;
  intent?: "neutral" | "danger" | "warning" | "success";
  label: string;
  state: RuntimeState;
  value: number | string;
};

type EvidenceSection = "register" | "package";

const evidenceSections: Array<{ id: EvidenceSection; label: string }> = [
  { id: "register", label: "Evidence register" },
  { id: "package", label: "Package workflow" },
];

const evidenceSectionFromParam = (value: string): EvidenceSection =>
  evidenceSections.some((section) => section.id === value) ? value as EvidenceSection : "register";

const inputClass = "mt-1 w-full rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-3 py-1.5 text-[13px] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-[color:var(--ring)] focus:outline-none focus:ring-1 focus:ring-[color:var(--ring)]";
const labelClass = "text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)]";
const linkClass = "text-indigo-600 hover:text-indigo-800 dark:text-indigo-400 dark:hover:text-indigo-300";
const primaryTextClass = "text-[var(--text-primary)]";
const secondaryTextClass = "text-[var(--text-secondary)]";
const mutedTextClass = "text-[var(--text-muted)]";
const monoSecondaryClass = "font-mono text-[12px] text-[var(--text-secondary)]";
const monoMutedClass = "font-mono text-[12px] text-[var(--text-muted)]";
const countTextClass = "tabular-nums text-[var(--text-secondary)]";

const questionnaireCitationCount = (answer: GRCQuestionnaireEvidenceAnswer) =>
  (answer.source_evidence?.length ?? 0) +
  (answer.policy_documents?.length ?? 0) +
  (answer.citations?.evidence_ids?.length ?? 0) +
  (answer.citations?.rule_ids?.length ?? 0) +
  (answer.citations?.claim_ids?.length ?? 0) +
  (answer.citations?.event_ids?.length ?? 0) +
  (answer.citations?.run_ids?.length ?? 0) +
  (answer.citations?.graph_root_urns?.length ?? 0);

export default function EvidencePage() {
  const [sectionParam, setSectionParam] = useQueryParamState("view");
  const [tenantID, setTenantID] = useQueryParamState("tenant_id");
  const [findingID, setFindingID] = useQueryParamState("finding_id");
  const [runID, setRunID] = useQueryParamState("run_id");
  const [ruleID, setRuleID] = useQueryParamState("rule_id");
  const [graphRoot, setGraphRoot] = useQueryParamState("graph_root_urn");
  const [selectedEvidenceID, setSelectedEvidenceID] = useState<string | null>(null);
  const debouncedTenantID = useDebouncedValue(tenantID.trim());
  const debouncedFindingID = useDebouncedValue(findingID.trim());
  const debouncedRunID = useDebouncedValue(runID.trim());
  const debouncedRuleID = useDebouncedValue(ruleID.trim());
  const debouncedGraphRoot = useDebouncedValue(graphRoot.trim());
  const activeSection = evidenceSectionFromParam(sectionParam);
  const shouldLoadPackaged = activeSection === "package";
  const setActiveSection = useCallback((section: EvidenceSection) => {
    setSectionParam(section === "register" ? "" : section);
  }, [setSectionParam]);
  const path = useMemo(
    () => grcPath("/grc/evidence", {
      tenant_id: debouncedTenantID,
      finding_id: debouncedFindingID,
      run_id: debouncedRunID,
      rule_id: debouncedRuleID,
      graph_root_urn: debouncedGraphRoot,
      limit: GRC_WORKLIST_LIMIT,
    }),
    [debouncedFindingID, debouncedGraphRoot, debouncedRuleID, debouncedRunID, debouncedTenantID],
  );
  const packagedPath = useMemo(
    () => shouldLoadPackaged ? grcPath("/grc/evidence-packets", {
      tenant_id: debouncedTenantID,
      limit: GRC_WORKLIST_LIMIT,
    }) : null,
    [debouncedTenantID, shouldLoadPackaged],
  );
  const { data, error, loading, lastSuccessfulAt, reload, state: queryState } = useGRCQuery<EvidenceResponse>(path);
  const { data: packagedData, error: packagedError, loading: packagedLoading, lastSuccessfulAt: packagedLastSuccessfulAt, reload: reloadPackaged, state: packagedQueryState } = useGRCQuery<GRCEvidencePacketsResponse>(packagedPath);
  const isRefreshing = loading && Boolean(data);
  const metricState: RuntimeState = queryState === "stale" ? "ready" : queryState === "empty" ? "ready" : queryState;
  const packagedMetricState: RuntimeState = packagedQueryState === "stale" ? "ready" : packagedQueryState;
  const boundedEvidence = useMemo(
    () => grcBoundedRows({ rows: data?.evidence, limit: GRC_WORKLIST_LIMIT, meta: data?.meta }),
    [data?.evidence, data?.meta],
  );
  const evidenceMeta = data ? boundedEvidence.meta : undefined;
  const evidenceView = useMemo(() => {
    const evidence = boundedEvidence.rows;
    const roots = new Set<string>();
    let events = 0, claims = 0;
    evidence.forEach((i) => {
      events += i.event_ids?.length ?? 0;
      claims += i.claim_ids?.length ?? 0;
      i.graph_root_urns?.forEach((u) => roots.add(u));
    });
    return { claims, events, evidence, graphRoots: roots.size };
  }, [boundedEvidence.rows]);
  const { claims, events, evidence, graphRoots } = evidenceView;
  const packagedMetrics = useMemo(() => evidencePacketMetrics(packagedData), [packagedData]);
  const selectedEvidence = evidence.find((item) => item.id === selectedEvidenceID) ?? null;
  const filterState = useGRCFilterState([
    { key: "tenant_id", label: "Tenant", value: tenantID, setValue: setTenantID },
    { key: "finding_id", label: "Finding", value: findingID, setValue: setFindingID },
    { key: "run_id", label: "Run", value: runID, setValue: setRunID },
    { key: "rule_id", label: "Rule", value: ruleID, setValue: setRuleID },
    { key: "graph_root_urn", label: "Graph root", value: graphRoot, setValue: setGraphRoot },
  ]);
  const evidenceColumns = useMemo<TableColumn<GRCEvidence>[]>(() => [
    { key: "id", label: "Evidence", render: (_value, item) => <span className={monoSecondaryClass}>{item.id}</span> },
    {
      key: "finding_id",
      label: "Finding",
      render: (_value, item) => item.finding_id ? (
        <Link href={`/findings/${encodeURIComponent(item.finding_id)}`} className={`font-medium text-[var(--text-primary)] hover:text-indigo-600 dark:hover:text-indigo-300`}>
          {item.finding_title || item.finding_id}
        </Link>
      ) : <span className={mutedTextClass}>&mdash;</span>,
    },
    {
      key: "run_id",
      label: "Run / Rule",
      render: (_value, item) => (
        <div className={`text-[12px] ${mutedTextClass}`}>
          <div>{shortEntity(item.run_id)}</div>
          <div>{shortEntity(item.rule_id)}</div>
        </div>
      ),
    },
    { key: "claim_ids", label: "Claims", render: (_value, item) => <span className={countTextClass}>{item.claim_ids?.length ?? 0}</span> },
    { key: "event_ids", label: "Events", render: (_value, item) => <span className={countTextClass}>{item.event_ids?.length ?? 0}</span> },
    {
      key: "graph_root_urns",
      label: "Graph Roots",
      render: (_value, item) => (
        <>
          {(item.graph_root_urns ?? []).slice(0, 2).map((urn) => (
            <Link key={urn} href={`/impact?root_urn=${encodeURIComponent(urn)}`} className={`mr-2 ${linkClass}`}>{shortEntity(urn)}</Link>
          ))}
        </>
      ),
    },
    { key: "created_at", label: "Created", render: (_value, item) => <span className={mutedTextClass}>{displayDate(item.created_at)}</span> },
  ], []);
  const requestColumns = useMemo<TableColumn<GRCEvidenceRequest>[]>(() => [
    { key: "title", label: "Request", render: (_value, item) => <span className={`font-medium ${primaryTextClass}`}>{item.title || shortEntity(item.id)}</span> },
    { key: "control_id", label: "Control", render: (_value, item) => <span className={monoSecondaryClass}>{shortEntity(item.control_id)}</span> },
    { key: "status", label: "Status", render: (_value, item) => <StatusPill status={item.status} /> },
    { key: "quality", label: "Quality", render: (_value, item) => <StatusPill status={item.quality} /> },
    { key: "review_status", label: "Review", render: (_value, item) => <ReviewPill status={item.review_status} /> },
    { key: "evidence_packet_ids", label: "Packets", render: (_value, item) => <span className={countTextClass}>{item.evidence_packet_ids?.length ?? 0}</span> },
  ], []);
  const controlColumns = useMemo<TableColumn<GRCControlPosture>[]>(() => [
    { key: "title", label: "Control", render: (_value, item) => <span className={`font-medium ${primaryTextClass}`}>{item.title || shortEntity(item.id)}</span> },
    { key: "framework_name", label: "Framework", render: (_value, item) => <span className={secondaryTextClass}>{item.framework_name || "—"}</span> },
    { key: "status", label: "Status", render: (_value, item) => <StatusPill status={item.status} /> },
    { key: "evidence_score", label: "Score", render: (_value, item) => <span className={countTextClass}>{item.evidence_score}</span> },
    { key: "missing_evidence_items", label: "Missing", render: (_value, item) => <span className={countTextClass}>{item.missing_evidence_items}</span> },
    { key: "stale_evidence_items", label: "Stale", render: (_value, item) => <span className={countTextClass}>{item.stale_evidence_items}</span> },
    { key: "evidence_request_ids", label: "Requests", render: (_value, item) => <span className={countTextClass}>{item.evidence_request_ids?.length ?? 0}</span> },
  ], []);
  const sourceColumns = useMemo<TableColumn<GRCCollectionSource>[]>(() => [
    { key: "source_id", label: "Source", render: (_value, item) => <span className={monoSecondaryClass}>{item.source_id || shortEntity(item.runtime_id)}</span> },
    { key: "runtime_id", label: "Runtime", render: (_value, item) => <span className={monoMutedClass}>{shortEntity(item.runtime_id)}</span> },
    { key: "status", label: "Status", render: (_value, item) => <StatusPill status={item.status} /> },
    { key: "evidence_item_count", label: "Evidence", render: (_value, item) => <span className={countTextClass}>{item.evidence_item_count}</span> },
    { key: "finding_count", label: "Findings", render: (_value, item) => <span className={countTextClass}>{item.finding_count}</span> },
    { key: "last_synced_at", label: "Synced", render: (_value, item) => <span className={mutedTextClass}>{displayDate(item.last_synced_at)}</span> },
  ], []);
  const questionnaireAnswerColumns = useMemo<TableColumn<GRCQuestionnaireEvidenceAnswer>[]>(() => [
    { key: "question", label: "Question", render: (_value, item) => <span className={`font-medium ${primaryTextClass}`}>{item.question || shortEntity(item.question_id)}</span> },
    { key: "answer_state", label: "Answer", render: (_value, item) => <StatusPill status={item.answer_state} /> },
    { key: "review_state", label: "Review", render: (_value, item) => <ReviewPill status={item.review_state} /> },
    { key: "controls", label: "Controls", render: (_value, item) => <span className={countTextClass}>{item.controls?.length ?? 0}</span> },
    { key: "evidence_packet_ids", label: "Packets", render: (_value, item) => <span className={countTextClass}>{item.evidence_packet_ids?.length ?? 0}</span> },
    { key: "citations", label: "Citations", render: (_value, item) => <span className={countTextClass}>{questionnaireCitationCount(item)}</span> },
    { key: "missing_evidence", label: "Gaps", render: (_value, item) => <span className={countTextClass}>{item.missing_evidence?.length ?? 0}</span> },
  ], []);
  const itemColumns = useMemo<TableColumn<GRCEvidenceItemRecord>[]>(() => [
    { key: "id", label: "Evidence", render: (_value, item) => <span className={monoSecondaryClass}>{shortEntity(item.id)}</span> },
    { key: "finding_id", label: "Finding", render: (_value, item) => <span className={monoMutedClass}>{shortEntity(item.finding_id)}</span> },
    { key: "rule_id", label: "Rule", render: (_value, item) => <span className={monoMutedClass}>{shortEntity(item.rule_id)}</span> },
    { key: "evidence_packet_ids", label: "Packets", render: (_value, item) => <span className={countTextClass}>{item.evidence_packet_ids?.length ?? 0}</span> },
    { key: "graph_root_urns", label: "Roots", render: (_value, item) => <span className={countTextClass}>{item.graph_root_urns?.length ?? 0}</span> },
    { key: "last_observed_at", label: "Observed", render: (_value, item) => <span className={mutedTextClass}>{displayDate(item.last_observed_at)}</span> },
  ], []);
  const lineageColumns = useMemo<TableColumn<GRCEvidenceLineage>[]>(() => [
    { key: "evidence_id", label: "Evidence", render: (_value, item) => <span className={monoSecondaryClass}>{shortEntity(item.evidence_id)}</span> },
    { key: "control_ids", label: "Controls", render: (_value, item) => <span className={countTextClass}>{item.control_ids?.length ?? 0}</span> },
    { key: "evidence_packet_ids", label: "Packets", render: (_value, item) => <span className={countTextClass}>{item.evidence_packet_ids?.length ?? 0}</span> },
    { key: "claim_ids", label: "Claims", render: (_value, item) => <span className={countTextClass}>{item.claim_ids?.length ?? 0}</span> },
    { key: "event_ids", label: "Events", render: (_value, item) => <span className={countTextClass}>{item.event_ids?.length ?? 0}</span> },
    { key: "graph_root_urns", label: "Roots", render: (_value, item) => <span className={countTextClass}>{item.graph_root_urns?.length ?? 0}</span> },
  ], []);
  const activeEvidence = selectedEvidence ?? evidence[0] ?? null;
  const activeEvidenceID = activeEvidence?.id ?? null;
  const detailRows = activeEvidence ? [
    ["Evidence ID", activeEvidence.id],
    ["Finding", activeEvidence.finding_id || "—"],
    ["Runtime", activeEvidence.runtime_id || "—"],
    ["Run", activeEvidence.run_id || "—"],
    ["Rule", activeEvidence.rule_id || "—"],
    ["Created", displayDate(activeEvidence.created_at)],
  ] : [];
  const evidenceRows = grcLoadedRows({ loaded: evidence.length, limit: GRC_WORKLIST_LIMIT, meta: evidenceMeta });
  const totalEvidence = evidenceRows.total ?? evidenceRows.loaded;
  const evidenceStats: EvidenceStat[] = [
    { label: "Evidence items", value: totalEvidence, detail: evidenceRows.truncated ? `${evidenceRows.loaded.toLocaleString()} loaded` : "in scope", state: metricState },
    { label: "Events", value: events, detail: "linked events", state: metricState },
    { label: "Claims", value: claims, detail: "claim references", state: metricState },
    { label: "Graph roots", value: graphRoots, detail: "impact anchors", state: metricState },
  ];
  const workflowStats: EvidenceStat[] = [
    { label: "Program", value: evidencePacketReadinessLabel(packagedData?.program?.status), detail: `${packagedData?.program?.readiness_score ?? 0}% readiness`, state: packagedMetricState },
    { label: "Requests", value: packagedMetrics.requests, detail: `${packagedMetrics.missingRequests} missing, ${packagedMetrics.staleRequests} stale`, state: packagedMetricState },
    { label: "Packets", value: packagedMetrics.packets, detail: `${packagedMetrics.readyPackets} ready`, state: packagedMetricState },
    { label: "Reviews", value: packagedMetrics.openReviews, detail: "open review records", intent: packagedMetrics.openReviews > 0 ? "warning" : "success", state: packagedMetricState },
    { label: "Answers", value: packagedMetrics.questionnaireAnswers, detail: "questionnaire records", state: packagedMetricState },
    { label: "Sources", value: packagedMetrics.sources, detail: `${packagedMetrics.collectedSources} collected`, state: packagedMetricState },
    { label: "Evidence items", value: packagedMetrics.evidenceItems, detail: "raw proof records", state: packagedMetricState },
    { label: "Lineage", value: packagedMetrics.lineage, detail: `${packagedMetrics.linkedLineage} fully linked`, state: packagedMetricState },
    { label: "Resources", value: packagedMetrics.resources, detail: "graph subjects", state: packagedMetricState },
    { label: "Claims", value: packagedMetrics.claims, detail: "assertion records", state: packagedMetricState },
    { label: "Runs", value: packagedMetrics.runs, detail: "evaluation runs", state: packagedMetricState },
    { label: "Graph paths", value: packagedMetrics.graphPaths, detail: "relationship records", state: packagedMetricState },
    { label: "Exports", value: packagedData?.export_artifacts?.length ?? 0, detail: "hashed artifacts", state: packagedMetricState },
  ];
  const activeFilterCount = Object.values(filterState.trimmedValues).filter(Boolean).length;
  const scopeLabel = activeFilterCount === 0
    ? shouldLoadPackaged ? "All package records" : "All evidence"
    : `${activeFilterCount} active ${activeFilterCount === 1 ? "filter" : "filters"}`;
  const scopeDescription = shouldLoadPackaged
    ? "Filter package requests, control posture, collection sources, evidence, and lineage by tenant or graph context."
    : "Narrow the register by tenant, finding, run, rule, or graph root.";
  const refreshCurrentView = () => {
    void reload();
    if (shouldLoadPackaged) void reloadPackaged();
  };

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="evidence"
        title="Evidence"
        description={shouldLoadPackaged ? "Package requests, review state, exports, lineage, and evidence completeness." : "Evidence linked to findings, rules, runs, claims, events, and graph roots."}
        action={
          <button type="button" onClick={refreshCurrentView} className="inline-flex items-center gap-1.5 rounded-md border border-[color:var(--primary)] bg-[var(--primary)] px-3 py-1.5 text-[13px] font-medium text-white transition hover:bg-[var(--primary-hover)]">
            <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
            {shouldLoadPackaged ? "Refresh workflow" : "Refresh evidence"}
          </button>
        }
      />

      <section className="overflow-hidden rounded-lg border border-[color:var(--border)] bg-[var(--surface)]">
        <div className="grid xl:grid-cols-[minmax(0,1fr)_320px]">
          <div className="space-y-4 p-5">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
                  <Search className="h-3.5 w-3.5" aria-hidden="true" />
                  Scope
                </div>
                <h2 className="mt-2 text-[17px] font-semibold text-[var(--text-primary)]">{scopeLabel}</h2>
                <p className="mt-1 text-[13px] text-[var(--text-muted)]">
                  {scopeDescription}
                </p>
              </div>
              {data?.generated_at && (
                <div className="text-right text-[12px] text-[var(--text-muted)]">
                  Loaded <span className="font-medium text-[var(--text-secondary)]">{displayDate(data.generated_at)}</span>
                </div>
              )}
            </div>
            <div className="grid gap-3 md:grid-cols-5">
              <label className={labelClass}>Tenant<input value={tenantID} onChange={(e) => setTenantID(e.target.value)} placeholder="All" className={inputClass} /></label>
              <label className={labelClass}>Finding<input value={findingID} onChange={(e) => setFindingID(e.target.value)} placeholder="All" className={inputClass} /></label>
              <label className={labelClass}>Run<input value={runID} onChange={(e) => setRunID(e.target.value)} placeholder="All" className={inputClass} /></label>
              <label className={labelClass}>Rule<input value={ruleID} onChange={(e) => setRuleID(e.target.value)} placeholder="All" className={inputClass} /></label>
              <label className={labelClass}>Graph Root<input value={graphRoot} onChange={(e) => setGraphRoot(e.target.value)} placeholder="urn:cerebro:..." className={inputClass} /></label>
            </div>
            <AppliedFilterChips filters={filterState.chips} onClearAll={filterState.clearAll} />
          </div>
          <div className="border-t border-[color:var(--border)] bg-[var(--surface-muted)] p-5 xl:border-l xl:border-t-0">
            <EvidenceScopePanel
              activeEvidence={activeEvidence}
              evidenceCount={totalEvidence}
              evidenceState={metricState}
              loadedEvidenceCount={evidenceRows.loaded}
              packageLoaded={shouldLoadPackaged}
              packageMode={shouldLoadPackaged}
              packagePacketCount={packagedMetrics.packets}
              packageRequestCount={packagedMetrics.requests}
              packageState={packagedMetricState}
              packagedError={packagedError}
            />
          </div>
        </div>
      </section>

      <EvidenceSectionSwitcher
        activeSection={activeSection}
        evidenceCount={evidence.length}
        onChange={setActiveSection}
        packageCount={packagedMetrics.requests}
        packageLoaded={Boolean(packagedData)}
      />

      {activeSection === "register" && (
        <EvidenceMetricStrip blockedLabel="Evidence totals did not load." stats={evidenceStats} pendingLabel="Loading evidence totals..." />
      )}

      {activeSection === "package" && (
        <section className="space-y-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <PackageCheck className="h-4 w-4 text-[var(--text-muted)]" aria-hidden="true" />
                <h2 className="text-[15px] font-semibold text-[var(--text-primary)]">Package workflow</h2>
              </div>
              <p className="mt-1 text-[13px] text-[var(--text-muted)]">
                Request, packet, review, export, and lineage records assembled from the evidence register.
              </p>
            </div>
            <button type="button" onClick={() => void reloadPackaged()} className="inline-flex items-center gap-1.5 rounded-md border border-[color:var(--border)] px-3 py-1.5 text-[13px] font-medium text-[var(--text-secondary)] transition hover:border-[color:var(--ring)] hover:text-[var(--primary)]">
              <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
              Refresh workflow
            </button>
          </div>
          <EvidenceWorkflowStats blockedLabel="Package records did not load." stats={workflowStats} pendingLabel="Loading package records..." />
          <DataStateBanner
            state={packagedQueryState}
            subject="Package records"
            error={packagedError}
            lastSuccessfulAt={packagedLastSuccessfulAt}
            onRetry={() => void reloadPackaged()}
            detail={packagedQueryState === "loading" ? "Loading package records." : packagedQueryState === "unavailable" ? "Package records will appear when graph data is reachable." : undefined}
          />
          {packagedError && <p className="text-[13px] text-[var(--text-muted)]">{packagedData ? "Showing the last loaded packaged evidence records; refresh will update when the endpoint is reachable." : "Packaged evidence records will appear when this endpoint is available."}</p>}
          {packagedData && (
            <div className="grid gap-4 xl:grid-cols-2">
              <WorklistTable
                title="Evidence requests"
                description="Requested proof units with quality, freshness, and review posture."
                rows={packagedData.evidence_requests ?? []}
                columns={requestColumns}
                emptyMessage="No packaged evidence requests are available."
                searchPlaceholder="Filter loaded requests"
                filterKeys={["id", "control_id", "title", "status", "quality", "review_status"]}
                pageSize={25}
                resultLimit={GRC_WORKLIST_LIMIT}
                resultNoun="requests"
                getRowKey={(item) => item.id}
                refreshing={packagedLoading}
              />
              <WorklistTable
                title="Questionnaire answers"
                description="Answer records linked to packets, controls, citations, and evidence gaps."
                rows={packagedData.questionnaire_answers ?? []}
                columns={questionnaireAnswerColumns}
                emptyMessage="No questionnaire answer records are available."
                searchPlaceholder="Filter loaded answers"
                filterKeys={["id", "question_id", "question", "answer", "answer_state", "review_state"]}
                pageSize={25}
                resultLimit={GRC_WORKLIST_LIMIT}
                resultNoun="answers"
                getRowKey={(item) => item.id}
                refreshing={packagedLoading}
              />
              <WorklistTable
                title="Control posture"
                description="Control-level evidence packaging status and mapped request counts."
                rows={packagedData.controls ?? []}
                columns={controlColumns}
                emptyMessage="No packaged controls are available."
                searchPlaceholder="Filter loaded controls"
                filterKeys={["id", "framework_name", "title", "status", "evidence_quality", "mapped_rules"]}
                pageSize={25}
                resultLimit={GRC_WORKLIST_LIMIT}
                resultNoun="controls"
                getRowKey={(item) => item.id}
                refreshing={packagedLoading}
              />
              <WorklistTable
                title="Collection sources"
                description="Runtime collection status, sync freshness, and evidence coverage."
                rows={packagedData.collection_sources ?? []}
                columns={sourceColumns}
                emptyMessage="No collection source records are available."
                searchPlaceholder="Filter loaded sources"
                filterKeys={["id", "runtime_id", "source_id", "tenant_id", "status"]}
                pageSize={25}
                resultLimit={GRC_WORKLIST_LIMIT}
                resultNoun="sources"
                getRowKey={(item) => item.id}
                refreshing={packagedLoading}
              />
              <WorklistTable
                title="Evidence items"
                description="Raw proof records linked to findings, requests, packets, and graph anchors."
                rows={packagedData.evidence_items ?? []}
                columns={itemColumns}
                emptyMessage="No evidence item records are available."
                searchPlaceholder="Filter loaded evidence items"
                filterKeys={["id", "finding_id", "rule_id", "run_id", "source_id", "runtime_id", "graph_root_urns"]}
                pageSize={25}
                resultLimit={GRC_WORKLIST_LIMIT}
                resultNoun="evidence items"
                getRowKey={(item) => item.id}
                refreshing={packagedLoading}
              />
              <WorklistTable
                title="Evidence lineage"
                description="End-to-end links from raw proof through packets, controls, claims, events, and graph roots."
                rows={packagedData.evidence_lineage ?? []}
                columns={lineageColumns}
                emptyMessage="No evidence lineage records are available."
                searchPlaceholder="Filter loaded lineage"
                filterKeys={["id", "evidence_id", "finding_id", "rule_id", "source_id", "runtime_id", "graph_root_urns"]}
                pageSize={25}
                resultLimit={GRC_WORKLIST_LIMIT}
                resultNoun="lineage records"
                getRowKey={(item) => item.id}
                refreshing={packagedLoading}
              />
            </div>
          )}
        </section>
      )}

      {activeSection === "register" && (
        <DataStateBanner
          state={queryState}
          subject="Evidence"
          error={error}
          lastSuccessfulAt={lastSuccessfulAt}
          onRetry={() => void reload()}
          detail={queryState === "loading" ? "Loading evidence." : queryState === "unavailable" ? "Evidence will appear when graph data is reachable." : undefined}
        />
      )}

      {activeSection === "register" && data && (
        <section className="overflow-hidden rounded-lg border border-[color:var(--border)] bg-[var(--surface)]">
          <div className="grid xl:grid-cols-[minmax(0,1fr)_360px]">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[color:var(--border)] px-5 py-4">
                <div>
                  <div className="flex items-center gap-2">
                    <FileText className="h-4 w-4 text-[var(--text-muted)]" aria-hidden="true" />
                    <h2 className="text-[15px] font-semibold text-[var(--text-primary)]">Evidence register</h2>
                  </div>
                  <p className="mt-1 text-[12px] text-[var(--text-muted)]">Search proof items by finding, run, rule, claim, event, or graph root.</p>
                </div>
                {isRefreshing && <div className="text-[12px] text-[var(--text-muted)]">Refreshing evidence...</div>}
              </div>
              <div className="p-4">
                <ResultLimitNotice
                  loaded={evidence.length}
                  meta={evidenceMeta}
                  limit={GRC_WORKLIST_LIMIT}
                  noun="evidence items"
                  className="mb-3"
                />
                <DataTable
                  rows={evidence}
                  columns={evidenceColumns}
                  emptyMessage="No evidence matches this view."
                  searchPlaceholder="Filter loaded evidence"
                  filterKeys={["id", "finding_id", "finding_title", "run_id", "rule_id", "claim_ids", "event_ids", "graph_root_urns"]}
                  pageSize={50}
                  resultMeta={evidenceMeta}
                  resultLimit={GRC_WORKLIST_LIMIT}
                  resultNoun="evidence items"
                  getRowKey={(item) => item.id}
                  selectedRowKey={activeEvidenceID}
                  onRowClick={(item) => setSelectedEvidenceID(item.id)}
                  rowActions={(item) => (
                    <button type="button" onClick={() => setSelectedEvidenceID(item.id)} className={`text-[12px] font-medium ${linkClass}`}>
                      Inspect
                    </button>
                  )}
                  tableContainerClassName="overflow-auto"
                />
              </div>
            </div>

            <aside className="border-t border-[color:var(--border)] bg-[var(--surface-muted)] xl:border-l xl:border-t-0">
              <div className="flex items-start justify-between gap-3 border-b border-[color:var(--border)] p-5">
              <div>
                <div className="flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4 text-[var(--text-muted)]" aria-hidden="true" />
                  <h2 className="text-[13px] font-semibold text-[var(--text-primary)]">Evidence detail</h2>
                </div>
                <p className="mt-1 text-[12px] text-[var(--text-muted)]">Proof links and graph anchors for the selected item.</p>
              </div>
              {selectedEvidenceID && evidence[0] && selectedEvidenceID !== evidence[0].id && (
                <button type="button" onClick={() => setSelectedEvidenceID(null)} className="text-[12px] font-medium text-[var(--text-muted)] hover:text-[var(--text-primary)]">
                  Show first
                </button>
              )}
            </div>
            {activeEvidence ? (
              <div className="space-y-5 p-5">
                <div>
                  <div className="text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)]">Selected item</div>
                  <div className="mt-2 break-words font-mono text-[12px] leading-5 text-[var(--text-primary)]">{activeEvidence.id}</div>
                  {activeEvidence.finding_id && (
                    <Link href={`/findings/${encodeURIComponent(activeEvidence.finding_id)}`} className={`mt-2 inline-flex items-center gap-1.5 text-[12px] font-medium ${linkClass}`}>
                      <Link2 className="h-3.5 w-3.5" aria-hidden="true" />
                      Open finding
                    </Link>
                  )}
                </div>
                <div className="space-y-2 border-t border-[color:var(--border)] pt-4">
                  {detailRows.map(([label, value]) => (
                    <div key={label} className="flex items-start justify-between gap-4">
                      <span className="text-[12px] text-[var(--text-muted)]">{label}</span>
                      <span className="max-w-[65%] break-words text-right font-mono text-[12px] text-[var(--text-secondary)]">{value}</span>
                    </div>
                  ))}
                </div>
                <div className="border-t border-[color:var(--border)] pt-4">
                  <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
                    <GitBranch className="h-3.5 w-3.5" aria-hidden="true" />
                    Graph roots
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {(activeEvidence.graph_root_urns ?? []).map((urn) => (
                      <Link key={urn} href={`/impact?root_urn=${encodeURIComponent(urn)}`} className="rounded-md bg-indigo-50 px-2 py-1 font-mono text-[11px] text-indigo-700 hover:bg-indigo-100 dark:bg-indigo-500/15 dark:text-indigo-200 dark:hover:bg-indigo-500/25">
                        {shortEntity(urn)}
                      </Link>
                    ))}
                    {(activeEvidence.graph_root_urns ?? []).length === 0 && <span className="text-[12px] text-[var(--text-muted)]">No graph roots attached.</span>}
                  </div>
                </div>
                <div className="border-t border-[color:var(--border)] pt-4">
                  <div className="text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)]">Raw references</div>
                  <pre className="mt-2 max-h-64 overflow-auto rounded-md bg-slate-950 p-3 text-[11px] leading-5 text-slate-100">{JSON.stringify({
                    claim_ids: activeEvidence.claim_ids ?? [],
                    event_ids: activeEvidence.event_ids ?? [],
                    graph_root_urns: activeEvidence.graph_root_urns ?? [],
                  }, null, 2)}</pre>
                </div>
              </div>
            ) : (
              <div className="p-6 text-[13px] text-[var(--text-muted)]">
                Evidence details appear when a row is available.
              </div>
            )}
          </aside>
          </div>
        </section>
      )}
    </div>
  );
}

function EvidenceSectionSwitcher({
  activeSection,
  evidenceCount,
  onChange,
  packageCount,
  packageLoaded,
}: {
  activeSection: EvidenceSection;
  evidenceCount: number;
  onChange: (section: EvidenceSection) => void;
  packageCount: number;
  packageLoaded: boolean;
}) {
  const detailBySection: Record<EvidenceSection, string> = {
    register: countLabel(evidenceCount, "loaded item"),
    package: packageLoaded ? countLabel(packageCount, "request") : "Load workflow",
  };
  return (
    <section className="border-b border-[color:var(--border)] pb-2">
      <div role="tablist" aria-label="Evidence work areas" className="flex flex-wrap gap-1.5">
        {evidenceSections.map((section) => {
          const selected = activeSection === section.id;
          return (
            <button
              key={section.id}
              type="button"
              role="tab"
              aria-selected={selected}
              onClick={() => onChange(section.id)}
              className={`rounded-md border px-3 py-2 text-left text-[13px] transition ${selected ? "border-[color:var(--border-strong)] bg-[var(--surface-muted)] text-[var(--text-primary)]" : "border-transparent text-[var(--text-secondary)] hover:border-[color:var(--border)] hover:bg-[var(--surface-muted)] hover:text-[var(--text-primary)]"}`}
            >
              <span className="block font-semibold">{section.label}</span>
              <span className="mt-0.5 block text-[11px] text-[var(--text-muted)]">{detailBySection[section.id]}</span>
            </button>
          );
        })}
      </div>
    </section>
  );
}

function EvidenceScopePanel({
  activeEvidence,
  evidenceCount,
  evidenceState,
  loadedEvidenceCount,
  packageLoaded,
  packageMode,
  packagePacketCount,
  packageRequestCount,
  packageState,
  packagedError,
}: {
  activeEvidence: GRCEvidence | null;
  evidenceCount: number;
  evidenceState: RuntimeState;
  loadedEvidenceCount: number;
  packageLoaded: boolean;
  packageMode: boolean;
  packagePacketCount: number;
  packageRequestCount: number;
  packageState: RuntimeState;
  packagedError?: string | null;
}) {
  const packageText = !packageLoaded ? "Open package workflow" : packageState === "ready" ? "Package records loaded" : packagedError ? "Package records unavailable" : runtimeStateDescription(packageState);
  const currentState = packageMode ? packageState : evidenceState;
  const currentValue = packageMode ? packageRequestCount : evidenceCount;
  const currentLabel = packageMode ? "package requests" : "total evidence items";
  const currentDetail = packageMode
    ? `${packagePacketCount.toLocaleString()} packet records`
    : `${loadedEvidenceCount.toLocaleString()} loaded in register`;
  const evidenceValue = currentState === "ready"
    ? currentValue.toLocaleString()
    : metricValueForState({ state: currentState, value: currentValue });
  const evidenceDetail = currentState === "ready"
    ? currentLabel
    : metricDetailForState({ state: currentState, detail: currentLabel });
  return (
    <div className="space-y-4">
      <div>
        <div className="text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)]">Current view</div>
        <div className="mt-2 text-2xl font-semibold text-[var(--text-primary)]">{evidenceValue}</div>
        <div className="mt-1 text-[13px] text-[var(--text-muted)]">{evidenceDetail}</div>
        {currentState === "ready" && <div className="mt-1 text-[12px] text-[var(--text-muted)]">{currentDetail}</div>}
      </div>
      <div className="space-y-3 border-t border-[color:var(--border)] pt-4">
        {!packageMode && (
          <div className="flex items-start gap-2.5">
            <FileText className="mt-0.5 h-4 w-4 shrink-0 text-[var(--text-muted)]" aria-hidden="true" />
            <div>
              <div className="text-[12px] font-medium text-[var(--text-primary)]">{activeEvidence ? shortEntity(activeEvidence.id) : "No item selected"}</div>
              <div className="mt-0.5 text-[12px] text-[var(--text-muted)]">detail pane</div>
            </div>
          </div>
        )}
        <div className="flex items-start gap-2.5">
          <PackageCheck className="mt-0.5 h-4 w-4 shrink-0 text-[var(--text-muted)]" aria-hidden="true" />
          <div>
            <div className="text-[12px] font-medium text-[var(--text-primary)]">{packageText}</div>
            <div className="mt-0.5 text-[12px] text-[var(--text-muted)]">workflow records</div>
          </div>
        </div>
      </div>
    </div>
  );
}

function EvidenceMetricStrip({ blockedLabel, pendingLabel, stats }: { blockedLabel: string; pendingLabel: string; stats: EvidenceStat[] }) {
  const blockedState = deferredStatState(stats);
  if (blockedState) return <EvidenceMetricNotice blockedLabel={blockedLabel} label={pendingLabel} state={blockedState} />;

  return (
    <dl className="grid gap-y-4 border-y border-[color:var(--border)] py-4 md:grid-cols-4 md:divide-x md:divide-[color:var(--border)]">
      {stats.map((stat) => (
        <EvidenceMetricCell key={stat.label} stat={stat} className="md:px-5 first:md:pl-0 last:md:pr-0" />
      ))}
    </dl>
  );
}

function EvidenceWorkflowStats({ blockedLabel, pendingLabel, stats }: { blockedLabel: string; pendingLabel: string; stats: EvidenceStat[] }) {
  const blockedState = deferredStatState(stats);
  if (blockedState) return <EvidenceMetricNotice blockedLabel={blockedLabel} label={pendingLabel} state={blockedState} />;

  return (
    <dl className="grid gap-x-10 md:grid-cols-2 xl:grid-cols-3">
      {stats.map((stat) => (
        <EvidenceMetricCell key={stat.label} stat={stat} className="border-t border-[color:var(--border)] py-3" compact />
      ))}
    </dl>
  );
}

function EvidenceMetricNotice({ blockedLabel, label, state }: { blockedLabel: string; label: string; state: RuntimeState }) {
  const loading = state === "loading";
  const message = loading ? label : state === "error" ? blockedLabel : runtimeStateDescription(state);
  return (
    <div className="flex items-center gap-2.5 border-y border-[color:var(--border)] py-4 text-[13px] text-[var(--text-muted)]">
      {loading && (
        <svg className="h-4 w-4 animate-spin text-[var(--primary)]" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
      )}
      <span>{message}</span>
    </div>
  );
}

function EvidenceMetricCell({
  className = "",
  compact = false,
  stat,
}: {
  className?: string;
  compact?: boolean;
  stat: EvidenceStat;
}) {
  const displayedValue = metricValueForState({ state: stat.state, value: stat.value });
  const displayedDetail = metricDetailForState({ detail: stat.detail, state: stat.state });
  const intent = stat.state === "ready" ? stat.intent ?? "neutral" : stat.state === "error" ? "danger" : "neutral";
  const intentClass = {
    danger: "text-red-600 dark:text-red-300",
    neutral: "text-[var(--text-primary)]",
    success: "text-emerald-600 dark:text-emerald-300",
    warning: "text-amber-600 dark:text-amber-300",
  }[intent];

  return (
    <div className={`min-w-0 ${className}`}>
      <dt className="text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)]">{stat.label}</dt>
      <dd className={`${compact ? "mt-1 flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1" : "mt-2"}`}>
        <span className={`break-words font-semibold ${compact ? "text-[20px]" : "text-2xl"} ${intentClass}`}>{displayedValue}</span>
        {displayedDetail && <span className={`${compact ? "text-[12px]" : "mt-1.5 block text-[13px]"} text-[var(--text-muted)]`}>{displayedDetail}</span>}
      </dd>
    </div>
  );
}

function deferredStatState(stats: EvidenceStat[]) {
  const deferredStates = new Set<RuntimeState>(["error", "loading", "permission-denied", "unavailable"]);
  const firstState = stats[0]?.state;
  if (firstState && deferredStates.has(firstState) && stats.every((stat) => stat.state === firstState)) return firstState;
  return null;
}

function StatusPill({ status }: { status?: string }) {
  const normalized = (status ?? "unknown").toLowerCase();
  const blocked = new Set(["missing", "fail", "failed", "failing", "blocked", "rejected"]);
  const attention = new Set(["stale", "partial", "manual", "needs_attention", "needs_review", "warning"]);
  const ready = new Set(["satisfied", "strong", "ready", "passing", "pass", "accepted", "collected"]);
  const tone = blocked.has(normalized)
    ? "bg-red-50 text-red-700 ring-red-100 dark:bg-red-500/10 dark:text-red-200 dark:ring-red-500/25"
    : attention.has(normalized)
      ? "bg-amber-50 text-amber-700 ring-amber-100 dark:bg-amber-500/10 dark:text-amber-200 dark:ring-amber-500/25"
      : ready.has(normalized)
        ? "bg-emerald-50 text-emerald-700 ring-emerald-100 dark:bg-emerald-500/10 dark:text-emerald-200 dark:ring-emerald-500/25"
        : "bg-[var(--surface-muted)] text-[var(--text-secondary)] ring-[color:var(--border)]";
  return <span className={`inline-flex rounded-full px-2 py-0.5 text-[11px] font-medium ring-1 ${tone}`}>{status || "unknown"}</span>;
}

function ReviewPill({ status }: { status?: string }) {
  const state = evidenceReviewState(status);
  const tone =
    state === "blocked"
      ? "bg-red-50 text-red-700 ring-red-100 dark:bg-red-500/10 dark:text-red-200 dark:ring-red-500/25"
      : state === "attention"
        ? "bg-amber-50 text-amber-700 ring-amber-100 dark:bg-amber-500/10 dark:text-amber-200 dark:ring-amber-500/25"
        : state === "ready"
          ? "bg-emerald-50 text-emerald-700 ring-emerald-100 dark:bg-emerald-500/10 dark:text-emerald-200 dark:ring-emerald-500/25"
          : "bg-[var(--surface-muted)] text-[var(--text-secondary)] ring-[color:var(--border)]";
  return <span className={`inline-flex rounded-full px-2 py-0.5 text-[11px] font-medium ring-1 ${tone}`}>{status || "unknown"}</span>;
}
